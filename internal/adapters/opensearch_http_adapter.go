/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package adapters

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OpenSearchHTTPAdapter provides HTTP access to OpenSearch
type OpenSearchHTTPAdapter struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// OpenSearchConfig holds OpenSearch connection configuration
type OpenSearchConfig struct {
	BaseURL  string
	Username string
	Password string
	CACert   []byte
	Insecure bool
	Timeout  time.Duration
}

// NewOpenSearchHTTPAdapter creates a new OpenSearch HTTP adapter
func NewOpenSearchHTTPAdapter(config OpenSearchConfig) (*OpenSearchHTTPAdapter, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
	}

	if len(config.CACert) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(config.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &OpenSearchHTTPAdapter{
		baseURL:  config.BaseURL,
		username: config.Username,
		password: config.Password,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}, nil
}

// doRequest performs an authenticated request
func (a *OpenSearchHTTPAdapter) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(a.username, a.password)
	req.Header.Set("Content-Type", "application/json")

	return a.httpClient.Do(req)
}

// ClusterHealth represents OpenSearch cluster health
type ClusterHealth struct {
	ClusterName                 string  `json:"cluster_name"`
	Status                      string  `json:"status"`
	TimedOut                    bool    `json:"timed_out"`
	NumberOfNodes               int     `json:"number_of_nodes"`
	NumberOfDataNodes           int     `json:"number_of_data_nodes"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	ActiveShards                int     `json:"active_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

// GetClusterHealth returns the cluster health
func (a *OpenSearchHTTPAdapter) GetClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	resp, err := a.doRequest(ctx, "GET", "/_cluster/health", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get cluster health: %s", string(body))
	}

	var health ClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode cluster health: %w", err)
	}

	return &health, nil
}

// IsHealthy checks if the cluster is healthy (green or yellow)
func (a *OpenSearchHTTPAdapter) IsHealthy(ctx context.Context) bool {
	health, err := a.GetClusterHealth(ctx)
	if err != nil {
		return false
	}
	return health.Status == "green" || health.Status == "yellow"
}

// SecurityUser represents an OpenSearch security user
type SecurityUser struct {
	Hash                    string            `json:"hash,omitempty"`
	Password                string            `json:"password,omitempty"`
	Reserved                bool              `json:"reserved,omitempty"`
	Hidden                  bool              `json:"hidden,omitempty"`
	BackendRoles            []string          `json:"backend_roles,omitempty"`
	Attributes              map[string]string `json:"attributes,omitempty"`
	Description             string            `json:"description,omitempty"`
	OpendistroSecurityRoles []string          `json:"opendistro_security_roles,omitempty"`
}

// CreateUser creates a security user
func (a *OpenSearchHTTPAdapter) CreateUser(ctx context.Context, username string, user SecurityUser) error {
	resp, err := a.doRequest(ctx, "PUT", "/_plugins/_security/api/internalusers/"+username, user)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create user: %s", string(body))
	}

	return nil
}

// GetUser retrieves a security user
func (a *OpenSearchHTTPAdapter) GetUser(ctx context.Context, username string) (*SecurityUser, error) {
	resp, err := a.doRequest(ctx, "GET", "/_plugins/_security/api/internalusers/"+username, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user: %s", string(body))
	}

	var users map[string]SecurityUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	if user, ok := users[username]; ok {
		return &user, nil
	}

	return nil, nil
}

// DeleteUser deletes a security user
func (a *OpenSearchHTTPAdapter) DeleteUser(ctx context.Context, username string) error {
	resp, err := a.doRequest(ctx, "DELETE", "/_plugins/_security/api/internalusers/"+username, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete user: %s", string(body))
	}

	return nil
}

// SecurityRole represents an OpenSearch security role
type SecurityRole struct {
	Reserved           bool               `json:"reserved,omitempty"`
	Hidden             bool               `json:"hidden,omitempty"`
	Description        string             `json:"description,omitempty"`
	ClusterPermissions []string           `json:"cluster_permissions,omitempty"`
	IndexPermissions   []IndexPermission  `json:"index_permissions,omitempty"`
	TenantPermissions  []TenantPermission `json:"tenant_permissions,omitempty"`
}

// IndexPermission represents index permissions
type IndexPermission struct {
	IndexPatterns         []string `json:"index_patterns"`
	DocumentLevelSecurity string   `json:"dls,omitempty"`
	FieldLevelSecurity    []string `json:"fls,omitempty"`
	MaskedFields          []string `json:"masked_fields,omitempty"`
	AllowedActions        []string `json:"allowed_actions"`
}

// TenantPermission represents tenant permissions
type TenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// CreateRole creates a security role
func (a *OpenSearchHTTPAdapter) CreateRole(ctx context.Context, roleName string, role SecurityRole) error {
	resp, err := a.doRequest(ctx, "PUT", "/_plugins/_security/api/roles/"+roleName, role)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role: %s", string(body))
	}

	return nil
}

// DeleteRole deletes a security role
func (a *OpenSearchHTTPAdapter) DeleteRole(ctx context.Context, roleName string) error {
	resp, err := a.doRequest(ctx, "DELETE", "/_plugins/_security/api/roles/"+roleName, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete role: %s", string(body))
	}

	return nil
}

// CreateIndex creates an index
func (a *OpenSearchHTTPAdapter) CreateIndex(ctx context.Context, indexName string, settings map[string]interface{}) error {
	resp, err := a.doRequest(ctx, "PUT", "/"+indexName, settings)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create index: %s", string(body))
	}

	return nil
}

// DeleteIndex deletes an index
func (a *OpenSearchHTTPAdapter) DeleteIndex(ctx context.Context, indexName string) error {
	resp, err := a.doRequest(ctx, "DELETE", "/"+indexName, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete index: %s", string(body))
	}

	return nil
}

// IndexExists checks if an index exists
func (a *OpenSearchHTTPAdapter) IndexExists(ctx context.Context, indexName string) (bool, error) {
	resp, err := a.doRequest(ctx, "HEAD", "/"+indexName, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}
