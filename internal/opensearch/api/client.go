/*
Copyright 2026.

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

// Package api provides OpenSearch API client implementations
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Client provides access to the OpenSearch API
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	// cluster and namespace are used for metrics labeling
	cluster   string
	namespace string
}

// ClientConfig holds client configuration
type ClientConfig struct {
	BaseURL  string
	Username string
	Password string
	CACert   []byte
	// ClientCert and ClientKey are used for mutual TLS authentication
	// Required for certificate reload API which needs admin cert authentication
	ClientCert []byte
	ClientKey  []byte
	Insecure   bool
	Timeout    time.Duration
	// Cluster and Namespace are used for metrics labeling
	Cluster   string
	Namespace string
}

// NewClient creates a new OpenSearch API client
func NewClient(config ClientConfig) (*Client, error) {
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

	// Configure client certificate authentication if provided
	// This is required for the certificate reload API
	if len(config.ClientCert) > 0 && len(config.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Wrap transport with OpenTelemetry instrumentation
	instrumentedTransport := telemetry.WrapTransport(transport, "opensearch-api")

	timeout := config.Timeout
	if timeout == 0 {
		timeout = constants.TimeoutOpenSearchRequest
	}

	return &Client{
		baseURL:   config.BaseURL,
		username:  config.Username,
		password:  config.Password,
		cluster:   config.Cluster,
		namespace: config.Namespace,
		httpClient: &http.Client{
			Transport: instrumentedTransport,
			Timeout:   timeout,
		},
	}, nil
}

// Request makes an HTTP request to the OpenSearch API
func (c *Client) Request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	startTime := time.Now()
	operation := method + " " + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)

	// Record metrics if cluster/namespace are configured
	if c.cluster != "" && c.namespace != "" {
		duration := time.Since(startTime).Seconds()
		metrics.RecordOpenSearchAPILatency(c.cluster, c.namespace, operation, duration)

		if err != nil {
			metrics.RecordOpenSearchAPIError(c.cluster, c.namespace, operation, "request_failed")
		} else if resp.StatusCode >= 400 {
			metrics.RecordOpenSearchAPIError(c.cluster, c.namespace, operation, strconv.Itoa(resp.StatusCode))
		}
	}

	return resp, err
}

// Get makes a GET request
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.Request(ctx, "GET", path, nil)
}

// Put makes a PUT request
func (c *Client) Put(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.Request(ctx, "PUT", path, body)
}

// Post makes a POST request
func (c *Client) Post(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.Request(ctx, "POST", path, body)
}

// Delete makes a DELETE request
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.Request(ctx, "DELETE", path, nil)
}

// PutJSON makes a PUT request with a JSON payload
// This is a convenience method for updating resources via the REST API
func (c *Client) PutJSON(ctx context.Context, path string, body map[string]any) (*http.Response, error) {
	return c.Request(ctx, "PUT", path, body)
}

// IsHealthy checks if OpenSearch is healthy
func (c *Client) IsHealthy(ctx context.Context) bool {
	resp, err := c.Get(ctx, "/_cluster/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return false
	}

	return health.Status == "green" || health.Status == "yellow"
}

// CertReloadResponse represents the response from the certificate reload API
type CertReloadResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ReloadTransportCertificates calls the API to reload transport layer TLS certificates
// This is required for OpenSearch 2.13 - 2.18.x where automatic hot reload is not available
// API: PUT /_plugins/_security/api/ssl/transport/reloadcerts
// Requires admin certificate authentication
func (c *Client) ReloadTransportCertificates(ctx context.Context) (*CertReloadResponse, error) {
	resp, err := c.Put(ctx, "/_plugins/_security/api/ssl/transport/reloadcerts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to reload transport certificates: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate reload failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CertReloadResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// If response is not JSON, treat as success if status is OK
		return &CertReloadResponse{Status: "OK", Message: string(body)}, nil
	}

	return &result, nil
}

// ReloadHTTPCertificates calls the API to reload HTTP layer TLS certificates
// This is required for OpenSearch 2.13 - 2.18.x where automatic hot reload is not available
// API: PUT /_plugins/_security/api/ssl/http/reloadcerts
// Requires admin certificate authentication
func (c *Client) ReloadHTTPCertificates(ctx context.Context) (*CertReloadResponse, error) {
	resp, err := c.Put(ctx, "/_plugins/_security/api/ssl/http/reloadcerts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to reload HTTP certificates: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate reload failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CertReloadResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// If response is not JSON, treat as success if status is OK
		return &CertReloadResponse{Status: "OK", Message: string(body)}, nil
	}

	return &result, nil
}

// ReloadAllCertificates reloads both transport and HTTP certificates
// Returns errors for both if they fail, nil if both succeed
func (c *Client) ReloadAllCertificates(ctx context.Context) error {
	var errs []error

	if _, err := c.ReloadTransportCertificates(ctx); err != nil {
		errs = append(errs, fmt.Errorf("transport: %w", err))
	}

	if _, err := c.ReloadHTTPCertificates(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http: %w", err))
	}

	if len(errs) > 0 {
		var errMsg strings.Builder
		errMsg.WriteString("certificate reload errors: ")
		for i, e := range errs {
			if i > 0 {
				errMsg.WriteString("; ")
			}
			errMsg.WriteString(e.Error())
		}
		return fmt.Errorf("%s", errMsg.String())
	}

	return nil
}

// SecurityHealthResponse represents the response from the security health API
type SecurityHealthResponse struct {
	// Status is the overall health status (e.g., "UP", "DOWN")
	Status string `json:"status"`
	// Message provides additional details about the health status
	Message string `json:"message,omitempty"`
}

// CheckSecurityHealth checks if the OpenSearch security plugin is initialized and healthy
// This is useful before calling security-related APIs like certificate reload
// API: GET /_plugins/_security/health
func (c *Client) CheckSecurityHealth(ctx context.Context) (*SecurityHealthResponse, error) {
	resp, err := c.Get(ctx, "/_plugins/_security/health")
	if err != nil {
		return nil, fmt.Errorf("failed to check security health: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("security health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result SecurityHealthResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// If we got a 200 but can't parse the response, consider it healthy
		return &SecurityHealthResponse{Status: "UP", Message: string(body)}, nil
	}

	return &result, nil
}

// IsSecurityHealthy returns true if the security plugin is initialized and healthy
func (c *Client) IsSecurityHealthy(ctx context.Context) bool {
	health, err := c.CheckSecurityHealth(ctx)
	if err != nil {
		return false
	}
	return health.Status == "UP"
}

// GetIndicesCount returns the total number of indices in the cluster
// API: GET /_cat/indices?format=json
func (c *Client) GetIndicesCount(ctx context.Context) (int, error) {
	resp, err := c.Get(ctx, "/_cat/indices?format=json")
	if err != nil {
		return 0, fmt.Errorf("failed to get indices: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("cat indices request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var indices []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&indices); err != nil {
		return 0, fmt.Errorf("failed to decode indices response: %w", err)
	}

	return len(indices), nil
}

// ISMPolicyListItem represents a single ISM policy from the list response
type ISMPolicyListItem struct {
	ID          string         `json:"_id"`
	SeqNo       int64          `json:"_seq_no"`
	PrimaryTerm int64          `json:"_primary_term"`
	Policy      map[string]any `json:"policy"`
}

// ISMPoliciesListResponse represents the response from listing ISM policies
type ISMPoliciesListResponse struct {
	TotalPolicies int                 `json:"total_policies"`
	Policies      []ISMPolicyListItem `json:"policies"`
}

// GetISMPoliciesCount returns the total number of ISM policies
// API: GET /_plugins/_ism/policies
func (c *Client) GetISMPoliciesCount(ctx context.Context) (int, error) {
	resp, err := c.Get(ctx, "/_plugins/_ism/policies")
	if err != nil {
		return 0, fmt.Errorf("failed to get ISM policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("ISM policies request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var policies ISMPoliciesListResponse
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return 0, fmt.Errorf("failed to decode ISM policies response: %w", err)
	}

	return policies.TotalPolicies, nil
}
