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

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// OpenSearchClient provides a public interface to interact with OpenSearch
type OpenSearchClient struct {
	adapter *adapters.OpenSearchHTTPAdapter
}

// OpenSearchClientConfig holds configuration for OpenSearchClient
type OpenSearchClientConfig struct {
	// BaseURL is the OpenSearch base URL (e.g., https://opensearch:9200)
	BaseURL string

	// Username for authentication
	Username string

	// Password for authentication
	Password string

	// CACert is the CA certificate for TLS verification
	CACert []byte

	// Insecure skips TLS verification if true
	Insecure bool

	// Timeout for HTTP requests
	Timeout time.Duration
}

// NewOpenSearchClient creates a new OpenSearchClient
func NewOpenSearchClient(config OpenSearchClientConfig) (*OpenSearchClient, error) {
	adapter, err := adapters.NewOpenSearchHTTPAdapter(adapters.OpenSearchConfig{
		BaseURL:  config.BaseURL,
		Username: config.Username,
		Password: config.Password,
		CACert:   config.CACert,
		Insecure: config.Insecure,
		Timeout:  config.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSearch adapter: %w", err)
	}

	return &OpenSearchClient{
		adapter: adapter,
	}, nil
}

// ClusterHealth represents OpenSearch cluster health
type ClusterHealth struct {
	ClusterName                 string
	Status                      string
	NumberOfNodes               int
	NumberOfDataNodes           int
	ActivePrimaryShards         int
	ActiveShards                int
	RelocatingShards            int
	InitializingShards          int
	UnassignedShards            int
	ActiveShardsPercentAsNumber float64
}

// GetClusterHealth returns the cluster health
func (c *OpenSearchClient) GetClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	health, err := c.adapter.GetClusterHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster health: %w", err)
	}

	return &ClusterHealth{
		ClusterName:                 health.ClusterName,
		Status:                      health.Status,
		NumberOfNodes:               health.NumberOfNodes,
		NumberOfDataNodes:           health.NumberOfDataNodes,
		ActivePrimaryShards:         health.ActivePrimaryShards,
		ActiveShards:                health.ActiveShards,
		RelocatingShards:            health.RelocatingShards,
		InitializingShards:          health.InitializingShards,
		UnassignedShards:            health.UnassignedShards,
		ActiveShardsPercentAsNumber: health.ActiveShardsPercentAsNumber,
	}, nil
}

// IsHealthy checks if the cluster is healthy (green or yellow)
func (c *OpenSearchClient) IsHealthy(ctx context.Context) bool {
	return c.adapter.IsHealthy(ctx)
}

// CreateIndex creates an index with the given settings
func (c *OpenSearchClient) CreateIndex(ctx context.Context, indexName string, settings map[string]interface{}) error {
	return c.adapter.CreateIndex(ctx, indexName, settings)
}

// DeleteIndex deletes an index
func (c *OpenSearchClient) DeleteIndex(ctx context.Context, indexName string) error {
	return c.adapter.DeleteIndex(ctx, indexName)
}

// IndexExists checks if an index exists
func (c *OpenSearchClient) IndexExists(ctx context.Context, indexName string) (bool, error) {
	return c.adapter.IndexExists(ctx, indexName)
}

// User represents an OpenSearch user
type User struct {
	Password     string
	BackendRoles []string
	Attributes   map[string]string
	Description  string
	Roles        []string
}

// CreateUser creates a security user
func (c *OpenSearchClient) CreateUser(ctx context.Context, username string, user User) error {
	return c.adapter.CreateUser(ctx, username, adapters.SecurityUser{
		Password:                user.Password,
		BackendRoles:            user.BackendRoles,
		Attributes:              user.Attributes,
		Description:             user.Description,
		OpendistroSecurityRoles: user.Roles,
	})
}

// DeleteUser deletes a security user
func (c *OpenSearchClient) DeleteUser(ctx context.Context, username string) error {
	return c.adapter.DeleteUser(ctx, username)
}

// UserExists checks if a user exists
func (c *OpenSearchClient) UserExists(ctx context.Context, username string) (bool, error) {
	user, err := c.adapter.GetUser(ctx, username)
	if err != nil {
		return false, err
	}
	return user != nil, nil
}

// Role represents an OpenSearch security role
type Role struct {
	Description        string
	ClusterPermissions []string
	IndexPermissions   []IndexPermission
	TenantPermissions  []TenantPermission
}

// IndexPermission represents index permissions
type IndexPermission struct {
	IndexPatterns  []string
	AllowedActions []string
}

// TenantPermission represents tenant permissions
type TenantPermission struct {
	TenantPatterns []string
	AllowedActions []string
}

// CreateRole creates a security role
func (c *OpenSearchClient) CreateRole(ctx context.Context, roleName string, role Role) error {
	indexPerms := make([]adapters.IndexPermission, len(role.IndexPermissions))
	for i, p := range role.IndexPermissions {
		indexPerms[i] = adapters.IndexPermission{
			IndexPatterns:  p.IndexPatterns,
			AllowedActions: p.AllowedActions,
		}
	}

	tenantPerms := make([]adapters.TenantPermission, len(role.TenantPermissions))
	for i, p := range role.TenantPermissions {
		tenantPerms[i] = adapters.TenantPermission{
			TenantPatterns: p.TenantPatterns,
			AllowedActions: p.AllowedActions,
		}
	}

	return c.adapter.CreateRole(ctx, roleName, adapters.SecurityRole{
		Description:        role.Description,
		ClusterPermissions: role.ClusterPermissions,
		IndexPermissions:   indexPerms,
		TenantPermissions:  tenantPerms,
	})
}
