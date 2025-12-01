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

// Package client provides public client implementations for external APIs
package client

import (
	"context"
	"fmt"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// WazuhClient provides a public interface to interact with Wazuh API
type WazuhClient struct {
	adapter *adapters.WazuhAPIAdapter
}

// WazuhClientConfig holds configuration for WazuhClient
type WazuhClientConfig struct {
	// BaseURL is the Wazuh API base URL (e.g., https://wazuh-manager:55000)
	BaseURL string

	// Username for API authentication
	Username string

	// Password for API authentication
	Password string

	// Insecure skips TLS verification if true
	Insecure bool

	// Timeout for HTTP requests
	Timeout time.Duration
}

// NewWazuhClient creates a new WazuhClient
func NewWazuhClient(config WazuhClientConfig) *WazuhClient {
	adapter := adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  config.BaseURL,
		Username: config.Username,
		Password: config.Password,
		Insecure: config.Insecure,
		Timeout:  config.Timeout,
	})

	return &WazuhClient{
		adapter: adapter,
	}
}

// ClusterStatus represents the status of the Wazuh cluster
type ClusterStatus struct {
	Enabled bool
	Running bool
	Name    string
	Node    string
}

// GetClusterStatus returns the cluster status
func (c *WazuhClient) GetClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	status, err := c.adapter.GetClusterStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster status: %w", err)
	}

	return &ClusterStatus{
		Enabled: status.Enabled,
		Running: status.Running,
		Name:    status.Name,
		Node:    status.Node,
	}, nil
}

// NodeInfo represents information about a Wazuh node
type NodeInfo struct {
	Name    string
	Type    string
	Version string
	IP      string
}

// GetClusterNodes returns information about cluster nodes
func (c *WazuhClient) GetClusterNodes(ctx context.Context) ([]NodeInfo, error) {
	nodes, err := c.adapter.GetClusterNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster nodes: %w", err)
	}

	result := make([]NodeInfo, len(nodes))
	for i, node := range nodes {
		result[i] = NodeInfo{
			Name:    node.Name,
			Type:    node.Type,
			Version: node.Version,
			IP:      node.IP,
		}
	}

	return result, nil
}

// ManagerInfo represents Wazuh manager information
type ManagerInfo struct {
	Version string
	Name    string
}

// GetManagerInfo returns manager information
func (c *WazuhClient) GetManagerInfo(ctx context.Context) (*ManagerInfo, error) {
	info, err := c.adapter.GetManagerInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get manager info: %w", err)
	}

	return &ManagerInfo{
		Version: info.Version,
		Name:    info.Name,
	}, nil
}

// IsHealthy checks if the Wazuh API is healthy
func (c *WazuhClient) IsHealthy(ctx context.Context) bool {
	return c.adapter.IsHealthy(ctx)
}

// Authenticate authenticates with the Wazuh API
func (c *WazuhClient) Authenticate(ctx context.Context) error {
	return c.adapter.Authenticate(ctx)
}
