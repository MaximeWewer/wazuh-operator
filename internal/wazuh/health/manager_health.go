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

// Package health provides health check utilities for Wazuh components
package health

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerHealthStatus represents the health status of a Wazuh Manager
type ManagerHealthStatus struct {
	// Healthy indicates overall health
	Healthy bool `json:"healthy"`
	// API indicates API availability
	API bool `json:"api"`
	// Cluster indicates cluster status
	Cluster bool `json:"cluster"`
	// ClusterEnabled indicates if cluster mode is enabled
	ClusterEnabled bool `json:"cluster_enabled"`
	// NodeType is the node type (master/worker)
	NodeType string `json:"node_type"`
	// NodeName is the name of this node
	NodeName string `json:"node_name"`
	// ConnectedNodes is the number of connected cluster nodes
	ConnectedNodes int `json:"connected_nodes"`
	// AgentsActive is the number of active agents
	AgentsActive int `json:"agents_active"`
	// AgentsTotal is the total number of agents
	AgentsTotal int `json:"agents_total"`
	// Error contains any error message
	Error string `json:"error,omitempty"`
}

// ManagerHealthChecker checks the health of Wazuh Manager
type ManagerHealthChecker struct {
	host       string
	port       int32
	username   string
	password   string
	tlsConfig  *tls.Config
	httpClient *http.Client
	timeout    time.Duration
}

// NewManagerHealthChecker creates a new ManagerHealthChecker
func NewManagerHealthChecker(host string) *ManagerHealthChecker {
	return &ManagerHealthChecker{
		host:    host,
		port:    constants.PortManagerAPI,
		timeout: 10 * time.Second,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // Default to skip verify for internal checks
		},
	}
}

// WithPort sets the API port
func (c *ManagerHealthChecker) WithPort(port int32) *ManagerHealthChecker {
	c.port = port
	return c
}

// WithCredentials sets the API credentials
func (c *ManagerHealthChecker) WithCredentials(username, password string) *ManagerHealthChecker {
	c.username = username
	c.password = password
	return c
}

// WithTLSConfig sets the TLS configuration
func (c *ManagerHealthChecker) WithTLSConfig(config *tls.Config) *ManagerHealthChecker {
	c.tlsConfig = config
	return c
}

// WithTimeout sets the timeout
func (c *ManagerHealthChecker) WithTimeout(timeout time.Duration) *ManagerHealthChecker {
	c.timeout = timeout
	return c
}

// Check performs a health check
func (c *ManagerHealthChecker) Check(ctx context.Context) (*ManagerHealthStatus, error) {
	status := &ManagerHealthStatus{}

	// Create HTTP client if not exists
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		}
	}

	// Check API health
	apiURL := fmt.Sprintf("https://%s:%d/", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		status.Error = fmt.Sprintf("API request failed: %v", err)
		return status, nil
	}
	defer resp.Body.Close()

	status.API = resp.StatusCode == http.StatusOK

	// Try to get cluster status
	clusterStatus, err := c.getClusterStatus(ctx)
	if err == nil && clusterStatus != nil {
		status.Cluster = clusterStatus.Enabled && clusterStatus.Running
		status.ClusterEnabled = clusterStatus.Enabled
		status.NodeType = clusterStatus.NodeType
		status.NodeName = clusterStatus.NodeName
		status.ConnectedNodes = clusterStatus.ConnectedNodes
	}

	// Try to get agent stats
	agentStats, err := c.getAgentStats(ctx)
	if err == nil && agentStats != nil {
		status.AgentsActive = agentStats.Active
		status.AgentsTotal = agentStats.Total
	}

	// Overall health
	status.Healthy = status.API && (!status.ClusterEnabled || status.Cluster)

	return status, nil
}

// ClusterStatus represents Wazuh cluster status
type ClusterStatus struct {
	Enabled        bool   `json:"enabled"`
	Running        bool   `json:"running"`
	NodeType       string `json:"node_type"`
	NodeName       string `json:"node_name"`
	ConnectedNodes int    `json:"connected_nodes"`
}

// getClusterStatus gets the cluster status from the API
func (c *ManagerHealthChecker) getClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	url := fmt.Sprintf("https://%s:%d/cluster/status", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apiResp struct {
		Data struct {
			Enabled string `json:"enabled"`
			Running string `json:"running"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return &ClusterStatus{
		Enabled: apiResp.Data.Enabled == "yes",
		Running: apiResp.Data.Running == "yes",
	}, nil
}

// AgentStats represents agent statistics
type AgentStats struct {
	Active int `json:"active"`
	Total  int `json:"total"`
}

// getAgentStats gets agent statistics from the API
func (c *ManagerHealthChecker) getAgentStats(ctx context.Context) (*AgentStats, error) {
	url := fmt.Sprintf("https://%s:%d/agents/summary/status", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var apiResp struct {
		Data struct {
			Connection struct {
				Active int `json:"active"`
				Total  int `json:"total"`
			} `json:"connection"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	return &AgentStats{
		Active: apiResp.Data.Connection.Active,
		Total:  apiResp.Data.Connection.Total,
	}, nil
}

// IsReady checks if the manager is ready to serve requests
func (c *ManagerHealthChecker) IsReady(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.API, nil
}

// IsHealthy checks if the manager is fully healthy
func (c *ManagerHealthChecker) IsHealthy(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Healthy, nil
}
