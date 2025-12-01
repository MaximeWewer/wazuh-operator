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

// WorkerHealthStatus represents the health status of a Wazuh Worker node
type WorkerHealthStatus struct {
	// Healthy indicates if the worker is healthy
	Healthy bool `json:"healthy"`
	// Ready indicates if the worker is ready to receive agents
	Ready bool `json:"ready"`
	// Connected indicates if the worker is connected to the master
	Connected bool `json:"connected"`
	// NodeName is the worker node name
	NodeName string `json:"node_name,omitempty"`
	// MasterNode is the master node this worker is connected to
	MasterNode string `json:"master_node,omitempty"`
	// AgentCount is the number of agents connected to this worker
	AgentCount int `json:"agent_count"`
	// Error contains any error message
	Error string `json:"error,omitempty"`
}

// WorkerHealthChecker checks the health of Wazuh Worker nodes
type WorkerHealthChecker struct {
	host       string
	port       int32
	username   string
	password   string
	tlsConfig  *tls.Config
	httpClient *http.Client
	timeout    time.Duration
}

// NewWorkerHealthChecker creates a new WorkerHealthChecker
func NewWorkerHealthChecker(host string) *WorkerHealthChecker {
	return &WorkerHealthChecker{
		host:    host,
		port:    constants.PortManagerAPI,
		timeout: 10 * time.Second,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// WithPort sets the API port
func (c *WorkerHealthChecker) WithPort(port int32) *WorkerHealthChecker {
	c.port = port
	return c
}

// WithCredentials sets the API credentials
func (c *WorkerHealthChecker) WithCredentials(username, password string) *WorkerHealthChecker {
	c.username = username
	c.password = password
	return c
}

// WithTLSConfig sets the TLS configuration
func (c *WorkerHealthChecker) WithTLSConfig(config *tls.Config) *WorkerHealthChecker {
	c.tlsConfig = config
	return c
}

// WithTimeout sets the request timeout
func (c *WorkerHealthChecker) WithTimeout(timeout time.Duration) *WorkerHealthChecker {
	c.timeout = timeout
	return c
}

// Check performs a health check on the worker
func (c *WorkerHealthChecker) Check(ctx context.Context) (*WorkerHealthStatus, error) {
	status := &WorkerHealthStatus{}

	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		}
	}

	// Check node info
	nodeURL := fmt.Sprintf("https://%s:%d/cluster/local/info", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nodeURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status, nil
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		status.Error = fmt.Sprintf("request failed: %v", err)
		return status, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		status.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
		return status, nil
	}

	var nodeResp struct {
		Data struct {
			AffectedItems []struct {
				Node   string `json:"node"`
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nodeResp); err != nil {
		status.Error = fmt.Sprintf("failed to decode response: %v", err)
		return status, nil
	}

	if len(nodeResp.Data.AffectedItems) > 0 {
		item := nodeResp.Data.AffectedItems[0]
		status.NodeName = item.Node
		status.Connected = item.Status == "connected"
		status.Healthy = status.Connected
		status.Ready = status.Connected
	}

	// Check agent count for this worker
	agentCount, err := c.getAgentCount(ctx)
	if err == nil {
		status.AgentCount = agentCount
	}

	return status, nil
}

// getAgentCount returns the number of agents connected to this worker
func (c *WorkerHealthChecker) getAgentCount(ctx context.Context) (int, error) {
	agentURL := fmt.Sprintf("https://%s:%d/agents?select=id&node_name=%s", c.host, c.port, c.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURL, nil)
	if err != nil {
		return 0, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var agentResp struct {
		Data struct {
			TotalAffectedItems int `json:"total_affected_items"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&agentResp); err != nil {
		return 0, err
	}

	return agentResp.Data.TotalAffectedItems, nil
}

// IsReady checks if the worker is ready
func (c *WorkerHealthChecker) IsReady(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Ready, nil
}

// IsHealthy checks if the worker is healthy
func (c *WorkerHealthChecker) IsHealthy(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Healthy, nil
}

// WaitForReady waits for the worker to become ready
func (c *WorkerHealthChecker) WaitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for worker to be ready")
			}
			ready, err := c.IsReady(ctx)
			if err != nil {
				continue
			}
			if ready {
				return nil
			}
		}
	}
}
