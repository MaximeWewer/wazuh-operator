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

package adapters

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WazuhAPIAdapter provides access to the Wazuh Manager API
type WazuhAPIAdapter struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	token      string
	tokenExp   time.Time
}

// WazuhAPIConfig holds Wazuh API configuration
type WazuhAPIConfig struct {
	BaseURL  string
	Username string
	Password string
	Insecure bool
	Timeout  time.Duration
}

// NewWazuhAPIAdapter creates a new Wazuh API adapter
func NewWazuhAPIAdapter(config WazuhAPIConfig) *WazuhAPIAdapter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
	}

	// Wrap transport with OpenTelemetry instrumentation
	instrumentedTransport := telemetry.WrapTransport(transport, "wazuh-api")

	timeout := config.Timeout
	if timeout == 0 {
		timeout = constants.TimeoutAPIRequest
	}

	return &WazuhAPIAdapter{
		baseURL:  config.BaseURL,
		username: config.Username,
		password: config.Password,
		httpClient: &http.Client{
			Transport: instrumentedTransport,
			Timeout:   timeout,
		},
	}
}

// AuthResponse represents the Wazuh API auth response
type AuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Error int `json:"error"`
}

// Authenticate authenticates with the Wazuh API
func (a *WazuhAPIAdapter) Authenticate(ctx context.Context) error {
	if a.token != "" && time.Now().Before(a.tokenExp) {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/security/user/authenticate", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.SetBasicAuth(a.username, a.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: %s", string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	a.token = authResp.Data.Token
	a.tokenExp = time.Now().Add(constants.TokenValidityDuration)

	return nil
}

// doRequest performs an authenticated request with JSON content type
func (a *WazuhAPIAdapter) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	return a.doRequestWithContentType(ctx, method, path, body, "application/json")
}

// doRequestWithContentType performs an authenticated request with a custom content type
func (a *WazuhAPIAdapter) doRequestWithContentType(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	if err := a.Authenticate(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", contentType)

	return a.httpClient.Do(req)
}

// ClusterStatus represents Wazuh cluster status
type ClusterStatus struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Name    string `json:"name"`
	Node    string `json:"node"`
}

// GetClusterStatus returns the cluster status
func (a *WazuhAPIAdapter) GetClusterStatus(ctx context.Context) (*ClusterStatus, error) {
	resp, err := a.doRequest(ctx, "GET", "/cluster/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get cluster status: %s", string(body))
	}

	var result struct {
		Data ClusterStatus `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode cluster status: %w", err)
	}

	return &result.Data, nil
}

// NodeInfo represents a Wazuh node
type NodeInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
	IP      string `json:"ip"`
}

// GetClusterNodes returns cluster nodes
func (a *WazuhAPIAdapter) GetClusterNodes(ctx context.Context) ([]NodeInfo, error) {
	resp, err := a.doRequest(ctx, "GET", "/cluster/nodes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get cluster nodes: %s", string(body))
	}

	var result struct {
		Data struct {
			AffectedItems []NodeInfo `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode cluster nodes: %w", err)
	}

	return result.Data.AffectedItems, nil
}

// ManagerInfo represents Wazuh manager info
type ManagerInfo struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

// GetManagerInfo returns manager information
func (a *WazuhAPIAdapter) GetManagerInfo(ctx context.Context) (*ManagerInfo, error) {
	resp, err := a.doRequest(ctx, "GET", "/manager/info", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get manager info: %s", string(body))
	}

	var result struct {
		Data ManagerInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode manager info: %w", err)
	}

	return &result.Data, nil
}

// IsHealthy checks if the Wazuh API is healthy
func (a *WazuhAPIAdapter) IsHealthy(ctx context.Context) bool {
	_, err := a.GetManagerInfo(ctx)
	return err == nil
}

// QueueStatus represents the status of a Wazuh queue
type QueueStatus struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	FilePath string `json:"path"`
	Status   string `json:"status"`
}

// QueueStatusResponse represents the response from queue status API
type QueueStatusResponse struct {
	EventQueue   *QueueStatus `json:"event_queue,omitempty"`
	AlertQueue   *QueueStatus `json:"alert_queue,omitempty"`
	ArchiveQueue *QueueStatus `json:"archive_queue,omitempty"`
	TotalEvents  int64        `json:"total_events"`
}

// GetQueueStatus returns the queue status for a specific node
// This helps determine if a worker has events that need to be processed
// before safe shutdown
func (a *WazuhAPIAdapter) GetQueueStatus(ctx context.Context, nodeName string) (*QueueStatusResponse, error) {
	path := "/manager/stats"
	if nodeName != "" {
		path = fmt.Sprintf("/cluster/%s/stats", nodeName)
	}

	resp, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get queue status: %s", string(body))
	}

	// Parse the response - Wazuh stats API returns queue info
	var result struct {
		Data struct {
			AffectedItems []struct {
				QueueSizeTotal      int64 `json:"queue_size_total"`
				QueueSizeRemote     int64 `json:"queue_size_remote"`
				QueueSizeIntegrated int64 `json:"queue_size_integrated"`
			} `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode queue status: %w", err)
	}

	// Aggregate queue sizes
	status := &QueueStatusResponse{}
	for _, item := range result.Data.AffectedItems {
		status.TotalEvents += item.QueueSizeTotal
	}

	return status, nil
}

// ClusterNodeStatus represents detailed status of a cluster node
type ClusterNodeStatus struct {
	Name          string `json:"name"`
	Type          string `json:"type"` // master, worker
	Version       string `json:"version"`
	IP            string `json:"ip"`
	Status        string `json:"status"` // connected, disconnected
	Synced        bool   `json:"synced"`
	AgentsCount   int    `json:"agents_count"`
	QueueSize     int64  `json:"queue_size"`
	LastKeepAlive string `json:"last_keep_alive,omitempty"`
}

// GetClusterNodeStatus returns the detailed status of a specific node in the cluster
func (a *WazuhAPIAdapter) GetClusterNodeStatus(ctx context.Context, nodeName string) (*ClusterNodeStatus, error) {
	path := fmt.Sprintf("/cluster/nodes?select=name,type,version,ip&node_name=%s", nodeName)

	resp, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get node status: %s", string(body))
	}

	var result struct {
		Data struct {
			AffectedItems []ClusterNodeStatus `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode node status: %w", err)
	}

	if len(result.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("node %s not found", nodeName)
	}

	return &result.Data.AffectedItems[0], nil
}

// GetAllNodesStatus returns status of all nodes in the cluster
func (a *WazuhAPIAdapter) GetAllNodesStatus(ctx context.Context) ([]ClusterNodeStatus, error) {
	resp, err := a.doRequest(ctx, "GET", "/cluster/nodes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get all nodes status: %s", string(body))
	}

	var result struct {
		Data struct {
			AffectedItems []ClusterNodeStatus `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode nodes status: %w", err)
	}

	return result.Data.AffectedItems, nil
}

// RestartResponse represents the response from restart operations
type RestartResponse struct {
	AffectedItems []string `json:"affected_items"`
	TotalItems    int      `json:"total_affected_items"`
	FailedItems   []string `json:"failed_items"`
}

// RestartManager restarts the Wazuh manager to reload configuration and rules
// This is required after adding or modifying custom rules
func (a *WazuhAPIAdapter) RestartManager(ctx context.Context) (*RestartResponse, error) {
	resp, err := a.doRequest(ctx, "PUT", "/manager/restart", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to restart manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("manager restart failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data RestartResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode restart response: %w", err)
	}

	return &result.Data, nil
}

// RestartCluster restarts all nodes in the Wazuh cluster to reload configuration and rules
// Use this when there are worker nodes that also need to reload rules
func (a *WazuhAPIAdapter) RestartCluster(ctx context.Context) (*RestartResponse, error) {
	resp, err := a.doRequest(ctx, "PUT", "/cluster/restart", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to restart cluster: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cluster restart failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data RestartResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode restart response: %w", err)
	}

	return &result.Data, nil
}

// RestartNode restarts a specific node in the Wazuh cluster
func (a *WazuhAPIAdapter) RestartNode(ctx context.Context, nodeName string) (*RestartResponse, error) {
	path := fmt.Sprintf("/cluster/%s/restart", nodeName)
	resp, err := a.doRequest(ctx, "PUT", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to restart node %s: %w", nodeName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node restart failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data RestartResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode restart response: %w", err)
	}

	return &result.Data, nil
}

// ReloadRules reloads the rules on the Wazuh manager without a full restart
// Note: For Wazuh 4.x, rules typically require a manager restart to take effect
// This method attempts to use the API reload endpoint if available
func (a *WazuhAPIAdapter) ReloadRules(ctx context.Context) error {
	// For Wazuh 4.x, the rules/reload endpoint may not be available
	// Fall back to manager restart if needed
	resp, err := a.doRequest(ctx, "PUT", "/manager/configuration/validation", nil)
	if err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("configuration validation failed: %s", string(body))
	}

	// If validation passes, restart manager to apply rules
	_, err = a.RestartManager(ctx)
	return err
}

// AgentsSummary represents the summary of agents by status
// API: GET /agents/summary/status
type AgentsSummary struct {
	Active       int `json:"active"`
	Disconnected int `json:"disconnected"`
	NeverConn    int `json:"never_connected"`
	Pending      int `json:"pending"`
	Total        int `json:"total"`
}

// GetAgentsSummary returns the summary of agents by connection status
// This is used for metrics: connected agents count
func (a *WazuhAPIAdapter) GetAgentsSummary(ctx context.Context) (*AgentsSummary, error) {
	resp, err := a.doRequest(ctx, "GET", "/agents/summary/status", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get agents summary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agents summary request failed: %s", string(body))
	}

	var result struct {
		Data struct {
			Connection AgentsSummary `json:"connection"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode agents summary: %w", err)
	}

	return &result.Data.Connection, nil
}

// GroupInfo represents a Wazuh agent group
type GroupInfo struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	MergedSum string `json:"mergedSum"`
	ConfigSum string `json:"configSum"`
}

// CreateGroup creates a new agent group
// API: POST /groups with JSON body {"group_id": "<name>"}
func (a *WazuhAPIAdapter) CreateGroup(ctx context.Context, groupName string) error {
	body := fmt.Sprintf(`{"group_id":"%s"}`, groupName)
	resp, err := a.doRequest(ctx, "POST", "/groups", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create group %s: %w", groupName, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// The Wazuh API may return a 500 with "agent-template.conf" missing
	// but the group is still created. Check if the group exists after.
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// Non-blocking error: agent-template.conf missing but group created
	if resp.StatusCode == http.StatusInternalServerError && strings.Contains(string(respBody), "agent-template.conf") {
		return nil
	}

	return fmt.Errorf("failed to create group %s (status %d): %s", groupName, resp.StatusCode, string(respBody))
}

// GetGroup returns information about a specific agent group, or nil if it doesn't exist
// API: GET /groups?groups_list={name}
// Note: Wazuh returns error code 1710 ("The group does not exist") with HTTP 200
// when the group is not found, so we check both affected_items and failed_items.
func (a *WazuhAPIAdapter) GetGroup(ctx context.Context, groupName string) (*GroupInfo, error) {
	path := fmt.Sprintf("/groups?groups_list=%s", groupName)
	resp, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get group %s: %w", groupName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get group %s (status %d): %s", groupName, resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			AffectedItems    []GroupInfo `json:"affected_items"`
			TotalItems       int         `json:"total_affected_items"`
			TotalFailedItems int         `json:"total_failed_items"`
		} `json:"data"`
		Error int `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode group response: %w", err)
	}

	// Group not found: error=1 with total_failed_items>0 (error 1710)
	if result.Data.TotalItems == 0 || len(result.Data.AffectedItems) == 0 {
		return nil, nil
	}

	return &result.Data.AffectedItems[0], nil
}

// DeleteGroup deletes an agent group
// API: DELETE /groups?groups_list={name}
func (a *WazuhAPIAdapter) DeleteGroup(ctx context.Context, groupName string) error {
	path := fmt.Sprintf("/groups?groups_list=%s", groupName)
	resp, err := a.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("failed to delete group %s: %w", groupName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete group %s (status %d): %s", groupName, resp.StatusCode, string(body))
	}

	return nil
}

// UpdateGroupConfiguration updates the agent.conf for a group
// API: PUT /groups/{group_id}/configuration with Content-Type: application/xml
func (a *WazuhAPIAdapter) UpdateGroupConfiguration(ctx context.Context, groupName, agentConf string) error {
	path := fmt.Sprintf("/groups/%s/configuration", groupName)
	resp, err := a.doRequestWithContentType(ctx, "PUT", path, strings.NewReader(agentConf), "application/xml")
	if err != nil {
		return fmt.Errorf("failed to update group %s configuration: %w", groupName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update group %s configuration (status %d): %s", groupName, resp.StatusCode, string(body))
	}

	return nil
}
