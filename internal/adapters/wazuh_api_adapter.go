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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &WazuhAPIAdapter{
		baseURL:  config.BaseURL,
		username: config.Username,
		password: config.Password,
		httpClient: &http.Client{
			Transport: transport,
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

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/security/user/authenticate", nil)
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
	a.tokenExp = time.Now().Add(15 * time.Minute) // Token valid for 15 minutes

	return nil
}

// doRequest performs an authenticated request
func (a *WazuhAPIAdapter) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if err := a.Authenticate(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")

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
