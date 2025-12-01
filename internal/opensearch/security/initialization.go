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

// Package security provides OpenSearch security initialization and synchronization
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// SecurityHealthResponse represents the response from /_plugins/_security/health
type SecurityHealthResponse struct {
	Status string `json:"status"`
	Mode   string `json:"mode"`
}

// SecurityInitializationChecker checks if OpenSearch security is initialized
type SecurityInitializationChecker struct {
	client *api.Client
}

// NewSecurityInitializationChecker creates a new SecurityInitializationChecker
func NewSecurityInitializationChecker(client *api.Client) *SecurityInitializationChecker {
	return &SecurityInitializationChecker{
		client: client,
	}
}

// CheckInitialized verifies the security plugin is ready by checking:
// 1. The /_plugins/_security/health endpoint returns OK
// 2. The .opendistro_security index exists
func (c *SecurityInitializationChecker) CheckInitialized(ctx context.Context) (bool, error) {
	// First check the security health endpoint
	healthOK, err := c.checkSecurityHealth(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check security health: %w", err)
	}
	if !healthOK {
		return false, nil
	}

	// Then verify the security index exists
	indexExists, err := c.checkSecurityIndexExists(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check security index: %w", err)
	}

	return indexExists, nil
}

// checkSecurityHealth checks the /_plugins/_security/health endpoint
func (c *SecurityInitializationChecker) checkSecurityHealth(ctx context.Context) (bool, error) {
	resp, err := c.client.Get(ctx, "/_plugins/_security/health")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If we get a 503 or similar, security is not ready
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("security health check returned status %d: %s", resp.StatusCode, string(body))
	}

	var health SecurityHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return false, fmt.Errorf("failed to decode security health response: %w", err)
	}

	// The security plugin is ready when status is "UP" or mode indicates normal operation
	return health.Status == "UP" || health.Mode == "normal", nil
}

// checkSecurityIndexExists verifies the .opendistro_security index exists
func (c *SecurityInitializationChecker) checkSecurityIndexExists(ctx context.Context) (bool, error) {
	resp, err := c.client.Get(ctx, "/.opendistro_security")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 200 means index exists, 404 means it doesn't
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("unexpected response checking security index: %d: %s", resp.StatusCode, string(body))
}

// WaitForInitialization blocks until security is ready or timeout is reached
func (c *SecurityInitializationChecker) WaitForInitialization(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for security initialization: %w", ctx.Err())
		case <-ticker.C:
			initialized, err := c.CheckInitialized(ctx)
			if err != nil {
				// Log error but continue trying
				continue
			}
			if initialized {
				return nil
			}
		}
	}
}

// GetSecurityInfo retrieves detailed security configuration info
func (c *SecurityInitializationChecker) GetSecurityInfo(ctx context.Context) (*SecurityInfo, error) {
	resp, err := c.client.Get(ctx, "/_plugins/_security/authinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get security info: %d: %s", resp.StatusCode, string(body))
	}

	var info SecurityInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode security info: %w", err)
	}

	return &info, nil
}

// SecurityInfo represents authentication information from the security plugin
type SecurityInfo struct {
	User           string          `json:"user"`
	UserName       string          `json:"user_name"`
	UserRequested  bool            `json:"user_requested_tenant"`
	RemoteAddress  string          `json:"remote_address"`
	BackendRoles   []string        `json:"backend_roles"`
	CustomAttrHash string          `json:"custom_attribute_names"`
	Roles          []string        `json:"roles"`
	Tenants        map[string]bool `json:"tenants"`
	Principal      string          `json:"principal"`
	Peer           string          `json:"peer_certificates"`
	SSLInfo        string          `json:"sso_logout_url"`
}
