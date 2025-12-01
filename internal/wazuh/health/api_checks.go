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

// APIHealthStatus represents the health status of the Wazuh API
type APIHealthStatus struct {
	// Available indicates if the API is reachable
	Available bool `json:"available"`
	// Authenticated indicates if authentication succeeded
	Authenticated bool `json:"authenticated"`
	// Version is the API version
	Version string `json:"version,omitempty"`
	// Revision is the API revision
	Revision string `json:"revision,omitempty"`
	// StatusCode is the HTTP status code
	StatusCode int `json:"status_code,omitempty"`
	// Error contains any error message
	Error string `json:"error,omitempty"`
}

// APIHealthChecker checks the health of the Wazuh API
type APIHealthChecker struct {
	host       string
	port       int32
	username   string
	password   string
	tlsConfig  *tls.Config
	httpClient *http.Client
	timeout    time.Duration
}

// NewAPIHealthChecker creates a new APIHealthChecker
func NewAPIHealthChecker(host string) *APIHealthChecker {
	return &APIHealthChecker{
		host:    host,
		port:    constants.PortManagerAPI,
		timeout: 10 * time.Second,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// WithPort sets the API port
func (c *APIHealthChecker) WithPort(port int32) *APIHealthChecker {
	c.port = port
	return c
}

// WithCredentials sets the API credentials
func (c *APIHealthChecker) WithCredentials(username, password string) *APIHealthChecker {
	c.username = username
	c.password = password
	return c
}

// WithTLSConfig sets the TLS configuration
func (c *APIHealthChecker) WithTLSConfig(config *tls.Config) *APIHealthChecker {
	c.tlsConfig = config
	return c
}

// WithTimeout sets the request timeout
func (c *APIHealthChecker) WithTimeout(timeout time.Duration) *APIHealthChecker {
	c.timeout = timeout
	return c
}

// Check performs a comprehensive API health check
func (c *APIHealthChecker) Check(ctx context.Context) (*APIHealthStatus, error) {
	status := &APIHealthStatus{}

	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		}
	}

	// Check API availability (unauthenticated endpoint)
	rootURL := fmt.Sprintf("https://%s:%d/", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status, nil
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		status.Error = fmt.Sprintf("API not reachable: %v", err)
		return status, nil
	}
	defer resp.Body.Close()

	status.StatusCode = resp.StatusCode
	status.Available = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized

	// Parse version info if available
	var rootResp struct {
		Data struct {
			Title    string `json:"title"`
			APIVer   string `json:"api_version"`
			Revision string `json:"revision"`
		} `json:"data"`
	}

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&rootResp); err == nil {
			status.Version = rootResp.Data.APIVer
			status.Revision = rootResp.Data.Revision
		}
	}

	// Check authentication if credentials provided
	if c.username != "" && c.password != "" {
		authStatus, err := c.checkAuth(ctx)
		if err == nil {
			status.Authenticated = authStatus
		}
	}

	return status, nil
}

// checkAuth verifies authentication credentials
func (c *APIHealthChecker) checkAuth(ctx context.Context) (bool, error) {
	authURL := fmt.Sprintf("https://%s:%d/security/user/authenticate", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// IsAvailable checks if the API is available
func (c *APIHealthChecker) IsAvailable(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Available, nil
}

// IsAuthenticated checks if the API accepts the credentials
func (c *APIHealthChecker) IsAuthenticated(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Authenticated, nil
}

// WaitForAvailable waits for the API to become available
func (c *APIHealthChecker) WaitForAvailable(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for API to be available")
			}
			available, err := c.IsAvailable(ctx)
			if err != nil {
				continue
			}
			if available {
				return nil
			}
		}
	}
}

// GetVersion returns the API version
func (c *APIHealthChecker) GetVersion(ctx context.Context) (string, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return "", err
	}
	if status.Version == "" {
		return "", fmt.Errorf("version not available")
	}
	return status.Version, nil
}

// Ping performs a simple connectivity check
func (c *APIHealthChecker) Ping(ctx context.Context) error {
	available, err := c.IsAvailable(ctx)
	if err != nil {
		return err
	}
	if !available {
		return fmt.Errorf("API is not available")
	}
	return nil
}
