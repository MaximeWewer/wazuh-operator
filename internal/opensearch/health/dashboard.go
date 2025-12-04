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
	"fmt"
	"net/http"
	"time"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardHealthStatus represents the health status of OpenSearch Dashboard
type DashboardHealthStatus struct {
	// Healthy indicates overall health
	Healthy bool `json:"healthy"`
	// Ready indicates if the dashboard is ready to serve requests
	Ready bool `json:"ready"`
	// StatusCode is the HTTP status code from the health check
	StatusCode int `json:"status_code,omitempty"`
	// Error contains any error message
	Error string `json:"error,omitempty"`
}

// DashboardHealthChecker checks the health of OpenSearch Dashboard
type DashboardHealthChecker struct {
	host       string
	port       int32
	tlsConfig  *tls.Config
	httpClient *http.Client
	timeout    time.Duration
}

// NewDashboardHealthChecker creates a new DashboardHealthChecker
func NewDashboardHealthChecker(host string) *DashboardHealthChecker {
	return &DashboardHealthChecker{
		host:    host,
		port:    constants.PortDashboardHTTP,
		timeout: constants.TimeoutHealthCheck,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // Default to skip verify for internal checks
		},
	}
}

// WithPort sets the HTTP port
func (c *DashboardHealthChecker) WithPort(port int32) *DashboardHealthChecker {
	c.port = port
	return c
}

// WithTLSConfig sets the TLS configuration
func (c *DashboardHealthChecker) WithTLSConfig(config *tls.Config) *DashboardHealthChecker {
	c.tlsConfig = config
	return c
}

// WithTimeout sets the timeout
func (c *DashboardHealthChecker) WithTimeout(timeout time.Duration) *DashboardHealthChecker {
	c.timeout = timeout
	return c
}

// Check performs a health check
func (c *DashboardHealthChecker) Check(ctx context.Context) (*DashboardHealthStatus, error) {
	status := &DashboardHealthStatus{}

	// Create HTTP client if not exists
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
			// Don't follow redirects for health checks
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	// Check dashboard health by accessing the status endpoint
	healthURL := fmt.Sprintf("https://%s:%d/api/status", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		status.Error = fmt.Sprintf("health request failed: %v", err)
		return status, nil
	}
	defer resp.Body.Close()

	status.StatusCode = resp.StatusCode

	// Dashboard is healthy if we get a 200 or 302 (redirect to login)
	// Note: 401 can also indicate the service is up but requires auth
	switch resp.StatusCode {
	case http.StatusOK, http.StatusFound, http.StatusUnauthorized:
		status.Healthy = true
		status.Ready = true
	default:
		status.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
	}

	return status, nil
}

// IsReady checks if the dashboard is ready to serve requests
func (c *DashboardHealthChecker) IsReady(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Ready, nil
}

// IsHealthy checks if the dashboard is fully healthy
func (c *DashboardHealthChecker) IsHealthy(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Healthy, nil
}

// WaitForReady waits for the dashboard to become ready
func (c *DashboardHealthChecker) WaitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(constants.PollIntervalHealthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for dashboard to be ready")
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
