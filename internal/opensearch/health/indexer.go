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

// Package health provides health check utilities for OpenSearch components
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

// ClusterHealth represents OpenSearch cluster health status
type ClusterHealth struct {
	// ClusterName is the name of the cluster
	ClusterName string `json:"cluster_name"`
	// Status is the cluster health status (green, yellow, red)
	Status string `json:"status"`
	// TimedOut indicates if the request timed out
	TimedOut bool `json:"timed_out"`
	// NumberOfNodes is the total number of nodes
	NumberOfNodes int `json:"number_of_nodes"`
	// NumberOfDataNodes is the number of data nodes
	NumberOfDataNodes int `json:"number_of_data_nodes"`
	// ActivePrimaryShards is the number of active primary shards
	ActivePrimaryShards int `json:"active_primary_shards"`
	// ActiveShards is the number of active shards
	ActiveShards int `json:"active_shards"`
	// RelocatingShards is the number of relocating shards
	RelocatingShards int `json:"relocating_shards"`
	// InitializingShards is the number of initializing shards
	InitializingShards int `json:"initializing_shards"`
	// UnassignedShards is the number of unassigned shards
	UnassignedShards int `json:"unassigned_shards"`
	// DelayedUnassignedShards is the number of delayed unassigned shards
	DelayedUnassignedShards int `json:"delayed_unassigned_shards"`
	// NumberOfPendingTasks is the number of pending tasks
	NumberOfPendingTasks int `json:"number_of_pending_tasks"`
	// NumberOfInFlightFetch is the number of in-flight fetches
	NumberOfInFlightFetch int `json:"number_of_in_flight_fetch"`
	// TaskMaxWaitingInQueueMillis is the max wait time for tasks in queue
	TaskMaxWaitingInQueueMillis int `json:"task_max_waiting_in_queue_millis"`
	// ActiveShardsPercentAsNumber is the percentage of active shards
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

// IndexerHealthStatus represents the health status of OpenSearch Indexer
type IndexerHealthStatus struct {
	// Healthy indicates overall health (green or yellow)
	Healthy bool `json:"healthy"`
	// Ready indicates if the cluster is ready to serve requests
	Ready bool `json:"ready"`
	// ClusterHealth contains detailed cluster health info
	ClusterHealth *ClusterHealth `json:"cluster_health,omitempty"`
	// Error contains any error message
	Error string `json:"error,omitempty"`
}

// IndexerHealthChecker checks the health of OpenSearch Indexer
type IndexerHealthChecker struct {
	host       string
	port       int32
	username   string
	password   string
	tlsConfig  *tls.Config
	httpClient *http.Client
	timeout    time.Duration
}

// NewIndexerHealthChecker creates a new IndexerHealthChecker
func NewIndexerHealthChecker(host string) *IndexerHealthChecker {
	return &IndexerHealthChecker{
		host:    host,
		port:    constants.PortIndexerREST,
		timeout: 10 * time.Second,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // Default to skip verify for internal checks
		},
	}
}

// WithPort sets the API port
func (c *IndexerHealthChecker) WithPort(port int32) *IndexerHealthChecker {
	c.port = port
	return c
}

// WithCredentials sets the API credentials
func (c *IndexerHealthChecker) WithCredentials(username, password string) *IndexerHealthChecker {
	c.username = username
	c.password = password
	return c
}

// WithTLSConfig sets the TLS configuration
func (c *IndexerHealthChecker) WithTLSConfig(config *tls.Config) *IndexerHealthChecker {
	c.tlsConfig = config
	return c
}

// WithTimeout sets the timeout
func (c *IndexerHealthChecker) WithTimeout(timeout time.Duration) *IndexerHealthChecker {
	c.timeout = timeout
	return c
}

// Check performs a health check
func (c *IndexerHealthChecker) Check(ctx context.Context) (*IndexerHealthStatus, error) {
	status := &IndexerHealthStatus{}

	// Create HTTP client if not exists
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		}
	}

	// Get cluster health
	healthURL := fmt.Sprintf("https://%s:%d/_cluster/health", c.host, c.port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status, err
	}

	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		status.Error = fmt.Sprintf("health request failed: %v", err)
		return status, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		status.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		return status, nil
	}

	var clusterHealth ClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&clusterHealth); err != nil {
		status.Error = fmt.Sprintf("failed to decode response: %v", err)
		return status, nil
	}

	status.ClusterHealth = &clusterHealth

	// Determine health status
	// Green = all primary and replica shards are active
	// Yellow = all primary shards are active, but not all replica shards
	// Red = not all primary shards are active
	status.Healthy = clusterHealth.Status == "green" || clusterHealth.Status == "yellow"
	status.Ready = clusterHealth.Status != "red" && clusterHealth.NumberOfNodes > 0

	return status, nil
}

// IsReady checks if the indexer is ready to serve requests
func (c *IndexerHealthChecker) IsReady(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Ready, nil
}

// IsHealthy checks if the indexer is fully healthy (green)
func (c *IndexerHealthChecker) IsHealthy(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	return status.Healthy, nil
}

// IsGreen checks if the cluster status is green
func (c *IndexerHealthChecker) IsGreen(ctx context.Context) (bool, error) {
	status, err := c.Check(ctx)
	if err != nil {
		return false, err
	}
	if status.ClusterHealth == nil {
		return false, nil
	}
	return status.ClusterHealth.Status == "green", nil
}

// WaitForGreen waits for the cluster to become green
func (c *IndexerHealthChecker) WaitForGreen(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for green status")
			}
			green, err := c.IsGreen(ctx)
			if err != nil {
				continue
			}
			if green {
				return nil
			}
		}
	}
}

// WaitForReady waits for the cluster to become ready (not red)
func (c *IndexerHealthChecker) WaitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for ready status")
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
