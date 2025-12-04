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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ClusterHealth represents the cluster health response
type ClusterHealth struct {
	ClusterName                 string  `json:"cluster_name"`
	Status                      string  `json:"status"`
	TimedOut                    bool    `json:"timed_out"`
	NumberOfNodes               int     `json:"number_of_nodes"`
	NumberOfDataNodes           int     `json:"number_of_data_nodes"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	ActiveShards                int     `json:"active_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	DelayedUnassignedShards     int     `json:"delayed_unassigned_shards"`
	NumberOfPendingTasks        int     `json:"number_of_pending_tasks"`
	NumberOfInFlightFetch       int     `json:"number_of_in_flight_fetch"`
	TaskMaxWaitingInQueueMillis int     `json:"task_max_waiting_in_queue_millis"`
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

// ShardInfo represents information about a shard
type ShardInfo struct {
	Index   string `json:"index"`
	Shard   string `json:"shard"`
	PriRep  string `json:"prirep"` // "p" for primary, "r" for replica
	State   string `json:"state"`  // STARTED, RELOCATING, INITIALIZING, UNASSIGNED
	Node    string `json:"node"`
	Docs    string `json:"docs,omitempty"`
	Store   string `json:"store,omitempty"`
	IP      string `json:"ip,omitempty"`
	Segment string `json:"segment,omitempty"`
}

// ClusterSettings represents cluster settings
type ClusterSettings struct {
	Persistent map[string]interface{} `json:"persistent"`
	Transient  map[string]interface{} `json:"transient"`
	Defaults   map[string]interface{} `json:"defaults,omitempty"`
}

// ClusterSettingsUpdate represents a cluster settings update request
type ClusterSettingsUpdate struct {
	Persistent map[string]interface{} `json:"persistent,omitempty"`
	Transient  map[string]interface{} `json:"transient,omitempty"`
}

// GetClusterHealth retrieves the cluster health status
func (c *Client) GetClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	resp, err := c.Get(ctx, "/_cluster/health")
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cluster health request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var health ClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode cluster health response: %w", err)
	}

	return &health, nil
}

// IsClusterGreen checks if the cluster health is green
func (c *Client) IsClusterGreen(ctx context.Context) (bool, error) {
	health, err := c.GetClusterHealth(ctx)
	if err != nil {
		return false, err
	}
	return health.Status == constants.OpenSearchHealthGreen, nil
}

// SetAllocationExclusion sets a node exclusion for shard allocation
// This causes OpenSearch to relocate all shards away from the specified node
func (c *Client) SetAllocationExclusion(ctx context.Context, nodeName string) error {
	settings := ClusterSettingsUpdate{
		Transient: map[string]interface{}{
			constants.OpenSearchAllocationExcludeNameKey: nodeName,
		},
	}

	resp, err := c.Put(ctx, "/_cluster/settings", settings)
	if err != nil {
		return fmt.Errorf("failed to set allocation exclusion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set allocation exclusion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ClearAllocationExclusion removes the node exclusion for shard allocation
func (c *Client) ClearAllocationExclusion(ctx context.Context) error {
	settings := ClusterSettingsUpdate{
		Transient: map[string]interface{}{
			constants.OpenSearchAllocationExcludeNameKey: nil,
		},
	}

	resp, err := c.Put(ctx, "/_cluster/settings", settings)
	if err != nil {
		return fmt.Errorf("failed to clear allocation exclusion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clear allocation exclusion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetShardsOnNode returns all shards located on a specific node
func (c *Client) GetShardsOnNode(ctx context.Context, nodeName string) ([]ShardInfo, error) {
	resp, err := c.Get(ctx, "/_cat/shards?h=index,shard,prirep,state,node,docs,store&format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to get shards: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get shards failed with status %d: %s", resp.StatusCode, string(body))
	}

	var allShards []ShardInfo
	if err := json.NewDecoder(resp.Body).Decode(&allShards); err != nil {
		return nil, fmt.Errorf("failed to decode shards response: %w", err)
	}

	// Filter shards on the specified node
	var nodeShards []ShardInfo
	for _, shard := range allShards {
		if shard.Node == nodeName {
			nodeShards = append(nodeShards, shard)
		}
	}

	return nodeShards, nil
}

// GetShardCount returns the number of shards on a specific node
func (c *Client) GetShardCount(ctx context.Context, nodeName string) (int, error) {
	shards, err := c.GetShardsOnNode(ctx, nodeName)
	if err != nil {
		return 0, err
	}
	return len(shards), nil
}

// WaitForNoRelocatingShards blocks until there are no relocating shards or timeout
func (c *Client) WaitForNoRelocatingShards(ctx context.Context, timeout time.Duration) error {
	// Use the wait_for_no_relocating_shards parameter
	timeoutStr := fmt.Sprintf("%ds", int(timeout.Seconds()))
	path := fmt.Sprintf("/_cluster/health?wait_for_no_relocating_shards=true&timeout=%s", timeoutStr)

	resp, err := c.Get(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to wait for no relocating shards: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("wait for no relocating shards failed with status %d: %s", resp.StatusCode, string(body))
	}

	var health ClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("failed to decode health response: %w", err)
	}

	if health.TimedOut {
		return fmt.Errorf("timed out waiting for shard relocation, %d shards still relocating", health.RelocatingShards)
	}

	return nil
}

// GetClusterSettings retrieves the current cluster settings
func (c *Client) GetClusterSettings(ctx context.Context, includeDefaults bool) (*ClusterSettings, error) {
	path := "/_cluster/settings"
	if includeDefaults {
		path += "?include_defaults=true"
	}

	resp, err := c.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster settings: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get cluster settings failed with status %d: %s", resp.StatusCode, string(body))
	}

	var settings ClusterSettings
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, fmt.Errorf("failed to decode cluster settings response: %w", err)
	}

	return &settings, nil
}

// GetAllocationExclusion returns the current allocation exclusion node name, if any
func (c *Client) GetAllocationExclusion(ctx context.Context) (string, error) {
	settings, err := c.GetClusterSettings(ctx, false)
	if err != nil {
		return "", err
	}

	// Check transient settings first
	if transient := settings.Transient; transient != nil {
		if cluster, ok := transient["cluster"].(map[string]interface{}); ok {
			if routing, ok := cluster["routing"].(map[string]interface{}); ok {
				if allocation, ok := routing["allocation"].(map[string]interface{}); ok {
					if exclude, ok := allocation["exclude"].(map[string]interface{}); ok {
						if name, ok := exclude["_name"].(string); ok {
							return name, nil
						}
					}
				}
			}
		}
	}

	// Check persistent settings
	if persistent := settings.Persistent; persistent != nil {
		if cluster, ok := persistent["cluster"].(map[string]interface{}); ok {
			if routing, ok := cluster["routing"].(map[string]interface{}); ok {
				if allocation, ok := routing["allocation"].(map[string]interface{}); ok {
					if exclude, ok := allocation["exclude"].(map[string]interface{}); ok {
						if name, ok := exclude["_name"].(string); ok {
							return name, nil
						}
					}
				}
			}
		}
	}

	return "", nil
}

// HasRelocatingShards checks if there are any shards currently relocating
func (c *Client) HasRelocatingShards(ctx context.Context) (bool, int, error) {
	health, err := c.GetClusterHealth(ctx)
	if err != nil {
		return false, 0, err
	}
	return health.RelocatingShards > 0, health.RelocatingShards, nil
}

// GetNodeDiskUsage returns disk usage statistics for a specific node
// This can be used to determine if shards can fit on remaining nodes
type NodeDiskStats struct {
	NodeID      string  `json:"node_id"`
	NodeName    string  `json:"node_name"`
	TotalBytes  int64   `json:"total_bytes"`
	UsedBytes   int64   `json:"used_bytes"`
	AvailBytes  int64   `json:"avail_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// GetNodesDiskStats returns disk statistics for all nodes
func (c *Client) GetNodesDiskStats(ctx context.Context) ([]NodeDiskStats, error) {
	resp, err := c.Get(ctx, "/_cat/allocation?h=node,disk.total,disk.used,disk.avail,disk.percent&format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to get node disk stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get node disk stats failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rawStats []map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&rawStats); err != nil {
		return nil, fmt.Errorf("failed to decode disk stats response: %w", err)
	}

	var stats []NodeDiskStats
	for _, raw := range rawStats {
		stat := NodeDiskStats{
			NodeName: raw["node"],
		}
		stats = append(stats, stat)
	}

	return stats, nil
}
