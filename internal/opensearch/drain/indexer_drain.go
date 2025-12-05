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

// Package drain provides OpenSearch-specific drain functionality for indexer scale-down
package drain

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	drainstate "github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerDrainer handles shard relocation for safe indexer scale-down
type IndexerDrainer interface {
	// StartDrain initiates the drain process for a node
	StartDrain(ctx context.Context, nodeName string) error

	// MonitorProgress checks and returns the current drain progress
	MonitorProgress(ctx context.Context, nodeName string) (DrainProgress, error)

	// VerifyComplete checks if the drain is complete (no shards on node)
	VerifyComplete(ctx context.Context, nodeName string) (bool, error)

	// CancelDrain cancels an in-progress drain (removes allocation exclusion)
	CancelDrain(ctx context.Context) error

	// EvaluateFeasibility checks if drain is feasible without executing (for dry-run)
	EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error)
}

// DrainProgress represents the current state of a drain operation
type DrainProgress struct {
	// Percent completion (0-100)
	Percent int32

	// ShardsRemaining on the target node
	ShardsRemaining int32

	// ShardsRelocating currently being moved
	ShardsRelocating int32

	// Message describing current status
	Message string

	// IsComplete indicates if drain is finished
	IsComplete bool

	// Error if any occurred
	Error error
}

// IndexerDrainerImpl implements IndexerDrainer
type IndexerDrainerImpl struct {
	client              *api.Client
	log                 logr.Logger
	timeout             time.Duration
	healthCheckInterval time.Duration
	initialShardCount   int32
}

// NewIndexerDrainer creates a new IndexerDrainer instance
func NewIndexerDrainer(client *api.Client, log logr.Logger, config *v1alpha1.IndexerDrainConfig) *IndexerDrainerImpl {
	timeout := constants.DefaultIndexerDrainTimeout
	healthCheckInterval := constants.DefaultIndexerHealthCheckInterval

	if config != nil {
		if config.Timeout != nil {
			timeout = config.Timeout.Duration
		}
		if config.HealthCheckInterval != nil {
			healthCheckInterval = config.HealthCheckInterval.Duration
		}
	}

	return &IndexerDrainerImpl{
		client:              client,
		log:                 log.WithName("indexer-drainer"),
		timeout:             timeout,
		healthCheckInterval: healthCheckInterval,
	}
}

// StartDrain initiates shard relocation by setting allocation exclusion
func (d *IndexerDrainerImpl) StartDrain(ctx context.Context, nodeName string) error {
	d.log.Info("Starting indexer drain", "node", nodeName)

	// Record initial shard count for progress tracking
	shardCount, err := d.client.GetShardCount(ctx, nodeName)
	if err != nil {
		return fmt.Errorf("failed to get initial shard count: %w", err)
	}
	d.initialShardCount = int32(shardCount)

	d.log.Info("Initial shard count recorded", "node", nodeName, "shards", shardCount)

	// Set allocation exclusion to trigger shard relocation
	if err := d.client.SetAllocationExclusion(ctx, nodeName); err != nil {
		return fmt.Errorf("failed to set allocation exclusion: %w", err)
	}

	d.log.Info("Allocation exclusion set, shards will begin relocating", "node", nodeName)
	return nil
}

// MonitorProgress checks the current drain progress
func (d *IndexerDrainerImpl) MonitorProgress(ctx context.Context, nodeName string) (DrainProgress, error) {
	progress := DrainProgress{}

	// Get current shard count on node
	shardCount, err := d.client.GetShardCount(ctx, nodeName)
	if err != nil {
		progress.Error = fmt.Errorf("failed to get shard count: %w", err)
		return progress, progress.Error
	}
	progress.ShardsRemaining = int32(shardCount)

	// Get relocating shards info
	hasRelocating, relocatingCount, err := d.client.HasRelocatingShards(ctx)
	if err != nil {
		progress.Error = fmt.Errorf("failed to check relocating shards: %w", err)
		return progress, progress.Error
	}
	progress.ShardsRelocating = int32(relocatingCount)

	// Calculate progress percentage
	if d.initialShardCount > 0 {
		movedShards := d.initialShardCount - int32(shardCount)
		progress.Percent = (movedShards * 100) / d.initialShardCount
	} else {
		progress.Percent = 100 // No shards to move
	}

	// Check if complete
	if shardCount == 0 && !hasRelocating {
		progress.IsComplete = true
		progress.Percent = 100
		progress.Message = "All shards relocated successfully"
	} else if hasRelocating {
		progress.Message = fmt.Sprintf("Relocating shards: %d remaining on node, %d currently relocating", shardCount, relocatingCount)
	} else {
		progress.Message = fmt.Sprintf("Waiting for shard relocation: %d shards remaining on node", shardCount)
	}

	d.log.V(1).Info("Drain progress",
		"node", nodeName,
		"shardsRemaining", shardCount,
		"relocating", relocatingCount,
		"percent", progress.Percent,
		"complete", progress.IsComplete,
	)

	return progress, nil
}

// VerifyComplete checks if all shards have been relocated from the node
func (d *IndexerDrainerImpl) VerifyComplete(ctx context.Context, nodeName string) (bool, error) {
	shardCount, err := d.client.GetShardCount(ctx, nodeName)
	if err != nil {
		return false, fmt.Errorf("failed to verify drain completion: %w", err)
	}

	if shardCount > 0 {
		d.log.Info("Drain not complete, shards remaining", "node", nodeName, "shards", shardCount)
		return false, nil
	}

	// Also verify no relocating shards
	hasRelocating, _, err := d.client.HasRelocatingShards(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check relocating shards: %w", err)
	}

	if hasRelocating {
		d.log.Info("Drain not complete, shards still relocating", "node", nodeName)
		return false, nil
	}

	d.log.Info("Drain verified complete", "node", nodeName)
	return true, nil
}

// CancelDrain removes the allocation exclusion, allowing shards back on the node
func (d *IndexerDrainerImpl) CancelDrain(ctx context.Context) error {
	d.log.Info("Canceling drain, clearing allocation exclusion")

	if err := d.client.ClearAllocationExclusion(ctx); err != nil {
		return fmt.Errorf("failed to clear allocation exclusion: %w", err)
	}

	d.log.Info("Allocation exclusion cleared")
	return nil
}

// EvaluateFeasibility checks if drain is feasible without executing (dry-run mode)
func (d *IndexerDrainerImpl) EvaluateFeasibility(ctx context.Context, nodeName string) (*v1alpha1.DryRunResult, error) {
	result := &v1alpha1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentIndexer,
	}

	// Check cluster health
	health, err := d.client.GetClusterHealth(ctx)
	if err != nil {
		result.Feasible = false
		result.Blockers = append(result.Blockers, fmt.Sprintf("Cannot check cluster health: %v", err))
		return result, nil
	}

	// Block if cluster is not green
	if health.Status != constants.OpenSearchHealthGreen {
		result.Feasible = false
		result.Blockers = append(result.Blockers,
			fmt.Sprintf("Cluster health is %s, must be %s before drain", health.Status, constants.OpenSearchHealthGreen))
	}

	// Check number of nodes
	if health.NumberOfDataNodes < 2 {
		result.Feasible = false
		result.Blockers = append(result.Blockers,
			"Cannot drain: only one data node in cluster")
	}

	// Check shards on node
	shardCount, err := d.client.GetShardCount(ctx, nodeName)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot determine shard count on %s: %v", nodeName, err))
	} else if shardCount == 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Node %s has no shards to relocate", nodeName))
	}

	// Check for existing allocation exclusion
	existingExclusion, err := d.client.GetAllocationExclusion(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Cannot check existing allocation exclusion: %v", err))
	} else if existingExclusion != "" && existingExclusion != nodeName {
		result.Feasible = false
		result.Blockers = append(result.Blockers,
			fmt.Sprintf("Another node (%s) is already excluded from allocation", existingExclusion))
	}

	// Estimate duration
	if shardCount > 0 {
		// Rough estimate: 30 seconds per shard
		estimatedSeconds := int64(shardCount * 30)
		if estimatedSeconds < 60 {
			estimatedSeconds = 60 // Minimum 1 minute
		}
		result.EstimatedDuration = &metav1.Duration{Duration: time.Duration(estimatedSeconds) * time.Second}
	} else {
		result.EstimatedDuration = &metav1.Duration{Duration: 30 * time.Second}
	}

	d.log.Info("Dry-run evaluation complete",
		"node", nodeName,
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
		"warnings", len(result.Warnings),
	)

	return result, nil
}

// WaitForDrainComplete blocks until drain completes or timeout
func (d *IndexerDrainerImpl) WaitForDrainComplete(ctx context.Context, nodeName string, status *v1alpha1.ComponentDrainStatus) error {
	startTime := time.Now()
	ticker := time.NewTicker(d.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Check timeout
			if time.Since(startTime) > d.timeout {
				return fmt.Errorf("drain timeout after %v", d.timeout)
			}

			// Get progress
			progress, err := d.MonitorProgress(ctx, nodeName)
			if err != nil {
				d.log.Error(err, "Error monitoring drain progress", "node", nodeName)
				continue
			}

			// Update status
			if status != nil {
				drainstate.UpdateProgress(status, progress.Percent, progress.Message)
				drainstate.UpdateShardCount(status, progress.ShardsRemaining)
			}

			if progress.IsComplete {
				d.log.Info("Drain complete", "node", nodeName, "duration", time.Since(startTime))
				return nil
			}
		}
	}
}

// GetTimeout returns the configured timeout for drain operations
func (d *IndexerDrainerImpl) GetTimeout() time.Duration {
	return d.timeout
}

// GetHealthCheckInterval returns the configured health check interval
func (d *IndexerDrainerImpl) GetHealthCheckInterval() time.Duration {
	return d.healthCheckInterval
}

// =============================================================================
// NodePool-Aware Drain Operations
// =============================================================================

// NodePoolScaleDownInfo contains information about a nodePool scale-down
type NodePoolScaleDownInfo struct {
	// PoolName is the name of the nodePool being scaled down
	PoolName string
	// Roles contains the node roles for this pool
	Roles []string
	// CurrentReplicas is the current number of replicas
	CurrentReplicas int32
	// DesiredReplicas is the target number of replicas
	DesiredReplicas int32
	// TargetPodNames are the pod names that will be removed
	TargetPodNames []string
}

// IsScaleDown returns true if this represents a scale-down operation
func (info *NodePoolScaleDownInfo) IsScaleDown() bool {
	return info.DesiredReplicas < info.CurrentReplicas
}

// GetReplicasDelta returns the number of replicas being removed
func (info *NodePoolScaleDownInfo) GetReplicasDelta() int32 {
	if !info.IsScaleDown() {
		return 0
	}
	return info.CurrentReplicas - info.DesiredReplicas
}

// HasRole checks if the nodePool has the specified role
func (info *NodePoolScaleDownInfo) HasRole(role string) bool {
	for _, r := range info.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasDataRole returns true if the nodePool has the data role
func (info *NodePoolScaleDownInfo) HasDataRole() bool {
	return info.HasRole(constants.OpenSearchRoleData)
}

// HasClusterManagerRole returns true if the nodePool has the cluster_manager role
func (info *NodePoolScaleDownInfo) HasClusterManagerRole() bool {
	return info.HasRole(constants.OpenSearchRoleClusterManager)
}

// IsCoordinatingOnly returns true if the nodePool is coordinating-only (no data/cluster_manager)
func (info *NodePoolScaleDownInfo) IsCoordinatingOnly() bool {
	// Coordinating-only nodes have no roles or only coordinating_only pseudo-role
	if len(info.Roles) == 0 {
		return true
	}
	for _, r := range info.Roles {
		if r == constants.OpenSearchRoleCoordinatingOnly {
			continue
		}
		// Any other role means it's not coordinating-only
		return false
	}
	return true
}

// NodePoolDrainResult contains the result of a nodePool drain evaluation
type NodePoolDrainResult struct {
	// NeedsDrain indicates if drain is required before scale-down
	NeedsDrain bool
	// SkipReason explains why drain can be skipped (if NeedsDrain is false)
	SkipReason string
	// Feasible indicates if the drain operation is feasible
	Feasible bool
	// Blockers contains reasons why drain cannot proceed
	Blockers []string
	// Warnings contains non-fatal issues
	Warnings []string
	// TargetNodes are the OpenSearch node names to drain
	TargetNodes []string
}

// EvaluateNodePoolScaleDown evaluates if a nodePool scale-down can proceed
// Returns information about whether drain is needed and if it's feasible
func (d *IndexerDrainerImpl) EvaluateNodePoolScaleDown(
	ctx context.Context,
	info *NodePoolScaleDownInfo,
	totalClusterManagers int32,
) (*NodePoolDrainResult, error) {
	result := &NodePoolDrainResult{
		Feasible: true,
	}

	if !info.IsScaleDown() {
		result.NeedsDrain = false
		result.SkipReason = "Not a scale-down operation"
		return result, nil
	}

	d.log.Info("Evaluating nodePool scale-down",
		"pool", info.PoolName,
		"current", info.CurrentReplicas,
		"desired", info.DesiredReplicas,
		"roles", info.Roles,
	)

	// 1. Check if coordinating-only node (no shards, no drain needed)
	if info.IsCoordinatingOnly() {
		result.NeedsDrain = false
		result.SkipReason = "Coordinating-only nodes do not hold shards"
		d.log.Info("Skipping drain for coordinating-only nodePool", "pool", info.PoolName)
		return result, nil
	}

	// 2. Check cluster_manager quorum
	if info.HasClusterManagerRole() {
		newTotal := totalClusterManagers - info.GetReplicasDelta()
		if newTotal < constants.MinClusterManagerNodes {
			result.Feasible = false
			result.Blockers = append(result.Blockers,
				fmt.Sprintf("Scale-down would reduce cluster_manager nodes from %d to %d, "+
					"below minimum quorum of %d",
					totalClusterManagers, newTotal, constants.MinClusterManagerNodes))
		}
	}

	// 3. Data nodes require drain
	if info.HasDataRole() {
		result.NeedsDrain = true
		result.TargetNodes = info.TargetPodNames

		// Verify cluster health
		if d.client != nil {
			health, err := d.client.GetClusterHealth(ctx)
			if err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Cannot verify cluster health: %v", err))
			} else if health.Status != constants.OpenSearchHealthGreen {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					fmt.Sprintf("Cluster health is %s, must be %s before drain",
						health.Status, constants.OpenSearchHealthGreen))
			}

			// Check number of data nodes
			if health.NumberOfDataNodes < 2 {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Cannot drain: only one data node in cluster")
			}
		}
	} else {
		// Non-data nodes (cluster_manager only) don't hold shards
		result.NeedsDrain = false
		result.SkipReason = "NodePool does not have data role"
	}

	d.log.Info("NodePool scale-down evaluation complete",
		"pool", info.PoolName,
		"needsDrain", result.NeedsDrain,
		"feasible", result.Feasible,
		"blockers", len(result.Blockers),
	)

	return result, nil
}

// GetNodePoolScaleDownTargets identifies which pods will be removed during scale-down
// StatefulSets scale down by removing highest-ordinal pods first
func GetNodePoolScaleDownTargets(clusterName, poolName string, currentReplicas, desiredReplicas int32) []string {
	if desiredReplicas >= currentReplicas {
		return nil
	}

	var targets []string
	for i := desiredReplicas; i < currentReplicas; i++ {
		podName := constants.IndexerNodePoolPodName(clusterName, poolName, int(i))
		targets = append(targets, podName)
	}
	return targets
}

// StartNodePoolDrain initiates drain for multiple nodes in a nodePool
func (d *IndexerDrainerImpl) StartNodePoolDrain(ctx context.Context, nodeNames []string) error {
	if len(nodeNames) == 0 {
		return nil
	}

	d.log.Info("Starting nodePool drain", "nodes", nodeNames)

	// Record initial shard counts
	var totalShards int32
	for _, nodeName := range nodeNames {
		shardCount, err := d.client.GetShardCount(ctx, nodeName)
		if err != nil {
			d.log.Error(err, "Failed to get shard count", "node", nodeName)
			continue
		}
		totalShards += int32(shardCount)
	}
	d.initialShardCount = totalShards

	d.log.Info("Initial shard count for nodePool drain", "totalShards", totalShards, "nodes", len(nodeNames))

	// Set allocation exclusion for all target nodes
	// OpenSearch supports comma-separated node names in cluster.routing.allocation.exclude._name
	for _, nodeName := range nodeNames {
		if err := d.client.SetAllocationExclusion(ctx, nodeName); err != nil {
			return fmt.Errorf("failed to set allocation exclusion for %s: %w", nodeName, err)
		}
	}

	d.log.Info("Allocation exclusion set for nodePool nodes, shards will begin relocating",
		"nodes", nodeNames)
	return nil
}

// MonitorNodePoolDrainProgress checks drain progress for multiple nodes
func (d *IndexerDrainerImpl) MonitorNodePoolDrainProgress(ctx context.Context, nodeNames []string) (DrainProgress, error) {
	progress := DrainProgress{}

	if len(nodeNames) == 0 {
		progress.IsComplete = true
		progress.Percent = 100
		progress.Message = "No nodes to drain"
		return progress, nil
	}

	// Sum up shards remaining across all target nodes
	var totalRemaining int32
	for _, nodeName := range nodeNames {
		shardCount, err := d.client.GetShardCount(ctx, nodeName)
		if err != nil {
			d.log.Error(err, "Failed to get shard count", "node", nodeName)
			continue
		}
		totalRemaining += int32(shardCount)
	}
	progress.ShardsRemaining = totalRemaining

	// Check relocating shards
	hasRelocating, relocatingCount, err := d.client.HasRelocatingShards(ctx)
	if err != nil {
		progress.Error = fmt.Errorf("failed to check relocating shards: %w", err)
		return progress, progress.Error
	}
	progress.ShardsRelocating = int32(relocatingCount)

	// Calculate progress
	if d.initialShardCount > 0 {
		movedShards := d.initialShardCount - totalRemaining
		progress.Percent = (movedShards * 100) / d.initialShardCount
	} else {
		progress.Percent = 100
	}

	// Check completion
	if totalRemaining == 0 && !hasRelocating {
		progress.IsComplete = true
		progress.Percent = 100
		progress.Message = fmt.Sprintf("All shards relocated from %d nodes", len(nodeNames))
	} else if hasRelocating {
		progress.Message = fmt.Sprintf("Relocating shards: %d remaining on nodes, %d currently relocating",
			totalRemaining, relocatingCount)
	} else {
		progress.Message = fmt.Sprintf("Waiting for shard relocation: %d shards remaining across %d nodes",
			totalRemaining, len(nodeNames))
	}

	d.log.V(1).Info("NodePool drain progress",
		"nodes", len(nodeNames),
		"shardsRemaining", totalRemaining,
		"relocating", relocatingCount,
		"percent", progress.Percent,
		"complete", progress.IsComplete,
	)

	return progress, nil
}

// VerifyNodePoolDrainComplete checks if all nodes in the nodePool have been drained
func (d *IndexerDrainerImpl) VerifyNodePoolDrainComplete(ctx context.Context, nodeNames []string) (bool, error) {
	for _, nodeName := range nodeNames {
		complete, err := d.VerifyComplete(ctx, nodeName)
		if err != nil {
			return false, err
		}
		if !complete {
			d.log.Info("Drain not complete for node", "node", nodeName)
			return false, nil
		}
	}

	// Also verify no relocating shards
	hasRelocating, _, err := d.client.HasRelocatingShards(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check relocating shards: %w", err)
	}
	if hasRelocating {
		d.log.Info("NodePool drain not complete, shards still relocating")
		return false, nil
	}

	d.log.Info("NodePool drain verified complete", "nodes", len(nodeNames))
	return true, nil
}
