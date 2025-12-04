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
