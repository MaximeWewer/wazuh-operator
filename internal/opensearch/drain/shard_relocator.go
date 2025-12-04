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

package drain

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// ShardRelocationState represents the state of shard relocation tracking
type ShardRelocationState string

const (
	// RelocationStateIdle indicates no relocation in progress
	RelocationStateIdle ShardRelocationState = "Idle"

	// RelocationStateActive indicates relocation is in progress
	RelocationStateActive ShardRelocationState = "Active"

	// RelocationStateComplete indicates relocation completed successfully
	RelocationStateComplete ShardRelocationState = "Complete"

	// RelocationStateFailed indicates relocation failed
	RelocationStateFailed ShardRelocationState = "Failed"

	// RelocationStateTimeout indicates relocation timed out
	RelocationStateTimeout ShardRelocationState = "Timeout"
)

// ShardRelocationInfo contains information about a shard being relocated
type ShardRelocationInfo struct {
	Index       string
	Shard       string
	IsPrimary   bool
	FromNode    string
	ToNode      string
	StartedAt   time.Time
	CompletedAt *time.Time
	State       ShardRelocationState
}

// ShardRelocator tracks and manages shard relocations during drain
type ShardRelocator struct {
	client *api.Client
	log    logr.Logger

	mu sync.RWMutex

	// nodeName is the node being drained
	nodeName string

	// initialShards are the shards on the node when drain started
	initialShards []api.ShardInfo

	// relocatedShards tracks shards that have completed relocation
	relocatedShards map[string]ShardRelocationInfo

	// startTime when relocation tracking started
	startTime time.Time

	// state of the overall relocation
	state ShardRelocationState
}

// NewShardRelocator creates a new ShardRelocator for tracking shard movements
func NewShardRelocator(client *api.Client, log logr.Logger, nodeName string) *ShardRelocator {
	return &ShardRelocator{
		client:          client,
		log:             log.WithName("shard-relocator"),
		nodeName:        nodeName,
		relocatedShards: make(map[string]ShardRelocationInfo),
		state:           RelocationStateIdle,
	}
}

// shardKey generates a unique key for a shard
func shardKey(indexName, shardNum, prirep string) string {
	return fmt.Sprintf("%s/%s/%s", indexName, shardNum, prirep)
}

// Start begins tracking shard relocations
func (r *ShardRelocator) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Get initial shards on the node
	shards, err := r.client.GetShardsOnNode(ctx, r.nodeName)
	if err != nil {
		return fmt.Errorf("failed to get initial shards: %w", err)
	}

	r.initialShards = shards
	r.startTime = time.Now()
	r.state = RelocationStateActive

	r.log.Info("Started tracking shard relocation",
		"node", r.nodeName,
		"initialShards", len(shards),
	)

	return nil
}

// GetProgress returns the current relocation progress
func (r *ShardRelocator) GetProgress(ctx context.Context) (*RelocationProgress, error) {
	r.mu.RLock()
	initialCount := len(r.initialShards)
	r.mu.RUnlock()

	if initialCount == 0 {
		return &RelocationProgress{
			TotalShards:      0,
			RelocatedShards:  0,
			RemainingShards:  0,
			RelocatingShards: 0,
			PercentComplete:  100,
			IsComplete:       true,
		}, nil
	}

	// Get current shards on node
	currentShards, err := r.client.GetShardsOnNode(ctx, r.nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to get current shards: %w", err)
	}

	// Get relocating shards
	_, relocatingCount, err := r.client.HasRelocatingShards(ctx)
	if err != nil {
		r.log.Error(err, "Failed to check relocating shards")
		relocatingCount = 0
	}

	progress := &RelocationProgress{
		TotalShards:      int32(initialCount),
		RemainingShards:  int32(len(currentShards)),
		RelocatedShards:  int32(initialCount - len(currentShards)),
		RelocatingShards: int32(relocatingCount),
		Duration:         time.Since(r.startTime),
	}

	// Calculate percentage
	if initialCount > 0 {
		progress.PercentComplete = int32((progress.RelocatedShards * 100) / progress.TotalShards)
	} else {
		progress.PercentComplete = 100
	}

	// Check if complete
	progress.IsComplete = len(currentShards) == 0 && relocatingCount == 0

	// Update internal state tracking
	r.mu.Lock()
	if progress.IsComplete {
		r.state = RelocationStateComplete
	}
	r.mu.Unlock()

	return progress, nil
}

// RelocationProgress represents the current state of shard relocation
type RelocationProgress struct {
	// TotalShards is the initial number of shards on the node
	TotalShards int32

	// RelocatedShards is the number of shards that have been moved
	RelocatedShards int32

	// RemainingShards is the number of shards still on the node
	RemainingShards int32

	// RelocatingShards is the number of shards currently being moved
	RelocatingShards int32

	// PercentComplete is the completion percentage (0-100)
	PercentComplete int32

	// Duration since relocation started
	Duration time.Duration

	// IsComplete indicates if all shards have been relocated
	IsComplete bool
}

// GetState returns the current relocation state
func (r *ShardRelocator) GetState() ShardRelocationState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.state
}

// SetFailed marks the relocation as failed
func (r *ShardRelocator) SetFailed(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = RelocationStateFailed
	r.log.Info("Shard relocation marked as failed", "reason", reason)
}

// SetTimeout marks the relocation as timed out
func (r *ShardRelocator) SetTimeout() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = RelocationStateTimeout
	r.log.Info("Shard relocation timed out", "duration", time.Since(r.startTime))
}

// GetInitialShardCount returns the initial number of shards on the node
func (r *ShardRelocator) GetInitialShardCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.initialShards)
}

// GetDuration returns the elapsed time since relocation started
func (r *ShardRelocator) GetDuration() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return time.Since(r.startTime)
}

// GetNodeName returns the node being drained
func (r *ShardRelocator) GetNodeName() string {
	return r.nodeName
}

// Reset clears the relocator state
func (r *ShardRelocator) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.initialShards = nil
	r.relocatedShards = make(map[string]ShardRelocationInfo)
	r.state = RelocationStateIdle
	r.startTime = time.Time{}
}
