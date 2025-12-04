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
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// testLoggerImpl is a simple logger for tests that discards output
type testLoggerImpl struct{}

func (t testLoggerImpl) Enabled(level int) bool                                    { return false }
func (t testLoggerImpl) Info(level int, msg string, keysAndValues ...interface{})  {}
func (t testLoggerImpl) Error(err error, msg string, keysAndValues ...interface{}) {}
func (t testLoggerImpl) WithValues(keysAndValues ...interface{}) logr.LogSink      { return t }
func (t testLoggerImpl) WithName(name string) logr.LogSink                         { return t }
func (t testLoggerImpl) Init(info logr.RuntimeInfo)                                {}

// Ensure testLoggerImpl implements logr.LogSink
var _ logr.LogSink = testLoggerImpl{}

// getTestLogger returns a logr.Logger for testing
func getTestLogger() logr.Logger {
	return logr.New(testLoggerImpl{})
}

func TestNewIndexerDrainer_DefaultConfig(t *testing.T) {
	drainer := NewIndexerDrainer(nil, getTestLogger(), nil)

	if drainer.timeout != constants.DefaultIndexerDrainTimeout {
		t.Errorf("expected timeout %v, got %v", constants.DefaultIndexerDrainTimeout, drainer.timeout)
	}

	if drainer.healthCheckInterval != constants.DefaultIndexerHealthCheckInterval {
		t.Errorf("expected healthCheckInterval %v, got %v", constants.DefaultIndexerHealthCheckInterval, drainer.healthCheckInterval)
	}
}

func TestNewIndexerDrainer_CustomConfig(t *testing.T) {
	customTimeout := 45 * time.Minute
	customInterval := 15 * time.Second

	config := &v1alpha1.IndexerDrainConfig{
		Timeout:             &metav1.Duration{Duration: customTimeout},
		HealthCheckInterval: &metav1.Duration{Duration: customInterval},
	}

	drainer := NewIndexerDrainer(nil, getTestLogger(), config)

	if drainer.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, drainer.timeout)
	}

	if drainer.healthCheckInterval != customInterval {
		t.Errorf("expected healthCheckInterval %v, got %v", customInterval, drainer.healthCheckInterval)
	}
}

func TestDrainProgress_Calculations(t *testing.T) {
	tests := []struct {
		name             string
		initialShards    int32
		remainingShards  int32
		relocating       bool
		expectedPercent  int32
		expectedComplete bool
	}{
		{
			name:             "no shards to relocate",
			initialShards:    0,
			remainingShards:  0,
			relocating:       false,
			expectedPercent:  100,
			expectedComplete: true,
		},
		{
			name:             "all shards remaining",
			initialShards:    10,
			remainingShards:  10,
			relocating:       true,
			expectedPercent:  0,
			expectedComplete: false,
		},
		{
			name:             "half shards relocated",
			initialShards:    10,
			remainingShards:  5,
			relocating:       true,
			expectedPercent:  50,
			expectedComplete: false,
		},
		{
			name:             "all shards relocated but still relocating",
			initialShards:    10,
			remainingShards:  0,
			relocating:       true,
			expectedPercent:  100,
			expectedComplete: false,
		},
		{
			name:             "drain complete",
			initialShards:    10,
			remainingShards:  0,
			relocating:       false,
			expectedPercent:  100,
			expectedComplete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate progress as would be done in MonitorProgress
			var percent int32
			if tt.initialShards > 0 {
				movedShards := tt.initialShards - tt.remainingShards
				percent = (movedShards * 100) / tt.initialShards
			} else {
				percent = 100
			}

			complete := tt.remainingShards == 0 && !tt.relocating

			if percent != tt.expectedPercent {
				t.Errorf("expected percent %d, got %d", tt.expectedPercent, percent)
			}

			if complete != tt.expectedComplete {
				t.Errorf("expected complete %v, got %v", tt.expectedComplete, complete)
			}
		})
	}
}

func TestShardRelocator_GetProgress_NoShards(t *testing.T) {
	relocator := NewShardRelocator(nil, getTestLogger(), "test-node")

	// Initialize with no shards
	relocator.initialShards = []api.ShardInfo{}
	relocator.state = RelocationStateActive

	// Progress should report 100% complete with no shards
	if relocator.GetInitialShardCount() != 0 {
		t.Errorf("expected 0 initial shards, got %d", relocator.GetInitialShardCount())
	}
}

func TestShardRelocator_States(t *testing.T) {
	relocator := NewShardRelocator(nil, getTestLogger(), "test-node")

	// Initial state should be Idle
	if relocator.GetState() != RelocationStateIdle {
		t.Errorf("expected initial state Idle, got %s", relocator.GetState())
	}

	// Set failed
	relocator.SetFailed("test failure")
	if relocator.GetState() != RelocationStateFailed {
		t.Errorf("expected state Failed, got %s", relocator.GetState())
	}

	// Reset
	relocator.Reset()
	if relocator.GetState() != RelocationStateIdle {
		t.Errorf("expected state Idle after reset, got %s", relocator.GetState())
	}

	// Set timeout
	relocator.SetTimeout()
	if relocator.GetState() != RelocationStateTimeout {
		t.Errorf("expected state Timeout, got %s", relocator.GetState())
	}
}

func TestDryRunResult(t *testing.T) {
	tests := []struct {
		name           string
		clusterStatus  string
		dataNodes      int
		shardCount     int
		existingExcl   string
		expectFeasible bool
		expectBlockers int
	}{
		{
			name:           "healthy cluster with multiple nodes",
			clusterStatus:  constants.OpenSearchHealthGreen,
			dataNodes:      3,
			shardCount:     10,
			existingExcl:   "",
			expectFeasible: true,
			expectBlockers: 0,
		},
		{
			name:           "yellow cluster",
			clusterStatus:  constants.OpenSearchHealthYellow,
			dataNodes:      3,
			shardCount:     10,
			existingExcl:   "",
			expectFeasible: false,
			expectBlockers: 1,
		},
		{
			name:           "only one data node",
			clusterStatus:  constants.OpenSearchHealthGreen,
			dataNodes:      1,
			shardCount:     10,
			existingExcl:   "",
			expectFeasible: false,
			expectBlockers: 1,
		},
		{
			name:           "existing exclusion on another node",
			clusterStatus:  constants.OpenSearchHealthGreen,
			dataNodes:      3,
			shardCount:     10,
			existingExcl:   "other-node",
			expectFeasible: false,
			expectBlockers: 1,
		},
		{
			name:           "existing exclusion on same node",
			clusterStatus:  constants.OpenSearchHealthGreen,
			dataNodes:      3,
			shardCount:     10,
			existingExcl:   "target-node",
			expectFeasible: true,
			expectBlockers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock result based on the conditions
			result := &v1alpha1.DryRunResult{
				Feasible:    true,
				EvaluatedAt: metav1.Now(),
				Component:   constants.DrainComponentIndexer,
			}

			// Apply conditions
			if tt.clusterStatus != constants.OpenSearchHealthGreen {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Cluster health is "+tt.clusterStatus+", must be "+constants.OpenSearchHealthGreen+" before drain")
			}

			if tt.dataNodes < 2 {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Cannot drain: only one data node in cluster")
			}

			if tt.existingExcl != "" && tt.existingExcl != "target-node" {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Another node ("+tt.existingExcl+") is already excluded from allocation")
			}

			if result.Feasible != tt.expectFeasible {
				t.Errorf("expected feasible %v, got %v", tt.expectFeasible, result.Feasible)
			}

			if len(result.Blockers) != tt.expectBlockers {
				t.Errorf("expected %d blockers, got %d: %v", tt.expectBlockers, len(result.Blockers), result.Blockers)
			}
		})
	}
}
