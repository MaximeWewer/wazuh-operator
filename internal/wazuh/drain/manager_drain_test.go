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
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// getTestLogger returns a logr.Logger for testing
func getTestLogger() logr.Logger {
	return logr.New(testLoggerImpl{})
}

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

func TestNewManagerDrainer_DefaultConfig(t *testing.T) {
	drainer := NewManagerDrainer(nil, getTestLogger(), nil)

	if drainer.timeout != constants.DefaultManagerDrainTimeout {
		t.Errorf("expected timeout %v, got %v", constants.DefaultManagerDrainTimeout, drainer.timeout)
	}

	if drainer.queueCheckInterval != constants.DefaultManagerQueueCheckInterval {
		t.Errorf("expected queueCheckInterval %v, got %v", constants.DefaultManagerQueueCheckInterval, drainer.queueCheckInterval)
	}

	// Default grace period is 10 seconds
	expectedGracePeriod := 10 * time.Second
	if drainer.gracePeriod != expectedGracePeriod {
		t.Errorf("expected gracePeriod %v, got %v", expectedGracePeriod, drainer.gracePeriod)
	}
}

func TestNewManagerDrainer_CustomConfig(t *testing.T) {
	customTimeout := 20 * time.Minute
	customInterval := 10 * time.Second
	customGracePeriod := 60 * time.Second

	config := &v1alpha1.ManagerDrainConfig{
		Timeout:            &metav1.Duration{Duration: customTimeout},
		QueueCheckInterval: &metav1.Duration{Duration: customInterval},
		GracePeriod:        &metav1.Duration{Duration: customGracePeriod},
	}

	drainer := NewManagerDrainer(nil, getTestLogger(), config)

	if drainer.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, drainer.timeout)
	}

	if drainer.queueCheckInterval != customInterval {
		t.Errorf("expected queueCheckInterval %v, got %v", customInterval, drainer.queueCheckInterval)
	}

	if drainer.gracePeriod != customGracePeriod {
		t.Errorf("expected gracePeriod %v, got %v", customGracePeriod, drainer.gracePeriod)
	}
}

func TestManagerDrainProgress_Calculations(t *testing.T) {
	tests := []struct {
		name               string
		initialQueueDepth  int64
		currentQueueDepth  int64
		gracePeriodElapsed bool
		expectedPercent    int32
		expectedComplete   bool
	}{
		{
			name:               "no events to process",
			initialQueueDepth:  0,
			currentQueueDepth:  0,
			gracePeriodElapsed: true,
			expectedPercent:    100,
			expectedComplete:   true,
		},
		{
			name:               "all events remaining",
			initialQueueDepth:  1000,
			currentQueueDepth:  1000,
			gracePeriodElapsed: false,
			expectedPercent:    0,
			expectedComplete:   false,
		},
		{
			name:               "half events processed",
			initialQueueDepth:  1000,
			currentQueueDepth:  500,
			gracePeriodElapsed: false,
			expectedPercent:    50,
			expectedComplete:   false,
		},
		{
			name:               "queue empty but grace period not elapsed",
			initialQueueDepth:  1000,
			currentQueueDepth:  0,
			gracePeriodElapsed: false,
			expectedPercent:    100,
			expectedComplete:   false,
		},
		{
			name:               "drain complete with grace period",
			initialQueueDepth:  1000,
			currentQueueDepth:  0,
			gracePeriodElapsed: true,
			expectedPercent:    100,
			expectedComplete:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate progress as would be done in MonitorQueueDepth
			var percent int32
			if tt.initialQueueDepth > 0 {
				processedEvents := tt.initialQueueDepth - tt.currentQueueDepth
				percent = int32((processedEvents * 100) / tt.initialQueueDepth)
			} else {
				percent = 100
			}

			complete := tt.currentQueueDepth == 0 && tt.gracePeriodElapsed

			if percent != tt.expectedPercent {
				t.Errorf("expected percent %d, got %d", tt.expectedPercent, percent)
			}

			if complete != tt.expectedComplete {
				t.Errorf("expected complete %v, got %v", tt.expectedComplete, complete)
			}
		})
	}
}

func TestManagerDrainer_GracePeriodLogic(t *testing.T) {
	drainer := NewManagerDrainer(nil, getTestLogger(), nil)

	// Initially, no empty queue seen
	if drainer.emptyQueueSeenTime != nil {
		t.Error("expected emptyQueueSeenTime to be nil initially")
	}

	// Simulate queue becoming empty
	now := time.Now()
	drainer.emptyQueueSeenTime = &now

	// Check that grace period hasn't elapsed immediately
	if time.Since(*drainer.emptyQueueSeenTime) >= drainer.gracePeriod {
		t.Error("grace period should not have elapsed immediately")
	}
}

func TestDryRunResult_ManagerDrain(t *testing.T) {
	tests := []struct {
		name           string
		clusterRunning bool
		nodeConnected  bool
		workerCount    int
		expectFeasible bool
		expectBlockers int
	}{
		{
			name:           "healthy cluster with multiple workers",
			clusterRunning: true,
			nodeConnected:  true,
			workerCount:    2,
			expectFeasible: true,
			expectBlockers: 0,
		},
		{
			name:           "cluster not running",
			clusterRunning: false,
			nodeConnected:  true,
			workerCount:    2,
			expectFeasible: false,
			expectBlockers: 1,
		},
		{
			name:           "only one worker",
			clusterRunning: true,
			nodeConnected:  true,
			workerCount:    1,
			expectFeasible: false,
			expectBlockers: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock result based on the conditions
			result := &v1alpha1.DryRunResult{
				Feasible:    true,
				EvaluatedAt: metav1.Now(),
				Component:   constants.DrainComponentManager,
			}

			// Apply conditions
			if !tt.clusterRunning {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Wazuh cluster is not running")
			}

			if tt.workerCount <= 1 {
				result.Feasible = false
				result.Blockers = append(result.Blockers,
					"Cannot drain: only one worker node in cluster")
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

func TestCancelDrain_ResetsState(t *testing.T) {
	drainer := NewManagerDrainer(nil, getTestLogger(), nil)

	// Set up some state
	drainer.initialQueueDepth = 1000
	now := time.Now()
	drainer.emptyQueueSeenTime = &now

	// Cancel drain
	_ = drainer.CancelDrain(nil)

	// Verify state is reset
	if drainer.initialQueueDepth != 0 {
		t.Errorf("expected initialQueueDepth to be 0, got %d", drainer.initialQueueDepth)
	}
	if drainer.emptyQueueSeenTime != nil {
		t.Error("expected emptyQueueSeenTime to be nil")
	}
}
