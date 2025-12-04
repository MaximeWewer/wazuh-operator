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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestRetryManager_ShouldRetry(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	tests := []struct {
		name          string
		status        *v1alpha1.ComponentDrainStatus
		config        *v1alpha1.DrainRetryConfig
		expectedRetry bool
	}{
		{
			name: "should retry - failed state, under max attempts",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: 1,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			expectedRetry: true,
		},
		{
			name: "should not retry - max attempts reached",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: 3,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			expectedRetry: false,
		},
		{
			name: "should not retry - not in failed state",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseDraining,
				AttemptCount: 1,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			expectedRetry: false,
		},
		{
			name: "should retry - use default config",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: 1,
			},
			config:        nil,
			expectedRetry: true,
		},
		{
			name: "should not retry - exceeded default max",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: constants.DefaultDrainRetryMaxAttempts,
			},
			config:        nil,
			expectedRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldRetry := manager.ShouldRetry(tt.status, tt.config)
			if shouldRetry != tt.expectedRetry {
				t.Errorf("expected shouldRetry=%v, got %v", tt.expectedRetry, shouldRetry)
			}
		})
	}
}

func TestRetryManager_CalculateNextRetryTime(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	tests := []struct {
		name           string
		attemptCount   int32
		config         *v1alpha1.DrainRetryConfig
		minExpectedDur time.Duration
		maxExpectedDur time.Duration
	}{
		{
			name:           "first attempt - default config",
			attemptCount:   1,
			config:         nil,
			minExpectedDur: 4*time.Minute + 55*time.Second,
			maxExpectedDur: 5*time.Minute + 5*time.Second,
		},
		{
			name:         "second attempt - exponential backoff",
			attemptCount: 2,
			config: &v1alpha1.DrainRetryConfig{
				InitialDelay:      &metav1.Duration{Duration: 1 * time.Minute},
				BackoffMultiplier: "2.0",
			},
			minExpectedDur: 1*time.Minute + 55*time.Second,
			maxExpectedDur: 2*time.Minute + 5*time.Second,
		},
		{
			name:         "capped at max delay",
			attemptCount: 10,
			config: &v1alpha1.DrainRetryConfig{
				InitialDelay:      &metav1.Duration{Duration: 5 * time.Minute},
				BackoffMultiplier: "2.0",
				MaxDelay:          &metav1.Duration{Duration: 10 * time.Minute},
			},
			minExpectedDur: 9*time.Minute + 55*time.Second,
			maxExpectedDur: 10*time.Minute + 5*time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &v1alpha1.ComponentDrainStatus{
				AttemptCount: tt.attemptCount,
			}

			nextRetry := manager.CalculateNextRetryTime(status, tt.config)
			delay := time.Until(nextRetry)

			if delay < tt.minExpectedDur || delay > tt.maxExpectedDur {
				t.Errorf("expected delay between %v and %v, got %v", tt.minExpectedDur, tt.maxExpectedDur, delay)
			}
		})
	}
}

func TestRetryManager_IncrementAttempt(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	status := &v1alpha1.ComponentDrainStatus{
		AttemptCount: 1,
	}

	config := &v1alpha1.DrainRetryConfig{
		InitialDelay:      &metav1.Duration{Duration: 1 * time.Minute},
		BackoffMultiplier: "2.0",
	}

	manager.IncrementAttempt(status, config)

	if status.AttemptCount != 2 {
		t.Errorf("expected attemptCount=2, got %d", status.AttemptCount)
	}

	if status.NextRetryTime == nil {
		t.Error("expected NextRetryTime to be set")
	}

	if status.NextRetryTime.Time.Before(time.Now()) {
		t.Error("expected NextRetryTime to be in the future")
	}
}

func TestRetryManager_IsRetryDue(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	tests := []struct {
		name        string
		status      *v1alpha1.ComponentDrainStatus
		expectedDue bool
	}{
		{
			name: "retry is due - time has passed",
			status: &v1alpha1.ComponentDrainStatus{
				NextRetryTime: &metav1.Time{Time: time.Now().Add(-1 * time.Minute)},
			},
			expectedDue: true,
		},
		{
			name: "retry not due - time in future",
			status: &v1alpha1.ComponentDrainStatus{
				NextRetryTime: &metav1.Time{Time: time.Now().Add(5 * time.Minute)},
			},
			expectedDue: false,
		},
		{
			name: "retry not due - no time set",
			status: &v1alpha1.ComponentDrainStatus{
				NextRetryTime: nil,
			},
			expectedDue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isDue := manager.IsRetryDue(tt.status)
			if isDue != tt.expectedDue {
				t.Errorf("expected isDue=%v, got %v", tt.expectedDue, isDue)
			}
		})
	}
}

func TestRetryManager_ResetRetryState(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	status := &v1alpha1.ComponentDrainStatus{
		AttemptCount:  3,
		NextRetryTime: &metav1.Time{Time: time.Now().Add(5 * time.Minute)},
	}

	manager.ResetRetryState(status)

	if status.AttemptCount != 0 {
		t.Errorf("expected attemptCount=0, got %d", status.AttemptCount)
	}

	if status.NextRetryTime != nil {
		t.Error("expected NextRetryTime to be nil")
	}
}

func TestRetryManager_EvaluateRetry(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	tests := []struct {
		name                     string
		status                   *v1alpha1.ComponentDrainStatus
		config                   *v1alpha1.DrainRetryConfig
		expectedShouldRetry      bool
		expectedRemainingGreater int32
	}{
		{
			name: "should retry with remaining attempts",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: 1,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			expectedShouldRetry:      true,
			expectedRemainingGreater: 1,
		},
		{
			name: "max attempts reached",
			status: &v1alpha1.ComponentDrainStatus{
				Phase:        v1alpha1.DrainPhaseFailed,
				AttemptCount: 3,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			expectedShouldRetry:      false,
			expectedRemainingGreater: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := manager.EvaluateRetry(tt.status, tt.config)

			if decision.ShouldRetry != tt.expectedShouldRetry {
				t.Errorf("expected ShouldRetry=%v, got %v", tt.expectedShouldRetry, decision.ShouldRetry)
			}

			if decision.RemainingAttempts <= tt.expectedRemainingGreater {
				t.Errorf("expected RemainingAttempts > %d, got %d", tt.expectedRemainingGreater, decision.RemainingAttempts)
			}
		})
	}
}

func TestRetryManager_GetRetryStatus(t *testing.T) {
	manager := NewRetryManager(getTestLogger())

	tests := []struct {
		name     string
		status   *v1alpha1.ComponentDrainStatus
		config   *v1alpha1.DrainRetryConfig
		contains string
	}{
		{
			name: "max attempts reached",
			status: &v1alpha1.ComponentDrainStatus{
				AttemptCount: 3,
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			contains: "manual intervention",
		},
		{
			name: "retry scheduled in future",
			status: &v1alpha1.ComponentDrainStatus{
				AttemptCount:  1,
				NextRetryTime: &metav1.Time{Time: time.Now().Add(5 * time.Minute)},
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			contains: "retry scheduled",
		},
		{
			name: "retry due",
			status: &v1alpha1.ComponentDrainStatus{
				AttemptCount:  1,
				NextRetryTime: &metav1.Time{Time: time.Now().Add(-1 * time.Minute)},
			},
			config: &v1alpha1.DrainRetryConfig{
				MaxAttempts: 3,
			},
			contains: "retry due",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusStr := manager.GetRetryStatus(tt.status, tt.config)
			if !containsSubstring(statusStr, tt.contains) {
				t.Errorf("expected status to contain %q, got %q", tt.contains, statusStr)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s[1:], substr) || s[:len(substr)] == substr)
}
