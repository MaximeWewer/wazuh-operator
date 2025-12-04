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

// Package drain provides drain strategy implementation for safe scale-down operations
package drain

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ValidTransitions defines the valid state transitions for drain operations
// Map key is the current phase, value is a slice of valid next phases
var ValidTransitions = map[v1alpha1.DrainPhase][]v1alpha1.DrainPhase{
	v1alpha1.DrainPhaseIdle: {
		v1alpha1.DrainPhasePending,
	},
	v1alpha1.DrainPhasePending: {
		v1alpha1.DrainPhaseDraining,
		v1alpha1.DrainPhaseIdle, // cancelled
	},
	v1alpha1.DrainPhaseDraining: {
		v1alpha1.DrainPhaseVerifying,
		v1alpha1.DrainPhaseFailed,
	},
	v1alpha1.DrainPhaseVerifying: {
		v1alpha1.DrainPhaseComplete,
		v1alpha1.DrainPhaseFailed,
	},
	v1alpha1.DrainPhaseComplete: {
		v1alpha1.DrainPhaseIdle,
	},
	v1alpha1.DrainPhaseFailed: {
		v1alpha1.DrainPhaseRollingBack,
		v1alpha1.DrainPhaseIdle, // manual reset
	},
	v1alpha1.DrainPhaseRollingBack: {
		v1alpha1.DrainPhasePending, // retry
		v1alpha1.DrainPhaseFailed,  // max retries exceeded
		v1alpha1.DrainPhaseIdle,    // manual reset
	},
}

// IsValidTransition checks if a transition from one phase to another is valid
func IsValidTransition(from, to v1alpha1.DrainPhase) bool {
	validTargets, ok := ValidTransitions[from]
	if !ok {
		return false
	}
	for _, valid := range validTargets {
		if valid == to {
			return true
		}
	}
	return false
}

// TransitionTo attempts to transition the drain status to a new phase
// Returns an error if the transition is invalid
func TransitionTo(status *v1alpha1.ComponentDrainStatus, to v1alpha1.DrainPhase, message string) error {
	if status == nil {
		return fmt.Errorf("status is nil")
	}

	from := status.Phase
	if from == "" {
		from = v1alpha1.DrainPhaseIdle
	}

	if !IsValidTransition(from, to) {
		return fmt.Errorf("invalid transition from %s to %s", from, to)
	}

	now := metav1.NewTime(time.Now())
	status.Phase = to
	status.LastTransitionTime = &now
	status.Message = message

	// Reset certain fields on specific transitions
	switch to {
	case v1alpha1.DrainPhaseIdle:
		// Clear all drain state
		status.TargetPod = ""
		status.PreviousReplicas = nil
		status.TargetReplicas = nil
		status.Progress = 0
		status.StartTime = nil
		status.AttemptCount = 0
		status.NextRetryTime = nil
		status.ShardCount = nil
		status.QueueDepth = nil
	case v1alpha1.DrainPhasePending:
		// Initialize for new drain
		status.StartTime = &now
		status.Progress = 0
	case v1alpha1.DrainPhaseComplete:
		status.Progress = 100
	}

	return nil
}

// InitializeDrainStatus creates a new ComponentDrainStatus with Idle phase
func InitializeDrainStatus() *v1alpha1.ComponentDrainStatus {
	return &v1alpha1.ComponentDrainStatus{
		Phase: v1alpha1.DrainPhaseIdle,
	}
}

// StartDrain initializes a new drain operation
func StartDrain(status *v1alpha1.ComponentDrainStatus, targetPod string, previousReplicas, targetReplicas int32) error {
	if status.Phase != v1alpha1.DrainPhaseIdle {
		return fmt.Errorf("cannot start drain: current phase is %s, expected Idle", status.Phase)
	}

	now := metav1.NewTime(time.Now())
	status.Phase = v1alpha1.DrainPhasePending
	status.TargetPod = targetPod
	status.PreviousReplicas = &previousReplicas
	status.TargetReplicas = &targetReplicas
	status.StartTime = &now
	status.LastTransitionTime = &now
	status.Progress = 0
	status.AttemptCount = 1
	status.Message = fmt.Sprintf("Scale-down detected: %d -> %d replicas, draining pod %s", previousReplicas, targetReplicas, targetPod)

	return nil
}

// UpdateProgress updates the progress percentage of a drain operation
func UpdateProgress(status *v1alpha1.ComponentDrainStatus, progress int32, message string) {
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	status.Progress = progress
	status.Message = message
}

// UpdateShardCount updates the remaining shard count (for indexer drain)
func UpdateShardCount(status *v1alpha1.ComponentDrainStatus, count int32) {
	status.ShardCount = &count
}

// UpdateQueueDepth updates the remaining queue depth (for manager drain)
func UpdateQueueDepth(status *v1alpha1.ComponentDrainStatus, depth int64) {
	status.QueueDepth = &depth
}

// MarkFailed marks the drain operation as failed
func MarkFailed(status *v1alpha1.ComponentDrainStatus, reason string) error {
	return TransitionTo(status, v1alpha1.DrainPhaseFailed, reason)
}

// MarkComplete marks the drain operation as complete
func MarkComplete(status *v1alpha1.ComponentDrainStatus) error {
	return TransitionTo(status, v1alpha1.DrainPhaseComplete, "Drain completed successfully")
}

// StartRollback initiates a rollback after failure
func StartRollback(status *v1alpha1.ComponentDrainStatus, reason string) error {
	return TransitionTo(status, v1alpha1.DrainPhaseRollingBack, reason)
}

// ScheduleRetry schedules a retry attempt after rollback
func ScheduleRetry(status *v1alpha1.ComponentDrainStatus, retryTime time.Time) {
	t := metav1.NewTime(retryTime)
	status.NextRetryTime = &t
	status.AttemptCount++
}

// IsRetryDue checks if it's time to retry
func IsRetryDue(status *v1alpha1.ComponentDrainStatus) bool {
	if status.NextRetryTime == nil {
		return false
	}
	return time.Now().After(status.NextRetryTime.Time)
}

// CanRetry checks if more retry attempts are allowed
func CanRetry(status *v1alpha1.ComponentDrainStatus, maxAttempts int32) bool {
	return status.AttemptCount < maxAttempts
}

// ResetForRetry resets status for a retry attempt
func ResetForRetry(status *v1alpha1.ComponentDrainStatus) error {
	if status.Phase != v1alpha1.DrainPhaseRollingBack {
		return fmt.Errorf("cannot reset for retry: current phase is %s, expected RollingBack", status.Phase)
	}

	now := metav1.NewTime(time.Now())
	status.Phase = v1alpha1.DrainPhasePending
	status.LastTransitionTime = &now
	status.Progress = 0
	status.NextRetryTime = nil
	status.Message = fmt.Sprintf("Retrying drain (attempt %d)", status.AttemptCount)

	return nil
}

// IsDrainInProgress returns true if a drain operation is currently active
func IsDrainInProgress(status *v1alpha1.ComponentDrainStatus) bool {
	if status == nil {
		return false
	}
	switch status.Phase {
	case v1alpha1.DrainPhasePending,
		v1alpha1.DrainPhaseDraining,
		v1alpha1.DrainPhaseVerifying,
		v1alpha1.DrainPhaseRollingBack:
		return true
	}
	return false
}

// IsDrainFailed returns true if the drain has failed
func IsDrainFailed(status *v1alpha1.ComponentDrainStatus) bool {
	if status == nil {
		return false
	}
	return status.Phase == v1alpha1.DrainPhaseFailed
}

// IsDrainComplete returns true if the drain has completed successfully
func IsDrainComplete(status *v1alpha1.ComponentDrainStatus) bool {
	if status == nil {
		return false
	}
	return status.Phase == v1alpha1.DrainPhaseComplete
}

// GetDrainDuration returns the elapsed time since drain started
func GetDrainDuration(status *v1alpha1.ComponentDrainStatus) time.Duration {
	if status == nil || status.StartTime == nil {
		return 0
	}
	return time.Since(status.StartTime.Time)
}

// IsTimeout checks if the drain has exceeded the timeout duration
func IsTimeout(status *v1alpha1.ComponentDrainStatus, timeout time.Duration) bool {
	if status == nil || status.StartTime == nil {
		return false
	}
	return time.Since(status.StartTime.Time) > timeout
}

// Reset resets the drain status to idle state
func Reset(status *v1alpha1.ComponentDrainStatus) {
	if status == nil {
		return
	}
	now := metav1.NewTime(time.Now())
	status.Phase = v1alpha1.DrainPhaseIdle
	status.LastTransitionTime = &now
	status.TargetPod = ""
	status.PreviousReplicas = nil
	status.TargetReplicas = nil
	status.Progress = 0
	status.StartTime = nil
	status.AttemptCount = 0
	status.NextRetryTime = nil
	status.ShardCount = nil
	status.QueueDepth = nil
	status.Message = "Reset to idle"
}
