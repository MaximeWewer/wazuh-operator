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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DrainEventRecorder provides helper methods for emitting drain-related Kubernetes events
type DrainEventRecorder struct {
	recorder record.EventRecorder
}

// NewDrainEventRecorder creates a new DrainEventRecorder
func NewDrainEventRecorder(recorder record.EventRecorder) *DrainEventRecorder {
	return &DrainEventRecorder{
		recorder: recorder,
	}
}

// EmitDrainStarted emits an event when a drain operation starts
func (r *DrainEventRecorder) EmitDrainStarted(obj runtime.Object, component, targetPod string) {
	r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonStarted,
		"[%s] Drain started for pod %s", component, targetPod)
}

// EmitDrainProgress emits an event at progress milestones
func (r *DrainEventRecorder) EmitDrainProgress(obj runtime.Object, component string, progress int32, message string) {
	r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonProgress,
		"[%s] Drain progress: %d%% - %s", component, progress, message)
}

// EmitDrainCompleted emits an event when a drain operation completes successfully
func (r *DrainEventRecorder) EmitDrainCompleted(obj runtime.Object, component, targetPod string, durationSeconds float64) {
	r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonCompleted,
		"[%s] Drain completed for pod %s in %.1fs", component, targetPod, durationSeconds)
}

// EmitDrainFailed emits an event when a drain operation fails
func (r *DrainEventRecorder) EmitDrainFailed(obj runtime.Object, component, targetPod, reason string) {
	r.recorder.Eventf(obj, corev1.EventTypeWarning, constants.DrainEventReasonFailed,
		"[%s] Drain failed for pod %s: %s", component, targetPod, reason)
}

// EmitDrainRollback emits an event when a rollback is triggered
func (r *DrainEventRecorder) EmitDrainRollback(obj runtime.Object, component string, previousReplicas int32) {
	r.recorder.Eventf(obj, corev1.EventTypeWarning, constants.DrainEventReasonRollback,
		"[%s] Rolling back to %d replicas due to drain failure", component, previousReplicas)
}

// EmitDrainRollbackComplete emits an event when a rollback completes
func (r *DrainEventRecorder) EmitDrainRollbackComplete(obj runtime.Object, component string, replicas int32) {
	r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonRollbackComplete,
		"[%s] Rollback complete, restored to %d replicas", component, replicas)
}

// EmitDrainRetry emits an event when a retry is scheduled
func (r *DrainEventRecorder) EmitDrainRetry(obj runtime.Object, component string, attemptCount, maxAttempts int32, nextRetry string) {
	r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonRetry,
		"[%s] Retry %d/%d scheduled for %s", component, attemptCount, maxAttempts, nextRetry)
}

// EmitDrainTimeout emits an event when a drain operation times out
func (r *DrainEventRecorder) EmitDrainTimeout(obj runtime.Object, component, targetPod string, timeout string) {
	r.recorder.Eventf(obj, corev1.EventTypeWarning, constants.DrainEventReasonTimeout,
		"[%s] Drain timed out for pod %s after %s", component, targetPod, timeout)
}

// EmitDrainMaxRetriesReached emits an event when max retries are exhausted
func (r *DrainEventRecorder) EmitDrainMaxRetriesReached(obj runtime.Object, component string, attempts int32) {
	r.recorder.Eventf(obj, corev1.EventTypeWarning, constants.DrainEventReasonMaxRetries,
		"[%s] Max retry attempts (%d) reached, manual intervention required", component, attempts)
}

// EmitDryRunResult emits an event with dry-run evaluation results
func (r *DrainEventRecorder) EmitDryRunResult(obj runtime.Object, result *v1alpha1.DryRunResult) {
	var message string
	eventType := corev1.EventTypeNormal

	if result.Feasible {
		message = "Dry-run: scale-down is feasible"
		if result.EstimatedDuration != nil {
			message += fmt.Sprintf(" (estimated duration: %v)", result.EstimatedDuration.Duration)
		}
		if len(result.Warnings) > 0 {
			message += fmt.Sprintf(" with %d warning(s)", len(result.Warnings))
		}
	} else {
		eventType = corev1.EventTypeWarning
		message = fmt.Sprintf("Dry-run: scale-down blocked by %d issue(s)", len(result.Blockers))
		if len(result.Blockers) > 0 {
			message += ": " + result.Blockers[0]
		}
	}

	r.recorder.Event(obj, eventType, constants.DrainEventReasonDryRun, message)
}

// EmitIndexerShardRelocation emits an event when shard relocation status changes
func (r *DrainEventRecorder) EmitIndexerShardRelocation(obj runtime.Object, targetNode string, remainingShards int32, totalShards int32) {
	if remainingShards == 0 {
		r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonShardsRelocated,
			"[indexer] All shards relocated from node %s", targetNode)
	} else {
		r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonProgress,
			"[indexer] Relocating shards from node %s: %d/%d remaining", targetNode, remainingShards, totalShards)
	}
}

// EmitManagerQueueDrain emits an event when manager queue drain status changes
func (r *DrainEventRecorder) EmitManagerQueueDrain(obj runtime.Object, targetNode string, remainingItems int64, isComplete bool) {
	if isComplete {
		r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonQueueDrained,
			"[manager] Queue drained for node %s", targetNode)
	} else {
		r.recorder.Eventf(obj, corev1.EventTypeNormal, constants.DrainEventReasonProgress,
			"[manager] Draining queue for node %s: %d items remaining", targetNode, remainingItems)
	}
}
