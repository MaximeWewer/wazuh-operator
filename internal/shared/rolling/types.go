/*
Copyright 2026.

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

// Package rolling provides quorum-safe rolling restart orchestration for StatefulSets.
// It works with OnDelete update strategy to control pod-by-pod restarts with
// cluster health verification between each pod replacement.
package rolling

import "context"

// HealthChecker verifies whether a cluster is healthy enough to tolerate
// a pod being restarted. Implementations are component-specific (e.g. OpenSearch
// cluster health, Wazuh manager pod readiness).
type HealthChecker interface {
	// IsHealthyForRestart checks if the cluster can safely tolerate a pod restart.
	// Returns healthy=true if a pod can be safely deleted, along with a human-readable message.
	IsHealthyForRestart(ctx context.Context) (healthy bool, message string, err error)
}

// RestartPhase represents the current phase of a rolling restart.
type RestartPhase string

const (
	// RestartPhaseIdle means no restart is needed (all pods are on target revision).
	RestartPhaseIdle RestartPhase = "Idle"

	// RestartPhaseInProgress means a rolling restart is actively in progress.
	RestartPhaseInProgress RestartPhase = "InProgress"

	// RestartPhaseComplete means all pods have been updated to the target revision.
	RestartPhaseComplete RestartPhase = "Complete"
)

// RestartResult contains the outcome of a single orchestration call.
type RestartResult struct {
	// Phase is the current rolling restart phase.
	Phase RestartPhase

	// TotalPods is the total number of pods in the StatefulSet.
	TotalPods int32

	// UpdatedPods is the number of pods already on the target revision.
	UpdatedPods int32

	// CurrentPod is the name of the pod being restarted (if any).
	CurrentPod string

	// Message is a human-readable status message.
	Message string
}
