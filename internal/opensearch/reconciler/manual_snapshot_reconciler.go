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

package reconciler

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// ManualSnapshotFinalizer is the finalizer for manual snapshots
	ManualSnapshotFinalizer = "opensearchsnapshot.resources.wazuh.com/finalizer"
)

// ManualSnapshotReconciler handles reconciliation of manual OpenSearch snapshots
type ManualSnapshotReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewManualSnapshotReconciler creates a new ManualSnapshotReconciler
func NewManualSnapshotReconciler(c client.Client, scheme *runtime.Scheme) *ManualSnapshotReconciler {
	return &ManualSnapshotReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *ManualSnapshotReconciler) WithAPIClient(apiClient *api.Client) *ManualSnapshotReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch manual snapshot
func (r *ManualSnapshotReconciler) Reconcile(ctx context.Context, snapshot *wazuhv1alpha1.OpenSearchSnapshot) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(snapshot, ManualSnapshotFinalizer) {
		controllerutil.AddFinalizer(snapshot, ManualSnapshotFinalizer)
		if err := r.Update(ctx, snapshot); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !snapshot.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, snapshot)
	}

	if r.APIClient == nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhasePending, "", "Waiting for OpenSearch API client")
	}

	snapshotsAPI := api.NewSnapshotsAPI(r.APIClient)

	// Validate repository exists
	repo, err := snapshotsAPI.GetRepository(ctx, snapshot.Spec.Repository)
	if err != nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", fmt.Sprintf("Failed to check repository: %v", err))
	}
	if repo == nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", fmt.Sprintf("Repository '%s' not found", snapshot.Spec.Repository))
	}

	// Generate snapshot name if not already done
	snapshotName := snapshot.Status.SnapshotName
	if snapshotName == "" {
		snapshotName = r.generateSnapshotName(snapshot.Name)
		snapshot.Status.SnapshotName = snapshotName
	}

	// Check if snapshot already exists
	existingSnapshot, err := snapshotsAPI.GetSnapshot(ctx, snapshot.Spec.Repository, snapshotName)
	if err != nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", fmt.Sprintf("Failed to check snapshot: %v", err))
	}

	if existingSnapshot == nil {
		// Create new snapshot
		log.Info("Creating snapshot", "name", snapshotName, "repository", snapshot.Spec.Repository)

		now := metav1.Now()
		snapshot.Status.StartTime = &now

		if err := r.updateStatus(ctx, snapshot, constants.SnapshotPhaseInProgress, "", "Creating snapshot"); err != nil {
			log.Error(err, "Failed to update status")
		}

		// Build snapshot request
		osSnapshot := api.Snapshot{
			Indices:            snapshot.Spec.Indices,
			IncludeGlobalState: snapshot.Spec.IncludeGlobalState,
		}

		if err := snapshotsAPI.CreateSnapshot(ctx, snapshot.Spec.Repository, snapshotName, osSnapshot); err != nil {
			return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", fmt.Sprintf("Failed to create snapshot: %v", err))
		}

		log.Info("Snapshot creation initiated", "name", snapshotName)
	}

	// Poll snapshot status
	return r.updateSnapshotStatus(ctx, snapshot, snapshotsAPI)
}

// generateSnapshotName generates a unique snapshot name with timestamp
func (r *ManualSnapshotReconciler) generateSnapshotName(baseName string) string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("%s-%s", baseName, timestamp)
}

// updateSnapshotStatus polls and updates snapshot status from OpenSearch
func (r *ManualSnapshotReconciler) updateSnapshotStatus(ctx context.Context, snapshot *wazuhv1alpha1.OpenSearchSnapshot, snapshotsAPI *api.SnapshotsAPI) error {
	log := logf.FromContext(ctx)

	snapshotName := snapshot.Status.SnapshotName
	if snapshotName == "" {
		return fmt.Errorf("snapshot name not set")
	}

	// Get snapshot info
	snapshotInfo, err := snapshotsAPI.GetSnapshot(ctx, snapshot.Spec.Repository, snapshotName)
	if err != nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", fmt.Sprintf("Failed to get snapshot status: %v", err))
	}

	if snapshotInfo == nil {
		return r.updateStatus(ctx, snapshot, constants.SnapshotPhaseFailed, "", "Snapshot not found in repository")
	}

	// Update status based on OpenSearch state
	snapshot.Status.State = snapshotInfo.State
	snapshot.Status.Indices = snapshotInfo.Indices

	// Get detailed status for size info
	statusResult, err := snapshotsAPI.GetSnapshotStatus(ctx, snapshot.Spec.Repository, snapshotName)
	if err == nil && statusResult != nil && len(statusResult.Snapshots) > 0 {
		status := statusResult.Snapshots[0]
		snapshot.Status.Shards = &wazuhv1alpha1.ShardStats{
			Total:      int32(status.ShardsStats.Total),
			Successful: int32(status.ShardsStats.Successful),
			Failed:     int32(status.ShardsStats.Failed),
		}
		// Format size
		totalBytes := status.Stats.Total.SizeInBytes
		snapshot.Status.TotalSize = formatBytes(totalBytes)
	}

	// Determine phase based on state
	var phase string
	var message string
	switch snapshotInfo.State {
	case constants.OpenSearchSnapshotStateInProgress:
		phase = constants.SnapshotPhaseInProgress
		message = "Snapshot in progress"
	case constants.OpenSearchSnapshotStateSuccess:
		phase = constants.SnapshotPhaseCompleted
		message = "Snapshot completed successfully"
		now := metav1.Now()
		snapshot.Status.EndTime = &now
		if snapshot.Status.StartTime != nil {
			duration := now.Sub(snapshot.Status.StartTime.Time)
			snapshot.Status.Duration = formatDuration(duration)
		}
	case constants.OpenSearchSnapshotStateFailed:
		phase = constants.SnapshotPhaseFailed
		message = "Snapshot failed"
		now := metav1.Now()
		snapshot.Status.EndTime = &now
	case constants.OpenSearchSnapshotStatePartial:
		phase = constants.SnapshotPhasePartial
		message = "Snapshot completed with some failures"
		now := metav1.Now()
		snapshot.Status.EndTime = &now
		if snapshot.Status.StartTime != nil {
			duration := now.Sub(snapshot.Status.StartTime.Time)
			snapshot.Status.Duration = formatDuration(duration)
		}
	default:
		phase = constants.SnapshotPhaseInProgress
		message = fmt.Sprintf("Unknown state: %s", snapshotInfo.State)
	}

	log.Info("Snapshot status updated", "name", snapshotName, "state", snapshotInfo.State, "phase", phase)
	return r.updateStatus(ctx, snapshot, phase, snapshotInfo.State, message)
}

// handleDeletion handles snapshot cleanup on CRD deletion
func (r *ManualSnapshotReconciler) handleDeletion(ctx context.Context, snapshot *wazuhv1alpha1.OpenSearchSnapshot) error {
	log := logf.FromContext(ctx)

	// Note: We don't delete the actual snapshot from OpenSearch
	// The snapshot data is valuable and should be retained
	// Users can manually delete snapshots from OpenSearch if needed
	log.Info("OpenSearchSnapshot CRD deleted, snapshot data retained in repository",
		"name", snapshot.Name,
		"snapshotName", snapshot.Status.SnapshotName,
		"repository", snapshot.Spec.Repository)

	// Remove finalizer
	controllerutil.RemoveFinalizer(snapshot, ManualSnapshotFinalizer)
	if err := r.Update(ctx, snapshot); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	return nil
}

// updateStatus updates the snapshot status
func (r *ManualSnapshotReconciler) updateStatus(ctx context.Context, snapshot *wazuhv1alpha1.OpenSearchSnapshot, phase, state, message string) error {
	snapshot.Status.Phase = phase
	snapshot.Status.Message = message
	if state != "" {
		snapshot.Status.State = state
	}
	snapshot.Status.ObservedGeneration = snapshot.Generation

	// Set condition
	conditionStatus := metav1.ConditionFalse
	reason := "SnapshotInProgress"
	if phase == constants.SnapshotPhaseCompleted {
		conditionStatus = metav1.ConditionTrue
		reason = "SnapshotComplete"
	} else if phase == constants.SnapshotPhaseFailed {
		reason = "SnapshotFailed"
	} else if phase == constants.SnapshotPhasePartial {
		conditionStatus = metav1.ConditionTrue
		reason = "SnapshotPartial"
	}

	meta.SetStatusCondition(&snapshot.Status.Conditions, metav1.Condition{
		Type:               constants.ConditionTypeSnapshotComplete,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: snapshot.Generation,
	})

	return r.Status().Update(ctx, snapshot)
}

// formatBytes formats bytes into human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatDuration formats duration into human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm%.0fs", d.Minutes(), d.Seconds()-d.Minutes()*60)
	}
	return fmt.Sprintf("%.0fh%.0fm", d.Hours(), d.Minutes()-d.Hours()*60)
}

// Delete handles cleanup when a snapshot CRD is deleted (called by controller)
func (r *ManualSnapshotReconciler) Delete(ctx context.Context, snapshot *wazuhv1alpha1.OpenSearchSnapshot) error {
	return r.handleDeletion(ctx, snapshot)
}
