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
	// RestoreFinalizer is the finalizer for restores
	RestoreFinalizer = "opensearchrestore.resources.wazuh.com/finalizer"
)

// RestoreReconciler handles reconciliation of OpenSearch restore operations
type RestoreReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewRestoreReconciler creates a new RestoreReconciler
func NewRestoreReconciler(c client.Client, scheme *runtime.Scheme) *RestoreReconciler {
	return &RestoreReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *RestoreReconciler) WithAPIClient(apiClient *api.Client) *RestoreReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch restore operation
func (r *RestoreReconciler) Reconcile(ctx context.Context, restore *wazuhv1alpha1.OpenSearchRestore) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(restore, RestoreFinalizer) {
		controllerutil.AddFinalizer(restore, RestoreFinalizer)
		if err := r.Update(ctx, restore); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !restore.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, restore)
	}

	// Skip if already completed or failed
	if restore.Status.Phase == constants.RestorePhaseCompleted || restore.Status.Phase == constants.RestorePhaseFailed {
		return nil
	}

	if r.APIClient == nil {
		return r.updateStatus(ctx, restore, constants.RestorePhasePending, "Waiting for OpenSearch API client")
	}

	snapshotsAPI := api.NewSnapshotsAPI(r.APIClient)

	// Phase: Validating
	if restore.Status.Phase == "" || restore.Status.Phase == constants.RestorePhasePending {
		if err := r.updateStatus(ctx, restore, constants.RestorePhaseValidating, "Validating snapshot and repository"); err != nil {
			log.Error(err, "Failed to update status")
		}

		// Validate repository exists
		repo, err := snapshotsAPI.GetRepository(ctx, restore.Spec.Repository)
		if err != nil {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Failed to check repository: %v", err))
		}
		if repo == nil {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Repository '%s' not found", restore.Spec.Repository))
		}

		// Validate snapshot exists
		snapshot, err := snapshotsAPI.GetSnapshot(ctx, restore.Spec.Repository, restore.Spec.Snapshot)
		if err != nil {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Failed to check snapshot: %v", err))
		}
		if snapshot == nil {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Snapshot '%s' not found in repository '%s'", restore.Spec.Snapshot, restore.Spec.Repository))
		}

		// Check snapshot state
		if snapshot.State != constants.OpenSearchSnapshotStateSuccess && snapshot.State != constants.OpenSearchSnapshotStatePartial {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Snapshot is not in a restorable state: %s", snapshot.State))
		}

		log.Info("Validation passed", "repository", restore.Spec.Repository, "snapshot", restore.Spec.Snapshot)
	}

	// Phase: Execute restore if not already started
	if restore.Status.Phase == constants.RestorePhaseValidating {
		log.Info("Starting restore", "repository", restore.Spec.Repository, "snapshot", restore.Spec.Snapshot)

		now := metav1.Now()
		restore.Status.StartTime = &now

		if err := r.updateStatus(ctx, restore, constants.RestorePhaseInProgress, "Restoring indices"); err != nil {
			log.Error(err, "Failed to update status")
		}

		// Build restore options
		opts := api.RestoreOptions{
			Indices:            restore.Spec.Indices,
			IgnoreUnavailable:  restore.Spec.IgnoreUnavailable,
			IncludeGlobalState: restore.Spec.IncludeGlobalState,
			RenamePattern:      restore.Spec.RenamePattern,
			RenameReplacement:  restore.Spec.RenameReplacement,
			Partial:            restore.Spec.Partial,
		}

		// Convert index settings
		if len(restore.Spec.IndexSettings) > 0 {
			opts.IndexSettings = make(map[string]interface{})
			for k, v := range restore.Spec.IndexSettings {
				opts.IndexSettings[k] = v
			}
		}

		// Execute restore
		result, err := snapshotsAPI.RestoreSnapshot(ctx, restore.Spec.Repository, restore.Spec.Snapshot, opts)
		if err != nil {
			return r.updateStatus(ctx, restore, constants.RestorePhaseFailed, fmt.Sprintf("Failed to restore snapshot: %v", err))
		}

		// Update status with initial result
		if result != nil {
			restore.Status.RestoredIndices = result.Snapshot.Indices
			restore.Status.Shards = &wazuhv1alpha1.ShardStats{
				Total:      int32(result.Snapshot.Shards.Total),
				Successful: int32(result.Snapshot.Shards.Successful),
				Failed:     int32(result.Snapshot.Shards.Failed),
			}
		}

		log.Info("Restore initiated", "indices", restore.Status.RestoredIndices)
	}

	// Monitor restore progress
	return r.monitorRestoreProgress(ctx, restore, snapshotsAPI)
}

// monitorRestoreProgress monitors the restore operation progress
func (r *RestoreReconciler) monitorRestoreProgress(ctx context.Context, restore *wazuhv1alpha1.OpenSearchRestore, snapshotsAPI *api.SnapshotsAPI) error {
	log := logf.FromContext(ctx)

	// Check recovery status for restored indices
	if len(restore.Status.RestoredIndices) == 0 {
		return r.updateStatus(ctx, restore, constants.RestorePhaseInProgress, "Waiting for restore to start")
	}

	// Check recovery status for the first index (as indicator)
	indexName := restore.Status.RestoredIndices[0]
	recoveryInfo, err := snapshotsAPI.GetRestoreStatus(ctx, indexName)
	if err != nil {
		log.Error(err, "Failed to get recovery status", "index", indexName)
		// Don't fail the restore, just continue monitoring
		return nil
	}

	if recoveryInfo == nil {
		// No recovery info means restore hasn't started or completed
		return r.updateStatus(ctx, restore, constants.RestorePhaseInProgress, "Restore in progress")
	}

	// Check if all shards are done
	allDone := true
	for _, info := range recoveryInfo {
		for _, shard := range info.Shards {
			if shard.Stage != "DONE" {
				allDone = false
				break
			}
		}
		if !allDone {
			break
		}
	}

	if allDone {
		// Restore completed
		now := metav1.Now()
		restore.Status.EndTime = &now
		if restore.Status.StartTime != nil {
			duration := now.Sub(restore.Status.StartTime.Time)
			restore.Status.Duration = formatDuration(duration)
		}

		log.Info("Restore completed", "indices", restore.Status.RestoredIndices, "duration", restore.Status.Duration)
		return r.updateStatus(ctx, restore, constants.RestorePhaseCompleted, "Restore completed successfully")
	}

	return r.updateStatus(ctx, restore, constants.RestorePhaseInProgress, "Restore in progress")
}

// handleDeletion handles restore cleanup on CRD deletion
func (r *RestoreReconciler) handleDeletion(ctx context.Context, restore *wazuhv1alpha1.OpenSearchRestore) error {
	log := logf.FromContext(ctx)

	// Note: We don't delete the restored indices
	// Restored data is valuable and should be retained
	log.Info("OpenSearchRestore CRD deleted, restored data retained",
		"name", restore.Name,
		"restoredIndices", restore.Status.RestoredIndices)

	// Remove finalizer
	controllerutil.RemoveFinalizer(restore, RestoreFinalizer)
	if err := r.Update(ctx, restore); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	return nil
}

// updateStatus updates the restore status
func (r *RestoreReconciler) updateStatus(ctx context.Context, restore *wazuhv1alpha1.OpenSearchRestore, phase, message string) error {
	restore.Status.Phase = phase
	restore.Status.Message = message
	restore.Status.ObservedGeneration = restore.Generation

	// Set condition
	conditionStatus := metav1.ConditionFalse
	reason := "RestoreInProgress"
	if phase == constants.RestorePhaseCompleted {
		conditionStatus = metav1.ConditionTrue
		reason = "RestoreComplete"
	} else if phase == constants.RestorePhaseFailed {
		reason = "RestoreFailed"
	}

	meta.SetStatusCondition(&restore.Status.Conditions, metav1.Condition{
		Type:               constants.ConditionTypeRestoreComplete,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: restore.Generation,
	})

	return r.Status().Update(ctx, restore)
}

// Delete handles cleanup when a restore CRD is deleted (called by controller)
func (r *RestoreReconciler) Delete(ctx context.Context, restore *wazuhv1alpha1.OpenSearchRestore) error {
	return r.handleDeletion(ctx, restore)
}
