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

package reconciler

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	retry "k8s.io/client-go/util/retry"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ActionGroupReconciler handles reconciliation of OpenSearch action groups
type ActionGroupReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewActionGroupReconciler creates a new ActionGroupReconciler
func NewActionGroupReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *ActionGroupReconciler {
	return &ActionGroupReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory for dynamic client resolution
func (r *ActionGroupReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *ActionGroupReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch action group
func (r *ActionGroupReconciler) Reconcile(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ActionGroupReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", ag.Name),
			attribute.String("resource.namespace", ag.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(ag, constants.ActionGroupFinalizer) {
		controllerutil.AddFinalizer(ag, constants.ActionGroupFinalizer)
		if err := r.Update(ctx, ag); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !ag.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, ag)
	}

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, ag, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	// Get OpenSearch client dynamically from cluster reference
	apiClient, err := r.ClientFactory.GetClientForRef(ctx, ag.Spec.ClusterRef, ag.Namespace)
	if err != nil {
		r.recordEvent(ag, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get OpenSearch client: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create Security API client
	securityAPI := api.NewSecurityAPI(apiClient)

	// Check if action group exists
	existing, err := securityAPI.GetActionGroup(ctx, ag.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, ag, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check action group existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(ag, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to check action group existence: %v", err))
		return fmt.Errorf("failed to check action group existence: %w", err)
	}

	// Build action group from spec
	actionGroup := r.buildActionGroup(ag)

	if existing == nil {
		log.Info("Creating action group", "name", ag.Name)
	} else {
		log.Info("Updating action group", "name", ag.Name)
	}
	if err := securityAPI.CreateActionGroup(ctx, ag.Name, actionGroup); err != nil {
		action := "create"
		if existing != nil {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, ag, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s action group: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(ag, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to %s action group: %v", action, err))
		return fmt.Errorf("failed to %s action group: %w", action, err)
	}

	r.recordEvent(ag, corev1.EventTypeNormal, "Synced", "Action group reconciled successfully")

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(ag.Spec)
	if hashErr == nil && ag.Status.LastAppliedHash != "" && ag.Status.LastAppliedHash != specHash {
		ag.Status.DriftDetected = true
		now := metav1.Now()
		ag.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchActionGroup", ag.Namespace)
		log.Info("Drift detected on OpenSearchActionGroup", "name", ag.Name)
	} else {
		ag.Status.DriftDetected = false
	}
	if hashErr == nil {
		ag.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, ag, wazuhv1.OpenSearchResourcePhaseReady, "Action group reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Action group reconciliation completed", "name", ag.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *ActionGroupReconciler) recordEvent(ag *wazuhv1.OpenSearchActionGroup, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(ag, eventType, reason, message)
	}
}

// buildActionGroup converts the CRD spec to an action group
func (r *ActionGroupReconciler) buildActionGroup(ag *wazuhv1.OpenSearchActionGroup) api.ActionGroup {
	return api.ActionGroup{
		AllowedActions: ag.Spec.AllowedActions,
		Description:    ag.Spec.Description,
		Type:           ag.Spec.Type,
	}
}

// updateStatus updates the action group status with retry on conflict
func (r *ActionGroupReconciler) updateStatus(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	ag.Status.Phase = phase
	ag.Status.Message = message
	now := metav1.Now()
	ag.Status.LastSyncTime = &now

	metrics.SetResourceSyncStatus("OpenSearchActionGroup", ag.Namespace, ag.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := ag.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchActionGroup{}
		if err := r.Get(ctx, types.NamespacedName{Name: ag.Name, Namespace: ag.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		ag.Status = latest.Status
		return nil
	})
}

// handleDeletion handles action group cleanup on deletion
func (r *ActionGroupReconciler) handleDeletion(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, ag); err != nil {
		log.Error(err, "Failed to delete action group from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(ag, constants.ActionGroupFinalizer)
	return r.Update(ctx, ag)
}

// Delete handles cleanup when an action group is deleted
func (r *ActionGroupReconciler) Delete(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping action group deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, ag.Spec.ClusterRef, ag.Namespace)
	if err != nil {
		log.Info("Skipping action group deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	securityAPI := api.NewSecurityAPI(apiClient)
	if err := securityAPI.DeleteActionGroup(ctx, ag.Name); err != nil {
		r.recordEvent(ag, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete action group: %v", err))
		return fmt.Errorf("failed to delete action group: %w", err)
	}

	r.recordEvent(ag, corev1.EventTypeNormal, "Deleted", "Action group deleted from OpenSearch")
	log.Info("Deleted OpenSearch action group", "name", ag.Name)
	return nil
}
