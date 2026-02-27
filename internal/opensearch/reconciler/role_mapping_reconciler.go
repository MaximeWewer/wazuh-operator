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

// RoleMappingReconciler handles reconciliation of OpenSearch role mappings
type RoleMappingReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewRoleMappingReconciler creates a new RoleMappingReconciler
func NewRoleMappingReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *RoleMappingReconciler {
	return &RoleMappingReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *RoleMappingReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *RoleMappingReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch role mapping
func (r *RoleMappingReconciler) Reconcile(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "RoleMappingReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", mapping.Name),
			attribute.String("resource.namespace", mapping.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(mapping, constants.RoleMappingFinalizer) {
		controllerutil.AddFinalizer(mapping, constants.RoleMappingFinalizer)
		if err := r.Update(ctx, mapping); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !mapping.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, mapping)
	}

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, mapping.Spec.ClusterRef, mapping.Namespace)
	if err != nil {
		r.recordEvent(mapping, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get OpenSearch client: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	securityAPI := api.NewSecurityAPI(apiClient)

	// Check if role mapping exists
	existing, err := securityAPI.GetRoleMapping(ctx, mapping.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check role mapping existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(mapping, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to check role mapping existence: %v", err))
		return fmt.Errorf("failed to check role mapping existence: %w", err)
	}

	// Build role mapping from spec
	roleMapping := r.buildRoleMapping(mapping)

	if existing == nil {
		log.Info("Creating role mapping", "name", mapping.Name)
	} else {
		log.Info("Updating role mapping", "name", mapping.Name)
	}
	if err := securityAPI.CreateRoleMapping(ctx, mapping.Name, roleMapping); err != nil {
		action := "create"
		if existing != nil {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s role mapping: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(mapping, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to %s role mapping: %v", action, err))
		return fmt.Errorf("failed to %s role mapping: %w", action, err)
	}

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(mapping.Spec)
	if hashErr == nil && mapping.Status.LastAppliedHash != "" && mapping.Status.LastAppliedHash != specHash {
		mapping.Status.DriftDetected = true
		now := metav1.Now()
		mapping.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchRoleMapping", mapping.Namespace)
		log.Info("Drift detected on OpenSearchRoleMapping", "name", mapping.Name)
	} else {
		mapping.Status.DriftDetected = false
	}
	if hashErr == nil {
		mapping.Status.LastAppliedHash = specHash
	}

	wasReady := mapping.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		mapping.Status.ObservedGeneration == mapping.Generation
	if err := r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhaseReady, "Role mapping reconciled successfully", !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if !wasReady {
		r.recordEvent(mapping, corev1.EventTypeNormal, "Synced", "Role mapping reconciled successfully")
	}

	log.Info("Role mapping reconciliation completed", "name", mapping.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *RoleMappingReconciler) recordEvent(mapping *wazuhv1.OpenSearchRoleMapping, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(mapping, eventType, reason, message)
	}
}

// buildRoleMapping converts the CRD spec to a role mapping
func (r *RoleMappingReconciler) buildRoleMapping(mapping *wazuhv1.OpenSearchRoleMapping) api.RoleMapping {
	return api.RoleMapping{
		Description:     mapping.Spec.Description,
		BackendRoles:    mapping.Spec.BackendRoles,
		Hosts:           mapping.Spec.Hosts,
		Users:           mapping.Spec.Users,
		AndBackendRoles: mapping.Spec.AndBackendRoles,
	}
}

// updateStatus updates the role mapping status with retry on conflict
func (r *RoleMappingReconciler) updateStatus(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	mapping.Status.Phase = phase
	mapping.Status.Message = message
	mapping.Status.ObservedGeneration = mapping.Generation
	if len(updateTimestamp) == 0 || updateTimestamp[0] {
		now := metav1.Now()
		mapping.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchRoleMapping", mapping.Namespace, mapping.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := mapping.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchRoleMapping{}
		if err := r.Get(ctx, types.NamespacedName{Name: mapping.Name, Namespace: mapping.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		mapping.Status = latest.Status
		return nil
	})
}

// handleDeletion handles role mapping cleanup on deletion
func (r *RoleMappingReconciler) handleDeletion(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, mapping); err != nil {
		log.Error(err, "Failed to delete role mapping from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchRoleMapping{}
		if err := r.Get(ctx, types.NamespacedName{Name: mapping.Name, Namespace: mapping.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.RoleMappingFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a role mapping is deleted
func (r *RoleMappingReconciler) Delete(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping role mapping deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, mapping.Spec.ClusterRef, mapping.Namespace)
	if err != nil {
		log.Info("Skipping role mapping deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	securityAPI := api.NewSecurityAPI(apiClient)
	if err := securityAPI.DeleteRoleMapping(ctx, mapping.Name); err != nil {
		r.recordEvent(mapping, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete role mapping: %v", err))
		return fmt.Errorf("failed to delete role mapping: %w", err)
	}

	r.recordEvent(mapping, corev1.EventTypeNormal, "Deleted", "Role mapping deleted from OpenSearch")
	log.Info("Deleted OpenSearch role mapping", "name", mapping.Name)
	return nil
}
