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

// TenantReconciler handles reconciliation of OpenSearch tenants
type TenantReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewTenantReconciler creates a new TenantReconciler
func NewTenantReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *TenantReconciler {
	return &TenantReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *TenantReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *TenantReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch tenant
func (r *TenantReconciler) Reconcile(ctx context.Context, tenant *wazuhv1.OpenSearchTenant) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "TenantReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", tenant.Name),
			attribute.String("resource.namespace", tenant.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(tenant, constants.TenantFinalizer) {
		controllerutil.AddFinalizer(tenant, constants.TenantFinalizer)
		if err := r.Update(ctx, tenant); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !tenant.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, tenant)
	}

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	// Get OpenSearch client dynamically from cluster reference
	apiClient, err := r.ClientFactory.GetClientForRef(ctx, tenant.Spec.ClusterRef, tenant.Namespace)
	if err != nil {
		r.recordEvent(tenant, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get OpenSearch client: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create Security API client
	securityAPI := api.NewSecurityAPI(apiClient)

	// Check if tenant exists
	existing, err := securityAPI.GetTenant(ctx, tenant.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check tenant existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(tenant, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to check tenant existence: %v", err))
		return fmt.Errorf("failed to check tenant existence: %w", err)
	}

	// Build tenant from spec
	osTenant := r.buildTenant(tenant)

	if existing == nil {
		log.Info("Creating tenant", "name", tenant.Name)
	} else {
		log.Info("Updating tenant", "name", tenant.Name)
	}
	if err := securityAPI.CreateTenant(ctx, tenant.Name, osTenant); err != nil {
		action := "create"
		if existing != nil {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s tenant: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(tenant, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to %s tenant: %v", action, err))
		return fmt.Errorf("failed to %s tenant: %w", action, err)
	}

	r.recordEvent(tenant, corev1.EventTypeNormal, "Synced", "Tenant reconciled successfully")

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(tenant.Spec)
	if hashErr == nil && tenant.Status.LastAppliedHash != "" && tenant.Status.LastAppliedHash != specHash {
		tenant.Status.DriftDetected = true
		now := metav1.Now()
		tenant.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchTenant", tenant.Namespace)
		log.Info("Drift detected on OpenSearchTenant", "name", tenant.Name)
	} else {
		tenant.Status.DriftDetected = false
	}
	if hashErr == nil {
		tenant.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhaseReady, "Tenant reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Tenant reconciliation completed", "name", tenant.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *TenantReconciler) recordEvent(tenant *wazuhv1.OpenSearchTenant, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(tenant, eventType, reason, message)
	}
}

// buildTenant converts the CRD spec to a tenant
func (r *TenantReconciler) buildTenant(tenant *wazuhv1.OpenSearchTenant) api.Tenant {
	return api.Tenant{
		Description: tenant.Spec.Description,
	}
}

// updateStatus updates the tenant status with retry on conflict
func (r *TenantReconciler) updateStatus(ctx context.Context, tenant *wazuhv1.OpenSearchTenant, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	tenant.Status.Phase = phase
	tenant.Status.Message = message
	now := metav1.Now()
	tenant.Status.LastSyncTime = &now

	metrics.SetResourceSyncStatus("OpenSearchTenant", tenant.Namespace, tenant.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := tenant.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchTenant{}
		if err := r.Get(ctx, types.NamespacedName{Name: tenant.Name, Namespace: tenant.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		tenant.Status = latest.Status
		return nil
	})
}

// handleDeletion handles tenant cleanup on deletion
func (r *TenantReconciler) handleDeletion(ctx context.Context, tenant *wazuhv1.OpenSearchTenant) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, tenant); err != nil {
		log.Error(err, "Failed to delete tenant from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchTenant{}
		if err := r.Get(ctx, types.NamespacedName{Name: tenant.Name, Namespace: tenant.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.TenantFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a tenant is deleted
func (r *TenantReconciler) Delete(ctx context.Context, tenant *wazuhv1.OpenSearchTenant) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping tenant deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, tenant.Spec.ClusterRef, tenant.Namespace)
	if err != nil {
		log.Info("Skipping tenant deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	securityAPI := api.NewSecurityAPI(apiClient)
	if err := securityAPI.DeleteTenant(ctx, tenant.Name); err != nil {
		r.recordEvent(tenant, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete tenant: %v", err))
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	r.recordEvent(tenant, corev1.EventTypeNormal, "Deleted", "Tenant deleted from OpenSearch")
	log.Info("Deleted OpenSearch tenant", "name", tenant.Name)
	return nil
}
