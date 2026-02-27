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
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RoleReconciler handles reconciliation of OpenSearch roles
type RoleReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewRoleReconciler creates a new RoleReconciler
func NewRoleReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *RoleReconciler {
	return &RoleReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory for dynamic client resolution
func (r *RoleReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *RoleReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch role
func (r *RoleReconciler) Reconcile(ctx context.Context, role *wazuhv1.OpenSearchRole) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "RoleReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", role.Name),
			attribute.String("resource.namespace", role.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(role, constants.RoleFinalizer) {
		controllerutil.AddFinalizer(role, constants.RoleFinalizer)
		if err := r.Update(ctx, role); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !role.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, role)
	}

	osClient, err := r.getOpenSearchClient(ctx, role)
	if err != nil {
		r.recordEvent(role, corev1.EventTypeWarning, "ConnectionError", fmt.Sprintf("Failed to connect to OpenSearch: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Build role from spec
	osRole := r.buildRole(role)

	// Create or update the role (using the CR name as role name)
	roleName := role.Name
	if err := osClient.CreateRole(ctx, roleName, osRole); err != nil {
		r.recordEvent(role, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to sync role to OpenSearch: %v", err))
		return fmt.Errorf("failed to create/update role: %w", err)
	}

	r.recordEvent(role, corev1.EventTypeNormal, "Synced", "Role successfully synchronized to OpenSearch")

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(role.Spec)
	if hashErr == nil && role.Status.LastAppliedHash != "" && role.Status.LastAppliedHash != specHash {
		// Spec changed since last sync - this is drift (external modification to CRD)
		role.Status.DriftDetected = true
		now := metav1.Now()
		role.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchRole", role.Namespace)
		log.Info("Drift detected on OpenSearchRole", "name", role.Name)
	} else {
		role.Status.DriftDetected = false
	}
	if hashErr == nil {
		role.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, role, wazuhv1.OpenSearchResourcePhaseReady, "Role reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Role reconciliation completed", "name", role.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *RoleReconciler) recordEvent(role *wazuhv1.OpenSearchRole, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(role, eventType, reason, message)
	}
}

// buildRole builds an OpenSearch role from the CRD spec
func (r *RoleReconciler) buildRole(role *wazuhv1.OpenSearchRole) adapters.SecurityRole {
	osRole := adapters.SecurityRole{
		Description:        role.Spec.Description,
		ClusterPermissions: role.Spec.ClusterPermissions,
	}

	// Convert index permissions
	for _, perm := range role.Spec.IndexPermissions {
		osRole.IndexPermissions = append(osRole.IndexPermissions, adapters.IndexPermission{
			IndexPatterns:  perm.IndexPatterns,
			AllowedActions: perm.AllowedActions,
		})
	}

	// Convert tenant permissions
	for _, perm := range role.Spec.TenantPermissions {
		osRole.TenantPermissions = append(osRole.TenantPermissions, adapters.TenantPermission{
			TenantPatterns: perm.TenantPatterns,
			AllowedActions: perm.AllowedActions,
		})
	}

	return osRole
}

// getOpenSearchClient gets an OpenSearch HTTP adapter using dynamic client resolution
func (r *RoleReconciler) getOpenSearchClient(ctx context.Context, role *wazuhv1.OpenSearchRole) (*adapters.OpenSearchHTTPAdapter, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("client factory not configured")
	}

	baseURL, username, password, caCert, err := r.ClientFactory.GetConnectionInfo(ctx, role.Spec.ClusterRef, role.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}

	config := adapters.OpenSearchConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the role status with retry on conflict
func (r *RoleReconciler) updateStatus(ctx context.Context, role *wazuhv1.OpenSearchRole, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	role.Status.Phase = phase
	role.Status.Message = message
	now := metav1.Now()
	role.Status.LastSyncTime = &now

	metrics.SetResourceSyncStatus("OpenSearchRole", role.Namespace, role.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := role.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchRole{}
		if err := r.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		role.Status = latest.Status
		return nil
	})
}

// handleDeletion handles role cleanup on deletion
func (r *RoleReconciler) handleDeletion(ctx context.Context, role *wazuhv1.OpenSearchRole) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, role); err != nil {
		log.Error(err, "Failed to delete role from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(role, constants.RoleFinalizer)
	return r.Update(ctx, role)
}

// Delete handles cleanup when a role is deleted
func (r *RoleReconciler) Delete(ctx context.Context, role *wazuhv1.OpenSearchRole) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, role)
	if err != nil {
		log.Info("Skipping role deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	if err := osClient.DeleteRole(ctx, role.Name); err != nil {
		r.recordEvent(role, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete role from OpenSearch: %v", err))
		return fmt.Errorf("failed to delete role: %w", err)
	}

	r.recordEvent(role, corev1.EventTypeNormal, "Deleted", "Role deleted from OpenSearch")
	log.Info("Deleted OpenSearch role", "name", role.Name)
	return nil
}
