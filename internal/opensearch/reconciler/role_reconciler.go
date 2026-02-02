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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// RoleReconciler handles reconciliation of OpenSearch roles
type RoleReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Recorder       record.EventRecorder
	OpenSearchAddr string
	OpenSearchUser string
	OpenSearchPass string
}

// NewRoleReconciler creates a new RoleReconciler
func NewRoleReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *RoleReconciler {
	return &RoleReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// Reconcile reconciles an OpenSearch role
func (r *RoleReconciler) Reconcile(ctx context.Context, role *wazuhv1.OpenSearchRole) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, role.Namespace)
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

	// Update status
	if err := r.updateStatus(ctx, role, "Ready", "Role reconciled successfully"); err != nil {
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

// getOpenSearchClient gets an OpenSearch HTTP adapter
func (r *RoleReconciler) getOpenSearchClient(_ context.Context, _ string) (*adapters.OpenSearchHTTPAdapter, error) {
	config := adapters.OpenSearchConfig{
		BaseURL:  r.OpenSearchAddr,
		Username: r.OpenSearchUser,
		Password: r.OpenSearchPass,
		Insecure: true,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the role status
func (r *RoleReconciler) updateStatus(ctx context.Context, role *wazuhv1.OpenSearchRole, phase, message string) error {
	role.Status.Phase = phase
	role.Status.Message = message
	now := metav1.Now()
	role.Status.LastSyncTime = &now

	return r.Status().Update(ctx, role)
}

// Delete handles cleanup when a role is deleted
func (r *RoleReconciler) Delete(ctx context.Context, role *wazuhv1.OpenSearchRole) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, role.Namespace)
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
