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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RoleMappingReconciler handles reconciliation of OpenSearch role mappings
type RoleMappingReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory *security.OpenSearchClientFactory
}

// NewRoleMappingReconciler creates a new RoleMappingReconciler
func NewRoleMappingReconciler(c client.Client, scheme *runtime.Scheme) *RoleMappingReconciler {
	return &RoleMappingReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *RoleMappingReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *RoleMappingReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch role mapping
func (r *RoleMappingReconciler) Reconcile(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping) error {
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
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	securityAPI := api.NewSecurityAPI(apiClient)

	// Check if role mapping exists
	existing, err := securityAPI.GetRoleMapping(ctx, mapping.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check role mapping existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
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
		return fmt.Errorf("failed to %s role mapping: %w", action, err)
	}

	// Update status
	if err := r.updateStatus(ctx, mapping, wazuhv1.OpenSearchResourcePhaseReady, "Role mapping reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Role mapping reconciliation completed", "name", mapping.Name)
	return nil
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

// updateStatus updates the role mapping status
func (r *RoleMappingReconciler) updateStatus(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	mapping.Status.Phase = phase
	mapping.Status.Message = message
	now := metav1.Now()
	mapping.Status.LastSyncTime = &now

	return r.Status().Update(ctx, mapping)
}

// handleDeletion handles role mapping cleanup on deletion
func (r *RoleMappingReconciler) handleDeletion(ctx context.Context, mapping *wazuhv1.OpenSearchRoleMapping) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, mapping); err != nil {
		log.Error(err, "Failed to delete role mapping from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(mapping, constants.RoleMappingFinalizer)
	return r.Update(ctx, mapping)
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
		return fmt.Errorf("failed to delete role mapping: %w", err)
	}

	log.Info("Deleted OpenSearch role mapping", "name", mapping.Name)
	return nil
}
