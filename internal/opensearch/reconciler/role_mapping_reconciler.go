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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// RoleMappingReconciler handles reconciliation of OpenSearch role mappings
type RoleMappingReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewRoleMappingReconciler creates a new RoleMappingReconciler
func NewRoleMappingReconciler(c client.Client, scheme *runtime.Scheme) *RoleMappingReconciler {
	return &RoleMappingReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *RoleMappingReconciler) WithAPIClient(apiClient *api.Client) *RoleMappingReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch role mapping
func (r *RoleMappingReconciler) Reconcile(ctx context.Context, mapping *wazuhv1alpha1.OpenSearchRoleMapping) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, mapping, "Pending", "Waiting for OpenSearch API client")
	}

	// Create Security API client
	securityAPI := api.NewSecurityAPI(r.APIClient)

	// Check if role mapping exists
	existing, err := securityAPI.GetRoleMapping(ctx, mapping.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, mapping, "Error", fmt.Sprintf("Failed to check role mapping existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check role mapping existence: %w", err)
	}

	// Build role mapping from spec
	roleMapping := r.buildRoleMapping(mapping)

	if existing == nil {
		// Create new role mapping
		log.Info("Creating role mapping", "name", mapping.Name)
		if err := securityAPI.CreateRoleMapping(ctx, mapping.Name, roleMapping); err != nil {
			if updateErr := r.updateStatus(ctx, mapping, "Error", fmt.Sprintf("Failed to create role mapping: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create role mapping: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, mapping, "Ready", "Role mapping reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Role mapping reconciliation completed", "name", mapping.Name)
	return nil
}

// buildRoleMapping converts the CRD spec to a role mapping
func (r *RoleMappingReconciler) buildRoleMapping(mapping *wazuhv1alpha1.OpenSearchRoleMapping) api.RoleMapping {
	return api.RoleMapping{
		Description:     mapping.Spec.Description,
		BackendRoles:    mapping.Spec.BackendRoles,
		Hosts:           mapping.Spec.Hosts,
		Users:           mapping.Spec.Users,
		AndBackendRoles: mapping.Spec.AndBackendRoles,
	}
}

// updateStatus updates the role mapping status
func (r *RoleMappingReconciler) updateStatus(ctx context.Context, mapping *wazuhv1alpha1.OpenSearchRoleMapping, phase, message string) error {
	mapping.Status.Phase = phase
	mapping.Status.Message = message
	now := metav1.Now()
	mapping.Status.LastSyncTime = &now

	return r.Status().Update(ctx, mapping)
}

// Delete handles cleanup when a role mapping is deleted
func (r *RoleMappingReconciler) Delete(ctx context.Context, mapping *wazuhv1alpha1.OpenSearchRoleMapping) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping role mapping deletion - no API client available")
		return nil
	}

	securityAPI := api.NewSecurityAPI(r.APIClient)
	if err := securityAPI.DeleteRoleMapping(ctx, mapping.Name); err != nil {
		return fmt.Errorf("failed to delete role mapping: %w", err)
	}

	log.Info("Deleted OpenSearch role mapping", "name", mapping.Name)
	return nil
}
