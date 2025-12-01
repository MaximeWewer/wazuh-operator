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

// TenantReconciler handles reconciliation of OpenSearch tenants
type TenantReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewTenantReconciler creates a new TenantReconciler
func NewTenantReconciler(c client.Client, scheme *runtime.Scheme) *TenantReconciler {
	return &TenantReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *TenantReconciler) WithAPIClient(apiClient *api.Client) *TenantReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch tenant
func (r *TenantReconciler) Reconcile(ctx context.Context, tenant *wazuhv1alpha1.OpenSearchTenant) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, tenant, "Pending", "Waiting for OpenSearch API client")
	}

	// Create Security API client
	securityAPI := api.NewSecurityAPI(r.APIClient)

	// Check if tenant exists
	existing, err := securityAPI.GetTenant(ctx, tenant.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, tenant, "Error", fmt.Sprintf("Failed to check tenant existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check tenant existence: %w", err)
	}

	// Build tenant from spec
	osTenant := r.buildTenant(tenant)

	if existing == nil {
		// Create new tenant
		log.Info("Creating tenant", "name", tenant.Name)
		if err := securityAPI.CreateTenant(ctx, tenant.Name, osTenant); err != nil {
			if updateErr := r.updateStatus(ctx, tenant, "Error", fmt.Sprintf("Failed to create tenant: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create tenant: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, tenant, "Ready", "Tenant reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Tenant reconciliation completed", "name", tenant.Name)
	return nil
}

// buildTenant converts the CRD spec to a tenant
func (r *TenantReconciler) buildTenant(tenant *wazuhv1alpha1.OpenSearchTenant) api.Tenant {
	return api.Tenant{
		Description: tenant.Spec.Description,
	}
}

// updateStatus updates the tenant status
func (r *TenantReconciler) updateStatus(ctx context.Context, tenant *wazuhv1alpha1.OpenSearchTenant, phase, message string) error {
	tenant.Status.Phase = phase
	tenant.Status.Message = message
	now := metav1.Now()
	tenant.Status.LastSyncTime = &now

	return r.Status().Update(ctx, tenant)
}

// Delete handles cleanup when a tenant is deleted
func (r *TenantReconciler) Delete(ctx context.Context, tenant *wazuhv1alpha1.OpenSearchTenant) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping tenant deletion - no API client available")
		return nil
	}

	securityAPI := api.NewSecurityAPI(r.APIClient)
	if err := securityAPI.DeleteTenant(ctx, tenant.Name); err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	log.Info("Deleted OpenSearch tenant", "name", tenant.Name)
	return nil
}
