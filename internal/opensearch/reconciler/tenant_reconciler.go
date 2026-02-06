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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
)

// TenantReconciler handles reconciliation of OpenSearch tenants
type TenantReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory *security.OpenSearchClientFactory
}

// NewTenantReconciler creates a new TenantReconciler
func NewTenantReconciler(c client.Client, scheme *runtime.Scheme) *TenantReconciler {
	return &TenantReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *TenantReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *TenantReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch tenant
func (r *TenantReconciler) Reconcile(ctx context.Context, tenant *wazuhv1.OpenSearchTenant) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	// Get OpenSearch client dynamically from cluster reference
	apiClient, err := r.ClientFactory.GetClientForRef(ctx, tenant.Spec.ClusterRef, tenant.Namespace)
	if err != nil {
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
		return fmt.Errorf("failed to check tenant existence: %w", err)
	}

	// Build tenant from spec
	osTenant := r.buildTenant(tenant)

	if existing == nil {
		// Create new tenant
		log.Info("Creating tenant", "name", tenant.Name)
		if err := securityAPI.CreateTenant(ctx, tenant.Name, osTenant); err != nil {
			if updateErr := r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to create tenant: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create tenant: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, tenant, wazuhv1.OpenSearchResourcePhaseReady, "Tenant reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Tenant reconciliation completed", "name", tenant.Name)
	return nil
}

// buildTenant converts the CRD spec to a tenant
func (r *TenantReconciler) buildTenant(tenant *wazuhv1.OpenSearchTenant) api.Tenant {
	return api.Tenant{
		Description: tenant.Spec.Description,
	}
}

// updateStatus updates the tenant status
func (r *TenantReconciler) updateStatus(ctx context.Context, tenant *wazuhv1.OpenSearchTenant, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	tenant.Status.Phase = phase
	tenant.Status.Message = message
	now := metav1.Now()
	tenant.Status.LastSyncTime = &now

	return r.Status().Update(ctx, tenant)
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
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	log.Info("Deleted OpenSearch tenant", "name", tenant.Name)
	return nil
}
