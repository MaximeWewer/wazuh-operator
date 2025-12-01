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

// ActionGroupReconciler handles reconciliation of OpenSearch action groups
type ActionGroupReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewActionGroupReconciler creates a new ActionGroupReconciler
func NewActionGroupReconciler(c client.Client, scheme *runtime.Scheme) *ActionGroupReconciler {
	return &ActionGroupReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *ActionGroupReconciler) WithAPIClient(apiClient *api.Client) *ActionGroupReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch action group
func (r *ActionGroupReconciler) Reconcile(ctx context.Context, ag *wazuhv1alpha1.OpenSearchActionGroup) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, ag, "Pending", "Waiting for OpenSearch API client")
	}

	// Create Security API client
	securityAPI := api.NewSecurityAPI(r.APIClient)

	// Check if action group exists
	existing, err := securityAPI.GetActionGroup(ctx, ag.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, ag, "Error", fmt.Sprintf("Failed to check action group existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check action group existence: %w", err)
	}

	// Build action group from spec
	actionGroup := r.buildActionGroup(ag)

	if existing == nil {
		// Create new action group
		log.Info("Creating action group", "name", ag.Name)
		if err := securityAPI.CreateActionGroup(ctx, ag.Name, actionGroup); err != nil {
			if updateErr := r.updateStatus(ctx, ag, "Error", fmt.Sprintf("Failed to create action group: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create action group: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, ag, "Ready", "Action group reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Action group reconciliation completed", "name", ag.Name)
	return nil
}

// buildActionGroup converts the CRD spec to an action group
func (r *ActionGroupReconciler) buildActionGroup(ag *wazuhv1alpha1.OpenSearchActionGroup) api.ActionGroup {
	return api.ActionGroup{
		AllowedActions: ag.Spec.AllowedActions,
		Description:    ag.Spec.Description,
		Type:           ag.Spec.Type,
	}
}

// updateStatus updates the action group status
func (r *ActionGroupReconciler) updateStatus(ctx context.Context, ag *wazuhv1alpha1.OpenSearchActionGroup, phase, message string) error {
	ag.Status.Phase = phase
	ag.Status.Message = message
	now := metav1.Now()
	ag.Status.LastSyncTime = &now

	return r.Status().Update(ctx, ag)
}

// Delete handles cleanup when an action group is deleted
func (r *ActionGroupReconciler) Delete(ctx context.Context, ag *wazuhv1alpha1.OpenSearchActionGroup) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping action group deletion - no API client available")
		return nil
	}

	securityAPI := api.NewSecurityAPI(r.APIClient)
	if err := securityAPI.DeleteActionGroup(ctx, ag.Name); err != nil {
		return fmt.Errorf("failed to delete action group: %w", err)
	}

	log.Info("Deleted OpenSearch action group", "name", ag.Name)
	return nil
}
