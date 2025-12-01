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

// PolicyReconciler handles reconciliation of OpenSearch ISM policies
type PolicyReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewPolicyReconciler creates a new PolicyReconciler
func NewPolicyReconciler(c client.Client, scheme *runtime.Scheme) *PolicyReconciler {
	return &PolicyReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *PolicyReconciler) WithAPIClient(apiClient *api.Client) *PolicyReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch ISM policy
func (r *PolicyReconciler) Reconcile(ctx context.Context, policy *wazuhv1alpha1.OpenSearchISMPolicy) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		return r.updateStatus(ctx, policy, "Pending", "Waiting for OpenSearch API client")
	}

	// Create ISM API client
	ismAPI := api.NewISMAPI(r.APIClient)

	// Check if policy exists
	exists, err := ismAPI.Exists(ctx, policy.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, policy, "Error", fmt.Sprintf("Failed to check policy existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check policy existence: %w", err)
	}

	// Build ISM policy from spec
	ismPolicy := r.buildISMPolicy(policy)

	if !exists {
		// Create new policy
		log.Info("Creating ISM policy", "name", policy.Name)
		if err := ismAPI.Create(ctx, policy.Name, ismPolicy); err != nil {
			if updateErr := r.updateStatus(ctx, policy, "Error", fmt.Sprintf("Failed to create policy: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create ISM policy: %w", err)
		}
	}

	// Update status
	if err := r.updateStatus(ctx, policy, "Ready", "ISM policy reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("ISM policy reconciliation completed", "name", policy.Name)
	return nil
}

// buildISMPolicy converts the CRD spec to an ISM policy
func (r *PolicyReconciler) buildISMPolicy(policy *wazuhv1alpha1.OpenSearchISMPolicy) api.ISMPolicy {
	ismPolicy := api.ISMPolicy{
		Policy: api.ISMPolicySpec{
			Description:  policy.Spec.Description,
			DefaultState: policy.Spec.DefaultState,
		},
	}

	// Convert states
	for _, state := range policy.Spec.States {
		ismState := api.ISMState{
			Name: state.Name,
		}

		// Convert actions - actions use RawExtension for flexibility
		for _, action := range state.Actions {
			ismAction := api.ISMAction{}
			// The action config is raw JSON, we pass it through
			if action.Config != nil && action.Config.Raw != nil {
				ismAction.RawConfig = action.Config.Raw
			}
			ismState.Actions = append(ismState.Actions, ismAction)
		}

		// Convert transitions
		for _, transition := range state.Transitions {
			ismTransition := api.ISMTransition{
				StateName: transition.StateName,
			}

			if transition.Conditions != nil {
				ismTransition.Conditions = &api.ISMConditions{
					MinIndexAge: transition.Conditions.MinIndexAge,
					MinDocCount: transition.Conditions.MinDocCount,
					MinSize:     transition.Conditions.MinSize,
				}
			}

			ismState.Transitions = append(ismState.Transitions, ismTransition)
		}

		ismPolicy.Policy.States = append(ismPolicy.Policy.States, ismState)
	}

	// Convert ISM template patterns
	for _, tmpl := range policy.Spec.ISMTemplate {
		ismPolicy.Policy.ISMTemplate = append(ismPolicy.Policy.ISMTemplate, api.ISMTemplatePattern{
			IndexPatterns: tmpl.IndexPatterns,
			Priority:      int(tmpl.Priority),
		})
	}

	return ismPolicy
}

// updateStatus updates the policy status
func (r *PolicyReconciler) updateStatus(ctx context.Context, policy *wazuhv1alpha1.OpenSearchISMPolicy, phase, message string) error {
	policy.Status.Phase = phase
	policy.Status.Message = message
	now := metav1.Now()
	policy.Status.LastSyncTime = &now

	return r.Status().Update(ctx, policy)
}

// Delete handles cleanup when a policy is deleted
func (r *PolicyReconciler) Delete(ctx context.Context, policy *wazuhv1alpha1.OpenSearchISMPolicy) error {
	log := logf.FromContext(ctx)

	if r.APIClient == nil {
		log.Info("Skipping ISM policy deletion - no API client available")
		return nil
	}

	ismAPI := api.NewISMAPI(r.APIClient)
	if err := ismAPI.Delete(ctx, policy.Name); err != nil {
		return fmt.Errorf("failed to delete ISM policy: %w", err)
	}

	log.Info("Deleted OpenSearch ISM policy", "name", policy.Name)
	return nil
}
