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

// PolicyReconciler handles reconciliation of OpenSearch ISM policies
type PolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewPolicyReconciler creates a new PolicyReconciler
func NewPolicyReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *PolicyReconciler {
	return &PolicyReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *PolicyReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *PolicyReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch ISM policy
func (r *PolicyReconciler) Reconcile(ctx context.Context, policy *wazuhv1.OpenSearchISMPolicy) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "PolicyReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", policy.Name),
			attribute.String("resource.namespace", policy.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(policy, constants.ISMPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, constants.ISMPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, policy)
	}

	if r.ClientFactory == nil {
		return r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhasePending, "Waiting for OpenSearch client factory")
	}

	ismPolicy := r.buildISMPolicy(policy)
	specHash, _ := patch.ComputeSpecHash(policy.Spec)

	res := ReconcileMultiCluster(ctx, policy.Spec.ClusterRefs, r.ClientFactory, policy.Status.ClusterStatuses,
		func(ctx context.Context, apiClient *api.Client, ref wazuhv1.WazuhClusterRef) (string, error) {
			ismAPI := api.NewISMAPI(apiClient)
			exists, err := ismAPI.Exists(ctx, policy.Name)
			if err != nil {
				return "", fmt.Errorf("failed to check ISM policy existence: %w", err)
			}
			if !exists {
				log.Info("Creating ISM policy", "name", policy.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
				if err := ismAPI.Create(ctx, policy.Name, ismPolicy); err != nil {
					return "", fmt.Errorf("failed to create ISM policy: %w", err)
				}
			} else {
				log.Info("Updating ISM policy", "name", policy.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
				existing, err := ismAPI.GetWithMeta(ctx, policy.Name)
				if err != nil {
					return "", fmt.Errorf("failed to get ISM policy for update: %w", err)
				}
				if err := ismAPI.Update(ctx, policy.Name, ismPolicy, existing.SeqNo, existing.PrimaryTerm); err != nil {
					return "", fmt.Errorf("failed to update ISM policy: %w", err)
				}
			}
			return specHash, nil
		})
	policy.Status.ClusterStatuses = res.Statuses

	if specHash != "" && policy.Status.LastAppliedHash != "" && policy.Status.LastAppliedHash != specHash {
		policy.Status.DriftDetected = true
		now := metav1.Now()
		policy.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchISMPolicy", policy.Namespace)
		log.Info("Drift detected on OpenSearchISMPolicy", "name", policy.Name)
	} else {
		policy.Status.DriftDetected = false
	}
	if specHash != "" {
		policy.Status.LastAppliedHash = specHash
	}

	wasReady := policy.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		policy.Status.ObservedGeneration == policy.Generation
	phase := res.AggregatePhase()
	msg := res.AggregateMessage()
	if res.AnyFailed {
		r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", res.FirstError.Error())
	}
	if err := r.updateStatus(ctx, policy, phase, msg, phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady {
		r.recordEvent(policy, corev1.EventTypeNormal, "Synced", "ISM policy synced on all target clusters")
	}

	if res.FirstError != nil {
		return res.FirstError
	}
	log.Info("ISM policy reconciliation completed", "name", policy.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *PolicyReconciler) recordEvent(policy *wazuhv1.OpenSearchISMPolicy, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(policy, eventType, reason, message)
	}
}

// buildISMPolicy converts the CRD spec to an ISM policy
func (r *PolicyReconciler) buildISMPolicy(policy *wazuhv1.OpenSearchISMPolicy) api.ISMPolicy {
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

// updateStatus updates the policy status with retry on conflict
func (r *PolicyReconciler) updateStatus(ctx context.Context, policy *wazuhv1.OpenSearchISMPolicy, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	shouldUpdateTS := len(updateTimestamp) == 0 || updateTimestamp[0]

	if policy.Status.Phase == phase && policy.Status.Message == message &&
		policy.Status.ObservedGeneration == policy.Generation && !shouldUpdateTS {
		return nil
	}

	policy.Status.Phase = phase
	policy.Status.Message = message
	policy.Status.ObservedGeneration = policy.Generation
	if shouldUpdateTS {
		now := metav1.Now()
		policy.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchISMPolicy", policy.Namespace, policy.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := policy.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchISMPolicy{}
		if err := r.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		policy.Status = latest.Status
		return nil
	})
}

// handleDeletion handles ISM policy cleanup on deletion
func (r *PolicyReconciler) handleDeletion(ctx context.Context, policy *wazuhv1.OpenSearchISMPolicy) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, policy); err != nil {
		log.Error(err, "Failed to delete ISM policy from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchISMPolicy{}
		if err := r.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.ISMPolicyFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a policy is deleted
func (r *PolicyReconciler) Delete(ctx context.Context, policy *wazuhv1.OpenSearchISMPolicy) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping ISM policy deletion - no client factory available")
		return nil
	}
	for _, ref := range policy.Spec.ClusterRefs {
		apiClient, err := r.ClientFactory.GetClientForClusterRef(ctx, ref)
		if err != nil {
			log.Info("Skipping ISM policy deletion on cluster - failed to get client",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace, "error", err)
			continue
		}
		ismAPI := api.NewISMAPI(apiClient)
		if err := ismAPI.Delete(ctx, policy.Name); err != nil {
			r.recordEvent(policy, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to delete ISM policy from %s/%s: %v", ref.Namespace, ref.Name, err))
			continue
		}
		log.Info("Deleted OpenSearch ISM policy on cluster",
			"name", policy.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
	}
	r.recordEvent(policy, corev1.EventTypeNormal, "Deleted", "ISM policy deletion processed on all target clusters")
	return nil
}
