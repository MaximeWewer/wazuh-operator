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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// SnapshotPolicyReconciler handles reconciliation of OpenSearch snapshot policies
type SnapshotPolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory *security.OpenSearchClientFactory
}

// NewSnapshotPolicyReconciler creates a new SnapshotPolicyReconciler
func NewSnapshotPolicyReconciler(c client.Client, scheme *runtime.Scheme) *SnapshotPolicyReconciler {
	return &SnapshotPolicyReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *SnapshotPolicyReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *SnapshotPolicyReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch snapshot policy
func (r *SnapshotPolicyReconciler) Reconcile(ctx context.Context, policy *wazuhv1.OpenSearchSnapshotPolicy) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(policy, constants.SnapshotPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, constants.SnapshotPolicyFinalizer)
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

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, policy.Spec.ClusterRef, policy.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create Snapshot API clients
	snapshotAPI := api.NewSnapshotAPI(apiClient)
	snapshotsAPI := api.NewSnapshotsAPI(apiClient)

	// Validate repository exists before creating/updating policy
	repoName := policy.Spec.Repository.Name
	if repoName != "" {
		repo, err := snapshotsAPI.GetRepository(ctx, repoName)
		if err != nil {
			log.Error(err, "Failed to check repository", "repository", repoName)
			if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check repository '%s': %v", repoName, err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to check repository '%s': %w", repoName, err)
		}
		if repo == nil {
			log.Info("Repository not found, waiting for repository to be created", "repository", repoName)
			if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhasePending, fmt.Sprintf("Repository '%s' not found - waiting for repository creation", repoName)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("repository '%s' not found, will retry", repoName)
		}
		log.V(1).Info("Repository validated", "repository", repoName)
	}

	// Check if policy exists
	exists, err := snapshotAPI.Exists(ctx, policy.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to check policy existence: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check snapshot policy existence: %w", err)
	}

	// Build snapshot policy from spec
	snapshotPolicy := r.buildSnapshotPolicy(policy)

	if !exists {
		log.Info("Creating snapshot policy", "name", policy.Name, "repository", repoName)
	} else {
		log.Info("Updating snapshot policy", "name", policy.Name, "repository", repoName)
	}
	if err := snapshotAPI.CreatePolicy(ctx, policy.Name, snapshotPolicy); err != nil {
		action := "create"
		if exists {
			action = "update"
		}
		if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to %s snapshot policy: %v", action, err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to %s snapshot policy: %w", action, err)
	}

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(policy.Spec)
	if hashErr == nil && policy.Status.LastAppliedHash != "" && policy.Status.LastAppliedHash != specHash {
		policy.Status.DriftDetected = true
		now := metav1.Now()
		policy.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchSnapshotPolicy", policy.Namespace)
		log.Info("Drift detected on OpenSearchSnapshotPolicy", "name", policy.Name)
	} else {
		policy.Status.DriftDetected = false
	}
	if hashErr == nil {
		policy.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseReady, "Snapshot policy reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Snapshot policy reconciliation completed", "name", policy.Name, "repository", repoName)
	return nil
}

// buildSnapshotPolicy converts the CRD spec to a snapshot policy
func (r *SnapshotPolicyReconciler) buildSnapshotPolicy(policy *wazuhv1.OpenSearchSnapshotPolicy) api.SnapshotPolicy {
	snapshotPolicy := api.SnapshotPolicy{
		Description: policy.Spec.Description,
		Enabled:     true, // Enabled by default
	}

	// Set snapshot config with repository from spec
	snapshotPolicy.SnapshotConfig = &api.SnapshotConfig{
		Repository: policy.Spec.Repository.Name,
	}

	// Set indices if provided
	if policy.Spec.SnapshotConfig != nil && len(policy.Spec.SnapshotConfig.Indices) > 0 {
		// Join indices into a comma-separated string
		snapshotPolicy.SnapshotConfig.Indices = strings.Join(policy.Spec.SnapshotConfig.Indices, ",")
	}

	// Set creation schedule
	snapshotPolicy.Creation = &api.SnapshotCreation{
		Schedule: &api.SnapshotPolicySchedule{
			Cron: &api.CronSchedule{
				Expression: policy.Spec.Creation.Schedule.Expression,
				Timezone:   policy.Spec.Creation.Schedule.Timezone,
			},
		},
	}
	if policy.Spec.Creation.TimeLimit != "" {
		snapshotPolicy.Creation.TimeLimit = policy.Spec.Creation.TimeLimit
	}

	// Set deletion schedule and conditions
	if policy.Spec.Deletion != nil {
		snapshotPolicy.Deletion = &api.SnapshotDeletion{}
		if policy.Spec.Deletion.Schedule != nil {
			snapshotPolicy.Deletion.Schedule = &api.SnapshotPolicySchedule{
				Cron: &api.CronSchedule{
					Expression: policy.Spec.Deletion.Schedule.Expression,
					Timezone:   policy.Spec.Deletion.Schedule.Timezone,
				},
			}
		}
		if policy.Spec.Deletion.Condition != nil {
			snapshotPolicy.Deletion.Condition = &api.SnapshotDeleteCondition{
				MaxAge: policy.Spec.Deletion.Condition.MaxAge,
			}
			if policy.Spec.Deletion.Condition.MaxCount != nil {
				snapshotPolicy.Deletion.Condition.MaxCount = int64(*policy.Spec.Deletion.Condition.MaxCount)
			}
			if policy.Spec.Deletion.Condition.MinCount != nil {
				snapshotPolicy.Deletion.Condition.MinCount = int64(*policy.Spec.Deletion.Condition.MinCount)
			}
		}
	}

	return snapshotPolicy
}

// updateStatus updates the policy status
func (r *SnapshotPolicyReconciler) updateStatus(ctx context.Context, policy *wazuhv1.OpenSearchSnapshotPolicy, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	policy.Status.Phase = phase
	policy.Status.Message = message
	now := metav1.Now()
	policy.Status.LastSyncTime = &now

	metrics.SetResourceSyncStatus("OpenSearchSnapshotPolicy", policy.Namespace, policy.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	return r.Status().Update(ctx, policy)
}

// handleDeletion handles snapshot policy cleanup on deletion
func (r *SnapshotPolicyReconciler) handleDeletion(ctx context.Context, policy *wazuhv1.OpenSearchSnapshotPolicy) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, policy); err != nil {
		log.Error(err, "Failed to delete snapshot policy from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(policy, constants.SnapshotPolicyFinalizer)
	return r.Update(ctx, policy)
}

// Delete handles cleanup when a snapshot policy is deleted
func (r *SnapshotPolicyReconciler) Delete(ctx context.Context, policy *wazuhv1.OpenSearchSnapshotPolicy) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping snapshot policy deletion - no client factory available")
		return nil
	}

	apiClient, err := r.ClientFactory.GetClientForRef(ctx, policy.Spec.ClusterRef, policy.Namespace)
	if err != nil {
		log.Info("Skipping snapshot policy deletion - failed to get OpenSearch client", "error", err)
		return nil
	}

	snapshotAPI := api.NewSnapshotAPI(apiClient)
	if err := snapshotAPI.DeletePolicy(ctx, policy.Name); err != nil {
		return fmt.Errorf("failed to delete snapshot policy: %w", err)
	}

	log.Info("Deleted OpenSearch snapshot policy", "name", policy.Name)
	return nil
}
