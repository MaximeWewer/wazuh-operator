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

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
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

// SnapshotPolicyReconciler handles reconciliation of OpenSearch snapshot policies
type SnapshotPolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewSnapshotPolicyReconciler creates a new SnapshotPolicyReconciler
func NewSnapshotPolicyReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *SnapshotPolicyReconciler {
	return &SnapshotPolicyReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory
func (r *SnapshotPolicyReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *SnapshotPolicyReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch snapshot policy
func (r *SnapshotPolicyReconciler) Reconcile(ctx context.Context, policy *wazuhv1.OpenSearchSnapshotPolicy) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "SnapshotPolicyReconciler.Reconcile",
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
		r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get OpenSearch client: %v", err))
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
			r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to check repository '%s': %v", repoName, err))
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

	// Get policy (includes seq_no/primary_term when it exists)
	policyInfo, err := snapshotAPI.GetPolicyInfo(ctx, policy.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to get snapshot policy: %v", err)); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to get snapshot policy: %v", err))
		return fmt.Errorf("failed to get snapshot policy: %w", err)
	}

	// Build snapshot policy from spec
	snapshotPolicy := r.buildSnapshotPolicy(policy)

	if policyInfo == nil {
		log.Info("Creating snapshot policy", "name", policy.Name, "repository", repoName)
		if err := snapshotAPI.CreatePolicy(ctx, policy.Name, snapshotPolicy); err != nil {
			// OpenSearch may return 400 "Sequence number and primary term must be provided"
			// if the policy already exists (e.g. brief race/eventual consistency window).
			if isSnapshotPolicyVersionRequiredError(err) {
				log.Info("Snapshot policy already exists, retrying as update", "name", policy.Name, "repository", repoName)
				latestPolicyInfo, getErr := snapshotAPI.GetPolicyInfo(ctx, policy.Name)
				if getErr == nil && latestPolicyInfo != nil {
					if updateErr := r.updateSnapshotPolicyWithRetry(ctx, snapshotAPI, policy.Name, snapshotPolicy, latestPolicyInfo); updateErr == nil {
						// Converted create race into successful update.
						err = nil
					} else {
						err = updateErr
					}
				}
			}
			if err == nil {
				goto policyApplied
			}
			if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to create snapshot policy: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to create snapshot policy: %v", err))
			return fmt.Errorf("failed to create snapshot policy: %w", err)
		}
	} else {
		log.Info("Updating snapshot policy", "name", policy.Name, "repository", repoName)
		if err := r.updateSnapshotPolicyWithRetry(ctx, snapshotAPI, policy.Name, snapshotPolicy, policyInfo); err != nil {
			if updateErr := r.updateStatus(ctx, policy, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to update snapshot policy: %v", err)); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			r.recordEvent(policy, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to update snapshot policy: %v", err))
			return fmt.Errorf("failed to update snapshot policy: %w", err)
		}
	}

policyApplied:
	r.recordEvent(policy, corev1.EventTypeNormal, "Synced", "Snapshot policy reconciled successfully")

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

func isSnapshotPolicyVersionRequiredError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sequence number and primary term must be provided")
}

func isSnapshotPolicyConflictError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "version_conflict_engine_exception") ||
		strings.Contains(msg, "\"status\":409") ||
		strings.Contains(msg, "version conflict")
}

func (r *SnapshotPolicyReconciler) updateSnapshotPolicyWithRetry(
	ctx context.Context,
	snapshotAPI *api.SnapshotAPI,
	policyName string,
	snapshotPolicy api.SnapshotPolicy,
	policyInfo *api.SnapshotPolicyInfo,
) error {
	current := policyInfo
	const maxAttempts = 4

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if current == nil {
			latest, err := snapshotAPI.GetPolicyInfo(ctx, policyName)
			if err != nil {
				return fmt.Errorf("failed to refresh snapshot policy metadata: %w", err)
			}
			if latest == nil {
				return fmt.Errorf("snapshot policy %s not found during update", policyName)
			}
			current = latest
		}

		err := snapshotAPI.UpdatePolicy(ctx, policyName, snapshotPolicy, current.SeqNo, current.PrimaryTerm)
		if err == nil {
			return nil
		}
		if !isSnapshotPolicyConflictError(err) || attempt == maxAttempts {
			return err
		}

		// Reload latest seq_no/primary_term and retry on optimistic-lock conflicts.
		latest, getErr := snapshotAPI.GetPolicyInfo(ctx, policyName)
		if getErr != nil {
			return fmt.Errorf("failed to refresh snapshot policy metadata after conflict: %w", getErr)
		}
		if latest == nil {
			return fmt.Errorf("snapshot policy %s disappeared during conflict retry", policyName)
		}
		current = latest
	}

	return fmt.Errorf("unexpected snapshot policy update retry termination")
}

// recordEvent emits an event if the recorder is available
func (r *SnapshotPolicyReconciler) recordEvent(policy *wazuhv1.OpenSearchSnapshotPolicy, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(policy, eventType, reason, message)
	}
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
	metrics.SetResourceSyncStatus("OpenSearchSnapshotPolicy", policy.Namespace, policy.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchSnapshotPolicy{}
		if err := r.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, latest); err != nil {
			return err
		}
		latest.Status.Phase = phase
		latest.Status.Message = message
		now := metav1.Now()
		latest.Status.LastSyncTime = &now
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		policy.Status = latest.Status
		return nil
	})
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
		r.recordEvent(policy, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete snapshot policy: %v", err))
		return fmt.Errorf("failed to delete snapshot policy: %w", err)
	}

	r.recordEvent(policy, corev1.EventTypeNormal, "Deleted", "Snapshot policy deleted from OpenSearch")
	log.Info("Deleted OpenSearch snapshot policy", "name", policy.Name)
	return nil
}
