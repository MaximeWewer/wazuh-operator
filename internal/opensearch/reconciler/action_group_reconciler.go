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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
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

// ActionGroupReconciler handles reconciliation of OpenSearch action groups
type ActionGroupReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewActionGroupReconciler creates a new ActionGroupReconciler
func NewActionGroupReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *ActionGroupReconciler {
	return &ActionGroupReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory for dynamic client resolution
func (r *ActionGroupReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *ActionGroupReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch action group
func (r *ActionGroupReconciler) Reconcile(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ActionGroupReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", ag.Name),
			attribute.String("resource.namespace", ag.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(ag, constants.ActionGroupFinalizer) {
		controllerutil.AddFinalizer(ag, constants.ActionGroupFinalizer)
		if err := r.Update(ctx, ag); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !ag.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, ag)
	}

	actionGroup := r.buildActionGroup(ag)
	specHash, _ := patch.ComputeSpecHash(ag.Spec)

	res := ReconcileMultiCluster(ctx, ag.Spec.ClusterRefs, r.ClientFactory, ag.Status.ClusterStatuses,
		func(ctx context.Context, apiClient *api.Client, ref wazuhv1.WazuhClusterRef) (string, error) {
			securityAPI := api.NewSecurityAPI(apiClient)
			existing, err := securityAPI.GetActionGroup(ctx, ag.Name)
			if err != nil {
				return "", fmt.Errorf("failed to check action group existence: %w", err)
			}
			if existing == nil {
				log.Info("Creating action group", "name", ag.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
			} else {
				log.Info("Updating action group", "name", ag.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
			}
			if err := securityAPI.CreateActionGroup(ctx, ag.Name, actionGroup); err != nil {
				return "", fmt.Errorf("failed to apply action group: %w", err)
			}
			return specHash, nil
		})

	ag.Status.ClusterStatuses = res.Statuses
	if specHash != "" && ag.Status.LastAppliedHash != "" && ag.Status.LastAppliedHash != specHash {
		ag.Status.DriftDetected = true
		now := metav1.Now()
		ag.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchActionGroup", ag.Namespace)
		log.Info("Drift detected on OpenSearchActionGroup", "name", ag.Name)
	} else {
		ag.Status.DriftDetected = false
	}
	if specHash != "" {
		ag.Status.LastAppliedHash = specHash
	}

	wasReady := ag.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		ag.Status.ObservedGeneration == ag.Generation
	phase := res.AggregatePhase()
	msg := res.AggregateMessage()
	if res.AnyFailed {
		r.recordEvent(ag, corev1.EventTypeWarning, "SyncFailed", res.FirstError.Error())
	}
	if err := r.updateStatus(ctx, ag, phase, msg, phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady {
		r.recordEvent(ag, corev1.EventTypeNormal, "Synced", "Action group reconciled on all target clusters")
	}

	if res.FirstError != nil {
		return res.FirstError
	}
	log.Info("Action group reconciliation completed", "name", ag.Name)
	return nil
}

// recordEvent emits an event if the recorder is available
func (r *ActionGroupReconciler) recordEvent(ag *wazuhv1.OpenSearchActionGroup, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(ag, eventType, reason, message)
	}
}

// buildActionGroup converts the CRD spec to an action group
func (r *ActionGroupReconciler) buildActionGroup(ag *wazuhv1.OpenSearchActionGroup) api.ActionGroup {
	return api.ActionGroup{
		AllowedActions: ag.Spec.AllowedActions,
		Description:    ag.Spec.Description,
		Type:           ag.Spec.Type,
	}
}

// updateStatus updates the action group status with retry on conflict
func (r *ActionGroupReconciler) updateStatus(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	shouldUpdateTS := len(updateTimestamp) == 0 || updateTimestamp[0]

	if ag.Status.Phase == phase && ag.Status.Message == message &&
		ag.Status.ObservedGeneration == ag.Generation && !shouldUpdateTS {
		return nil
	}

	ag.Status.Phase = phase
	ag.Status.Message = message
	ag.Status.ObservedGeneration = ag.Generation
	if shouldUpdateTS {
		now := metav1.Now()
		ag.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchActionGroup", ag.Namespace, ag.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := ag.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchActionGroup{}
		if err := r.Get(ctx, types.NamespacedName{Name: ag.Name, Namespace: ag.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		ag.Status = latest.Status
		return nil
	})
}

// handleDeletion handles action group cleanup on deletion
func (r *ActionGroupReconciler) handleDeletion(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) error {
	if err := r.Delete(ctx, ag); err != nil {
		// Keep the finalizer and let the controller requeue: never remove it while the
		// OpenSearch object may still exist, or it would be leaked.
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchActionGroup{}
		if err := r.Get(ctx, types.NamespacedName{Name: ag.Name, Namespace: ag.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.ActionGroupFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when an action group is deleted
func (r *ActionGroupReconciler) Delete(ctx context.Context, ag *wazuhv1.OpenSearchActionGroup) error {
	log := logf.FromContext(ctx)

	if r.ClientFactory == nil {
		log.Info("Skipping action group deletion - no client factory available")
		return nil
	}

	// Delete on every target cluster.
	var cleanupErrs []string
	for _, ref := range ag.Spec.ClusterRefs {
		apiClient, err := r.ClientFactory.GetClientForClusterRef(ctx, ref)
		if err != nil {
			if errors.IsNotFound(err) {
				// The cluster itself is gone, so the action group went with it: nothing to delete.
				log.Info("Cluster not found during delete, skipping OpenSearch cleanup",
					"cluster", ref.Name, "clusterNamespace", ref.Namespace)
				continue
			}
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: connect: %v", ref.Namespace, ref.Name, err))
			continue
		}
		securityAPI := api.NewSecurityAPI(apiClient)
		if err := securityAPI.DeleteActionGroup(ctx, ag.Name); err != nil {
			r.recordEvent(ag, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to delete action group on %s/%s: %v", ref.Namespace, ref.Name, err))
			log.Error(err, "Failed to delete action group", "cluster", ref.Name)
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: delete action group: %v", ref.Namespace, ref.Name, err))
			continue
		}
		log.Info("Deleted OpenSearch action group on cluster",
			"name", ag.Name, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
	}
	if len(cleanupErrs) > 0 {
		// Keep the finalizer and retry: the action group must actually be removed from OpenSearch,
		// not silently leaked when the API is unavailable or the delete fails.
		return fmt.Errorf("action group %q cleanup incomplete, will retry: %s", ag.Name, strings.Join(cleanupErrs, "; "))
	}
	r.recordEvent(ag, corev1.EventTypeNormal, "Deleted", "Action group deletion processed on all target clusters")
	return nil
}
