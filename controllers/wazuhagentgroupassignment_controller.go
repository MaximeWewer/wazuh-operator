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

package controllers

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"
)

// defaultAgentGroupAssignmentRequeue is used when the spec interval is unset.
const defaultAgentGroupAssignmentRequeue = 60 * time.Second

// WazuhAgentGroupAssignmentReconciler reconciles a WazuhAgentGroupAssignment object
type WazuhAgentGroupAssignmentReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	AssignmentReconciler *wazuhreconciler.WazuhAPIAgentGroupAssignmentReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroupassignments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroupassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroupassignments/finalizers,verbs=update
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is the main reconciliation loop for WazuhAgentGroupAssignment
func (r *WazuhAgentGroupAssignmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhAgentGroupAssignment.Reconcile",
		telemetry.WithAttributes(
			attribute.String("namespace", req.Namespace),
			attribute.String("name", req.Name),
		))
	defer span.End()

	startTime := time.Now()
	defer func() {
		reconcileResult := "success"
		if reconcileErr != nil {
			reconcileResult = "error"
		}
		metrics.RecordReconciliation("WazuhAgentGroupAssignment", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	assignment := &wazuhv1.WazuhAgentGroupAssignment{}
	if err := r.Get(ctx, req.NamespacedName, assignment); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhAgentGroupAssignment resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhAgentGroupAssignment")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !assignment.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(assignment, wazuhreconciler.WazuhAgentGroupAssignmentFinalizer) {
			log.Info("Handling deletion of WazuhAgentGroupAssignment", "name", assignment.Name)

			if err := r.AssignmentReconciler.Delete(ctx, assignment); err != nil {
				log.Error(err, "Failed to cleanup WazuhAgentGroupAssignment")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhAgentGroupAssignment{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.WazuhAgentGroupAssignmentFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhAgentGroupAssignment", "name", assignment.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(assignment, wazuhreconciler.WazuhAgentGroupAssignmentFinalizer) {
		log.Info("Adding finalizer to WazuhAgentGroupAssignment", "name", assignment.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhAgentGroupAssignment{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.WazuhAgentGroupAssignmentFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.AssignmentReconciler.Reconcile(ctx, assignment); err != nil {
		if wazuhreconciler.IsAPIUnavailable(err) {
			log.Info("Wazuh API unavailable, requeuing", "error", err)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		log.Error(err, "Failed to reconcile WazuhAgentGroupAssignment")
		return ctrl.Result{}, err
	}

	// Agents register dynamically, so re-scan periodically even without a spec change.
	requeue := defaultAgentGroupAssignmentRequeue
	if assignment.Spec.ReconcileIntervalSeconds >= 15 {
		requeue = time.Duration(assignment.Spec.ReconcileIntervalSeconds) * time.Second
	}

	log.Info("Successfully reconciled WazuhAgentGroupAssignment", "name", assignment.Name)
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhAgentGroupAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhAgentGroupAssignment{}).
		WithEventFilter(eventLogPredicate("WazuhAgentGroupAssignment", &wazuhv1.WazuhAgentGroupAssignment{})).
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findAssignmentsForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhagentgroupassignment").
		Complete(r)
}

// findAssignmentsForCluster returns reconcile requests for all
// WazuhAgentGroupAssignments referencing a cluster.
func (r *WazuhAgentGroupAssignmentReconciler) findAssignmentsForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	list := &wazuhv1.WazuhAgentGroupAssignmentList{}
	if err := r.List(ctx, list); err != nil {
		log.Error(err, "Failed to list WazuhAgentGroupAssignments for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, assignment := range list.Items {
		for _, ref := range assignment.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: assignment.Name, Namespace: assignment.Namespace},
				})
				break
			}
		}
	}
	return requests
}
