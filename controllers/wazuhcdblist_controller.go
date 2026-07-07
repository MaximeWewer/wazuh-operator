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

	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"

	corev1 "k8s.io/api/core/v1"
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
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

// WazuhCDBListReconciler reconciles a WazuhCDBList object.
type WazuhCDBListReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	CDBListReconciler *wazuhreconciler.CDBListReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcdblists,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcdblists/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcdblists/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhCDBList.
func (r *WazuhCDBListReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhCDBList.Reconcile",
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
		metrics.RecordReconciliation("WazuhCDBList", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	list := &wazuhv1.WazuhCDBList{}
	if err := r.Get(ctx, req.NamespacedName, list); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhCDBList resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhCDBList")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !list.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(list, wazuhreconciler.CDBListFinalizer) {
			log.Info("Handling deletion of WazuhCDBList", "name", list.Name)

			if err := r.CDBListReconciler.Delete(ctx, list); err != nil {
				log.Error(err, "Failed to cleanup WazuhCDBList")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhCDBList{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.CDBListFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhCDBList", "name", list.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(list, wazuhreconciler.CDBListFinalizer) {
		log.Info("Adding finalizer to WazuhCDBList", "name", list.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhCDBList{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.CDBListFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler. It returns the periodic refresh interval for
	// URL-backed lists (0 for static lists).
	requeueAfter, err := r.CDBListReconciler.Reconcile(ctx, list)
	if err != nil {
		log.Error(err, "Failed to reconcile WazuhCDBList")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhCDBList", "name", list.Name)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WazuhCDBListReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhCDBList{}).
		WithEventFilter(eventLogPredicate("WazuhCDBList", &wazuhv1.WazuhCDBList{})).
		Owns(&corev1.ConfigMap{}).
		// Re-reconcile CDB lists when a referenced cluster changes.
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findCDBListsForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhcdblist").
		Complete(r)
}

// findCDBListsForCluster returns reconcile requests for all WazuhCDBLists that reference a given cluster.
func (r *WazuhCDBListReconciler) findCDBListsForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	listList := &wazuhv1.WazuhCDBListList{}
	if err := r.List(ctx, listList); err != nil {
		log.Error(err, "Failed to list WazuhCDBLists for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, list := range listList.Items {
		for _, ref := range list.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: list.Name, Namespace: list.Namespace},
				})
				break
			}
		}
	}
	return requests
}
