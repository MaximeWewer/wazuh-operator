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

// WazuhActiveResponseReconciler reconciles a WazuhActiveResponse object.
type WazuhActiveResponseReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	ActiveResponseReconciler *wazuhreconciler.ActiveResponseReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhactiveresponses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhactiveresponses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhactiveresponses/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhActiveResponse.
func (r *WazuhActiveResponseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhActiveResponse.Reconcile",
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
		metrics.RecordReconciliation("WazuhActiveResponse", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	ar := &wazuhv1.WazuhActiveResponse{}
	if err := r.Get(ctx, req.NamespacedName, ar); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhActiveResponse resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhActiveResponse")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !ar.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(ar, wazuhreconciler.ActiveResponseFinalizer) {
			log.Info("Handling deletion of WazuhActiveResponse", "name", ar.Name)

			if err := r.ActiveResponseReconciler.Delete(ctx, ar); err != nil {
				log.Error(err, "Failed to cleanup WazuhActiveResponse")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhActiveResponse{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.ActiveResponseFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhActiveResponse", "name", ar.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(ar, wazuhreconciler.ActiveResponseFinalizer) {
		log.Info("Adding finalizer to WazuhActiveResponse", "name", ar.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhActiveResponse{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.ActiveResponseFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.ActiveResponseReconciler.Reconcile(ctx, ar); err != nil {
		log.Error(err, "Failed to reconcile WazuhActiveResponse")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhActiveResponse", "name", ar.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WazuhActiveResponseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhActiveResponse{}).
		WithEventFilter(eventLogPredicate("WazuhActiveResponse", &wazuhv1.WazuhActiveResponse{})).
		Owns(&corev1.ConfigMap{}).
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findActiveResponsesForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhactiveresponse").
		Complete(r)
}

// findActiveResponsesForCluster returns reconcile requests for all WazuhActiveResponses that reference a given cluster.
func (r *WazuhActiveResponseReconciler) findActiveResponsesForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	list := &wazuhv1.WazuhActiveResponseList{}
	if err := r.List(ctx, list); err != nil {
		log.Error(err, "Failed to list WazuhActiveResponses for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, ar := range list.Items {
		for _, ref := range ar.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: ar.Name, Namespace: ar.Namespace},
				})
				break
			}
		}
	}
	return requests
}
