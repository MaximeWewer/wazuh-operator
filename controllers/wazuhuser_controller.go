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

// WazuhUserReconciler reconciles a WazuhUser object
type WazuhUserReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	UserReconciler *wazuhreconciler.WazuhAPIUserReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhusers/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhUser
func (r *WazuhUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhUser.Reconcile",
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
		metrics.RecordReconciliation("WazuhUser", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	user := &wazuhv1.WazuhUser{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhUser resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhUser")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !user.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(user, wazuhreconciler.WazuhUserFinalizer) {
			log.Info("Handling deletion of WazuhUser", "name", user.Name)

			if err := r.UserReconciler.Delete(ctx, user); err != nil {
				log.Error(err, "Failed to cleanup WazuhUser")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhUser{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.WazuhUserFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhUser", "name", user.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(user, wazuhreconciler.WazuhUserFinalizer) {
		log.Info("Adding finalizer to WazuhUser", "name", user.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhUser{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.WazuhUserFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.UserReconciler.Reconcile(ctx, user); err != nil {
		if wazuhreconciler.IsAPIUnavailable(err) {
			log.Info("Wazuh API unavailable, requeuing", "error", err)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		log.Error(err, "Failed to reconcile WazuhUser")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhUser", "name", user.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhUser{}).
		WithEventFilter(eventLogPredicate("WazuhUser", &wazuhv1.WazuhUser{})).
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findUsersForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhuser").
		Complete(r)
}

// findUsersForCluster returns reconcile requests for all WazuhUsers referencing a cluster.
func (r *WazuhUserReconciler) findUsersForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	userList := &wazuhv1.WazuhUserList{}
	if err := r.List(ctx, userList); err != nil {
		log.Error(err, "Failed to list WazuhUsers for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, user := range userList.Items {
		for _, ref := range user.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: user.Name, Namespace: user.Namespace},
				})
				break
			}
		}
	}
	return requests
}
