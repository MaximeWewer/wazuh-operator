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

// WazuhRoleReconciler reconciles a WazuhRole object
type WazuhRoleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	RoleReconciler *wazuhreconciler.WazuhAPIRoleReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhroles/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhRole
func (r *WazuhRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhRole.Reconcile",
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
		metrics.RecordReconciliation("WazuhRole", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	role := &wazuhv1.WazuhRole{}
	if err := r.Get(ctx, req.NamespacedName, role); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhRole resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhRole")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !role.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(role, wazuhreconciler.WazuhRoleFinalizer) {
			log.Info("Handling deletion of WazuhRole", "name", role.Name)

			if err := r.RoleReconciler.Delete(ctx, role); err != nil {
				log.Error(err, "Failed to cleanup WazuhRole")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhRole{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.WazuhRoleFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhRole", "name", role.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(role, wazuhreconciler.WazuhRoleFinalizer) {
		log.Info("Adding finalizer to WazuhRole", "name", role.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhRole{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.WazuhRoleFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.RoleReconciler.Reconcile(ctx, role); err != nil {
		if wazuhreconciler.IsAPIUnavailable(err) {
			log.Info("Wazuh API unavailable, requeuing", "error", err)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		log.Error(err, "Failed to reconcile WazuhRole")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhRole", "name", role.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhRole{}).
		WithEventFilter(eventLogPredicate("WazuhRole", &wazuhv1.WazuhRole{})).
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findRolesForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhrole").
		Complete(r)
}

// findRolesForCluster returns reconcile requests for all WazuhRoles referencing a cluster.
func (r *WazuhRoleReconciler) findRolesForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	roleList := &wazuhv1.WazuhRoleList{}
	if err := r.List(ctx, roleList); err != nil {
		log.Error(err, "Failed to list WazuhRoles for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, role := range roleList.Items {
		for _, ref := range role.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: role.Name, Namespace: role.Namespace},
				})
				break
			}
		}
	}
	return requests
}
