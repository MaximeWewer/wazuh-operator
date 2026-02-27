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
	"time"

	"go.opentelemetry.io/otel/attribute"

	"context"

	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	retry "k8s.io/client-go/util/retry"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

// WazuhAgentGroupReconciler reconciles a WazuhAgentGroup object
type WazuhAgentGroupReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	AgentGroupReconciler *wazuhreconciler.AgentGroupReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhagentgroups/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhAgentGroup
func (r *WazuhAgentGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhAgentGroup.Reconcile",
		telemetry.WithAttributes(
			attribute.String("namespace", req.Namespace),
			attribute.String("name", req.Name),
		))
	defer span.End()

	// Track reconciliation metrics
	startTime := time.Now()
	defer func() {
		reconcileResult := "success"
		if reconcileErr != nil {
			reconcileResult = "error"
		}
		duration := time.Since(startTime).Seconds()
		metrics.RecordReconciliation("WazuhAgentGroup", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	// Fetch the WazuhAgentGroup instance
	group := &wazuhv1.WazuhAgentGroup{}
	if err := r.Get(ctx, req.NamespacedName, group); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhAgentGroup resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhAgentGroup")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !group.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(group, wazuhreconciler.AgentGroupFinalizer) {
			log.Info("Handling deletion of WazuhAgentGroup", "name", group.Name)

			if err := r.AgentGroupReconciler.Delete(ctx, group); err != nil {
				log.Error(err, "Failed to cleanup WazuhAgentGroup")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhAgentGroup{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.AgentGroupFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhAgentGroup", "name", group.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(group, wazuhreconciler.AgentGroupFinalizer) {
		log.Info("Adding finalizer to WazuhAgentGroup", "name", group.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhAgentGroup{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.AgentGroupFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.AgentGroupReconciler.Reconcile(ctx, group); err != nil {
		if wazuhreconciler.IsAPIUnavailable(err) {
			log.Info("Wazuh API unavailable, requeuing", "error", err)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		log.Error(err, "Failed to reconcile WazuhAgentGroup")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhAgentGroup", "name", group.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhAgentGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhAgentGroup{}).
		Owns(&corev1.ConfigMap{}).
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findGroupsForCluster),
		).
		Named("wazuhagentgroup").
		Complete(r)
}

// findGroupsForCluster returns reconcile requests for all WazuhAgentGroups that reference a given cluster
func (r *WazuhAgentGroupReconciler) findGroupsForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	groupList := &wazuhv1.WazuhAgentGroupList{}
	if err := r.List(ctx, groupList, client.InNamespace(cluster.Namespace)); err != nil {
		log.Error(err, "Failed to list WazuhAgentGroups for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, group := range groupList.Items {
		clusterNamespace := group.Spec.ClusterRef.Namespace
		if clusterNamespace == "" {
			clusterNamespace = group.Namespace
		}
		if group.Spec.ClusterRef.Name == cluster.Name && clusterNamespace == cluster.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      group.Name,
					Namespace: group.Namespace,
				},
			})
		}
	}

	if len(requests) > 0 {
		log.Info("Cluster changed, triggering reconciliation for agent groups",
			"cluster", cluster.Name, "groupsCount", len(requests))
	}

	return requests
}
