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

// WazuhRuleReconciler reconciles a WazuhRule object
type WazuhRuleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	RuleReconciler *wazuhreconciler.RuleReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrules/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhRule
func (r *WazuhRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhRule.Reconcile",
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
		metrics.RecordReconciliation("WazuhRule", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	// Fetch the WazuhRule instance
	rule := &wazuhv1.WazuhRule{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhRule resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhRule")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !rule.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(rule, wazuhreconciler.RuleFinalizer) {
			log.Info("Handling deletion of WazuhRule", "name", rule.Name)

			// Perform cleanup
			if err := r.RuleReconciler.Delete(ctx, rule); err != nil {
				log.Error(err, "Failed to cleanup WazuhRule")
				return ctrl.Result{}, err
			}

			// Remove finalizer
			controllerutil.RemoveFinalizer(rule, wazuhreconciler.RuleFinalizer)
			if err := r.Update(ctx, rule); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhRule", "name", rule.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(rule, wazuhreconciler.RuleFinalizer) {
		log.Info("Adding finalizer to WazuhRule", "name", rule.Name)
		controllerutil.AddFinalizer(rule, wazuhreconciler.RuleFinalizer)
		if err := r.Update(ctx, rule); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		// Requeue after adding finalizer
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.RuleReconciler.Reconcile(ctx, rule); err != nil {
		log.Error(err, "Failed to reconcile WazuhRule")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhRule", "name", rule.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhRule{}).
		Owns(&corev1.ConfigMap{}).
		// Watch for WazuhCluster changes to re-reconcile rules when cluster changes
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findRulesForCluster),
		).
		Named("wazuhrule").
		Complete(r)
}

// findRulesForCluster returns reconcile requests for all WazuhRules that reference a given cluster
func (r *WazuhRuleReconciler) findRulesForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	// List all WazuhRules in the cluster's namespace
	ruleList := &wazuhv1.WazuhRuleList{}
	if err := r.List(ctx, ruleList, client.InNamespace(cluster.Namespace)); err != nil {
		log.Error(err, "Failed to list WazuhRules for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, rule := range ruleList.Items {
		// Check if this rule references the changed cluster
		clusterNamespace := rule.Spec.ClusterRef.Namespace
		if clusterNamespace == "" {
			clusterNamespace = rule.Namespace
		}
		if rule.Spec.ClusterRef.Name == cluster.Name && clusterNamespace == cluster.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      rule.Name,
					Namespace: rule.Namespace,
				},
			})
		}
	}

	if len(requests) > 0 {
		log.Info("Cluster changed, triggering reconciliation for rules",
			"cluster", cluster.Name, "rulesCount", len(requests))
	}

	return requests
}
