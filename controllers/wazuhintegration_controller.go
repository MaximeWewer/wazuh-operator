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

// WazuhIntegrationReconciler reconciles a WazuhIntegration object.
type WazuhIntegrationReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	IntegrationReconciler *wazuhreconciler.IntegrationReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhintegrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhintegrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhintegrations/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhIntegration.
func (r *WazuhIntegrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhIntegration.Reconcile",
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
		duration := time.Since(startTime).Seconds()
		metrics.RecordReconciliation("WazuhIntegration", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	integration := &wazuhv1.WazuhIntegration{}
	if err := r.Get(ctx, req.NamespacedName, integration); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhIntegration resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhIntegration")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !integration.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(integration, wazuhreconciler.IntegrationFinalizer) {
			log.Info("Handling deletion of WazuhIntegration", "name", integration.Name)

			if err := r.IntegrationReconciler.Delete(ctx, integration); err != nil {
				log.Error(err, "Failed to cleanup WazuhIntegration")
				return ctrl.Result{}, err
			}

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhIntegration{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.IntegrationFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhIntegration", "name", integration.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(integration, wazuhreconciler.IntegrationFinalizer) {
		log.Info("Adding finalizer to WazuhIntegration", "name", integration.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhIntegration{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.IntegrationFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.IntegrationReconciler.Reconcile(ctx, integration); err != nil {
		log.Error(err, "Failed to reconcile WazuhIntegration")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhIntegration", "name", integration.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WazuhIntegrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhIntegration{}).
		Owns(&corev1.ConfigMap{}).
		// Watch for WazuhCluster spec changes to re-reconcile integrations when cluster changes
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findIntegrationsForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhintegration").
		Complete(r)
}

// findIntegrationsForCluster returns reconcile requests for all WazuhIntegrations that reference a given cluster.
func (r *WazuhIntegrationReconciler) findIntegrationsForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	list := &wazuhv1.WazuhIntegrationList{}
	if err := r.List(ctx, list); err != nil {
		log.Error(err, "Failed to list WazuhIntegrations for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, integration := range list.Items {
		for _, ref := range integration.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      integration.Name,
						Namespace: integration.Namespace,
					},
				})
				break
			}
		}
	}

	if len(requests) > 0 {
		log.Info("Cluster changed, triggering reconciliation for integrations",
			"cluster", cluster.Name, "integrationsCount", len(requests))
	}

	return requests
}
