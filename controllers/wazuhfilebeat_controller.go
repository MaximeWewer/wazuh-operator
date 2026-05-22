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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"
)

// WazuhFilebeatReconciler reconciles a WazuhFilebeat object
type WazuhFilebeatReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	FilebeatReconciler *wazuhreconciler.FilebeatReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhfilebeats,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhfilebeats/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhfilebeats/finalizers,verbs=update
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is the main reconciliation loop for WazuhFilebeat
func (r *WazuhFilebeatReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhFilebeat.Reconcile",
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
		metrics.RecordReconciliation("WazuhFilebeat", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	// Fetch the WazuhFilebeat instance
	filebeat := &wazuhv1.WazuhFilebeat{}
	if err := r.Get(ctx, req.NamespacedName, filebeat); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhFilebeat resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhFilebeat")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.FilebeatReconciler.Reconcile(ctx, filebeat); err != nil {
		log.Error(err, "Failed to reconcile WazuhFilebeat")
		// Requeue with backoff for transient errors
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	log.Info("Successfully reconciled WazuhFilebeat", "name", filebeat.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhFilebeatReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhFilebeat{}).
		WithEventFilter(eventLogPredicate("WazuhFilebeat", &wazuhv1.WazuhFilebeat{})).
		Owns(&corev1.ConfigMap{}).
		// Watch for WazuhCluster spec changes that this filebeat references
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findFilebeatForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhfilebeat").
		Complete(r)
}

// findFilebeatForCluster returns reconcile requests for WazuhFilebeat resources
// that reference the changed WazuhCluster
func (r *WazuhFilebeatReconciler) findFilebeatForCluster(ctx context.Context, obj client.Object) []ctrl.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	// Find all WazuhFilebeat resources that reference this cluster
	filebeatList := &wazuhv1.WazuhFilebeatList{}
	if err := r.List(ctx, filebeatList); err != nil {
		log.Error(err, "Failed to list WazuhFilebeat resources")
		return nil
	}

	var requests []ctrl.Request
	for _, fb := range filebeatList.Items {
		for _, ref := range fb.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, ctrl.Request{
					NamespacedName: client.ObjectKey{
						Name:      fb.Name,
						Namespace: fb.Namespace,
					},
				})
				break
			}
		}
	}

	return requests
}
