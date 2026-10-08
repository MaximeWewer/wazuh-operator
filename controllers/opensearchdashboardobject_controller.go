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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"
)

// dashboardObjectConfigMapIndex indexes OpenSearchDashboardObjects by the ConfigMap
// holding their export, so a ConfigMap change re-imports the objects right away.
const dashboardObjectConfigMapIndex = "spec.source.configMapRef.name"

// OpenSearchDashboardObjectReconciler reconciles an OpenSearchDashboardObject object
type OpenSearchDashboardObjectReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	DashboardObjectReconciler *opensearchreconciler.DashboardObjectReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchdashboardobjects,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchdashboardobjects/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchdashboardobjects/finalizers,verbs=update

// Reconcile imports the saved objects and schedules the next sync. A change made in the
// Dashboards UI to a managed object is reverted at that next sync (the source is the truth).
func (r *OpenSearchDashboardObjectReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "OpenSearchDashboardObject.Reconcile",
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
			telemetry.RecordError(span, reconcileErr)
		}
		metrics.RecordReconciliation("OpenSearchDashboardObject", req.Namespace, reconcileResult, time.Since(startTime).Seconds())
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	obj := &wazuhv1.OpenSearchDashboardObject{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	requeueAfter, err := r.DashboardObjectReconciler.Reconcile(ctx, obj)
	if err != nil {
		log.Error(err, "Failed to reconcile OpenSearchDashboardObject")
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchDashboardObjectReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &wazuhv1.OpenSearchDashboardObject{}, dashboardObjectConfigMapIndex,
		func(o client.Object) []string {
			obj := o.(*wazuhv1.OpenSearchDashboardObject)
			if obj.Spec.Source.ConfigMapRef == nil {
				return nil
			}
			return []string{obj.Spec.Source.ConfigMapRef.Name}
		}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Status writes (lastSyncTime at every sync) must not trigger another import:
		// only spec changes and deletion do; the periodic resync comes from RequeueAfter.
		For(&wazuhv1.OpenSearchDashboardObject{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.findObjectsForConfigMap)).
		WithEventFilter(eventLogPredicate("OpenSearchDashboardObject", &wazuhv1.OpenSearchDashboardObject{})).
		Named("opensearchdashboardobject").
		Complete(r)
}

// findObjectsForConfigMap enqueues the OpenSearchDashboardObjects reading a ConfigMap.
func (r *OpenSearchDashboardObjectReconciler) findObjectsForConfigMap(ctx context.Context, cm client.Object) []reconcile.Request {
	list := &wazuhv1.OpenSearchDashboardObjectList{}
	if err := r.List(ctx, list, client.InNamespace(cm.GetNamespace()),
		client.MatchingFields{dashboardObjectConfigMapIndex: cm.GetName()}); err != nil {
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, item := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: item.Name, Namespace: item.Namespace}})
	}
	return requests
}
