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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
)

// OpenSearchIndexerReconciler reconciles an OpenSearchIndexer object
type OpenSearchIndexerReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	IndexerReconciler *opensearchreconciler.IndexerReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindexers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindexers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindexers/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchIndexer
func (r *OpenSearchIndexerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "OpenSearchIndexer.Reconcile",
		telemetry.WithAttributes(
			attribute.String("namespace", req.Namespace),
			attribute.String("name", req.Name),
		))
	defer span.End()

	// Track reconciliation metrics
	startTime := time.Now()
	var reconcileResult = "success"
	defer func() {
		duration := time.Since(startTime).Seconds()
		metrics.RecordReconciliation("OpenSearchIndexer", req.Namespace, reconcileResult, duration)
	}()

	log := logf.FromContext(ctx)

	// Fetch the OpenSearchIndexer instance
	indexer := &wazuhv1.OpenSearchIndexer{}
	if err := r.Get(ctx, req.NamespacedName, indexer); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchIndexer resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchIndexer")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.IndexerReconciler.ReconcileStandalone(ctx, indexer); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchIndexer")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchIndexer", "name", indexer.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchIndexerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.OpenSearchIndexer{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Named("opensearchindexer").
		Complete(r)
}
