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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
)

// OpenSearchRoleMappingReconciler reconciles a OpenSearchRoleMapping object
type OpenSearchRoleMappingReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	RoleMappingReconciler *opensearchreconciler.RoleMappingReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchrolemappings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchrolemappings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchrolemappings/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchRoleMapping
func (r *OpenSearchRoleMappingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "OpenSearchRoleMapping.Reconcile",
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
		metrics.RecordReconciliation("OpenSearchRoleMapping", req.Namespace, reconcileResult, duration)
	}()

	log := logf.FromContext(ctx)

	// Fetch the OpenSearchRoleMapping instance
	mapping := &wazuhv1.OpenSearchRoleMapping{}
	if err := r.Get(ctx, req.NamespacedName, mapping); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchRoleMapping resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchRoleMapping")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.RoleMappingReconciler.Reconcile(ctx, mapping); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchRoleMapping")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchRoleMapping", "name", mapping.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchRoleMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.OpenSearchRoleMapping{}).
		Named("opensearchrolemapping").
		Complete(r)
}
