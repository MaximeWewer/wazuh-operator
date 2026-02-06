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
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WazuhRestoreReconciler reconciles a WazuhRestore object
type WazuhRestoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	RestoreReconciler *wazuhreconciler.WazuhRestoreReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrestores,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrestores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhrestores/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhRestore
func (r *WazuhRestoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhRestore.Reconcile",
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
		metrics.RecordReconciliation("WazuhRestore", req.Namespace, reconcileResult, duration)
	}()

	log := logf.FromContext(ctx)

	// Fetch the WazuhRestore instance
	restore := &wazuhv1.WazuhRestore{}
	if err := r.Get(ctx, req.NamespacedName, restore); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhRestore resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhRestore")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.RestoreReconciler.Reconcile(ctx, restore); err != nil {
		log.Error(err, "Failed to reconcile WazuhRestore")
		// Requeue with backoff for transient errors
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Requeue if restore is still in progress
	if restore.Status.Phase == constants.WazuhRestorePhaseRestoring ||
		restore.Status.Phase == constants.WazuhRestorePhasePending ||
		restore.Status.Phase == constants.WazuhRestorePhaseValidating ||
		restore.Status.Phase == constants.WazuhRestorePhaseStopping ||
		restore.Status.Phase == constants.WazuhRestorePhaseBackingUp ||
		restore.Status.Phase == constants.WazuhRestorePhaseStarting {
		log.Info("Restore in progress, requeuing for status check", "name", restore.Name, "phase", restore.Status.Phase)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	log.Info("Successfully reconciled WazuhRestore", "name", restore.Name, "phase", restore.Status.Phase)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhRestoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhRestore{}).
		Owns(&batchv1.Job{}).
		Watches(
			&batchv1.Job{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &wazuhv1.WazuhRestore{}),
		).
		Named("wazuhrestore").
		Complete(r)
}
