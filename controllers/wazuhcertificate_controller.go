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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

// WazuhCertificateReconciler reconciles a WazuhCertificate object
type WazuhCertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	CertificateReconciler *wazuhreconciler.CertificateReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create

// Reconcile is the main reconciliation loop for WazuhCertificate
func (r *WazuhCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhCertificate.Reconcile",
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
		metrics.RecordReconciliation("WazuhCertificate", req.Namespace, reconcileResult, duration)
	}()

	log := logf.FromContext(ctx)

	// Fetch the WazuhCertificate instance
	cert := &wazuhv1.WazuhCertificate{}
	if err := r.Get(ctx, req.NamespacedName, cert); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhCertificate resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhCertificate")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.CertificateReconciler.ReconcileStandalone(ctx, cert); err != nil {
		log.Error(err, "Failed to reconcile WazuhCertificate")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhCertificate", "name", cert.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhCertificate{}).
		Owns(&corev1.Secret{}).
		Named("wazuhcertificate").
		Complete(r)
}
