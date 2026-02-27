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
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"context"

	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	retry "k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	certreconciler "github.com/MaximeWewer/wazuh-operator/internal/certificates/reconciler"
)

// WazuhCertificateReconciler reconciles a WazuhCertificate object
type WazuhCertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	CertificateReconciler *certreconciler.CertificateReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhcertificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create

// Reconcile is the main reconciliation loop for WazuhCertificate
func (r *WazuhCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhCertificate.Reconcile",
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
		metrics.RecordReconciliation("WazuhCertificate", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
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
		// Update status to Failed
		if statusErr := r.updateCertificateStatus(ctx, cert, wazuhv1.CertificatePhaseFailed, fmt.Sprintf("Reconciliation failed: %v", err)); statusErr != nil {
			log.Error(statusErr, "Failed to update certificate status")
		}
		return ctrl.Result{}, err
	}

	// Update status to Ready
	if err := r.updateCertificateStatus(ctx, cert, wazuhv1.CertificatePhaseReady, ""); err != nil {
		log.Error(err, "Failed to update certificate status")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhCertificate", "name", cert.Name)
	return ctrl.Result{}, nil
}

// updateCertificateStatus updates the WazuhCertificate status subresource
func (r *WazuhCertificateReconciler) updateCertificateStatus(ctx context.Context, cert *wazuhv1.WazuhCertificate, phase wazuhv1.CertificatePhase, message string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.WazuhCertificate{}
		if err := r.Get(ctx, types.NamespacedName{Name: cert.Name, Namespace: cert.Namespace}, latest); err != nil {
			return err
		}
		// Check if status actually changed to avoid no-op updates
		newPhase := phase
		newSecretRef := &corev1.LocalObjectReference{Name: cert.Spec.SecretName}

		var newCondStatus metav1.ConditionStatus
		var newReason, newMessage string
		if phase == wazuhv1.CertificatePhaseReady {
			newCondStatus = metav1.ConditionTrue
			newReason = "ReconcileSuccess"
			newMessage = "Certificate reconciled successfully"
		} else {
			newCondStatus = metav1.ConditionFalse
			newReason = "ReconcileFailed"
			newMessage = message
		}

		// Check if anything actually changed
		existingCond := meta.FindStatusCondition(latest.Status.Conditions, wazuhv1.CertificateConditionReady)
		if latest.Status.Phase == newPhase &&
			latest.Status.ObservedGeneration == latest.Generation &&
			latest.Status.SecretRef != nil && latest.Status.SecretRef.Name == newSecretRef.Name &&
			existingCond != nil &&
			existingCond.Status == newCondStatus &&
			existingCond.Reason == newReason &&
			existingCond.Message == newMessage &&
			existingCond.ObservedGeneration == latest.Generation {
			return nil
		}

		latest.Status.Phase = newPhase
		latest.Status.ObservedGeneration = latest.Generation
		latest.Status.SecretRef = newSecretRef

		readyCond := metav1.Condition{
			Type:               wazuhv1.CertificateConditionReady,
			ObservedGeneration: latest.Generation,
			LastTransitionTime: metav1.Now(),
			Status:             newCondStatus,
			Reason:             newReason,
			Message:            newMessage,
		}
		// Preserve LastTransitionTime if status didn't change
		if existingCond != nil && existingCond.Status == newCondStatus {
			readyCond.LastTransitionTime = existingCond.LastTransitionTime
		}
		meta.SetStatusCondition(&latest.Status.Conditions, readyCond)

		return r.Status().Update(ctx, latest)
	})
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhCertificate{}).
		Owns(&corev1.Secret{}).
		Named("wazuhcertificate").
		Complete(r)
}
