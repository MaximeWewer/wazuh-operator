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

// WazuhDecoderReconciler reconciles a WazuhDecoder object
type WazuhDecoderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconciler
	DecoderReconciler *wazuhreconciler.DecoderReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhdecoders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhdecoders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhdecoders/finalizers,verbs=update

// Reconcile is the main reconciliation loop for WazuhDecoder
func (r *WazuhDecoderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhDecoder.Reconcile",
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
		metrics.RecordReconciliation("WazuhDecoder", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	// Fetch the WazuhDecoder instance
	decoder := &wazuhv1.WazuhDecoder{}
	if err := r.Get(ctx, req.NamespacedName, decoder); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhDecoder resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhDecoder")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !decoder.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(decoder, wazuhreconciler.DecoderFinalizer) {
			log.Info("Handling deletion of WazuhDecoder", "name", decoder.Name)

			// Perform cleanup
			if err := r.DecoderReconciler.Delete(ctx, decoder); err != nil {
				log.Error(err, "Failed to cleanup WazuhDecoder")
				return ctrl.Result{}, err
			}

			// Remove finalizer
			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &wazuhv1.WazuhDecoder{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				controllerutil.RemoveFinalizer(latest, wazuhreconciler.DecoderFinalizer)
				return r.Update(ctx, latest)
			}); err != nil {
				log.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			log.Info("Successfully removed finalizer from WazuhDecoder", "name", decoder.Name)
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(decoder, wazuhreconciler.DecoderFinalizer) {
		log.Info("Adding finalizer to WazuhDecoder", "name", decoder.Name)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &wazuhv1.WazuhDecoder{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			controllerutil.AddFinalizer(latest, wazuhreconciler.DecoderFinalizer)
			return r.Update(ctx, latest)
		}); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		// Requeue after adding finalizer
		return ctrl.Result{Requeue: true}, nil
	}

	// Delegate to helper reconciler
	if err := r.DecoderReconciler.Reconcile(ctx, decoder); err != nil {
		log.Error(err, "Failed to reconcile WazuhDecoder")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled WazuhDecoder", "name", decoder.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhDecoderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhDecoder{}).
		WithEventFilter(eventLogPredicate("WazuhDecoder", &wazuhv1.WazuhDecoder{})).
		Owns(&corev1.ConfigMap{}).
		// Watch for WazuhCluster spec changes to re-reconcile decoders when cluster changes
		Watches(
			&wazuhv1.WazuhCluster{},
			handler.EnqueueRequestsFromMapFunc(r.findDecodersForCluster),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("wazuhdecoder").
		Complete(r)
}

// findDecodersForCluster returns reconcile requests for all WazuhDecoders that reference a given cluster
func (r *WazuhDecoderReconciler) findDecodersForCluster(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	cluster, ok := obj.(*wazuhv1.WazuhCluster)
	if !ok {
		return nil
	}

	// List WazuhDecoders across all namespaces - they can target any cluster.
	decoderList := &wazuhv1.WazuhDecoderList{}
	if err := r.List(ctx, decoderList); err != nil {
		log.Error(err, "Failed to list WazuhDecoders for cluster", "cluster", cluster.Name)
		return nil
	}

	var requests []reconcile.Request
	for _, decoder := range decoderList.Items {
		for _, ref := range decoder.Spec.ClusterRefs {
			if ref.Name == cluster.Name && ref.Namespace == cluster.Namespace {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      decoder.Name,
						Namespace: decoder.Namespace,
					},
				})
				break
			}
		}
	}

	if len(requests) > 0 {
		log.Info("Cluster changed, triggering reconciliation for decoders",
			"cluster", cluster.Name, "decodersCount", len(requests))
	}

	return requests
}
