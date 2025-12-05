/*
Copyright 2025.

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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// OpenSearchSnapshotReconciler reconciles a OpenSearchSnapshot object
type OpenSearchSnapshotReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	ManualSnapshotReconciler *opensearchreconciler.ManualSnapshotReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshots/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchSnapshot
func (r *OpenSearchSnapshotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchSnapshot instance
	snapshot := &wazuhv1alpha1.OpenSearchSnapshot{}
	if err := r.Get(ctx, req.NamespacedName, snapshot); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchSnapshot resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchSnapshot")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.ManualSnapshotReconciler.Reconcile(ctx, snapshot); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchSnapshot")
		// Requeue with backoff for transient errors
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Requeue if snapshot is still in progress
	if snapshot.Status.Phase == constants.SnapshotPhaseInProgress || snapshot.Status.Phase == constants.SnapshotPhasePending {
		log.Info("Snapshot in progress, requeuing for status check", "name", snapshot.Name)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	log.Info("Successfully reconciled OpenSearchSnapshot", "name", snapshot.Name, "phase", snapshot.Status.Phase)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchSnapshotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchSnapshot{}).
		Named("opensearchsnapshot").
		Complete(r)
}
