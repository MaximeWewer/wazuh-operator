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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
)

// OpenSearchIndexReconciler reconciles a OpenSearchIndex object
type OpenSearchIndexReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	IndexReconciler *opensearchreconciler.IndexReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindices,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindices/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindices/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchIndex
func (r *OpenSearchIndexReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchIndex instance
	index := &wazuhv1alpha1.OpenSearchIndex{}
	if err := r.Get(ctx, req.NamespacedName, index); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchIndex resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchIndex")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.IndexReconciler.Reconcile(ctx, index); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchIndex")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchIndex", "name", index.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchIndexReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchIndex{}).
		Named("opensearchindex").
		Complete(r)
}
