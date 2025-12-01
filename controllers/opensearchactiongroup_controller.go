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

// OpenSearchActionGroupReconciler reconciles a OpenSearchActionGroup object
type OpenSearchActionGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	ActionGroupReconciler *opensearchreconciler.ActionGroupReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchactiongroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchactiongroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchactiongroups/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchActionGroup
func (r *OpenSearchActionGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchActionGroup instance
	actionGroup := &wazuhv1alpha1.OpenSearchActionGroup{}
	if err := r.Get(ctx, req.NamespacedName, actionGroup); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchActionGroup resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchActionGroup")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.ActionGroupReconciler.Reconcile(ctx, actionGroup); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchActionGroup")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchActionGroup", "name", actionGroup.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchActionGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchActionGroup{}).
		Named("opensearchactiongroup").
		Complete(r)
}
