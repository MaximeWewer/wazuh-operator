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

// OpenSearchIndexTemplateReconciler reconciles a OpenSearchIndexTemplate object
type OpenSearchIndexTemplateReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	TemplateReconciler *opensearchreconciler.TemplateReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindextemplates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindextemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchindextemplates/finalizers,verbs=update

// Reconcile is the main reconciliation loop for OpenSearchIndexTemplate
func (r *OpenSearchIndexTemplateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchIndexTemplate instance
	template := &wazuhv1alpha1.OpenSearchIndexTemplate{}
	if err := r.Get(ctx, req.NamespacedName, template); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchIndexTemplate resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchIndexTemplate")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.TemplateReconciler.Reconcile(ctx, template); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchIndexTemplate")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchIndexTemplate", "name", template.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchIndexTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchIndexTemplate{}).
		Named("opensearchindextemplate").
		Complete(r)
}
