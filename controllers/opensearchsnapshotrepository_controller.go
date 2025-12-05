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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
)

// OpenSearchSnapshotRepositoryReconciler reconciles a OpenSearchSnapshotRepository object
type OpenSearchSnapshotRepositoryReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	SnapshotRepositoryReconciler *opensearchreconciler.SnapshotRepositoryReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshotrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshotrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchsnapshotrepositories/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is the main reconciliation loop for OpenSearchSnapshotRepository
func (r *OpenSearchSnapshotRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchSnapshotRepository instance
	repo := &wazuhv1alpha1.OpenSearchSnapshotRepository{}
	if err := r.Get(ctx, req.NamespacedName, repo); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchSnapshotRepository resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchSnapshotRepository")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.SnapshotRepositoryReconciler.Reconcile(ctx, repo); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchSnapshotRepository")
		// Requeue with backoff for transient errors
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	log.Info("Successfully reconciled OpenSearchSnapshotRepository", "name", repo.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchSnapshotRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchSnapshotRepository{}).
		// Watch Secrets that may contain credentials
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findRepositoriesForSecret),
		).
		Named("opensearchsnapshotrepository").
		Complete(r)
}

// findRepositoriesForSecret returns reconcile requests for repositories that reference the given secret
func (r *OpenSearchSnapshotRepositoryReconciler) findRepositoriesForSecret(ctx context.Context, obj client.Object) []ctrl.Request {
	log := logf.FromContext(ctx)
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	// List all repositories in the same namespace
	repoList := &wazuhv1alpha1.OpenSearchSnapshotRepositoryList{}
	if err := r.List(ctx, repoList, client.InNamespace(secret.Namespace)); err != nil {
		log.Error(err, "Failed to list OpenSearchSnapshotRepository resources")
		return nil
	}

	var requests []ctrl.Request
	for _, repo := range repoList.Items {
		// Check if this repository references the secret
		if repo.Spec.Settings.CredentialsSecret != nil &&
			repo.Spec.Settings.CredentialsSecret.Name == secret.Name {
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKey{
					Name:      repo.Name,
					Namespace: repo.Namespace,
				},
			})
		}
	}

	return requests
}
