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

// OpenSearchAuthConfigReconciler reconciles a OpenSearchAuthConfig object
type OpenSearchAuthConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	AuthConfigReconciler *opensearchreconciler.AuthConfigReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchauthconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchauthconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=opensearchauthconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch

// Reconcile is the main reconciliation loop for OpenSearchAuthConfig
func (r *OpenSearchAuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the OpenSearchAuthConfig instance
	authConfig := &wazuhv1alpha1.OpenSearchAuthConfig{}
	if err := r.Get(ctx, req.NamespacedName, authConfig); err != nil {
		if errors.IsNotFound(err) {
			log.Info("OpenSearchAuthConfig resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get OpenSearchAuthConfig")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.AuthConfigReconciler.Reconcile(ctx, authConfig); err != nil {
		log.Error(err, "Failed to reconcile OpenSearchAuthConfig")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled OpenSearchAuthConfig", "name", authConfig.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *OpenSearchAuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.OpenSearchAuthConfig{}).
		// Watch secrets for secret references (client secret, exchange key, etc.)
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findAuthConfigsForSecret),
		).
		Named("opensearchauthconfig").
		Complete(r)
}

// findAuthConfigsForSecret finds all AuthConfigs that reference the given secret
func (r *OpenSearchAuthConfigReconciler) findAuthConfigsForSecret(ctx context.Context, obj client.Object) []ctrl.Request {
	log := logf.FromContext(ctx)
	secret := obj.(*corev1.Secret)

	authConfigs := &wazuhv1alpha1.OpenSearchAuthConfigList{}
	if err := r.List(ctx, authConfigs, client.InNamespace(secret.Namespace)); err != nil {
		log.Error(err, "Failed to list OpenSearchAuthConfigs")
		return nil
	}

	var requests []ctrl.Request
	for _, authConfig := range authConfigs.Items {
		// Check if this auth config references this secret
		if r.authConfigReferencesSecret(&authConfig, secret.Name) {
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKeyFromObject(&authConfig),
			})
		}
	}

	return requests
}

// authConfigReferencesSecret checks if the auth config references the given secret
func (r *OpenSearchAuthConfigReconciler) authConfigReferencesSecret(authConfig *wazuhv1alpha1.OpenSearchAuthConfig, secretName string) bool {
	// Check OIDC client secret
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.ClientSecretRef != nil {
		if authConfig.Spec.OIDC.ClientSecretRef.Name == secretName {
			return true
		}
	}

	// Check OIDC cookie password
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Dashboard != nil &&
		authConfig.Spec.OIDC.Dashboard.CookiePasswordRef != nil {
		if authConfig.Spec.OIDC.Dashboard.CookiePasswordRef.Name == secretName {
			return true
		}
	}

	// Check SAML exchange key
	if authConfig.Spec.SAML != nil && authConfig.Spec.SAML.ExchangeKeyRef != nil {
		if authConfig.Spec.SAML.ExchangeKeyRef.Name == secretName {
			return true
		}
	}

	// Check LDAP bind password
	if authConfig.Spec.LDAP != nil && authConfig.Spec.LDAP.Authentication.BindPasswordRef != nil {
		if authConfig.Spec.LDAP.Authentication.BindPasswordRef.Name == secretName {
			return true
		}
	}

	return false
}
