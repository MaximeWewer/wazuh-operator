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

package reconciler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
)

// AuthConfigReconciler handles reconciliation of OpenSearch authentication configuration
type AuthConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewAuthConfigReconciler creates a new AuthConfigReconciler
func NewAuthConfigReconciler(c client.Client, scheme *runtime.Scheme) *AuthConfigReconciler {
	return &AuthConfigReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles an OpenSearchAuthConfig
func (r *AuthConfigReconciler) Reconcile(ctx context.Context, authConfig *wazuhv1alpha1.OpenSearchAuthConfig) error {
	log := logf.FromContext(ctx)

	// Resolve secrets
	secrets, err := r.resolveSecrets(ctx, authConfig)
	if err != nil {
		return r.updateStatus(ctx, authConfig, "Failed", fmt.Sprintf("Failed to resolve secrets: %v", err))
	}

	// Validate configuration
	if err := r.validateConfig(authConfig, secrets); err != nil {
		return r.updateStatus(ctx, authConfig, "Failed", fmt.Sprintf("Validation failed: %v", err))
	}

	// Get the referenced cluster name for ConfigMap naming
	clusterName := authConfig.Spec.ClusterRef.Name
	namespace := authConfig.Namespace

	// Reconcile indexer security config
	if err := r.reconcileIndexerSecurityConfig(ctx, authConfig, clusterName, namespace, secrets); err != nil {
		return r.updateStatus(ctx, authConfig, "Failed", fmt.Sprintf("Failed to reconcile indexer config: %v", err))
	}

	// Reconcile dashboard config
	if err := r.reconcileDashboardConfig(ctx, authConfig, clusterName, namespace, secrets); err != nil {
		return r.updateStatus(ctx, authConfig, "Failed", fmt.Sprintf("Failed to reconcile dashboard config: %v", err))
	}

	log.Info("Auth config reconciliation completed",
		"name", authConfig.Name,
		"activeAuthDomains", r.getActiveAuthDomains(authConfig))

	return r.updateStatus(ctx, authConfig, "Ready", "Authentication configuration applied")
}

// resolveSecrets resolves all secret references in the auth config
func (r *AuthConfigReconciler) resolveSecrets(ctx context.Context, authConfig *wazuhv1alpha1.OpenSearchAuthConfig) (map[string]string, error) {
	secrets := make(map[string]string)
	namespace := authConfig.Namespace

	// OIDC client secret
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.ClientSecretRef != nil {
		value, err := r.getSecretValue(ctx, namespace, authConfig.Spec.OIDC.ClientSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC client secret: %w", err)
		}
		secrets["oidc_client_secret"] = value
	}

	// OIDC cookie password
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Dashboard != nil &&
		authConfig.Spec.OIDC.Dashboard.CookiePasswordRef != nil {
		value, err := r.getSecretValue(ctx, namespace, authConfig.Spec.OIDC.Dashboard.CookiePasswordRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC cookie password: %w", err)
		}
		secrets["oidc_cookie_password"] = value
	}

	// SAML exchange key
	if authConfig.Spec.SAML != nil && authConfig.Spec.SAML.ExchangeKeyRef != nil {
		value, err := r.getSecretValue(ctx, namespace, authConfig.Spec.SAML.ExchangeKeyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve SAML exchange key: %w", err)
		}
		secrets["saml_exchange_key"] = value
	}

	// LDAP bind password
	if authConfig.Spec.LDAP != nil && authConfig.Spec.LDAP.Authentication.BindPasswordRef != nil {
		value, err := r.getSecretValue(ctx, namespace, authConfig.Spec.LDAP.Authentication.BindPasswordRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve LDAP bind password: %w", err)
		}
		secrets["ldap_bind_password"] = value
	}

	return secrets, nil
}

// getSecretValue retrieves a value from a Kubernetes secret
func (r *AuthConfigReconciler) getSecretValue(ctx context.Context, namespace string, ref *wazuhv1alpha1.SecretKeyRef) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return "", err
	}

	key := ref.Key
	if key == "" {
		key = "password"
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, ref.Name)
	}

	return string(value), nil
}

// validateConfig validates the auth configuration
func (r *AuthConfigReconciler) validateConfig(authConfig *wazuhv1alpha1.OpenSearchAuthConfig, secrets map[string]string) error {
	builder := config.NewAuthConfigBuilder(&authConfig.Spec)
	for key, value := range secrets {
		builder.WithSecret(key, value)
	}

	// Validate challenge settings (only one can be true)
	if err := builder.ValidateChallengeSettings(); err != nil {
		return err
	}

	// Validate OIDC config
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Enabled {
		oidcBuilder := config.NewOIDCConfigBuilder(authConfig.Spec.OIDC)
		if err := oidcBuilder.ValidateConfig(); err != nil {
			return err
		}
	}

	// Validate SAML config
	if authConfig.Spec.SAML != nil && authConfig.Spec.SAML.Enabled {
		samlBuilder := config.NewSAMLConfigBuilder(authConfig.Spec.SAML)
		if err := samlBuilder.ValidateConfig(); err != nil {
			return err
		}
	}

	// Validate LDAP config
	if authConfig.Spec.LDAP != nil && authConfig.Spec.LDAP.Enabled {
		ldapBuilder := config.NewLDAPConfigBuilder(authConfig.Spec.LDAP)
		if err := ldapBuilder.ValidateConfig(); err != nil {
			return err
		}
	}

	return nil
}

// reconcileIndexerSecurityConfig creates/updates the security config for the indexer
func (r *AuthConfigReconciler) reconcileIndexerSecurityConfig(
	ctx context.Context,
	authConfig *wazuhv1alpha1.OpenSearchAuthConfig,
	clusterName, namespace string,
	secrets map[string]string,
) error {
	log := logf.FromContext(ctx)

	// Build security config.yml
	builder := config.NewAuthConfigBuilder(&authConfig.Spec)
	for key, value := range secrets {
		builder.WithSecret(key, value)
	}
	securityConfigYML := builder.BuildSecurityConfig()

	// Create ConfigMap for security config
	configMapName := fmt.Sprintf("%s-security-config", clusterName)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "opensearch-security-config",
				"app.kubernetes.io/instance":   clusterName,
				"app.kubernetes.io/component":  "security",
				"app.kubernetes.io/managed-by": "wazuh-operator",
			},
		},
		Data: map[string]string{
			"config.yml": securityConfigYML,
		},
	}

	// Check if ConfigMap exists
	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, existing)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create new ConfigMap
		if err := r.Create(ctx, cm); err != nil {
			return err
		}
		log.Info("Created security config ConfigMap", "name", configMapName)
	} else {
		// Update existing ConfigMap
		existing.Data = cm.Data
		if err := r.Update(ctx, existing); err != nil {
			return err
		}
		log.Info("Updated security config ConfigMap", "name", configMapName)
	}

	return nil
}

// reconcileDashboardConfig creates/updates the dashboard config for SSO
func (r *AuthConfigReconciler) reconcileDashboardConfig(
	ctx context.Context,
	authConfig *wazuhv1alpha1.OpenSearchAuthConfig,
	clusterName, namespace string,
	secrets map[string]string,
) error {
	log := logf.FromContext(ctx)

	// Check if OIDC or SAML is enabled (dashboard config is only needed for SSO)
	needsSSOConfig := (authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Enabled) ||
		(authConfig.Spec.SAML != nil && authConfig.Spec.SAML.Enabled)

	if !needsSSOConfig {
		log.V(1).Info("No SSO methods enabled, skipping dashboard auth config")
		return nil
	}

	// Build dashboard auth config
	builder := config.NewDashboardAuthConfigBuilder(&authConfig.Spec)
	for key, value := range secrets {
		builder.WithSecret(key, value)
	}
	authSection := builder.BuildAuthSection()

	// Create ConfigMap for dashboard auth config
	configMapName := fmt.Sprintf("%s-dashboard-auth-config", clusterName)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "opensearch-dashboard-auth",
				"app.kubernetes.io/instance":   clusterName,
				"app.kubernetes.io/component":  "dashboard-auth",
				"app.kubernetes.io/managed-by": "wazuh-operator",
			},
		},
		Data: map[string]string{
			"auth.yml": authSection,
		},
	}

	// Check if ConfigMap exists
	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, existing)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create new ConfigMap
		if err := r.Create(ctx, cm); err != nil {
			return err
		}
		log.Info("Created dashboard auth config ConfigMap", "name", configMapName)
	} else {
		// Update existing ConfigMap
		existing.Data = cm.Data
		if err := r.Update(ctx, existing); err != nil {
			return err
		}
		log.Info("Updated dashboard auth config ConfigMap", "name", configMapName)
	}

	return nil
}

// getActiveAuthDomains returns the list of enabled auth methods
func (r *AuthConfigReconciler) getActiveAuthDomains(authConfig *wazuhv1alpha1.OpenSearchAuthConfig) []string {
	var domains []string

	if authConfig.Spec.BasicAuth != nil && authConfig.Spec.BasicAuth.Enabled {
		domains = append(domains, "basic")
	}
	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Enabled {
		domains = append(domains, "oidc")
	}
	if authConfig.Spec.SAML != nil && authConfig.Spec.SAML.Enabled {
		domains = append(domains, "saml")
	}
	if authConfig.Spec.LDAP != nil && authConfig.Spec.LDAP.Enabled {
		domains = append(domains, "ldap")
	}

	return domains
}

// updateStatus updates the status of the OpenSearchAuthConfig
func (r *AuthConfigReconciler) updateStatus(ctx context.Context, authConfig *wazuhv1alpha1.OpenSearchAuthConfig, phase, message string) error {
	authConfig.Status.Phase = phase
	authConfig.Status.Message = message
	authConfig.Status.ObservedGeneration = authConfig.Generation
	authConfig.Status.ActiveAuthDomains = r.getActiveAuthDomains(authConfig)
	authConfig.Status.ConfigSynced = phase == "Ready"
	authConfig.Status.DashboardConfigSynced = phase == "Ready"

	now := metav1.Now()
	if phase == "Ready" {
		authConfig.Status.LastSyncTime = &now
	}

	return r.Status().Update(ctx, authConfig)
}

// Ensure IndexerConfigMapBuilder uses our auth config builder
var _ = configmaps.NewIndexerConfigMapBuilder
