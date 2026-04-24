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

package reconciler

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	retry "k8s.io/client-go/util/retry"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// AuthConfigReconciler handles reconciliation of OpenSearch authentication configuration
type AuthConfigReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	Recorder              record.EventRecorder
	SecurityAdminExecutor *security.SecurityAdminExecutor
}

// NewAuthConfigReconciler creates a new AuthConfigReconciler
func NewAuthConfigReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *AuthConfigReconciler {
	return &AuthConfigReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithSecurityAdminExecutor sets the SecurityAdmin executor for applying security config
func (r *AuthConfigReconciler) WithSecurityAdminExecutor(executor *security.SecurityAdminExecutor) *AuthConfigReconciler {
	r.SecurityAdminExecutor = executor
	return r
}

// Reconcile reconciles an OpenSearchAuthConfig
func (r *AuthConfigReconciler) Reconcile(ctx context.Context, authConfig *wazuhv1.OpenSearchAuthConfig) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "AuthConfigReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", authConfig.Name),
			attribute.String("resource.namespace", authConfig.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Resolve secrets
	secrets, err := config.ResolveAuthSecrets(ctx, r.Client, authConfig)
	if err != nil {
		r.recordEvent(authConfig, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to resolve secrets: %v", err))
		return r.updateStatus(ctx, authConfig, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Failed to resolve secrets: %v", err))
	}

	// Validate configuration
	if err := r.validateConfig(authConfig, secrets); err != nil {
		r.recordEvent(authConfig, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Validation failed: %v", err))
		return r.updateStatus(ctx, authConfig, wazuhv1.OpenSearchResourcePhaseFailed, fmt.Sprintf("Validation failed: %v", err))
	}

	// Get the referenced cluster name for ConfigMap naming
	clusterName := authConfig.Spec.ClusterRef.Name
	namespace := authConfig.Namespace

	// The indexer security config and the dashboard opensearch_dashboards.yml are now
	// produced by IndexerReconciler and DashboardReconciler respectively (they fetch the
	// matching OpenSearchAuthConfig themselves). The WazuhCluster controller watches
	// OpenSearchAuthConfig, so updates here trigger a cluster reconcile which rebuilds
	// both. This reconciler only needs to validate the spec and hot-apply it via
	// securityadmin.sh so running indexers pick up the change without a pod restart.

	// Best-effort cleanup of ConfigMaps this reconciler used to create before that
	// wiring existed. Keeping them would leave orphan objects in the namespace forever.
	r.cleanupLegacyConfigMaps(ctx, clusterName, namespace)

	// Apply security config via securityadmin.sh (non-fatal if exec fails)
	if r.SecurityAdminExecutor != nil {
		if err := r.SecurityAdminExecutor.ApplySecurityConfig(ctx, clusterName, namespace); err != nil {
			log.Error(err, "Failed to apply security config via securityadmin.sh - config will apply on next indexer restart")
		} else {
			log.Info("Security config applied via securityadmin.sh")
		}
	}

	log.Info("Auth config reconciliation completed",
		"name", authConfig.Name,
		"activeAuthDomains", r.getActiveAuthDomains(authConfig))

	r.recordEvent(authConfig, corev1.EventTypeNormal, "Synced", "Authentication configuration applied successfully")
	return r.updateStatus(ctx, authConfig, wazuhv1.OpenSearchResourcePhaseReady, "Authentication configuration applied")
}

// recordEvent emits an event if the recorder is available
func (r *AuthConfigReconciler) recordEvent(authConfig *wazuhv1.OpenSearchAuthConfig, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(authConfig, eventType, reason, message)
	}
}

// validateConfig validates the auth configuration
func (r *AuthConfigReconciler) validateConfig(authConfig *wazuhv1.OpenSearchAuthConfig, secrets map[string]string) error {
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

// cleanupLegacyConfigMaps deletes ConfigMaps this reconciler used to create before
// indexer/dashboard wiring existed. Nothing mounts them, and they have no owner
// references, so they would otherwise linger forever. Errors are logged but not
// returned since cleanup must not block reconciliation.
func (r *AuthConfigReconciler) cleanupLegacyConfigMaps(ctx context.Context, clusterName, namespace string) {
	log := logf.FromContext(ctx)

	legacyNames := []string{
		fmt.Sprintf("%s-security-config", clusterName),
		constants.DashboardAuthConfigName(clusterName),
	}
	for _, name := range legacyNames {
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cm); err != nil {
			if client.IgnoreNotFound(err) != nil {
				log.V(1).Info("Failed to check legacy ConfigMap", "name", name, "err", err)
			}
			continue
		}
		if err := r.Delete(ctx, cm); err != nil && client.IgnoreNotFound(err) != nil {
			log.V(1).Info("Failed to delete legacy ConfigMap", "name", name, "err", err)
			continue
		}
		log.Info("Deleted legacy ConfigMap superseded by indexer/dashboard reconcilers", "name", name)
	}
}

// getActiveAuthDomains returns the list of enabled auth methods
func (r *AuthConfigReconciler) getActiveAuthDomains(authConfig *wazuhv1.OpenSearchAuthConfig) []string {
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

// updateStatus updates the status of the OpenSearchAuthConfig with retry on conflict
func (r *AuthConfigReconciler) updateStatus(ctx context.Context, authConfig *wazuhv1.OpenSearchAuthConfig, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	activeDomains := r.getActiveAuthDomains(authConfig)
	configSynced := phase == "Ready"

	// Skip entirely when nothing changed
	if authConfig.Status.Phase == phase && authConfig.Status.Message == message &&
		authConfig.Status.ObservedGeneration == authConfig.Generation &&
		authConfig.Status.ConfigSynced == configSynced &&
		authConfig.Status.DashboardConfigSynced == configSynced {
		return nil
	}

	// Only update LastSyncTime when transitioning to Ready
	wasReady := authConfig.Status.Phase == wazuhv1.OpenSearchResourcePhase("Ready") &&
		authConfig.Status.ObservedGeneration == authConfig.Generation
	if phase == "Ready" && !wasReady {
		now := metav1.Now()
		authConfig.Status.LastSyncTime = &now
	}

	authConfig.Status.Phase = phase
	authConfig.Status.Message = message
	authConfig.Status.ObservedGeneration = authConfig.Generation
	authConfig.Status.ActiveAuthDomains = activeDomains
	authConfig.Status.ConfigSynced = configSynced
	authConfig.Status.DashboardConfigSynced = configSynced

	desiredStatus := authConfig.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchAuthConfig{}
		if err := r.Get(ctx, types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		authConfig.Status = latest.Status
		return nil
	})
}

