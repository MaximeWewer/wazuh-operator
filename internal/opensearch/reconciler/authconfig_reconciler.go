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
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
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

	// basic_internal_auth_domain is always emitted: the dashboard (kibanaserver),
	// the operator's own API client (admin) and securityadmin all authenticate via
	// HTTP Basic, so disabling it would lock them out. Warn instead of honoring it.
	if authConfig.Spec.BasicAuth != nil && !authConfig.Spec.BasicAuth.Enabled {
		log.Info("basicAuth.enabled=false is ignored: internal basic auth is always kept so the dashboard and operator service accounts keep working; use basicAuth.challenge/order to tune it instead",
			"name", authConfig.Name)
		r.recordEvent(authConfig, corev1.EventTypeWarning, "BasicAuthAlwaysOn",
			"basicAuth.enabled=false is ignored; internal basic auth is always kept (required by the dashboard and operator)")
	}

	// Iterate over each target cluster: cleanup orphan ConfigMaps and apply
	// the security config via securityadmin.sh per cluster. Errors are logged
	// per cluster but do not abort the loop.
	//
	// config.yml is rendered per cluster (not once) because JWKS-based JWT auth is
	// routed to a different authenticator depending on the cluster's OpenSearch
	// version, so target clusters on different versions need different output. We push
	// it inline via securityadmin.sh because the pod's mounted config.yml (a Secret
	// subPath) is not refreshed after pod creation and would otherwise be stale.
	newStatuses := make([]wazuhv1.OpenSearchClusterStatus, 0, len(authConfig.Spec.ClusterRefs))
	for _, ref := range authConfig.Spec.ClusterRefs {
		st := wazuhv1.OpenSearchClusterStatus{Name: ref.Name, Namespace: ref.Namespace}
		r.cleanupLegacyConfigMaps(ctx, ref.Name, ref.Namespace)

		// Resolve the target cluster's Wazuh version (best effort) to route JWKS-based
		// JWT auth to the authenticator its OpenSearch version supports.
		cfgBuilder := config.NewAuthConfigBuilder(&authConfig.Spec).WithWazuhVersion(r.clusterWazuhVersion(ctx, ref.Name, ref.Namespace))
		for k, v := range secrets {
			cfgBuilder.WithSecret(k, v)
		}
		securityConfigYML := cfgBuilder.BuildSecurityConfig()

		if r.SecurityAdminExecutor != nil {
			if err := r.SecurityAdminExecutor.ApplySecurityConfig(ctx, ref.Name, ref.Namespace, securityConfigYML); err != nil {
				log.Error(err, "Failed to apply security config via securityadmin.sh on cluster",
					"cluster", ref.Name, "clusterNamespace", ref.Namespace)
				st.Phase = wazuhv1.OpenSearchResourcePhasePending
				st.Message = fmt.Sprintf("securityadmin.sh: %v", err)
			} else {
				now := metav1.Now()
				st.Phase = wazuhv1.OpenSearchResourcePhaseReady
				st.LastSyncTime = &now
			}
		} else {
			now := metav1.Now()
			st.Phase = wazuhv1.OpenSearchResourcePhaseReady
			st.LastSyncTime = &now
		}
		newStatuses = append(newStatuses, st)
	}
	authConfig.Status.ClusterStatuses = newStatuses

	// Derive the overall phase from per-cluster results: a single cluster that
	// failed to apply must not be reported as a fully Ready resource.
	var failed []string
	for _, st := range newStatuses {
		if st.Phase != wazuhv1.OpenSearchResourcePhaseReady {
			failed = append(failed, fmt.Sprintf("%s/%s", st.Namespace, st.Name))
		}
	}

	log.Info("Auth config reconciliation completed",
		"name", authConfig.Name,
		"activeAuthDomains", r.getActiveAuthDomains(authConfig),
		"failedClusters", failed)

	if len(failed) > 0 {
		r.recordEvent(authConfig, corev1.EventTypeWarning, "SyncPartial",
			fmt.Sprintf("Failed to apply security config on: %v", failed))
		return r.updateStatus(ctx, authConfig, wazuhv1.OpenSearchResourcePhasePending,
			fmt.Sprintf("Security config not applied on %d of %d target cluster(s): %v",
				len(failed), len(newStatuses), failed))
	}

	r.recordEvent(authConfig, corev1.EventTypeNormal, "Synced", "Authentication configuration applied on all target clusters")
	return r.updateStatus(ctx, authConfig, wazuhv1.OpenSearchResourcePhaseReady, "Authentication configuration applied")
}

// clusterWazuhVersion returns the target WazuhCluster's version, or "" if it cannot be
// resolved. Best effort: a missing version simply makes the auth builder fall back to the
// version-agnostic routing (JWKS via the openid authenticator).
func (r *AuthConfigReconciler) clusterWazuhVersion(ctx context.Context, name, namespace string) string {
	cluster := &wazuhv1.WazuhCluster{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cluster); err != nil {
		logf.FromContext(ctx).V(1).Info("Could not resolve target cluster version for auth routing",
			"cluster", name, "namespace", namespace, "err", err)
		return ""
	}
	return cluster.Spec.Version
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

	// Enforce the dashboard-side requirement that `basicauth` is part of any
	// multi-auth configuration (checked by security-dashboards-plugin on all
	// supported versions, 2.13 through 2.19).
	if err := builder.ValidateMultiAuthRequiresBasic(); err != nil {
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

	// Validate JWT config
	if authConfig.Spec.JWT != nil && authConfig.Spec.JWT.Enabled {
		jwtBuilder := config.NewJWTConfigBuilder(authConfig.Spec.JWT)
		if err := jwtBuilder.ValidateConfig(); err != nil {
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
	if authConfig.Spec.JWT != nil && authConfig.Spec.JWT.Enabled {
		domains = append(domains, "jwt")
	}

	return domains
}

// updateStatus updates the status of the OpenSearchAuthConfig with retry on conflict
func (r *AuthConfigReconciler) updateStatus(ctx context.Context, authConfig *wazuhv1.OpenSearchAuthConfig, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	activeDomains := r.getActiveAuthDomains(authConfig)
	configSynced := phase == "Ready"
	// ClusterStatuses were populated on authConfig.Status by Reconcile before this call.
	clusterStatuses := authConfig.Status.ClusterStatuses

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchAuthConfig{}
		if err := r.Get(ctx, types.NamespacedName{Name: authConfig.Name, Namespace: authConfig.Namespace}, latest); err != nil {
			return err
		}

		// Skip the write only when the persisted status already matches the desired
		// one — including per-cluster statuses. The earlier version compared only the
		// scalar fields, so a corrected ClusterStatuses (e.g. a cluster moving from
		// Pending to Ready while the overall phase stayed Ready) was never persisted.
		if latest.Status.Phase == phase && latest.Status.Message == message &&
			latest.Status.ObservedGeneration == authConfig.Generation &&
			latest.Status.ConfigSynced == configSynced &&
			latest.Status.DashboardConfigSynced == configSynced &&
			clusterStatusesEqual(latest.Status.ClusterStatuses, clusterStatuses) {
			authConfig.Status = latest.Status
			return nil
		}

		// Only refresh LastSyncTime when transitioning to Ready; otherwise preserve the
		// persisted value so repeated reconciles do not churn the status.
		wasReady := latest.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
			latest.Status.ObservedGeneration == authConfig.Generation
		lastSyncTime := latest.Status.LastSyncTime
		if phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady {
			now := metav1.Now()
			lastSyncTime = &now
		}

		latest.Status.Phase = phase
		latest.Status.Message = message
		latest.Status.ObservedGeneration = authConfig.Generation
		latest.Status.ActiveAuthDomains = activeDomains
		latest.Status.ConfigSynced = configSynced
		latest.Status.DashboardConfigSynced = configSynced
		latest.Status.ClusterStatuses = clusterStatuses
		latest.Status.LastSyncTime = lastSyncTime

		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		authConfig.Status = latest.Status
		return nil
	})
}

// clusterStatusesEqual compares per-cluster statuses ignoring LastSyncTime, which is
// timestamp noise that would otherwise force a write on every reconcile.
func clusterStatusesEqual(a, b []wazuhv1.OpenSearchClusterStatus) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct{ name, namespace string }
	index := make(map[key]wazuhv1.OpenSearchClusterStatus, len(a))
	for _, s := range a {
		index[key{s.Name, s.Namespace}] = s
	}
	for _, s := range b {
		prev, ok := index[key{s.Name, s.Namespace}]
		if !ok || prev.Phase != s.Phase || prev.Message != s.Message {
			return false
		}
	}
	return true
}
