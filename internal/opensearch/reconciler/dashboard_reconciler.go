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
	"net"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	opensearchcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/opensearch"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/hpa"
	osservices "github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	opensearchconfig "github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/serviceaccount"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardReconciler handles reconciliation of OpenSearch Dashboard
type DashboardReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewDashboardReconciler creates a new DashboardReconciler
func NewDashboardReconciler(c client.Client, scheme *runtime.Scheme) *DashboardReconciler {
	return &DashboardReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithRecorder sets the event recorder for the reconciler
func (r *DashboardReconciler) WithRecorder(recorder record.EventRecorder) *DashboardReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the OpenSearch Dashboard
func (r *DashboardReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "DashboardReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", cluster.Name),
			attribute.String("resource.namespace", cluster.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard secrets: %w", err)
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard configmap: %w", err)
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard service: %w", err)
	}

	// Reconcile Deployment
	if err := r.reconcileDeployment(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard deployment: %w", err)
	}

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard PDB: %w", err)
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard HPA: %w", err)
	}

	log.Info("Dashboard reconciliation completed")
	return nil
}

// reconcileSecrets reconciles dashboard secrets
func (r *DashboardReconciler) reconcileSecrets(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if certificates already exist
	certsSecretName := constants.DashboardCertsName(cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Get CA from indexer certificates
		indexerCertsSecret := &corev1.Secret{}
		indexerCertsName := constants.IndexerCertsName(cluster.Name)
		if err := r.Get(ctx, types.NamespacedName{Name: indexerCertsName, Namespace: cluster.Namespace}, indexerCertsSecret); err != nil {
			return fmt.Errorf("failed to get indexer certificates (required for dashboard): %w", err)
		}

		caCertPEM, ok := indexerCertsSecret.Data[constants.SecretKeyCACert]
		if !ok {
			return fmt.Errorf("CA certificate not found in indexer secrets")
		}

		// Parse the CA to sign dashboard certificate
		// We need the CA private key which might be stored separately or we generate a new CA
		// For simplicity, we'll generate dashboard-specific certs using the same approach
		certs, err := r.generateDashboardCertificates(ctx, cluster, caCertPEM)
		if err != nil {
			return fmt.Errorf("failed to generate dashboard certificates: %w", err)
		}

		certsBuilder := opensearchcerts.NewDashboardCertsSecretBuilder(cluster.Name, cluster.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithDashboardCert(certs.dashboardCert).
			WithDashboardKey(certs.dashboardKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(cluster, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for dashboard certs: %w", err)
		}

		log.Info("Creating Dashboard certificates secret", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create dashboard certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard certs secret: %w", err)
	}

	return nil
}

// dashboardCertificates holds all generated certificates for the dashboard
type dashboardCertificates struct {
	caCert        []byte
	dashboardCert []byte
	dashboardKey  []byte
}

// generateDashboardCertificates generates certificates for the dashboard
// This generates a self-signed certificate for the dashboard HTTPS server.
// The CA for connecting to OpenSearch comes from the indexer-certs secret.
func (r *DashboardReconciler) generateDashboardCertificates(ctx context.Context, cluster *wazuhv1.WazuhCluster, _ []byte) (*dashboardCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate a self-signed CA for dashboard's HTTPS server certificate
	// This is separate from the indexer CA (which is used for OpenSearch connection)
	caConfig := certificates.DefaultCAConfig(constants.DashboardCAName(cluster.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for dashboard HTTPS server")

	// Generate dashboard certificate with SANs
	dashboardConfig := certificates.DefaultDashboardCertConfig()
	dashboardConfig.DNSNames = certificates.GenerateDashboardSANs(cluster.Name, cluster.Namespace)
	dashboardConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	dashboardCert, err := certificates.GenerateDashboardCert(dashboardConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dashboard certificate: %w", err)
	}
	log.V(1).Info("Generated dashboard certificate", "sans", dashboardConfig.DNSNames)

	// Return the dashboard's own CA for its HTTPS server
	// The indexer CA is mounted separately via indexer-certs volume
	return &dashboardCertificates{
		caCert:        ca.CertificatePEM, // Dashboard's own CA for HTTPS server
		dashboardCert: dashboardCert.CertificatePEM,
		dashboardKey:  dashboardCert.PrivateKeyPEM,
	}, nil
}

// reconcileConfigMap reconciles the dashboard ConfigMap
func (r *DashboardReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Build dashboard configuration (already generates opensearch_dashboards.yml)
	configBuilder := configmaps.NewDashboardConfigMapBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Dashboard != nil {
		configBuilder.WithEnableSSL(cluster.Spec.Dashboard.EnableSSL)
	}

	// Apply authentication configuration from the matching OpenSearchAuthConfig CR.
	// Without this, the generated opensearch_dashboards.yml always falls back to basicauth
	// even when OIDC / SAML / LDAP is configured via an OpenSearchAuthConfig.
	authConfig, err := opensearchconfig.FindAuthConfigForCluster(ctx, r.Client, cluster.Name, cluster.Namespace)
	if err != nil {
		log.Error(err, "Failed to list OpenSearchAuthConfigs, dashboard will use basicauth fallback")
	} else if authConfig != nil {
		authSecrets, secErr := opensearchconfig.ResolveAuthSecrets(ctx, r.Client, authConfig)
		if secErr != nil {
			log.Error(secErr, "Failed to resolve auth secrets, dashboard will use basicauth fallback", "authConfig", authConfig.Name)
		} else {
			// Ensure a stable OIDC cookie password exists when the user did not supply one.
			// Otherwise the dashboard config builder generates a fresh random value on every
			// reconcile, which makes the rendered opensearch_dashboards.yml differ each pass
			// and produces an infinite reconcile loop.
			if err := r.ensureOIDCCookiePassword(ctx, cluster, authConfig, authSecrets); err != nil {
				log.Error(err, "Failed to ensure OIDC cookie password, dashboard may reconcile-loop", "authConfig", authConfig.Name)
			}
			configBuilder.WithAuthConfig(&authConfig.Spec).WithAuthSecrets(authSecrets)
		}
	}

	// Pass wazuhPlugin configuration if defined
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.WazuhPlugin != nil {
		configBuilder.WithWazuhPlugin(cluster.Spec.Dashboard.WazuhPlugin)

		// Resolve credentials from secrets for API endpoints
		resolvedCredentials, err := r.resolveAPIEndpointCredentials(ctx, cluster.Namespace, cluster.Spec.Dashboard.WazuhPlugin)
		if err != nil {
			log.Error(err, "Failed to resolve API endpoint credentials from secrets")
			// Continue without resolved credentials - will fall back to inline values
		} else if len(resolvedCredentials) > 0 {
			configBuilder.WithResolvedCredentials(resolvedCredentials)
		}
	}

	// Auto-resolve default API credentials from the operator-managed secret
	// when no explicit wazuhPlugin credentials are configured
	if configBuilder.NeedsDefaultCredentials() {
		resolvedCredentials := make(map[string]string)
		apiSecretName := constants.APICredentialsName(cluster.Name)
		apiSecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: apiSecretName, Namespace: cluster.Namespace}, apiSecret); err == nil {
			if username, ok := apiSecret.Data[constants.SecretKeyAPIUsername]; ok {
				resolvedCredentials["default:username"] = string(username)
			}
			if password, ok := apiSecret.Data[constants.SecretKeyAPIPassword]; ok {
				resolvedCredentials["default:password"] = string(password)
			}
			if len(resolvedCredentials) > 0 {
				configBuilder.WithResolvedCredentials(resolvedCredentials)
			}
		} else {
			log.V(1).Info("Could not find API credentials secret for dashboard", "secret", apiSecretName)
		}
	}

	configMap, err := configBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build dashboard configmap: %w", err)
	}

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return err
	}

	// Reconcile the wazuh.yml Secret (credentials stored in a Secret, not a ConfigMap)
	wazuhSecret := configBuilder.BuildWazuhConfigSecret()
	if err := controllerutil.SetControllerReference(cluster, wazuhSecret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard wazuh config secret: %w", err)
	}

	return r.createOrUpdate(ctx, wazuhSecret)
}

// getConfigHash retrieves the current config hash from the dashboard ConfigMap
func (r *DashboardReconciler) getConfigHash(ctx context.Context, cluster *wazuhv1.WazuhCluster) string {
	configMapName := constants.DashboardConfigName(cluster.Name)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// ensureOIDCCookiePassword guarantees a stable value for the global
// opensearch-dashboards cookie password. Dashboards uses it to HMAC-sign session
// cookies for OIDC and SAML flows alike; the same value must therefore be
// reused across reconciles and across dashboard replicas. If the user supplied
// an OIDC CookiePasswordRef it is resolved upstream by ResolveAuthSecrets and
// we leave authSecrets untouched.
func (r *DashboardReconciler) ensureOIDCCookiePassword(ctx context.Context, cluster *wazuhv1.WazuhCluster, authConfig *wazuhv1.OpenSearchAuthConfig, authSecrets map[string]string) error {
	oidcEnabled := authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Enabled
	samlEnabled := authConfig.Spec.SAML != nil && authConfig.Spec.SAML.Enabled
	if !oidcEnabled && !samlEnabled {
		return nil
	}
	if oidcEnabled && authConfig.Spec.OIDC.Dashboard != nil && authConfig.Spec.OIDC.Dashboard.CookiePasswordRef != nil {
		return nil // user-managed, already resolved upstream
	}
	if v, ok := authSecrets[opensearchconfig.AuthSecretKeyOIDCCookiePassword]; ok && v != "" {
		return nil
	}

	secretName := fmt.Sprintf("%s-dashboard-oidc-cookie", cluster.Name)
	key := types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}

	existing := &corev1.Secret{}
	err := r.Get(ctx, key, existing)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get OIDC cookie secret %s: %w", secretName, err)
	}
	if err == nil {
		if v, ok := existing.Data["cookie_password"]; ok && len(v) > 0 {
			authSecrets[opensearchconfig.AuthSecretKeyOIDCCookiePassword] = string(v)
			return nil
		}
	}

	password, genErr := utils.GenerateRandomPassword(32)
	if genErr != nil {
		return fmt.Errorf("failed to generate OIDC cookie password: %w", genErr)
	}

	if errors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: cluster.Namespace,
				Labels: map[string]string{
					constants.LabelName:      constants.AppName + "-dashboard-oidc-cookie",
					constants.LabelInstance:  cluster.Name,
					constants.LabelComponent: constants.ComponentDashboard,
					constants.LabelManagedBy: constants.OperatorName,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"cookie_password": []byte(password)},
		}
		if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference on OIDC cookie secret: %w", err)
		}
		if err := r.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create OIDC cookie secret: %w", err)
		}
	} else {
		// Secret existed without cookie_password key: backfill it in-place so the
		// next reconcile reads the same persisted value.
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data["cookie_password"] = []byte(password)
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update OIDC cookie secret: %w", err)
		}
	}
	authSecrets[opensearchconfig.AuthSecretKeyOIDCCookiePassword] = password
	return nil
}

// resolveAPIEndpointCredentials resolves credentials from secret references for API endpoints
// Returns a map with keys "endpointID:username" and "endpointID:password"
func (r *DashboardReconciler) resolveAPIEndpointCredentials(ctx context.Context, namespace string, wazuhPlugin *wazuhv1.WazuhPluginConfig) (map[string]string, error) {
	resolvedCredentials := make(map[string]string)

	if wazuhPlugin == nil {
		return resolvedCredentials, nil
	}

	// Resolve credentials for explicit API endpoints
	for _, endpoint := range wazuhPlugin.APIEndpoints {
		if endpoint.CredentialsSecretRef == nil || endpoint.CredentialsSecretRef.SecretName == "" {
			continue
		}

		secret := &corev1.Secret{}
		secretName := endpoint.CredentialsSecretRef.SecretName

		err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s for endpoint %s: %w", secretName, endpoint.ID, err)
		}

		// Get username key (default: "username")
		usernameKey := endpoint.CredentialsSecretRef.UsernameKey
		if usernameKey == "" {
			usernameKey = "username"
		}
		if usernameBytes, ok := secret.Data[usernameKey]; ok {
			resolvedCredentials[endpoint.ID+":username"] = string(usernameBytes)
		}

		// Get password key (default: "password")
		passwordKey := endpoint.CredentialsSecretRef.PasswordKey
		if passwordKey == "" {
			passwordKey = "password"
		}
		if passwordBytes, ok := secret.Data[passwordKey]; ok {
			resolvedCredentials[endpoint.ID+":password"] = string(passwordBytes)
		}
	}

	// Resolve credentials for default API endpoint (when no explicit endpoints defined)
	if len(wazuhPlugin.APIEndpoints) == 0 && wazuhPlugin.DefaultAPIEndpoint != nil && wazuhPlugin.DefaultAPIEndpoint.CredentialsSecret != nil {
		secretRef := wazuhPlugin.DefaultAPIEndpoint.CredentialsSecret
		if secretRef.SecretName != "" {
			secret := &corev1.Secret{}
			err := r.Get(ctx, types.NamespacedName{Name: secretRef.SecretName, Namespace: namespace}, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret %s for default API endpoint: %w", secretRef.SecretName, err)
			}

			// Get username key (default: "username")
			usernameKey := secretRef.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			if usernameBytes, ok := secret.Data[usernameKey]; ok {
				resolvedCredentials["default:username"] = string(usernameBytes)
			}

			// Get password key (default: "password")
			passwordKey := secretRef.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}
			if passwordBytes, ok := secret.Data[passwordKey]; ok {
				resolvedCredentials["default:password"] = string(passwordBytes)
			}
		}
	}

	return resolvedCredentials, nil
}

// reconcileService reconciles the dashboard service
func (r *DashboardReconciler) reconcileService(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	serviceBuilder := osservices.NewDashboardServiceBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Service != nil {
		svcSpec := cluster.Spec.Dashboard.Service
		if svcSpec.Type != "" {
			serviceBuilder.WithServiceType(svcSpec.Type)
		}
		if len(svcSpec.Annotations) > 0 {
			serviceBuilder.WithAnnotations(svcSpec.Annotations)
		}
		if svcSpec.LoadBalancerIP != "" {
			serviceBuilder.WithLoadBalancerIP(svcSpec.LoadBalancerIP)
		}
		if len(svcSpec.Ports) > 0 {
			serviceBuilder.WithPorts(convertServicePorts(svcSpec.Ports))
		}
	}
	service := serviceBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard service: %w", err)
	}

	return r.createOrUpdate(ctx, service)
}

// reconcileDeployment reconciles the dashboard Deployment
func (r *DashboardReconciler) reconcileDeployment(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	return r.reconcileDeploymentWithCertHash(ctx, cluster, "")
}

// reconcileDeploymentWithCertHash reconciles the dashboard Deployment with an optional certificate hash
// When the cert hash changes, the deployment will be updated which triggers a pod rollout
func (r *DashboardReconciler) reconcileDeploymentWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	deployBuilder := deployments.NewDashboardDeploymentBuilder(cluster.Name, cluster.Namespace)

	// Set version from cluster spec
	if cluster.Spec.Version != "" {
		deployBuilder.WithVersion(cluster.Spec.Version)
	}

	if cluster.Spec.Dashboard != nil {
		if cluster.Spec.Dashboard.Replicas > 0 {
			deployBuilder.WithReplicas(cluster.Spec.Dashboard.Replicas)
		}
		if cluster.Spec.Dashboard.Resources != nil {
			deployBuilder.WithResources(cluster.Spec.Dashboard.Resources)
		}
		deployBuilder.WithEnableSSL(cluster.Spec.Dashboard.EnableSSL)
		// Drive run_as from the Wazuh plugin API endpoint config so changing it
		// rolls out the dashboard and regenerates the effective wazuh.yml.
		if wp := cluster.Spec.Dashboard.WazuhPlugin; wp != nil {
			runAs := false
			if len(wp.APIEndpoints) > 0 {
				runAs = wp.APIEndpoints[0].RunAs
			} else if wp.DefaultAPIEndpoint != nil {
				runAs = wp.DefaultAPIEndpoint.RunAs
			}
			deployBuilder.WithRunAs(runAs)
		}
		if cluster.Spec.Dashboard.Image != nil {
			if cluster.Spec.Dashboard.Image.PullPolicy != "" {
				deployBuilder.WithImagePullPolicy(cluster.Spec.Dashboard.Image.PullPolicy)
			}
			dashboardImage := cluster.Spec.Dashboard.Image.ResolveImage(constants.DefaultWazuhDashboardImage, cluster.Spec.Version)
			if dashboardImage != "" {
				deployBuilder.WithImage(dashboardImage)
			}
		}
		if len(cluster.Spec.Dashboard.Annotations) > 0 {
			deployBuilder.WithAnnotations(cluster.Spec.Dashboard.Annotations)
		}
		if len(cluster.Spec.Dashboard.PodAnnotations) > 0 {
			deployBuilder.WithPodAnnotations(cluster.Spec.Dashboard.PodAnnotations)
		}
		if cluster.Spec.Dashboard.NodeSelector != nil {
			deployBuilder.WithNodeSelector(cluster.Spec.Dashboard.NodeSelector)
		}
		if cluster.Spec.Dashboard.Tolerations != nil {
			deployBuilder.WithTolerations(cluster.Spec.Dashboard.Tolerations)
		}
		if cluster.Spec.Dashboard.Affinity != nil {
			deployBuilder.WithAffinity(cluster.Spec.Dashboard.Affinity)
		}
		if len(cluster.Spec.Dashboard.TopologySpreadConstraints) > 0 {
			deployBuilder.WithTopologySpreadConstraints(cluster.Spec.Dashboard.TopologySpreadConstraints)
		}
		if len(cluster.Spec.Dashboard.Env) > 0 {
			deployBuilder.WithEnv(cluster.Spec.Dashboard.Env)
		}
		if len(cluster.Spec.Dashboard.EnvFrom) > 0 {
			deployBuilder.WithEnvFrom(cluster.Spec.Dashboard.EnvFrom)
		}
		if len(cluster.Spec.Dashboard.ExtraVolumes) > 0 {
			deployBuilder.WithVolumes(cluster.Spec.Dashboard.ExtraVolumes)
		}
		if len(cluster.Spec.Dashboard.ExtraVolumeMounts) > 0 {
			deployBuilder.WithVolumeMounts(cluster.Spec.Dashboard.ExtraVolumeMounts)
		}
		if len(cluster.Spec.Dashboard.ExtraInitContainers) > 0 {
			deployBuilder.WithExtraInitContainers(cluster.Spec.Dashboard.ExtraInitContainers)
		}
		if len(cluster.Spec.Dashboard.ExtraContainers) > 0 {
			deployBuilder.WithExtraContainers(cluster.Spec.Dashboard.ExtraContainers)
		}
		if cluster.Spec.Dashboard.SecurityContext != nil {
			deployBuilder.WithSecurityContext(cluster.Spec.Dashboard.SecurityContext)
		}
		if cluster.Spec.Dashboard.ContainerSecurityContext != nil {
			deployBuilder.WithContainerSecurityContext(cluster.Spec.Dashboard.ContainerSecurityContext)
		}
	}

	// Set image pull secrets (cluster-level)
	if len(cluster.Spec.ImagePullSecrets) > 0 {
		deployBuilder.WithImagePullSecrets(cluster.Spec.ImagePullSecrets)
	}

	// Set cert hash to trigger pod restart on cert renewal
	if certHash != "" {
		deployBuilder.WithCertHash(certHash)
	}

	// Set termination grace period (default + user override)
	terminationGracePeriod := constants.DefaultDashboardTerminationGracePeriod
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.TerminationGracePeriodSeconds != nil {
		terminationGracePeriod = *cluster.Spec.Dashboard.TerminationGracePeriodSeconds
	}
	deployBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)

	// Reconcile and set ServiceAccount if configured
	var dashboardSAName string
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.ServiceAccount != nil {
		saName, saErr := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, cluster,
			cluster.Spec.Dashboard.ServiceAccount, cluster.Name, cluster.Namespace, "dashboard")
		if saErr != nil {
			return fmt.Errorf("failed to reconcile dashboard ServiceAccount: %w", saErr)
		}
		dashboardSAName = saName
	}
	if dashboardSAName != "" {
		deployBuilder.WithServiceAccountName(dashboardSAName)
	}

	// Compute spec hash for change detection
	specHash := ""
	if cluster.Spec.Dashboard != nil {
		var imagePullPolicy corev1.PullPolicy
		var image string
		if cluster.Spec.Dashboard.Image != nil {
			imagePullPolicy = cluster.Spec.Dashboard.Image.PullPolicy
			image = cluster.Spec.Dashboard.Image.ResolveImage(constants.DefaultWazuhDashboardImage, cluster.Spec.Version)
		}
		hash, err := patch.ComputeDashboardSpecHashFull(patch.DashboardSpecInput{
			Replicas:                      cluster.Spec.Dashboard.Replicas,
			Version:                       cluster.Spec.Version,
			Resources:                     cluster.Spec.Dashboard.Resources,
			Image:                         image,
			NodeSelector:                  cluster.Spec.Dashboard.NodeSelector,
			Tolerations:                   cluster.Spec.Dashboard.Tolerations,
			Affinity:                      cluster.Spec.Dashboard.Affinity,
			ImagePullSecrets:              cluster.Spec.ImagePullSecrets,
			TopologySpreadConstraints:     cluster.Spec.Dashboard.TopologySpreadConstraints,
			Env:                           cluster.Spec.Dashboard.Env,
			EnvFrom:                       cluster.Spec.Dashboard.EnvFrom,
			Annotations:                   cluster.Spec.Dashboard.Annotations,
			PodAnnotations:                cluster.Spec.Dashboard.PodAnnotations,
			ExtraVolumes:                  cluster.Spec.Dashboard.ExtraVolumes,
			ExtraVolumeMounts:             cluster.Spec.Dashboard.ExtraVolumeMounts,
			ExtraInitContainers:           cluster.Spec.Dashboard.ExtraInitContainers,
			ExtraContainers:               cluster.Spec.Dashboard.ExtraContainers,
			ServiceAccountName:            dashboardSAName,
			SecurityContext:               cluster.Spec.Dashboard.SecurityContext,
			ContainerSecurityContext:      cluster.Spec.Dashboard.ContainerSecurityContext,
			TerminationGracePeriodSeconds: cluster.Spec.Dashboard.TerminationGracePeriodSeconds,
			ImagePullPolicy:               imagePullPolicy,
			EnableSSL:                     cluster.Spec.Dashboard.EnableSSL,
		})
		if err != nil {
			log.Error(err, "Failed to compute dashboard spec hash, continuing without spec tracking")
		} else {
			specHash = hash
		}
	}
	if specHash != "" {
		deployBuilder.WithSpecHash(specHash)
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster)
	if configHash != "" {
		deployBuilder.WithConfigHash(configHash)
	}

	deployment := deployBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, deployment, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard deployment: %w", err)
	}

	found := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard Deployment", "name", deployment.Name, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, deployment); err != nil {
			return fmt.Errorf("failed to create dashboard deployment: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard deployment: %w", err)
	}

	// Check if update is needed (cert hash, spec hash, or replicas changed)
	existingCertHash := ""
	existingSpecHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
		existingSpecHash = found.Spec.Template.Annotations[constants.AnnotationSpecHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	certHashChanged := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Dashboard Deployment due to certificate hash change",
				"name", deployment.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
			certHashChanged = true
		}
	}

	// Check if spec hash changed (detects all CRD spec field changes)
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Updating Dashboard Deployment due to spec change",
			"name", deployment.Name,
			"oldSpecHash", utils.ShortHash(existingSpecHash),
			"newSpecHash", utils.ShortHash(specHash))
		needsUpdate = true
	}

	// Check if replicas changed
	var desiredReplicas int32
	if cluster.Spec.Dashboard != nil {
		desiredReplicas = cluster.Spec.Dashboard.Replicas
	}
	if found.Spec.Replicas != nil && *found.Spec.Replicas != desiredReplicas {
		log.Info("Updating Dashboard Deployment due to replica count change",
			"name", deployment.Name,
			"oldReplicas", *found.Spec.Replicas,
			"newReplicas", desiredReplicas)
		direction := "up"
		if desiredReplicas < *found.Spec.Replicas {
			direction = "down"
		}
		metrics.RecordScaleOperation(cluster.Name, cluster.Namespace, "dashboard", direction)
		needsUpdate = true
	}

	if needsUpdate {
		if err := r.updateDeploymentWithRetry(ctx, deployment); err != nil {
			recreated, recErr := utils.RecreateDeploymentOnError(ctx, r.Client, r.Recorder, deployment, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update dashboard deployment: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update dashboard deployment: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted Deployment %s/%s due to immutable field change; re-creation on next reconciliation", deployment.Namespace, deployment.Name))
			}
			return fmt.Errorf("deployment %s/%s deleted for immutable field recreation", deployment.Namespace, deployment.Name)
		}

		// Only wait for rollout on cert hash changes (pod restart required)
		// Replica changes don't need rollout wait - Kubernetes handles scaling
		if certHashChanged {
			log.Info("Waiting for Dashboard deployment to be ready after certificate renewal",
				"name", deployment.Name,
				"timeout", utils.DefaultRolloutTimeout)

			waiter := utils.NewRolloutWaiter(r.Client)
			result := waiter.WaitForDeploymentReadyWithResult(ctx, deployment.Namespace, deployment.Name)
			if result.TimedOut {
				log.Error(result.Error, "Timeout waiting for Dashboard deployment to be ready",
					"name", deployment.Name,
					"timeout", utils.DefaultRolloutTimeout)
				// Don't fail the reconcile on timeout - the deployment strategy ensures
				// maxUnavailable=0, so old pods are kept until new ones are ready
				return nil
			}
			if result.Error != nil {
				return fmt.Errorf("error waiting for dashboard deployment to be ready: %w", result.Error)
			}

			log.Info("Dashboard deployment is ready after certificate renewal", "name", deployment.Name)
		}
	}

	return nil
}

// reconcilePDB reconciles the PodDisruptionBudget for dashboard pods
func (r *DashboardReconciler) reconcilePDB(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	pdbName := pdb.GetPDBName(cluster.Name)

	// Check if PDB should exist
	if !pdb.ShouldCreatePDB(cluster) {
		// If PDB should not exist, delete it if it does
		existing := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Dashboard PDB (no longer needed)", "name", pdbName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete dashboard PDB: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get dashboard PDB: %w", err)
		}
		return nil
	}

	// Build the PDB
	builder := pdb.NewDashboardPDBBuilder(cluster)
	dashboardPDB := builder.Build()

	if err := controllerutil.SetControllerReference(cluster, dashboardPDB, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard PDB: %w", err)
	}

	// Check if PDB exists
	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard PDB", "name", pdbName)
		if err := r.Create(ctx, dashboardPDB); err != nil {
			return fmt.Errorf("failed to create dashboard PDB: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard PDB: %w", err)
	}

	// Skip update if nothing changed
	if apiequality.Semantic.DeepEqual(existing.Spec, dashboardPDB.Spec) &&
		mapsEqualStr(existing.Labels, dashboardPDB.Labels) {
		return nil
	}

	// Update PDB
	dashboardPDB.SetResourceVersion(existing.GetResourceVersion())
	log.V(1).Info("Updating Dashboard PDB", "name", pdbName)
	if err := r.Update(ctx, dashboardPDB); err != nil {
		return fmt.Errorf("failed to update dashboard PDB: %w", err)
	}

	return nil
}

// reconcileHPA reconciles the HorizontalPodAutoscaler for dashboard
func (r *DashboardReconciler) reconcileHPA(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	hpaName := cluster.Name + "-dashboard"

	// Check if HPA should be enabled
	hpaEnabled := cluster.Spec.Dashboard != nil &&
		cluster.Spec.Dashboard.HPA != nil &&
		cluster.Spec.Dashboard.HPA.Enabled

	if !hpaEnabled {
		// If HPA should not exist, delete it if it does
		existing := &autoscalingv2.HorizontalPodAutoscaler{}
		err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Dashboard HPA (no longer needed)", "name", hpaName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete dashboard HPA: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get dashboard HPA: %w", err)
		}
		return nil
	}

	// Build the HPA
	builder := hpa.NewDashboardHPABuilder(cluster.Name, cluster.Namespace).
		WithSpec(cluster.Spec.Dashboard.HPA)

	dashboardHPA := builder.Build()
	if dashboardHPA == nil {
		return nil
	}

	if err := controllerutil.SetControllerReference(cluster, dashboardHPA, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard HPA: %w", err)
	}

	// Check if HPA exists
	existing := &autoscalingv2.HorizontalPodAutoscaler{}
	err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard HPA", "name", hpaName,
			"minReplicas", *dashboardHPA.Spec.MinReplicas,
			"maxReplicas", dashboardHPA.Spec.MaxReplicas)
		if err := r.Create(ctx, dashboardHPA); err != nil {
			return fmt.Errorf("failed to create dashboard HPA: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard HPA: %w", err)
	}

	// Skip update if nothing changed
	if apiequality.Semantic.DeepEqual(existing.Spec, dashboardHPA.Spec) &&
		mapsEqualStr(existing.Labels, dashboardHPA.Labels) {
		return nil
	}

	// Update HPA
	dashboardHPA.SetResourceVersion(existing.GetResourceVersion())
	log.V(1).Info("Updating Dashboard HPA", "name", hpaName)
	if err := r.Update(ctx, dashboardHPA); err != nil {
		return fmt.Errorf("failed to update dashboard HPA: %w", err)
	}

	return nil
}

// ReconcileWithCertHash reconciles the OpenSearch Dashboard with certificate hash for pod restart.
//
// Deprecated: Use ReconcileNonBlocking for non-blocking rollouts.
func (r *DashboardReconciler) ReconcileWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard secrets: %w", err)
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard configmap: %w", err)
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard service: %w", err)
	}

	// Reconcile Deployment with cert hash
	if err := r.reconcileDeploymentWithCertHash(ctx, cluster, certHash); err != nil {
		return fmt.Errorf("failed to reconcile dashboard deployment: %w", err)
	}

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard PDB: %w", err)
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard HPA: %w", err)
	}

	log.Info("Dashboard reconciliation completed")
	return nil
}

// DashboardReconcileResult contains the result of dashboard reconciliation
type DashboardReconcileResult struct {
	// PendingRollout contains a rollout that was initiated but not yet complete
	PendingRollout *utils.PendingRollout
	// Error if any occurred during reconciliation
	Error error
}

// ReconcileNonBlocking reconciles the OpenSearch Dashboard without blocking on rollouts
// Returns a pending rollout that should be tracked and monitored by the caller
func (r *DashboardReconciler) ReconcileNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) DashboardReconcileResult {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard secrets: %w", err)}
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard configmap: %w", err)}
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard service: %w", err)}
	}

	// Reconcile Deployment with cert hash (non-blocking)
	pendingRollout, err := r.reconcileDeploymentNonBlocking(ctx, cluster, certHash)
	if err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard deployment: %w", err)}
	}

	// Ensure the dashboard's API user allows run_as impersonation to match the
	// configured runAs (best-effort; does not block reconciliation).
	r.ensureAPIUserRunAs(ctx, cluster)

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard PDB: %w", err)}
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard HPA: %w", err)}
	}

	log.Info("Dashboard reconciliation completed (non-blocking)", "hasPendingRollout", pendingRollout != nil)
	return DashboardReconcileResult{PendingRollout: pendingRollout}
}

// reconcileDeploymentNonBlocking reconciles the dashboard Deployment without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *DashboardReconciler) reconcileDeploymentNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	var (
		replicas                      int32
		version                       = cluster.Spec.Version
		resources                     *corev1.ResourceRequirements
		image                         string
		nodeSelector                  map[string]string
		tolerations                   []corev1.Toleration
		affinity                      *corev1.Affinity
		topologySpreadConstraints     []corev1.TopologySpreadConstraint
		env                           []corev1.EnvVar
		envFrom                       []corev1.EnvFromSource
		annotations                   map[string]string
		podAnnotations                map[string]string
		securityContext               *corev1.PodSecurityContext
		containerSecurityContext      *corev1.SecurityContext
		terminationGracePeriodSeconds *int64
		imagePullPolicy               corev1.PullPolicy
	)
	imagePullSecrets := cluster.Spec.ImagePullSecrets

	if cluster.Spec.Dashboard != nil {
		replicas = cluster.Spec.Dashboard.Replicas
		resources = cluster.Spec.Dashboard.Resources
		nodeSelector = cluster.Spec.Dashboard.NodeSelector
		tolerations = cluster.Spec.Dashboard.Tolerations
		affinity = cluster.Spec.Dashboard.Affinity
		topologySpreadConstraints = cluster.Spec.Dashboard.TopologySpreadConstraints
		env = cluster.Spec.Dashboard.Env
		envFrom = cluster.Spec.Dashboard.EnvFrom
		annotations = cluster.Spec.Dashboard.Annotations
		podAnnotations = cluster.Spec.Dashboard.PodAnnotations
		securityContext = cluster.Spec.Dashboard.SecurityContext
		containerSecurityContext = cluster.Spec.Dashboard.ContainerSecurityContext
		terminationGracePeriodSeconds = cluster.Spec.Dashboard.TerminationGracePeriodSeconds
		if cluster.Spec.Dashboard.Image != nil {
			image = cluster.Spec.Dashboard.Image.ResolveImage(constants.DefaultWazuhDashboardImage, cluster.Spec.Version)
			if cluster.Spec.Dashboard.Image.PullPolicy != "" {
				imagePullPolicy = cluster.Spec.Dashboard.Image.PullPolicy
			}
		}
	}

	// Extract extra volumes, init containers, and sidecar containers
	var extraVolumes []corev1.Volume
	var extraVolumeMounts []corev1.VolumeMount
	var extraInitContainers []corev1.Container
	var extraContainers []corev1.Container
	if cluster.Spec.Dashboard != nil {
		extraVolumes = cluster.Spec.Dashboard.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Dashboard.ExtraVolumeMounts
		extraInitContainers = cluster.Spec.Dashboard.ExtraInitContainers
		extraContainers = cluster.Spec.Dashboard.ExtraContainers
	}

	// Reconcile ServiceAccount if configured
	var dashboardSAName string
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.ServiceAccount != nil {
		saName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, cluster,
			cluster.Spec.Dashboard.ServiceAccount, cluster.Name, cluster.Namespace, "dashboard")
		if err != nil {
			return nil, fmt.Errorf("failed to reconcile dashboard ServiceAccount: %w", err)
		}
		dashboardSAName = saName
	}

	// Extract enableSSL before hash computation (defaults to true via kubebuilder)
	enableSSL := true
	if cluster.Spec.Dashboard != nil {
		enableSSL = cluster.Spec.Dashboard.EnableSSL
	}

	// Extract run_as from the Wazuh plugin API endpoint config. Included in the
	// spec hash so toggling it rolls out the dashboard, and passed to the
	// builder as the RUN_AS env consumed by wazuh_app_config.sh.
	runAs := false
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.WazuhPlugin != nil {
		wp := cluster.Spec.Dashboard.WazuhPlugin
		if len(wp.APIEndpoints) > 0 {
			runAs = wp.APIEndpoints[0].RunAs
		} else if wp.DefaultAPIEndpoint != nil {
			runAs = wp.DefaultAPIEndpoint.RunAs
		}
	}

	// Compute spec hash for change detection (includes all configurable fields)
	specHash, err := patch.ComputeDashboardSpecHashFull(patch.DashboardSpecInput{
		Replicas:                      replicas,
		Version:                       version,
		Resources:                     resources,
		Image:                         image,
		NodeSelector:                  nodeSelector,
		Tolerations:                   tolerations,
		Affinity:                      affinity,
		ImagePullSecrets:              imagePullSecrets,
		TopologySpreadConstraints:     topologySpreadConstraints,
		Env:                           env,
		EnvFrom:                       envFrom,
		Annotations:                   annotations,
		PodAnnotations:                podAnnotations,
		ExtraVolumes:                  extraVolumes,
		ExtraVolumeMounts:             extraVolumeMounts,
		ExtraInitContainers:           extraInitContainers,
		ExtraContainers:               extraContainers,
		ServiceAccountName:            dashboardSAName,
		SecurityContext:               securityContext,
		ContainerSecurityContext:      containerSecurityContext,
		TerminationGracePeriodSeconds: terminationGracePeriodSeconds,
		ImagePullPolicy:               imagePullPolicy,
		EnableSSL:                     enableSSL,
		RunAs:                         runAs,
	})
	if err != nil {
		log.Error(err, "Failed to compute dashboard spec hash, continuing without spec tracking")
		specHash = ""
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster)

	deployBuilder := deployments.NewDashboardDeploymentBuilder(cluster.Name, cluster.Namespace)
	deployBuilder.WithEnableSSL(enableSSL)
	deployBuilder.WithRunAs(runAs)
	if imagePullPolicy != "" {
		deployBuilder.WithImagePullPolicy(imagePullPolicy)
	}

	if cluster.Spec.Version != "" {
		deployBuilder.WithVersion(cluster.Spec.Version)
	}

	if replicas > 0 {
		deployBuilder.WithReplicas(replicas)
	}
	if resources != nil {
		deployBuilder.WithResources(resources)
	}
	if nodeSelector != nil {
		deployBuilder.WithNodeSelector(nodeSelector)
	}
	if tolerations != nil {
		deployBuilder.WithTolerations(tolerations)
	}
	if affinity != nil {
		deployBuilder.WithAffinity(affinity)
	}
	if len(topologySpreadConstraints) > 0 {
		deployBuilder.WithTopologySpreadConstraints(topologySpreadConstraints)
	}
	if len(imagePullSecrets) > 0 {
		deployBuilder.WithImagePullSecrets(imagePullSecrets)
	}
	if len(env) > 0 {
		deployBuilder.WithEnv(env)
	}
	if len(envFrom) > 0 {
		deployBuilder.WithEnvFrom(envFrom)
	}
	if len(annotations) > 0 {
		deployBuilder.WithAnnotations(annotations)
	}
	if len(podAnnotations) > 0 {
		deployBuilder.WithPodAnnotations(podAnnotations)
	}

	// Wire extra volumes, init containers, and sidecar containers
	if len(extraVolumes) > 0 {
		deployBuilder.WithVolumes(extraVolumes)
	}
	if len(extraVolumeMounts) > 0 {
		deployBuilder.WithVolumeMounts(extraVolumeMounts)
	}
	if len(extraInitContainers) > 0 {
		deployBuilder.WithExtraInitContainers(extraInitContainers)
	}
	if len(extraContainers) > 0 {
		deployBuilder.WithExtraContainers(extraContainers)
	}

	// Set image override from CRD
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Image != nil {
		dashboardImage := cluster.Spec.Dashboard.Image.ResolveImage(constants.DefaultWazuhDashboardImage, cluster.Spec.Version)
		if dashboardImage != "" {
			deployBuilder.WithImage(dashboardImage)
		}
	}
	// Set security context overrides
	if securityContext != nil {
		deployBuilder.WithSecurityContext(securityContext)
	}
	if containerSecurityContext != nil {
		deployBuilder.WithContainerSecurityContext(containerSecurityContext)
	}
	// Set termination grace period
	dashboardTerminationGracePeriod := constants.DefaultDashboardTerminationGracePeriod
	if terminationGracePeriodSeconds != nil {
		dashboardTerminationGracePeriod = *terminationGracePeriodSeconds
	}
	deployBuilder.WithTerminationGracePeriodSeconds(&dashboardTerminationGracePeriod)

	if certHash != "" {
		deployBuilder.WithCertHash(certHash)
	}

	// Set ServiceAccount name if configured
	if dashboardSAName != "" {
		deployBuilder.WithServiceAccountName(dashboardSAName)
	}

	// Set spec hash for change detection
	if specHash != "" {
		deployBuilder.WithSpecHash(specHash)
	}

	// Set config hash to trigger pod restart on config changes
	if configHash != "" {
		deployBuilder.WithConfigHash(configHash)
	}

	deployment := deployBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, deployment, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for dashboard deployment: %w", err)
	}

	found := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard Deployment", "name", deployment.Name, "certHash", utils.ShortHash(certHash), "specHash", utils.ShortHash(specHash))
		if err := r.Create(ctx, deployment); err != nil {
			return nil, fmt.Errorf("failed to create dashboard deployment: %w", err)
		}
		// New Deployment - return pending rollout to track initial readiness
		return &utils.PendingRollout{
			Component: "dashboard",
			Namespace: deployment.Namespace,
			Name:      deployment.Name,
			Type:      utils.RolloutTypeDeployment,
			StartTime: time.Now(),
			Reason:    "initial-creation",
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get dashboard deployment: %w", err)
	}

	// Check if update is needed
	needsUpdate := false
	updateReason := ""

	// Get existing hashes from annotations
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}
	existingSpecHash := ""
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	// Check spec hash (version, resources, replicas changes)
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Dashboard spec changed",
			"name", deployment.Name,
			"oldSpecHash", utils.ShortHash(existingSpecHash),
			"newSpecHash", utils.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Record spec hash change metric
		metrics.RecordSpecHashChange(cluster.Name, cluster.Namespace, "dashboard")
		metrics.RecordPatchDetection(cluster.Name, cluster.Namespace, "dashboard", "spec-change")

		// Emit Kubernetes event for spec change
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Dashboard spec changed (version=%s, replicas=%d)", version, replicas))
		}
	}
	if !apiequality.Semantic.DeepEqual(found.Spec.Template.Spec.Tolerations, deployment.Spec.Template.Spec.Tolerations) {
		log.Info("Dashboard tolerations changed", "name", deployment.Name)
		needsUpdate = true
		if updateReason == "" {
			updateReason = "tolerations-change"
		} else {
			updateReason += ",tolerations-change"
		}
	}
	if !apiequality.Semantic.DeepEqual(found.Spec.Template.Spec.Affinity, deployment.Spec.Template.Spec.Affinity) {
		log.Info("Dashboard affinity changed", "name", deployment.Name)
		needsUpdate = true
		if updateReason == "" {
			updateReason = "affinity-change"
		} else {
			updateReason += ",affinity-change"
		}
	}

	// Check cert hash (requires pod restart)
	if certHash != "" && certHash != existingCertHash {
		log.Info("Dashboard certificate hash changed",
			"name", deployment.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "certificate-renewal"
		} else {
			updateReason += ",certificate-renewal"
		}
	}

	// Check config hash (ConfigMap content changes)
	existingConfigHash := ""
	if found.Spec.Template.Annotations != nil {
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}

	if configHash != "" && configHash != existingConfigHash {
		log.Info("Dashboard ConfigMap hash changed",
			"name", deployment.Name,
			"oldConfigHash", utils.ShortHash(existingConfigHash),
			"newConfigHash", utils.ShortHash(configHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "config-change"
		} else {
			updateReason += ",config-change"
		}

		// Record config hash change metric
		metrics.RecordConfigHashChange(cluster.Name, cluster.Namespace, "dashboard")
		metrics.RecordPatchDetection(cluster.Name, cluster.Namespace, "dashboard", "config-change")

		// Emit event for config change detection
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "ConfigChanged",
				fmt.Sprintf("Dashboard ConfigMap changed, pods will restart (Deployment %s)", deployment.Name))
		}
	}

	if needsUpdate {
		log.Info("Updating Dashboard Deployment (non-blocking)",
			"name", deployment.Name,
			"reason", updateReason)

		if err := r.updateDeploymentWithRetry(ctx, deployment); err != nil {
			recreated, recErr := utils.RecreateDeploymentOnError(ctx, r.Client, r.Recorder, deployment, found, err)
			if recErr != nil {
				return nil, fmt.Errorf("failed to update dashboard deployment: %w", recErr)
			}
			if !recreated {
				return nil, fmt.Errorf("failed to update dashboard deployment: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted Deployment %s/%s due to immutable field change; re-creation on next reconciliation", deployment.Namespace, deployment.Name))
			}
			return nil, fmt.Errorf("deployment %s/%s deleted for immutable field recreation", deployment.Namespace, deployment.Name)
		}

		// Return pending rollout instead of waiting
		return &utils.PendingRollout{
			Component: "dashboard",
			Namespace: deployment.Namespace,
			Name:      deployment.Name,
			Type:      utils.RolloutTypeDeployment,
			StartTime: time.Now(),
			Reason:    updateReason,
		}, nil
	}

	return nil, nil
}

// GetStatus gets the dashboard status
func (r *DashboardReconciler) GetStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.ComponentStatus, error) {
	dep := &appsv1.Deployment{}
	name := constants.DashboardName(cluster.Name)

	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, dep); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// Get desired replicas from the spec
	var desiredReplicas int32
	if cluster.Spec.Dashboard != nil {
		desiredReplicas = cluster.Spec.Dashboard.Replicas
	}

	return &wazuhv1.ComponentStatus{
		Replicas:        dep.Status.Replicas,
		ReadyReplicas:   dep.Status.ReadyReplicas,
		DesiredReplicas: desiredReplicas,
		Phase:           getDeploymentPhase(dep),
	}, nil
}

// createOrUpdate creates or updates a resource
func (r *DashboardReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	key := types.NamespacedName{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	existing, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("failed to deep copy object")
	}

	err := r.Get(ctx, key, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}

	return utils.RetryOnConflict(ctx, func() error {
		current, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("failed to deep copy object")
		}

		if err := r.Get(ctx, key, current); err != nil {
			return err
		}

		// Preserve immutable fields for Services and skip no-op updates
		if svc, ok := obj.(*corev1.Service); ok {
			if currentSvc, ok := current.(*corev1.Service); ok {
				preserveServiceDefaults(svc, currentSvc)
				if apiequality.Semantic.DeepEqual(svc.Spec, currentSvc.Spec) &&
					mapsEqualStr(svc.Labels, currentSvc.Labels) &&
					mapsEqualStr(svc.Annotations, currentSvc.Annotations) {
					return nil
				}
			}
		}

		// Skip no-op updates for ConfigMaps
		if cm, ok := obj.(*corev1.ConfigMap); ok {
			if currentCM, ok := current.(*corev1.ConfigMap); ok {
				if mapsEqualStr(cm.Data, currentCM.Data) &&
					mapsEqualStr(cm.Labels, currentCM.Labels) &&
					mapsEqualStr(cm.Annotations, currentCM.Annotations) {
					return nil
				}
			}
		}

		// Skip no-op updates for Secrets
		if sec, ok := obj.(*corev1.Secret); ok {
			if currentSec, ok := current.(*corev1.Secret); ok {
				if mapsEqualBytes(sec.Data, currentSec.Data) &&
					mapsEqualStr(sec.Labels, currentSec.Labels) &&
					mapsEqualStr(sec.Annotations, currentSec.Annotations) {
					return nil
				}
			}
		}

		log.V(1).Info("Updating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		obj.SetResourceVersion(current.GetResourceVersion())
		return r.Update(ctx, obj)
	})
}

// updateDeploymentWithRetry updates a Deployment with retry-on-conflict.
// It merges mutable fields from desired into the current server object rather than
// doing a full PUT replacement, which avoids issues with server-defaulted fields
// causing silent update failures.
func (r *DashboardReconciler) updateDeploymentWithRetry(ctx context.Context, desired *appsv1.Deployment) error {
	return utils.RetryOnConflict(ctx, func() error {
		current := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, current); err != nil {
			return err
		}
		patch.MergeDeploymentUpdate(current, desired)
		return r.Update(ctx, current)
	})
}

// getDeploymentPhase returns the phase of a Deployment
func getDeploymentPhase(dep *appsv1.Deployment) wazuhv1.ComponentStatusPhase {
	if dep.Status.ReadyReplicas == 0 {
		return wazuhv1.ComponentStatusPhaseStarting
	}
	if dep.Status.ReadyReplicas < dep.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseDegraded
	}
	if dep.Status.UpdatedReplicas < dep.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseScaling
	}
	return wazuhv1.ComponentStatusPhaseReady
}

// ensureAPIUserRunAs sets allow_run_as on the dashboard's Wazuh API user to
// match the configured runAs, so the run_as auth-context flow works without
// manual intervention. Best-effort: any failure (API unavailable, user not
// found) is logged and never blocks dashboard reconciliation.
func (r *DashboardReconciler) ensureAPIUserRunAs(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	if cluster.Spec.Dashboard == nil || cluster.Spec.Dashboard.WazuhPlugin == nil {
		return
	}
	wp := cluster.Spec.Dashboard.WazuhPlugin
	runAs := false
	if len(wp.APIEndpoints) > 0 {
		runAs = wp.APIEndpoints[0].RunAs
	} else if wp.DefaultAPIEndpoint != nil {
		runAs = wp.DefaultAPIEndpoint.RunAs
	}

	// The dashboard authenticates to the Manager API with the operator-managed
	// API credentials secret (same as the API_USERNAME/API_PASSWORD env vars).
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: constants.APICredentialsName(cluster.Name), Namespace: cluster.Namespace}, secret); err != nil {
		log.V(1).Info("Skipping allow_run_as: cannot read API credentials secret", "error", err)
		return
	}
	username := string(secret.Data[constants.SecretKeyAPIUsername])
	password := string(secret.Data[constants.SecretKeyAPIPassword])
	if username == "" || password == "" {
		log.V(1).Info("Skipping allow_run_as: API credentials secret missing username/password")
		return
	}

	baseURL := fmt.Sprintf("https://%s:%d", constants.ManagerMasterServiceFQDN(cluster.Name, cluster.Namespace), constants.PortManagerAPI)
	apiClient := adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Insecure: true,
	})
	if !apiClient.IsHealthy(ctx) {
		log.V(1).Info("Skipping allow_run_as: Wazuh API not reachable yet")
		return
	}

	id, err := apiClient.GetUserByName(ctx, username)
	if err != nil || id == 0 {
		log.V(1).Info("Skipping allow_run_as: API user not resolved", "user", username, "error", err)
		return
	}
	if err := apiClient.SetUserRunAs(ctx, id, runAs); err != nil {
		log.Info("Failed to set allow_run_as on dashboard API user (best-effort)", "user", username, "runAs", runAs, "error", err)
		return
	}
	log.V(1).Info("Ensured dashboard API user allow_run_as", "user", username, "allowRunAs", runAs)
}
