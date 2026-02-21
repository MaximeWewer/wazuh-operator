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

// Package reconciler provides helper reconcilers for OpenSearch components
package reconciler

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/crypto/bcrypt"

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

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	opensearchcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/opensearch"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/hpa"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/secrets"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/drain"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	affinityutil "github.com/MaximeWewer/wazuh-operator/internal/shared/affinity"
	drainstate "github.com/MaximeWewer/wazuh-operator/internal/shared/drain"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/serviceaccount"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/storage"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerReconciler handles reconciliation of OpenSearch Indexer
type IndexerReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	Recorder              record.EventRecorder
	ClientFactory         *security.OpenSearchClientFactory
	SecurityAdminExecutor *security.SecurityAdminExecutor

	// drainer handles indexer drain operations for safe scale-down
	drainer *drain.IndexerDrainerImpl
	// osClient is the OpenSearch API client for drain operations
	osClient *api.Client
}

// NewIndexerReconciler creates a new IndexerReconciler
func NewIndexerReconciler(c client.Client, scheme *runtime.Scheme) *IndexerReconciler {
	return &IndexerReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithClientFactory sets the shared OpenSearch client factory
func (r *IndexerReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *IndexerReconciler {
	r.ClientFactory = factory
	return r
}

// WithSecurityAdminExecutor sets the SecurityAdminExecutor for credential recovery
func (r *IndexerReconciler) WithSecurityAdminExecutor(executor *security.SecurityAdminExecutor) *IndexerReconciler {
	r.SecurityAdminExecutor = executor
	return r
}

// WithRecorder sets the event recorder
func (r *IndexerReconciler) WithRecorder(recorder record.EventRecorder) *IndexerReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the OpenSearch Indexer
func (r *IndexerReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "IndexerReconciler.Reconcile",
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

	// Detect topology mode
	isAdvancedMode := cluster.Spec.Indexer != nil && cluster.Spec.Indexer.IsAdvancedMode()

	// Reconcile Secrets (shared between both modes)
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer secrets: %w", err)
	}

	if isAdvancedMode {
		// Advanced topology mode: reconcile nodePools
		log.Info("Reconciling indexer in advanced topology mode", "nodePools", len(cluster.Spec.Indexer.NodePools))
		if err := r.reconcileAdvancedMode(ctx, cluster); err != nil {
			return err
		}
		// Reconcile PDB for advanced mode (covers all indexer pods across nodePools)
		if err := r.reconcileIndexerPDB(ctx, cluster); err != nil {
			return fmt.Errorf("failed to reconcile indexer PDB: %w", err)
		}
		// Collect OpenSearch metrics via API (non-blocking, best-effort)
		r.CollectOpenSearchMetrics(ctx, cluster)
		return nil
	}

	// Simple mode: original reconciliation logic
	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer configmap: %w", err)
	}

	// Reconcile Services
	if err := r.reconcileServices(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer services: %w", err)
	}

	// Reconcile StatefulSet
	if err := r.reconcileStatefulSet(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer statefulset: %w", err)
	}

	// Reconcile Volume Expansion (after StatefulSet to ensure PVCs exist)
	if err := r.reconcileVolumeExpansion(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer volume expansion: %w", err)
	}

	// Reconcile Cluster Settings (after cluster is running)
	if err := r.reconcileClusterSettings(ctx, cluster); err != nil {
		// Log warning but don't fail reconciliation - settings will be retried
		log.Error(err, "Failed to reconcile cluster settings, will retry")
	}

	// Reconcile PDB for simple mode
	if err := r.reconcileIndexerPDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer PDB: %w", err)
	}

	// Reconcile HPA for simple mode (if enabled)
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer HPA: %w", err)
	}

	// Reconcile Security Init Job (ensures internal users are synced)
	if err := r.reconcileSecurityInitJob(ctx, cluster); err != nil {
		// Log warning but don't fail - security init will be retried
		log.Error(err, "Failed to reconcile security init job, will retry")
	}

	// Collect OpenSearch metrics via API (non-blocking, best-effort)
	r.CollectOpenSearchMetrics(ctx, cluster)

	log.Info("Indexer reconciliation completed")
	return nil
}

// reconcileSecrets reconciles indexer secrets (certs, credentials, security config)
func (r *IndexerReconciler) reconcileSecrets(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if certificates already exist
	certsSecretName := fmt.Sprintf("%s-indexer-certs", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Generate new certificates
		certs, err := r.generateIndexerCertificates(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to generate indexer certificates: %w", err)
		}

		certsBuilder := opensearchcerts.NewIndexerCertsSecretBuilder(cluster.Name, cluster.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithNodeCert(certs.nodeCert).
			WithNodeKey(certs.nodeKey).
			WithAdminCert(certs.adminCert).
			WithAdminKey(certs.adminKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(cluster, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for indexer certs: %w", err)
		}

		log.Info("Creating Indexer certificates secret", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create indexer certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get indexer certs secret: %w", err)
	}

	// Get admin credentials - either from external secret reference or generate
	var adminUsername, adminPassword string
	adminUsername = constants.DefaultOpenSearchAdminUsername // default username

	// Check if external credentials are provided via secretRef
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Credentials != nil && cluster.Spec.Indexer.Credentials.SecretName != "" {
		// Read credentials from the referenced secret
		credentialsRef := cluster.Spec.Indexer.Credentials
		externalSecret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: credentialsRef.SecretName, Namespace: cluster.Namespace}, externalSecret)
		if err != nil {
			return fmt.Errorf("failed to get external credentials secret %s: %w", credentialsRef.SecretName, err)
		}

		// Get username (default key: "username")
		usernameKey := credentialsRef.UsernameKey
		if usernameKey == "" {
			usernameKey = "username"
		}
		if usernameBytes, ok := externalSecret.Data[usernameKey]; ok {
			adminUsername = string(usernameBytes)
		}

		// Get password (default key: "password")
		passwordKey := credentialsRef.PasswordKey
		if passwordKey == "" {
			passwordKey = "password"
		}
		if passwordBytes, ok := externalSecret.Data[passwordKey]; ok {
			adminPassword = string(passwordBytes)
		} else {
			return fmt.Errorf("password key %s not found in secret %s", passwordKey, credentialsRef.SecretName)
		}

		log.Info("Using external credentials from secret", "secretName", credentialsRef.SecretName, "username", adminUsername)
	}

	// Credentials secret for dashboard and other components - create this FIRST
	// so we can use the same password for the security config
	credsSecretName := fmt.Sprintf("%s-indexer-credentials", cluster.Name)
	existingCreds := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: credsSecretName, Namespace: cluster.Namespace}, existingCreds)
	if err != nil && errors.IsNotFound(err) {
		// If no external credentials provided, generate a random password
		if adminPassword == "" {
			var err error
			adminPassword, err = utils.GenerateRandomPassword(24)
			if err != nil {
				return fmt.Errorf("failed to generate admin password: %w", err)
			}
		}
		credsBuilder := secrets.NewIndexerCredentialsSecretBuilder(cluster.Name, cluster.Namespace)
		credsBuilder.WithAdminCredentials(adminUsername, adminPassword)
		credsSecret := credsBuilder.Build()

		if err := controllerutil.SetControllerReference(cluster, credsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for indexer credentials: %w", err)
		}

		log.Info("Creating Indexer credentials secret", "name", credsSecret.Name)
		if err := r.Create(ctx, credsSecret); err != nil {
			return fmt.Errorf("failed to create indexer credentials secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get indexer credentials secret: %w", err)
	} else if adminPassword == "" {
		// Get existing password from credentials secret (but prefer external if specified)
		adminPassword = string(existingCreds.Data[constants.SecretKeyAdminPassword])
	}

	// Security config secret with default configurations
	// Uses the same password as credentials secret
	securitySecretName := fmt.Sprintf("%s-indexer-security", cluster.Name)
	err = r.Get(ctx, types.NamespacedName{Name: securitySecretName, Namespace: cluster.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Build admin DN from TLS config for roles mapping
		adminDN := certificates.DefaultAdminDN()
		if cluster.Spec.TLS != nil && cluster.Spec.TLS.CertConfig != nil {
			cfg := cluster.Spec.TLS.CertConfig
			dnOpts := certificates.DNOptions{
				OrganizationalUnit: cfg.OrganizationalUnit,
				Organization:       cfg.Organization,
				Locality:           cfg.Locality,
				State:              cfg.State,
				Country:            cfg.Country,
			}
			adminDN = certificates.AdminDN(dnOpts)
		}

		securityBuilder := secrets.NewIndexerSecuritySecretBuilder(cluster.Name, cluster.Namespace)
		// Add default security configuration files with the SAME password as credentials
		securityBuilder.WithInternalUsers(generateDefaultInternalUsers(adminPassword))
		securityBuilder.WithRoles(generateDefaultRoles())
		securityBuilder.WithRolesMapping(generateDefaultRolesMapping(adminDN))
		securityBuilder.WithActionGroups(generateDefaultActionGroups())
		securityBuilder.WithTenants(generateDefaultTenants())
		securityBuilder.WithConfig(generateDefaultSecurityConfig())
		securitySecret := securityBuilder.Build()

		if err := controllerutil.SetControllerReference(cluster, securitySecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for indexer security: %w", err)
		}

		log.Info("Creating Indexer security secret", "name", securitySecret.Name)
		if err := r.Create(ctx, securitySecret); err != nil {
			return fmt.Errorf("failed to create indexer security secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get indexer security secret: %w", err)
	}

	return nil
}

// indexerCertificates holds all generated certificates for the indexer
type indexerCertificates struct {
	caCert    []byte
	nodeCert  []byte
	nodeKey   []byte
	adminCert []byte
	adminKey  []byte
}

// generateIndexerCertificates generates all certificates needed for the indexer
func (r *IndexerReconciler) generateIndexerCertificates(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*indexerCertificates, error) {
	log := logf.FromContext(ctx)

	// Build DN options from WazuhCluster TLS config
	var dnOpts *certificates.DNOptions
	if cluster.Spec.TLS != nil && cluster.Spec.TLS.CertConfig != nil {
		cfg := cluster.Spec.TLS.CertConfig
		dnOpts = &certificates.DNOptions{
			OrganizationalUnit: cfg.OrganizationalUnit,
			Organization:       cfg.Organization,
			Locality:           cfg.Locality,
			State:              cfg.State,
			Country:            cfg.Country,
		}
	}

	// Generate CA with DN options
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-indexer-ca", cluster.Name))
	if dnOpts != nil {
		if dnOpts.Country != "" {
			caConfig.Country = dnOpts.Country
		}
		if dnOpts.State != "" {
			caConfig.State = dnOpts.State
		}
		if dnOpts.Locality != "" {
			caConfig.Locality = dnOpts.Locality
		}
		if dnOpts.Organization != "" {
			caConfig.Organization = dnOpts.Organization
		}
		if dnOpts.OrganizationalUnit != "" {
			caConfig.OrganizationalUnit = dnOpts.OrganizationalUnit
		}
	}
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate")

	// Determine replicas for SANs
	replicas := int32(1)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		replicas = cluster.Spec.Indexer.Replicas
	}

	// Generate node certificate with SANs and DN options
	// CommonName is derived from the cluster name + component (not user-configurable)
	nodeConfig := certificates.DefaultNodeCertConfig(fmt.Sprintf("%s-indexer", cluster.Name))
	nodeConfig.DNSNames = certificates.GenerateIndexerNodeSANs(cluster.Name, cluster.Namespace, replicas)
	nodeConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	if dnOpts != nil {
		if dnOpts.Country != "" {
			nodeConfig.Country = dnOpts.Country
		}
		if dnOpts.State != "" {
			nodeConfig.State = dnOpts.State
		}
		if dnOpts.Locality != "" {
			nodeConfig.Locality = dnOpts.Locality
		}
		if dnOpts.Organization != "" {
			nodeConfig.Organization = dnOpts.Organization
		}
		if dnOpts.OrganizationalUnit != "" {
			nodeConfig.OrganizationalUnit = dnOpts.OrganizationalUnit
		}
	}

	nodeCert, err := certificates.GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node certificate: %w", err)
	}
	log.V(1).Info("Generated node certificate", "sans", nodeConfig.DNSNames)

	// Generate admin certificate with DN options
	// CommonName for admin cert is always "admin" (required by OpenSearch security plugin)
	adminConfig := certificates.DefaultAdminCertConfig()
	if dnOpts != nil {
		if dnOpts.Country != "" {
			adminConfig.Country = dnOpts.Country
		}
		if dnOpts.State != "" {
			adminConfig.State = dnOpts.State
		}
		if dnOpts.Locality != "" {
			adminConfig.Locality = dnOpts.Locality
		}
		if dnOpts.Organization != "" {
			adminConfig.Organization = dnOpts.Organization
		}
		if dnOpts.OrganizationalUnit != "" {
			adminConfig.OrganizationalUnit = dnOpts.OrganizationalUnit
		}
	}
	adminCert, err := certificates.GenerateAdminCert(adminConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin certificate: %w", err)
	}
	log.V(1).Info("Generated admin certificate")

	return &indexerCertificates{
		caCert:    ca.CertificatePEM,
		nodeCert:  nodeCert.CertificatePEM,
		nodeKey:   nodeCert.PrivateKeyPEM,
		adminCert: adminCert.CertificatePEM,
		adminKey:  adminCert.PrivateKeyPEM,
	}, nil
}

// reconcileConfigMap reconciles the indexer ConfigMap
func (r *IndexerReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	// Determine replicas
	replicas := int32(1)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		replicas = cluster.Spec.Indexer.Replicas
	}

	// Build DN options from WazuhCluster TLS config
	// Note: CommonName is not included as it's auto-generated per certificate type
	var dnOpts *certificates.DNOptions
	if cluster.Spec.TLS != nil && cluster.Spec.TLS.CertConfig != nil {
		cfg := cluster.Spec.TLS.CertConfig
		dnOpts = &certificates.DNOptions{
			OrganizationalUnit: cfg.OrganizationalUnit,
			Organization:       cfg.Organization,
			Locality:           cfg.Locality,
			State:              cfg.State,
			Country:            cfg.Country,
		}
	}

	// Prefer DN options derived from the actual indexer certificate when available.
	// This prevents nodes_dn mismatches after upgrades when defaults change.
	if optsFromCert, err := r.dnOptionsFromIndexerCertSecret(ctx, cluster.Name, cluster.Namespace); err == nil && optsFromCert != nil {
		dnOpts = optsFromCert
	}

	// Build opensearch.yml content (version-aware configuration with DN options)
	opensearchYML := config.BuildIndexerConfigWithDN(cluster.Name, cluster.Namespace, replicas, cluster.Spec.Version, dnOpts)

	configBuilder := configmaps.NewIndexerConfigMapBuilder(cluster.Name, cluster.Namespace)
	configBuilder.WithOpenSearchYML(opensearchYML)
	configMap := configBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer configmap: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// dnOptionsFromIndexerCertSecret extracts DN options from the indexer TLS cert secret.
func (r *IndexerReconciler) dnOptionsFromIndexerCertSecret(ctx context.Context, clusterName, namespace string) (*certificates.DNOptions, error) {
	secretName := constants.IndexerCertsName(clusterName)
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return nil, err
	}

	certPEM, ok := secret.Data[constants.SecretKeyTLSCert]
	if !ok || len(certPEM) == 0 {
		return nil, fmt.Errorf("tls.crt not found in secret %s", secretName)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || len(block.Bytes) == 0 {
		return nil, fmt.Errorf("failed to decode tls.crt from secret %s", secretName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tls.crt from secret %s: %w", secretName, err)
	}

	subject := cert.Subject
	opts := &certificates.DNOptions{}
	if len(subject.OrganizationalUnit) > 0 {
		opts.OrganizationalUnit = subject.OrganizationalUnit[0]
	}
	if len(subject.Organization) > 0 {
		opts.Organization = subject.Organization[0]
	}
	if len(subject.Locality) > 0 {
		opts.Locality = subject.Locality[0]
	}
	if len(subject.Province) > 0 {
		opts.State = subject.Province[0]
	}
	if len(subject.Country) > 0 {
		opts.Country = subject.Country[0]
	}

	return opts, nil
}

// getConfigHash retrieves the current config hash from the indexer ConfigMap
func (r *IndexerReconciler) getConfigHash(ctx context.Context, cluster *wazuhv1.WazuhCluster) string {
	configMapName := fmt.Sprintf("%s-indexer-config", cluster.Name)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// reconcileServices reconciles indexer services
func (r *IndexerReconciler) reconcileServices(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	serviceBuilder := services.NewIndexerServiceBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Service != nil {
		svcSpec := cluster.Spec.Indexer.Service
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

	// Regular service
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer service: %w", err)
	}

	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile indexer service: %w", err)
	}

	// Headless service
	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer headless service: %w", err)
	}

	return r.createOrUpdate(ctx, headlessService)
}

// reconcileStatefulSet reconciles the indexer StatefulSet
func (r *IndexerReconciler) reconcileStatefulSet(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	return r.reconcileStatefulSetWithCertHash(ctx, cluster, "")
}

// reconcileStatefulSetWithCertHash reconciles the indexer StatefulSet with an optional certificate hash
// When the cert hash changes, the StatefulSet will be updated which triggers a pod rollout
func (r *IndexerReconciler) reconcileStatefulSetWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	stsBuilder := deployments.NewIndexerStatefulSetBuilder(cluster.Name, cluster.Namespace)

	// Set the Wazuh version for the indexer image tag
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}

	if cluster.Spec.Indexer != nil {
		if cluster.Spec.Indexer.Replicas > 0 {
			stsBuilder.WithReplicas(cluster.Spec.Indexer.Replicas)
		}
		if cluster.Spec.Indexer.Resources != nil {
			stsBuilder.WithResources(cluster.Spec.Indexer.Resources)
		}
		if cluster.Spec.Indexer.StorageSize != "" {
			stsBuilder.WithStorageSize(cluster.Spec.Indexer.StorageSize)
		}
		if cluster.Spec.Indexer.StorageClass != nil && *cluster.Spec.Indexer.StorageClass != "" {
			stsBuilder.WithStorageClassName(*cluster.Spec.Indexer.StorageClass)
		} else if cluster.Spec.StorageClassName != nil && *cluster.Spec.StorageClassName != "" {
			stsBuilder.WithStorageClassName(*cluster.Spec.StorageClassName)
		}
		if cluster.Spec.Indexer.JavaOpts != "" {
			stsBuilder.WithJavaOpts(cluster.Spec.Indexer.JavaOpts)
		}
		if len(cluster.Spec.Indexer.Annotations) > 0 {
			stsBuilder.WithAnnotations(cluster.Spec.Indexer.Annotations)
		}
		if len(cluster.Spec.Indexer.PodAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(cluster.Spec.Indexer.PodAnnotations)
		}
	}

	// Set cert hash to trigger pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	// Set cluster reference for monitoring (Prometheus plugin and metrics)
	stsBuilder.WithCluster(cluster)

	// Set termination grace period (default + user override)
	terminationGracePeriod := constants.DefaultIndexerTerminationGracePeriod
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.TerminationGracePeriodSeconds != nil {
		terminationGracePeriod = *cluster.Spec.Indexer.TerminationGracePeriodSeconds
	}
	stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)

	// Set image pull policy if configured
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Image != nil && cluster.Spec.Indexer.Image.PullPolicy != "" {
		stsBuilder.WithImagePullPolicy(cluster.Spec.Indexer.Image.PullPolicy)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Indexer StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create indexer statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get indexer statefulset: %w", err)
	}

	// Check if recreation is needed due to immutable field changes (SecurityContext, PodManagementPolicy)
	needsRecreation, recreationReason := patch.NeedsStatefulSetRecreation(found, sts)
	if needsRecreation {
		log.Info("Indexer StatefulSet requires recreation due to immutable field change",
			"name", sts.Name,
			"reason", recreationReason)

		// Delete the old StatefulSet (PVCs will be preserved)
		if err := r.Delete(ctx, found); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete indexer statefulset for recreation: %w", err)
		}

		// Create the new StatefulSet
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create indexer statefulset after recreation: %w", err)
		}

		// Wait for the StatefulSet to be ready after recreation
		log.Info("Waiting for Indexer StatefulSet to be ready after recreation",
			"name", sts.Name,
			"timeout", utils.DefaultRolloutTimeout)

		waiter := utils.NewRolloutWaiter(r.Client)
		result := waiter.WaitForStatefulSetReadyWithResult(ctx, sts.Namespace, sts.Name)
		if result.TimedOut {
			log.Error(result.Error, "Timeout waiting for Indexer StatefulSet to be ready after recreation",
				"name", sts.Name)
			return nil
		}
		if result.Error != nil {
			return fmt.Errorf("error waiting for indexer statefulset to be ready after recreation: %w", result.Error)
		}

		log.Info("Indexer StatefulSet is ready after recreation", "name", sts.Name)
		return nil
	}

	// Check if update is needed (cert hash changed or replicas changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	certHashChanged := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Indexer StatefulSet due to certificate hash change",
				"name", sts.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
			certHashChanged = true
		}
	}

	// Check if replicas changed
	var desiredReplicas int32
	if cluster.Spec.Indexer != nil {
		desiredReplicas = cluster.Spec.Indexer.Replicas
	}
	if found.Spec.Replicas != nil && *found.Spec.Replicas != desiredReplicas {
		log.Info("Updating Indexer StatefulSet due to replica count change",
			"name", sts.Name,
			"oldReplicas", *found.Spec.Replicas,
			"newReplicas", desiredReplicas)
		direction := "up"
		if desiredReplicas < *found.Spec.Replicas {
			direction = "down"
		}
		metrics.RecordScaleOperation(cluster.Name, cluster.Namespace, "indexer", direction)
		needsUpdate = true
	}

	if needsUpdate {
		if err := r.updateStatefulSetWithRetry(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, r.Recorder, sts, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update indexer statefulset: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update indexer statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}

		// Only wait for rollout on cert hash changes (pod restart required)
		// Replica changes don't need rollout wait - Kubernetes handles scaling
		if certHashChanged {
			log.Info("Waiting for Indexer StatefulSet to be ready after certificate renewal",
				"name", sts.Name,
				"timeout", utils.DefaultRolloutTimeout)

			waiter := utils.NewRolloutWaiter(r.Client)
			result := waiter.WaitForStatefulSetReadyWithResult(ctx, sts.Namespace, sts.Name)
			if result.TimedOut {
				log.Error(result.Error, "Timeout waiting for Indexer StatefulSet to be ready",
					"name", sts.Name,
					"timeout", utils.DefaultRolloutTimeout)
				// Don't fail the reconcile on timeout - the StatefulSet strategy ensures
				// OrderedReady, so old pods are kept until new ones are ready
				return nil
			}
			if result.Error != nil {
				return fmt.Errorf("error waiting for indexer statefulset to be ready: %w", result.Error)
			}

			log.Info("Indexer StatefulSet is ready after certificate renewal", "name", sts.Name)
		}
	}

	return nil
}

// ReconcileWithCertHash reconciles the OpenSearch Indexer with certificate hash for pod restart.
//
// Deprecated: Use ReconcileNonBlocking for non-blocking rollouts.
func (r *IndexerReconciler) ReconcileWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer secrets: %w", err)
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer configmap: %w", err)
	}

	// Reconcile Services
	if err := r.reconcileServices(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer services: %w", err)
	}

	// Reconcile StatefulSet with cert hash
	if err := r.reconcileStatefulSetWithCertHash(ctx, cluster, certHash); err != nil {
		return fmt.Errorf("failed to reconcile indexer statefulset: %w", err)
	}

	log.Info("Indexer reconciliation completed")
	return nil
}

// IndexerReconcileResult contains the result of indexer reconciliation
type IndexerReconcileResult struct {
	// PendingRollout contains a rollout that was initiated but not yet complete
	PendingRollout *utils.PendingRollout
	// Error if any occurred during reconciliation
	Error error
}

// ReconcileNonBlocking reconciles the OpenSearch Indexer without blocking on rollouts
// Returns a pending rollout that should be tracked and monitored by the caller
func (r *IndexerReconciler) ReconcileNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (result IndexerReconcileResult) {
	ctx, span := telemetry.Tracer().Start(ctx, "IndexerReconciler.ReconcileNonBlocking",
		telemetry.WithAttributes(
			attribute.String("resource.name", cluster.Name),
			attribute.String("resource.namespace", cluster.Namespace),
		))
	defer span.End()
	defer func() {
		if result.Error != nil {
			telemetry.RecordError(span, result.Error)
		}
	}()

	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return IndexerReconcileResult{Error: fmt.Errorf("failed to reconcile indexer secrets: %w", err)}
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return IndexerReconcileResult{Error: fmt.Errorf("failed to reconcile indexer configmap: %w", err)}
	}

	// Reconcile Services
	if err := r.reconcileServices(ctx, cluster); err != nil {
		return IndexerReconcileResult{Error: fmt.Errorf("failed to reconcile indexer services: %w", err)}
	}

	// Reconcile StatefulSet with cert hash (non-blocking)
	pendingRollout, err := r.reconcileStatefulSetNonBlocking(ctx, cluster, certHash)
	if err != nil {
		return IndexerReconcileResult{Error: fmt.Errorf("failed to reconcile indexer statefulset: %w", err)}
	}

	// Reconcile Security Init Job (ensures internal users are synced)
	if err := r.reconcileSecurityInitJob(ctx, cluster); err != nil {
		// Log warning but don't fail - security init will be retried
		log.Error(err, "Failed to reconcile security init job, will retry")
	}

	log.Info("Indexer reconciliation completed (non-blocking)", "hasPendingRollout", pendingRollout != nil)
	return IndexerReconcileResult{PendingRollout: pendingRollout}
}

// reconcileStatefulSetNonBlocking reconciles the indexer StatefulSet without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *IndexerReconciler) reconcileStatefulSetNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	var (
		replicas                      = constants.DefaultIndexerReplicas
		resources                     *corev1.ResourceRequirements
		storageSize                   = constants.DefaultIndexerStorageSize
		javaOpts                      = constants.DefaultIndexerJavaOpts
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
	version := cluster.Spec.Version
	imagePullSecrets := cluster.Spec.ImagePullSecrets

	if cluster.Spec.Indexer != nil {
		if cluster.Spec.Indexer.Replicas > 0 {
			replicas = cluster.Spec.Indexer.Replicas
		}
		resources = cluster.Spec.Indexer.Resources
		if cluster.Spec.Indexer.StorageSize != "" {
			storageSize = cluster.Spec.Indexer.StorageSize
		}
		if cluster.Spec.Indexer.JavaOpts != "" {
			javaOpts = cluster.Spec.Indexer.JavaOpts
		}
		nodeSelector = cluster.Spec.Indexer.NodeSelector
		tolerations = cluster.Spec.Indexer.Tolerations
		affinity = cluster.Spec.Indexer.Affinity
		topologySpreadConstraints = cluster.Spec.Indexer.TopologySpreadConstraints
		env = cluster.Spec.Indexer.Env
		envFrom = cluster.Spec.Indexer.EnvFrom
		annotations = cluster.Spec.Indexer.Annotations
		podAnnotations = cluster.Spec.Indexer.PodAnnotations
		securityContext = cluster.Spec.Indexer.SecurityContext
		containerSecurityContext = cluster.Spec.Indexer.ContainerSecurityContext
		terminationGracePeriodSeconds = cluster.Spec.Indexer.TerminationGracePeriodSeconds
		if cluster.Spec.Indexer.Image != nil && cluster.Spec.Indexer.Image.PullPolicy != "" {
			imagePullPolicy = cluster.Spec.Indexer.Image.PullPolicy
		}

		// Apply cluster-level anti-affinity if enabled
		if affinityutil.ShouldApplyIndexerAntiAffinity(cluster) {
			clusterAntiAffinity := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)
			affinity = affinityutil.MergeAntiAffinity(clusterAntiAffinity, affinity)
		}
	}

	// Extract extra volumes, init containers, and sidecar containers
	var extraVolumes []corev1.Volume
	var extraVolumeMounts []corev1.VolumeMount
	var extraInitContainers []corev1.Container
	var extraContainers []corev1.Container
	if cluster.Spec.Indexer != nil {
		extraVolumes = cluster.Spec.Indexer.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Indexer.ExtraVolumeMounts
		extraInitContainers = cluster.Spec.Indexer.ExtraInitContainers
		extraContainers = cluster.Spec.Indexer.ExtraContainers
	}

	// Convert repository plugins for hash computation
	var repoPluginsHash []patch.RepositoryPluginHashInput
	if cluster.Spec.Indexer != nil {
		for _, p := range cluster.Spec.Indexer.RepositoryPlugins {
			secretName := ""
			if p.CredentialsSecret != nil {
				secretName = p.CredentialsSecret.Name
			}
			repoPluginsHash = append(repoPluginsHash, patch.RepositoryPluginHashInput{
				Name:              p.Name,
				ClientName:        p.ClientName,
				CredentialsSecret: secretName,
			})
		}
	}

	// Reconcile ServiceAccount if configured
	var indexerSAName string
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.ServiceAccount != nil {
		saName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, cluster,
			cluster.Spec.Indexer.ServiceAccount, cluster.Name, cluster.Namespace, "indexer")
		if err != nil {
			return nil, fmt.Errorf("failed to reconcile indexer ServiceAccount: %w", err)
		}
		indexerSAName = saName
	}

	// Compute spec hash for change detection (includes all configurable fields)
	specHash, err := patch.ComputeIndexerSpecHashFull(patch.IndexerSpecInput{
		Replicas:                      replicas,
		Version:                       version,
		Resources:                     resources,
		StorageSize:                   storageSize,
		JavaOpts:                      javaOpts,
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
		IndexerExporter:               toIndexerExporterHashInput(cluster),
		RepositoryPlugins:             repoPluginsHash,
		ServiceAccountName:            indexerSAName,
		SecurityContext:               securityContext,
		ContainerSecurityContext:      containerSecurityContext,
		TerminationGracePeriodSeconds: terminationGracePeriodSeconds,
		ImagePullPolicy:               imagePullPolicy,
	})
	if err != nil {
		log.Error(err, "Failed to compute indexer spec hash, proceeding without spec hash tracking")
		specHash = ""
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster)

	stsBuilder := deployments.NewIndexerStatefulSetBuilder(cluster.Name, cluster.Namespace)

	if version != "" {
		stsBuilder.WithVersion(version)
	}

	if cluster.Spec.Indexer != nil {
		if cluster.Spec.Indexer.Replicas > 0 {
			stsBuilder.WithReplicas(replicas)
		}
		if resources != nil {
			stsBuilder.WithResources(resources)
		}
		if cluster.Spec.Indexer.StorageSize != "" {
			stsBuilder.WithStorageSize(storageSize)
		}
		if cluster.Spec.Indexer.StorageClass != nil && *cluster.Spec.Indexer.StorageClass != "" {
			stsBuilder.WithStorageClassName(*cluster.Spec.Indexer.StorageClass)
		} else if cluster.Spec.StorageClassName != nil && *cluster.Spec.StorageClassName != "" {
			stsBuilder.WithStorageClassName(*cluster.Spec.StorageClassName)
		}
		if cluster.Spec.Indexer.JavaOpts != "" {
			stsBuilder.WithJavaOpts(javaOpts)
		}
		if nodeSelector != nil {
			stsBuilder.WithNodeSelector(nodeSelector)
		}
		if tolerations != nil {
			stsBuilder.WithTolerations(tolerations)
		}
		if affinity != nil {
			stsBuilder.WithAffinity(affinity)
		}
		if len(topologySpreadConstraints) > 0 {
			stsBuilder.WithTopologySpreadConstraints(topologySpreadConstraints)
		}
		if len(env) > 0 {
			stsBuilder.WithEnv(env)
		}
		if len(envFrom) > 0 {
			stsBuilder.WithEnvFrom(envFrom)
		}
		if len(annotations) > 0 {
			stsBuilder.WithAnnotations(annotations)
		}
		if len(podAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(podAnnotations)
		}
	}

	// Wire extra volumes, init containers, and sidecar containers
	if len(extraVolumes) > 0 {
		stsBuilder.WithVolumes(extraVolumes)
	}
	if len(extraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(extraVolumeMounts)
	}
	if len(extraInitContainers) > 0 {
		stsBuilder.WithExtraInitContainers(extraInitContainers)
	}
	if len(extraContainers) > 0 {
		stsBuilder.WithExtraContainers(extraContainers)
	}

	// Apply cluster-level imagePullSecrets
	if len(imagePullSecrets) > 0 {
		stsBuilder.WithImagePullSecrets(imagePullSecrets)
	}

	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}

	// Set config hash to trigger pod restart on config changes
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}
	// Set cluster reference for monitoring (Prometheus plugin and metrics)
	stsBuilder.WithCluster(cluster)

	// Set termination grace period (default + user override)
	terminationGracePeriod := constants.DefaultIndexerTerminationGracePeriod
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.TerminationGracePeriodSeconds != nil {
		terminationGracePeriod = *cluster.Spec.Indexer.TerminationGracePeriodSeconds
	}
	stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)

	// Set ServiceAccount name if configured
	if indexerSAName != "" {
		stsBuilder.WithServiceAccountName(indexerSAName)
	}

	// Set image pull policy if configured
	if imagePullPolicy != "" {
		stsBuilder.WithImagePullPolicy(imagePullPolicy)
	}

	sts := stsBuilder.Build()

	// Set spec hash annotation on the StatefulSet
	if specHash != "" {
		if sts.Annotations == nil {
			sts.Annotations = make(map[string]string)
		}
		sts.Annotations[constants.AnnotationSpecHash] = specHash
	}

	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for indexer statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Indexer StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash), "specHash", utils.ShortHash(specHash))
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create indexer statefulset: %w", err)
		}
		// New StatefulSet - return pending rollout to track initial readiness
		return &utils.PendingRollout{
			Component: "indexer",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "initial-creation",
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get indexer statefulset: %w", err)
	}

	// Check if recreation is needed due to immutable field changes (SecurityContext, PodManagementPolicy)
	needsRecreation, recreationReason := patch.NeedsStatefulSetRecreation(found, sts)
	if needsRecreation {
		log.Info("Indexer StatefulSet requires recreation due to immutable field change",
			"name", sts.Name,
			"reason", recreationReason)

		// Delete the old StatefulSet (PVCs will be preserved)
		if err := r.Delete(ctx, found); err != nil && !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to delete indexer statefulset for recreation: %w", err)
		}

		// Create the new StatefulSet
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create indexer statefulset after recreation: %w", err)
		}

		return &utils.PendingRollout{
			Component: "indexer",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "recreation-" + recreationReason,
		}, nil
	}

	// Check if update is needed
	needsUpdate := false
	updateReason := ""

	// Check spec hash (version, resources, replicas, javaOpts changes)
	existingSpecHash := ""
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	if specHash != "" && specHash != existingSpecHash {
		log.Info("Indexer spec changed",
			"name", sts.Name,
			"oldSpecHash", utils.ShortHash(existingSpecHash),
			"newSpecHash", utils.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Record spec hash change metric
		metrics.RecordSpecHashChange(cluster.Name, cluster.Namespace, "indexer")
		metrics.RecordPatchDetection(cluster.Name, cluster.Namespace, "indexer", "spec-change")

		// Emit event for spec change detection
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Indexer spec changed, updating StatefulSet %s", sts.Name))
		}
	}
	if !apiequality.Semantic.DeepEqual(found.Spec.Template.Spec.Tolerations, sts.Spec.Template.Spec.Tolerations) {
		log.Info("Indexer tolerations changed", "name", sts.Name)
		needsUpdate = true
		if updateReason == "" {
			updateReason = "tolerations-change"
		} else {
			updateReason += ",tolerations-change"
		}
	}
	if !apiequality.Semantic.DeepEqual(found.Spec.Template.Spec.Affinity, sts.Spec.Template.Spec.Affinity) {
		log.Info("Indexer affinity changed", "name", sts.Name)
		needsUpdate = true
		if updateReason == "" {
			updateReason = "affinity-change"
		} else {
			updateReason += ",affinity-change"
		}
	}

	// Check cert hash (certificate renewal)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	if certHash != "" && certHash != existingCertHash {
		log.Info("Certificate hash changed",
			"name", sts.Name,
			"oldCertHash", utils.ShortHash(existingCertHash),
			"newCertHash", utils.ShortHash(certHash))
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
		log.Info("ConfigMap hash changed",
			"name", sts.Name,
			"oldConfigHash", utils.ShortHash(existingConfigHash),
			"newConfigHash", utils.ShortHash(configHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "config-change"
		} else {
			updateReason += ",config-change"
		}

		// Record config hash change metric
		metrics.RecordConfigHashChange(cluster.Name, cluster.Namespace, "indexer")
		metrics.RecordPatchDetection(cluster.Name, cluster.Namespace, "indexer", "config-change")

		// Emit event for config change detection
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "ConfigChanged",
				fmt.Sprintf("Indexer ConfigMap changed, pods will restart (StatefulSet %s)", sts.Name))
		}
	}

	if needsUpdate {
		log.Info("Updating Indexer StatefulSet (non-blocking)",
			"name", sts.Name,
			"reason", updateReason)

		if err := r.updateStatefulSetWithRetry(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, r.Recorder, sts, found, err)
			if recErr != nil {
				return nil, fmt.Errorf("failed to update indexer statefulset: %w", recErr)
			}
			if !recreated {
				return nil, fmt.Errorf("failed to update indexer statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return nil, fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}

		// Return pending rollout instead of waiting
		return &utils.PendingRollout{
			Component: "indexer",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    updateReason,
		}, nil
	}

	return nil, nil
}

// GetStatus gets the indexer status
func (r *IndexerReconciler) GetStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.ComponentStatus, error) {
	sts := &appsv1.StatefulSet{}
	name := fmt.Sprintf("%s-indexer", cluster.Name)

	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// Get desired replicas from the spec
	desiredReplicas := int32(0)
	if cluster.Spec.Indexer != nil {
		desiredReplicas = cluster.Spec.Indexer.Replicas
	}

	// Record OpenSearch node metrics
	metrics.SetOpenSearchNodes(cluster.Name, cluster.Namespace, "ready", int(sts.Status.ReadyReplicas))
	metrics.SetOpenSearchNodes(cluster.Name, cluster.Namespace, "total", int(sts.Status.Replicas))

	return &wazuhv1.ComponentStatus{
		Replicas:        sts.Status.Replicas,
		ReadyReplicas:   sts.Status.ReadyReplicas,
		DesiredReplicas: desiredReplicas,
		Phase:           getStatefulSetPhase(sts),
	}, nil
}

// DrainCheckResult represents the result of a drain check
type DrainCheckResult struct {
	// NeedsDrain indicates if drain is required before scale-down
	NeedsDrain bool
	// DrainInProgress indicates if drain is currently running
	DrainInProgress bool
	// DrainComplete indicates if drain has completed successfully
	DrainComplete bool
	// TargetPod is the pod to be drained
	TargetPod string
	// Progress is the current drain progress (if in progress)
	Progress *drain.DrainProgress
	// Error if any occurred
	Error error
}

// CheckScaleDownDrain checks if an indexer scale-down requires drain and handles it
// Returns true if scale-down should proceed, false if waiting for drain
func (r *IndexerReconciler) CheckScaleDownDrain(ctx context.Context, cluster *wazuhv1.WazuhCluster, desiredReplicas int32) (*DrainCheckResult, error) {
	log := logf.FromContext(ctx)
	result := &DrainCheckResult{}

	// Get the current StatefulSet
	sts := &appsv1.StatefulSet{}
	stsName := fmt.Sprintf("%s-indexer", cluster.Name)
	if err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			// No StatefulSet yet, no drain needed
			return result, nil
		}
		return nil, fmt.Errorf("failed to get indexer StatefulSet: %w", err)
	}

	// Detect scale-down
	scaleInfo := drainstate.DetectStatefulSetScaleDown(sts, desiredReplicas)
	if !scaleInfo.Detected {
		// No scale-down detected
		return result, nil
	}

	log.Info("Scale-down detected for indexer",
		"currentReplicas", scaleInfo.CurrentReplicas,
		"desiredReplicas", scaleInfo.TargetReplicas,
		"targetPod", scaleInfo.TargetPodName)

	result.NeedsDrain = true
	result.TargetPod = scaleInfo.TargetPodName

	// Check if drain configuration is enabled
	if cluster.Spec.Drain == nil || cluster.Spec.Drain.Indexer == nil ||
		cluster.Spec.Drain.Indexer.Enabled == nil || !*cluster.Spec.Drain.Indexer.Enabled {
		log.Info("Indexer drain is not enabled, proceeding with scale-down without drain")
		result.NeedsDrain = false
		return result, nil
	}

	// Initialize or get drain status
	drainStatus := r.getOrInitDrainStatus(cluster)

	// Check current drain phase
	switch drainStatus.Phase {
	case wazuhv1.DrainPhaseIdle, "":
		// Start new drain
		log.Info("Starting indexer drain for scale-down", "targetPod", scaleInfo.TargetPodName)
		metrics.RecordDrainStarted(cluster.Name, cluster.Namespace, "indexer")
		if err := r.startDrain(ctx, cluster, scaleInfo, drainStatus); err != nil {
			metrics.RecordDrainFailed(cluster.Name, cluster.Namespace, "indexer")
			result.Error = err
			return result, err
		}
		result.DrainInProgress = true
		return result, nil

	case wazuhv1.DrainPhasePending, wazuhv1.DrainPhaseDraining:
		// Drain in progress, check status
		result.DrainInProgress = true
		progress, err := r.monitorDrainProgress(ctx, cluster, scaleInfo.TargetPodName, drainStatus)
		if err != nil {
			result.Error = err
			return result, nil //nolint:nilerr // Error stored in result.Error for caller to handle
		}
		if progress != nil {
			metrics.RecordDrainProgress(cluster.Name, cluster.Namespace, "indexer", float64(progress.Percent))
			metrics.SetIndexerShardCount(cluster.Name, cluster.Namespace, scaleInfo.TargetPodName, progress.ShardsRemaining)
		}
		result.Progress = progress
		return result, nil

	case wazuhv1.DrainPhaseVerifying:
		// Verify completion
		complete, err := r.verifyDrainComplete(ctx, cluster, scaleInfo.TargetPodName, drainStatus)
		if err != nil {
			result.Error = err
			return result, nil //nolint:nilerr // Error stored in result.Error for caller to handle
		}
		if complete {
			// Compute drain duration from status start time
			var durationSeconds float64
			if drainStatus.StartTime != nil {
				durationSeconds = time.Since(drainStatus.StartTime.Time).Seconds()
			}
			metrics.RecordDrainCompleted(cluster.Name, cluster.Namespace, "indexer")
			metrics.RecordDrainOperation(cluster.Name, cluster.Namespace, "indexer", "success", durationSeconds)
			metrics.ShardRelocationDuration.WithLabelValues(cluster.Name, cluster.Namespace).Observe(durationSeconds)
			result.DrainComplete = true
			result.DrainInProgress = false
		} else {
			result.DrainInProgress = true
		}
		return result, nil

	case wazuhv1.DrainPhaseComplete:
		// Drain complete, proceed with scale-down
		log.Info("Indexer drain complete, proceeding with scale-down")
		metrics.ResetDrainMetrics(cluster.Name, cluster.Namespace, "indexer")
		result.DrainComplete = true
		return result, nil

	case wazuhv1.DrainPhaseFailed:
		// Drain failed - check if we should retry or skip
		log.Info("Previous drain failed", "message", drainStatus.Message)
		metrics.RecordDrainFailed(cluster.Name, cluster.Namespace, "indexer")
		var durationSeconds float64
		if drainStatus.StartTime != nil {
			durationSeconds = time.Since(drainStatus.StartTime.Time).Seconds()
		}
		metrics.RecordDrainOperation(cluster.Name, cluster.Namespace, "indexer", "failure", durationSeconds)
		result.Error = fmt.Errorf("drain failed: %s", drainStatus.Message)
		return result, nil

	default:
		log.Info("Unknown drain phase", "phase", drainStatus.Phase)
		return result, nil
	}
}

// getOrInitDrainStatus returns the current drain status or initializes a new one
func (r *IndexerReconciler) getOrInitDrainStatus(cluster *wazuhv1.WazuhCluster) *wazuhv1.ComponentDrainStatus {
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1.DrainStatus{}
	}
	if cluster.Status.Drain.Indexer == nil {
		cluster.Status.Drain.Indexer = &wazuhv1.ComponentDrainStatus{
			Phase: wazuhv1.DrainPhaseIdle,
		}
	}
	return cluster.Status.Drain.Indexer
}

// startDrain initiates the drain process for an indexer node
func (r *IndexerReconciler) startDrain(ctx context.Context, cluster *wazuhv1.WazuhCluster, scaleInfo drainstate.ScaleDownInfo, status *wazuhv1.ComponentDrainStatus) error {
	log := logf.FromContext(ctx)

	// Initialize OpenSearch client if needed
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	// Get drain configuration
	var drainConfig *wazuhv1.IndexerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Indexer
	}

	// Create drainer if not exists
	if r.drainer == nil {
		r.drainer = drain.NewIndexerDrainer(r.osClient, log, drainConfig)
	}

	// Get the node name from the pod name (for OpenSearch)
	// In OpenSearch, the node name typically matches the pod hostname
	nodeName := scaleInfo.TargetPodName

	// Update status to pending
	if err := drainstate.StartDrain(status, nodeName, scaleInfo.CurrentReplicas, scaleInfo.TargetReplicas); err != nil {
		return fmt.Errorf("failed to transition drain state: %w", err)
	}

	// Emit event
	if r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.DrainEventReasonStarted,
			fmt.Sprintf("Starting indexer drain for node %s before scale-down", nodeName))
	}

	// Start the actual drain
	if err := r.drainer.StartDrain(ctx, nodeName); err != nil {
		// Mark as failed
		_ = drainstate.MarkFailed(status, fmt.Sprintf("Failed to start drain: %v", err))
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.DrainEventReasonFailed,
				fmt.Sprintf("Failed to start indexer drain: %v", err))
		}
		return err
	}

	// Transition to draining phase
	if err := drainstate.TransitionTo(status, wazuhv1.DrainPhaseDraining, "Relocating shards from node"); err != nil {
		log.Error(err, "Failed to transition to draining phase")
	}

	log.Info("Indexer drain started successfully", "node", nodeName)
	return nil
}

// monitorDrainProgress checks the current drain progress
//
//nolint:unparam // cluster param kept for consistency with other reconcilers
func (r *IndexerReconciler) monitorDrainProgress(ctx context.Context, _ *wazuhv1.WazuhCluster, nodeName string, status *wazuhv1.ComponentDrainStatus) (*drain.DrainProgress, error) {
	log := logf.FromContext(ctx)

	if r.drainer == nil {
		return nil, fmt.Errorf("drainer not initialized")
	}

	progress, err := r.drainer.MonitorProgress(ctx, nodeName)
	if err != nil {
		log.Error(err, "Failed to monitor drain progress")
		return nil, err
	}

	// Update status
	drainstate.UpdateProgress(status, progress.Percent, progress.Message)
	drainstate.UpdateShardCount(status, progress.ShardsRemaining)

	log.V(1).Info("Drain progress",
		"node", nodeName,
		"percent", progress.Percent,
		"shardsRemaining", progress.ShardsRemaining,
		"relocating", progress.ShardsRelocating,
		"complete", progress.IsComplete)

	// Check for completion
	if progress.IsComplete {
		if err := drainstate.TransitionTo(status, wazuhv1.DrainPhaseVerifying, "Verifying drain completion"); err != nil {
			log.Error(err, "Failed to transition to verifying phase")
		}
	}

	return &progress, nil
}

// verifyDrainComplete verifies that drain is fully complete
func (r *IndexerReconciler) verifyDrainComplete(ctx context.Context, cluster *wazuhv1.WazuhCluster, nodeName string, status *wazuhv1.ComponentDrainStatus) (bool, error) {
	log := logf.FromContext(ctx)

	if r.drainer == nil {
		return false, fmt.Errorf("drainer not initialized")
	}

	complete, err := r.drainer.VerifyComplete(ctx, nodeName)
	if err != nil {
		log.Error(err, "Failed to verify drain completion")
		return false, err
	}

	if complete {
		// Mark as complete
		if err := drainstate.MarkComplete(status); err != nil {
			log.Error(err, "Failed to mark drain as complete")
		}

		// Clear allocation exclusion
		if err := r.drainer.CancelDrain(ctx); err != nil {
			log.Error(err, "Failed to clear allocation exclusion after drain")
			// Don't fail, drain is still complete
		}

		// Emit event
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.DrainEventReasonCompleted,
				fmt.Sprintf("Indexer drain completed for node %s", nodeName))
		}

		log.Info("Indexer drain verified complete", "node", nodeName)
	}

	return complete, nil
}

// ensureOpenSearchClient creates or reuses an OpenSearch client
func (r *IndexerReconciler) ensureOpenSearchClient(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	if r.osClient != nil {
		return nil
	}

	factory := r.getClientFactory()
	newClient, err := factory.GetClientForCluster(ctx, cluster)
	if err != nil {
		return err
	}

	r.osClient = newClient
	return nil
}

// getClientFactory returns the shared ClientFactory or creates one as fallback
func (r *IndexerReconciler) getClientFactory() *security.OpenSearchClientFactory {
	if r.ClientFactory != nil {
		return r.ClientFactory
	}
	return security.NewOpenSearchClientFactory(r.Client)
}

// ResetDrainState resets the drain state after a successful scale-down
func (r *IndexerReconciler) ResetDrainState(cluster *wazuhv1.WazuhCluster) {
	if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
		drainstate.Reset(cluster.Status.Drain.Indexer)
	}
	// Clear cached drainer for next operation
	r.drainer = nil
}

// EvaluateDrainFeasibility evaluates if drain is feasible (for dry-run mode)
func (r *IndexerReconciler) EvaluateDrainFeasibility(ctx context.Context, cluster *wazuhv1.WazuhCluster, nodeName string) (*wazuhv1.DryRunResult, error) {
	// Initialize OpenSearch client if needed
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return &wazuhv1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentIndexer,
			Blockers:    []string{fmt.Sprintf("Cannot connect to OpenSearch: %v", err)},
		}, nil
	}

	// Get drain configuration
	var drainConfig *wazuhv1.IndexerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Indexer
	}

	// Create drainer for evaluation
	drainer := drain.NewIndexerDrainer(r.osClient, logf.FromContext(ctx), drainConfig)
	return drainer.EvaluateFeasibility(ctx, nodeName)
}

// createOrUpdate creates or updates a resource with retry on conflict
func (r *IndexerReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
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
			createErr := r.Create(ctx, obj)
			// If resource was created between our check and create, treat as success and retry to update
			if errors.IsAlreadyExists(createErr) {
				return createErr // Will trigger retry which will find and update
			}
			return createErr
		} else if err != nil {
			return err
		}

		// Preserve immutable fields for Services
		if svc, ok := obj.(*corev1.Service); ok {
			if existingSvc, ok := existing.(*corev1.Service); ok {
				svc.Spec.ClusterIP = existingSvc.Spec.ClusterIP
				svc.Spec.ClusterIPs = existingSvc.Spec.ClusterIPs
			}
		}

		log.V(1).Info("Updating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		obj.SetResourceVersion(existing.GetResourceVersion())
		return r.Update(ctx, obj)
	})
}

// updateStatefulSetWithRetry updates a StatefulSet with retry-on-conflict, always using the latest resourceVersion.
func (r *IndexerReconciler) updateStatefulSetWithRetry(ctx context.Context, desired *appsv1.StatefulSet) error {
	return utils.RetryOnConflict(ctx, func() error {
		current := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, current); err != nil {
			return err
		}
		desired.SetResourceVersion(current.GetResourceVersion())
		return r.Update(ctx, desired)
	})
}

// toIndexerExporterHashInput converts the cluster's IndexerExporter config to a hash input struct.
func toIndexerExporterHashInput(cluster *wazuhv1.WazuhCluster) *patch.IndexerExporterHashInput {
	if cluster.Spec.Monitoring == nil || !cluster.Spec.Monitoring.Enabled ||
		cluster.Spec.Monitoring.IndexerExporter == nil {
		return nil
	}
	e := cluster.Spec.Monitoring.IndexerExporter
	return &patch.IndexerExporterHashInput{
		Enabled: e.Enabled,
		Version: e.Version,
	}
}

// getStatefulSetPhase returns the phase of a StatefulSet
func getStatefulSetPhase(sts *appsv1.StatefulSet) wazuhv1.ComponentStatusPhase {
	if sts.Status.ReadyReplicas == 0 {
		return wazuhv1.ComponentStatusPhaseStarting
	}
	if sts.Status.ReadyReplicas < sts.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseDegraded
	}
	if sts.Status.UpdatedReplicas < sts.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseScaling
	}
	return wazuhv1.ComponentStatusPhaseReady
}

// ReconcileStandalone reconciles a standalone OpenSearchIndexer resource
func (r *IndexerReconciler) ReconcileStandalone(ctx context.Context, indexer *wazuhv1.OpenSearchIndexer) error {
	log := logf.FromContext(ctx)

	// Check if certificates exist, generate if needed
	certsSecretName := fmt.Sprintf("%s-certs", indexer.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: indexer.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		certs, err := r.generateStandaloneIndexerCertificates(ctx, indexer)
		if err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}

		certsBuilder := opensearchcerts.NewIndexerCertsSecretBuilder(indexer.Name, indexer.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithNodeCert(certs.nodeCert).
			WithNodeKey(certs.nodeKey).
			WithAdminCert(certs.adminCert).
			WithAdminKey(certs.adminKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(indexer, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for certs: %w", err)
		}

		log.Info("Creating standalone indexer certificates", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get certs secret: %w", err)
	}

	// Build ConfigMap
	replicas := int32(1)
	if indexer.Spec.Replicas > 0 {
		replicas = indexer.Spec.Replicas
	}
	// For standalone deployments, version-aware config is not available (no Wazuh version)
	opensearchYML := config.BuildIndexerConfig(indexer.Name, indexer.Namespace, replicas, "")
	configBuilder := configmaps.NewIndexerConfigMapBuilder(indexer.Name, indexer.Namespace)
	configBuilder.WithOpenSearchYML(opensearchYML)
	configMap := configBuilder.Build()

	if err := controllerutil.SetControllerReference(indexer, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile configmap: %w", err)
	}

	// Build Services
	serviceBuilder := services.NewIndexerServiceBuilder(indexer.Name, indexer.Namespace)
	if indexer.Spec.Service != nil {
		svcSpec := indexer.Spec.Service
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
	if err := controllerutil.SetControllerReference(indexer, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(indexer, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for headless service: %w", err)
	}
	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	// Build StatefulSet
	stsBuilder := deployments.NewIndexerStatefulSetBuilder(indexer.Name, indexer.Namespace)
	stsBuilder.WithReplicas(replicas)
	if indexer.Spec.Version != "" {
		stsBuilder.WithVersion(indexer.Spec.Version)
	}
	if indexer.Spec.Resources != nil {
		stsBuilder.WithResources(indexer.Spec.Resources)
	}
	if indexer.Spec.Tolerations != nil {
		stsBuilder.WithTolerations(indexer.Spec.Tolerations)
	}
	if indexer.Spec.Affinity != nil {
		stsBuilder.WithAffinity(indexer.Spec.Affinity)
	}
	if len(indexer.Spec.Annotations) > 0 {
		stsBuilder.WithAnnotations(indexer.Spec.Annotations)
	}
	if len(indexer.Spec.PodAnnotations) > 0 {
		stsBuilder.WithPodAnnotations(indexer.Spec.PodAnnotations)
	}
	if indexer.Spec.Image != nil && indexer.Spec.Image.PullPolicy != "" {
		stsBuilder.WithImagePullPolicy(indexer.Spec.Image.PullPolicy)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(indexer, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for statefulset: %w", err)
	}

	foundSts := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, foundSts)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating standalone Indexer StatefulSet", "name", sts.Name)
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create statefulset: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get statefulset: %w", err)
	} else {
		needsUpdate := false
		if utils.HashMap(sts.Annotations) != utils.HashMap(foundSts.Annotations) {
			log.Info("Updating standalone Indexer StatefulSet due to annotation change", "name", sts.Name)
			needsUpdate = true
		}
		if utils.HashMap(sts.Spec.Template.Annotations) != utils.HashMap(foundSts.Spec.Template.Annotations) {
			log.Info("Updating standalone Indexer StatefulSet due to pod annotation change", "name", sts.Name)
			needsUpdate = true
		}
		if !apiequality.Semantic.DeepEqual(sts.Spec.Template.Spec.Tolerations, foundSts.Spec.Template.Spec.Tolerations) {
			log.Info("Updating standalone Indexer StatefulSet due to tolerations change", "name", sts.Name)
			needsUpdate = true
		}
		if !apiequality.Semantic.DeepEqual(sts.Spec.Template.Spec.Affinity, foundSts.Spec.Template.Spec.Affinity) {
			log.Info("Updating standalone Indexer StatefulSet due to affinity change", "name", sts.Name)
			needsUpdate = true
		}
		if needsUpdate {
			if err := r.updateStatefulSetWithRetry(ctx, sts); err != nil {
				recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, r.Recorder, sts, foundSts, err)
				if recErr != nil {
					return fmt.Errorf("failed to update statefulset: %w", recErr)
				}
				if !recreated {
					return fmt.Errorf("failed to update statefulset: %w", err)
				}
				// Workload deleted for recreation; emit event and requeue
				if r.Recorder != nil {
					r.Recorder.Event(indexer, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
						fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
				}
				return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
			}
		}
	}

	log.Info("Standalone indexer reconciliation completed", "name", indexer.Name)
	return nil
}

// generateStandaloneIndexerCertificates generates certificates for standalone indexer
func (r *IndexerReconciler) generateStandaloneIndexerCertificates(ctx context.Context, indexer *wazuhv1.OpenSearchIndexer) (*indexerCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate CA
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-ca", indexer.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for standalone indexer")

	replicas := int32(1)
	if indexer.Spec.Replicas > 0 {
		replicas = indexer.Spec.Replicas
	}

	nodeConfig := certificates.DefaultNodeCertConfig(indexer.Name)
	nodeConfig.DNSNames = certificates.GenerateIndexerNodeSANs(indexer.Name, indexer.Namespace, replicas)
	nodeConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	nodeCert, err := certificates.GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node certificate: %w", err)
	}

	adminConfig := certificates.DefaultAdminCertConfig()
	adminCert, err := certificates.GenerateAdminCert(adminConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin certificate: %w", err)
	}

	return &indexerCertificates{
		caCert:    ca.CertificatePEM,
		nodeCert:  nodeCert.CertificatePEM,
		nodeKey:   nodeCert.PrivateKeyPEM,
		adminCert: adminCert.CertificatePEM,
		adminKey:  adminCert.PrivateKeyPEM,
	}, nil
}

// generateDefaultInternalUsers generates the internal_users.yml content with bcrypt hashed password
func generateDefaultInternalUsers(adminPassword string) []byte {
	// Generate bcrypt hash for the admin password (cost 12 for security)
	// bcrypt.GenerateFromPassword should never fail with valid string input
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), 12)
	if err != nil {
		// This should never happen, but if it does, use a safe fallback hash for "admin"
		// Generated with: bcrypt.GenerateFromPassword([]byte("admin"), 12)
		passwordHash = []byte("$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG")
	}

	return []byte(fmt.Sprintf(`---
# Internal users configuration
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "%s"
  reserved: true
  backend_roles:
    - "admin"
  description: "Admin user"

kibanaserver:
  hash: "%s"
  reserved: true
  description: "Kibana server user"
`, string(passwordHash), string(passwordHash)))
}

// generateDefaultRoles generates the roles.yml content
func generateDefaultRoles() []byte {
	return []byte(`---
# Roles configuration
_meta:
  type: "roles"
  config_version: 2
`)
}

// generateDefaultRolesMapping generates the roles_mapping.yml content
// adminDN is the Distinguished Name for the admin certificate (used for mTLS authentication)
func generateDefaultRolesMapping(adminDN string) []byte {
	return []byte(fmt.Sprintf(`---
# Role mappings configuration
_meta:
  type: "rolesmapping"
  config_version: 2

all_access:
  reserved: false
  backend_roles:
    - "admin"
  users:
    # Admin certificate DN - required for certificate hot reload API
    - "%s"
  description: "Maps admin to all_access"

own_index:
  reserved: false
  users:
    - "*"
  description: "Allow full access to an index named like the username"

logstash:
  reserved: false
  backend_roles:
    - "logstash"

kibana_user:
  reserved: false
  backend_roles:
    - "kibanauser"
  description: "Maps kibanauser to kibana_user"

readall:
  reserved: false
  backend_roles:
    - "readall"

manage_snapshots:
  reserved: false
  backend_roles:
    - "snapshotrestore"

kibana_server:
  reserved: true
  users:
    - "kibanaserver"
`, adminDN))
}

// generateDefaultActionGroups generates the action_groups.yml content
func generateDefaultActionGroups() []byte {
	return []byte(`---
# Action groups configuration
_meta:
  type: "actiongroups"
  config_version: 2
`)
}

// generateDefaultTenants generates the tenants.yml content
func generateDefaultTenants() []byte {
	return []byte(`---
# Tenants configuration
_meta:
  type: "tenants"
  config_version: 2

admin_tenant:
  reserved: false
  description: "Admin tenant"
`)
}

// generateDefaultSecurityConfig generates the config.yml content
func generateDefaultSecurityConfig() []byte {
	return []byte(`---
# Security plugin configuration
_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    http:
      anonymous_auth_enabled: false
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
`)
}

// reconcileSecurityInitJob ensures internal users (admin, kibanaserver) are synced
// to the .opendistro_security index when credentials change.
// This is a best-effort operation - if it fails due to auth issues on a new cluster,
// the security plugin's auto-init from internal_users.yml will handle it.
func (r *IndexerReconciler) reconcileSecurityInitJob(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if indexer is ready first
	status, err := r.GetStatus(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get indexer status: %w", err)
	}
	if status == nil || status.ReadyReplicas == 0 {
		log.V(1).Info("Indexer not ready yet, skipping security sync")
		return nil
	}

	// Get credentials from secret
	credSecretName := constants.IndexerCredentialsName(cluster.Name)
	credSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: credSecretName, Namespace: cluster.Namespace}, credSecret); err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Credentials secret not found, skipping security sync")
			return nil
		}
		return fmt.Errorf("failed to get credentials secret: %w", err)
	}

	// Get the password from secret
	password := string(credSecret.Data[constants.SecretKeyAdminPassword])
	if password == "" {
		log.V(1).Info("Admin password not found in credentials secret")
		return nil
	}

	// Compute hash to check if we've already synced this config
	configHash := patch.ComputeSecretHash(credSecret.Data)

	// Check if we've already synced this configuration
	if cluster.Status.Security != nil && cluster.Status.Security.CredentialsHash == configHash {
		log.V(1).Info("Security credentials already synced", "hash", configHash)
		return nil
	}

	// Try to create OpenSearch client and update users
	osClient, err := r.getClientFactory().GetClientForCluster(ctx, cluster)
	if err != nil {
		// Auth failed - try securityadmin.sh to force-push internal_users.yml
		// This handles the case where PVCs survive CR deletion but credential secrets
		// are regenerated, causing a password mismatch with the security index.
		if r.SecurityAdminExecutor != nil {
			log.Info("REST API auth failed, attempting credential recovery via securityadmin.sh")
			if saErr := r.SecurityAdminExecutor.ApplyInternalUsers(ctx, cluster.Name, cluster.Namespace, cluster.Spec.Version); saErr != nil {
				log.Error(saErr, "securityadmin.sh credential recovery failed")
				return nil // Will retry on next reconciliation
			}
			log.Info("Credentials pushed via securityadmin.sh, will sync via REST API on next reconciliation")
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "SecurityCredentialsRecovered",
					"Recovered credentials via securityadmin.sh after auth failure (PVC reuse detected)")
			}
		} else {
			log.V(1).Info("Failed to create OpenSearch client for security sync (expected on first startup)", "error", err)
		}
		return nil
	}

	// Update admin user
	log.Info("Syncing admin user to security index")
	adminPayload := map[string]interface{}{
		"password":      password,
		"backend_roles": []string{"admin"},
		"description":   "Admin user",
	}
	resp, err := osClient.PutJSON(ctx, "/_plugins/_security/api/internalusers/admin", adminPayload)
	if err != nil {
		log.V(1).Info("Failed to update admin user (may be expected on new cluster)", "error", err)
		return nil
	}
	resp.Body.Close()

	// Check for auth failure (401/403) - indicates credential mismatch with security index
	// This happens when PVCs survive CR deletion and contain old password hashes
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		log.Info("REST API returned auth error during credential sync, attempting recovery via securityadmin.sh",
			"statusCode", resp.StatusCode)
		if r.SecurityAdminExecutor != nil {
			if saErr := r.SecurityAdminExecutor.ApplyInternalUsers(ctx, cluster.Name, cluster.Namespace, cluster.Spec.Version); saErr != nil {
				log.Error(saErr, "securityadmin.sh credential recovery failed")
				return nil // Will retry on next reconciliation
			}
			log.Info("Credentials pushed via securityadmin.sh, will sync via REST API on next reconciliation")
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "SecurityCredentialsRecovered",
					"Recovered credentials via securityadmin.sh after REST API auth failure (PVC reuse detected)")
			}

			// Restart the dashboard to break out of CrashLoopBackOff.
			// The dashboard already has the correct password from the secret, but may be stuck
			// in exponential backoff after repeated auth failures against the indexer.
			r.restartDashboard(ctx, cluster)
		}
		return nil
	}

	// Update kibanaserver user
	log.Info("Syncing kibanaserver user to security index")
	kibanaPayload := map[string]interface{}{
		"password":    password,
		"description": "Kibana server user",
	}
	resp, err = osClient.PutJSON(ctx, "/_plugins/_security/api/internalusers/kibanaserver", kibanaPayload)
	if err != nil {
		log.V(1).Info("Failed to update kibanaserver user", "error", err)
		return nil
	}
	resp.Body.Close()

	// Update status to track that we've synced this config
	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}
	cluster.Status.Security.CredentialsHash = configHash

	log.Info("Security credentials synced successfully", "hash", configHash)
	if r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, "SecurityCredentialsSynced",
			"Internal users synchronized to security index")
	}

	return nil
}

// restartDashboard triggers a rolling restart of the dashboard deployment by patching
// an annotation on the pod template. This is used after credential recovery to break
// the dashboard out of CrashLoopBackOff.
func (r *IndexerReconciler) restartDashboard(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	dashboardName := constants.DashboardName(cluster.Name)
	var deployment appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Name: dashboardName, Namespace: cluster.Namespace}, &deployment); err != nil {
		log.V(1).Info("Dashboard deployment not found, skipping restart", "error", err)
		return
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = make(map[string]string)
	}
	deployment.Spec.Template.Annotations["wazuh.com/credential-recovery-restart"] = time.Now().Format(time.RFC3339)

	if err := r.Update(ctx, &deployment); err != nil {
		log.Error(err, "Failed to restart dashboard after credential recovery")
		return
	}
	log.Info("Dashboard restart triggered after credential recovery", "deployment", dashboardName)
}

// CheckSecurityInitialization checks if OpenSearch security is initialized
// and updates the cluster status accordingly
func (r *IndexerReconciler) CheckSecurityInitialization(ctx context.Context, cluster *wazuhv1.WazuhCluster) (bool, error) {
	log := logf.FromContext(ctx)

	// First check if the indexer is ready
	status, err := r.GetStatus(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("failed to get indexer status: %w", err)
	}
	if status == nil || status.ReadyReplicas == 0 {
		log.V(1).Info("Indexer not ready yet, skipping security check")
		return false, nil
	}

	// Get an OpenSearch client (cached by the shared factory)
	osClient, err := r.getClientFactory().GetClientForCluster(ctx, cluster)
	if err != nil {
		log.V(1).Info("Failed to create OpenSearch client", "error", err)
		return false, nil // Not an error, just not ready
	}

	// Check security initialization
	checker := security.NewSecurityInitializationChecker(osClient)
	initialized, err := checker.CheckInitialized(ctx)
	if err != nil {
		log.V(1).Info("Security initialization check failed", "error", err)
		return false, nil // Transient error, will retry
	}

	// Update security status
	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}

	if initialized && !cluster.Status.Security.Initialized {
		// Security just became initialized
		cluster.Status.Security.Initialized = true
		now := metav1.Now()
		cluster.Status.Security.InitializationTime = &now
		log.Info("OpenSearch security is now initialized")

		// Record event
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SecurityInitialized",
				"OpenSearch security plugin has been initialized")
		}
	}

	cluster.Status.Security.Initialized = initialized
	return initialized, nil
}

// SyncSecurityCRDs synchronizes all security-related CRDs to OpenSearch
func (r *IndexerReconciler) SyncSecurityCRDs(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if security is initialized
	if cluster.Status.Security == nil || !cluster.Status.Security.Initialized {
		log.V(1).Info("Security not initialized, skipping CRD sync")
		return nil
	}

	// Create synchronizer using the shared client factory
	synchronizer := security.NewSecurityConfigSynchronizer(r.Client, r.getClientFactory(), r.Recorder)

	// Sync all security CRDs
	result, err := synchronizer.SyncAllForCluster(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to sync security CRDs: %w", err)
	}

	// Update security status with sync results
	now := metav1.Now()
	cluster.Status.Security.LastSyncTime = &now
	cluster.Status.Security.SyncedUsers = result.UsersUpdated + result.UsersCreated
	cluster.Status.Security.SyncedRoles = result.RolesUpdated + result.RolesCreated
	cluster.Status.Security.SyncedRoleMappings = result.MappingsUpdated + result.MappingsCreated
	cluster.Status.Security.SyncedTenants = result.TenantsUpdated + result.TenantsCreated
	cluster.Status.Security.SyncedActionGroups = result.ActionGroupsUpdated + result.ActionGroupsCreated

	if result.HasErrors() {
		log.Error(fmt.Errorf("sync errors: %v", result.Errors), "Some security CRDs failed to sync")
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "SecuritySyncPartialFailure",
				fmt.Sprintf("Some security CRDs failed to sync: %d errors", len(result.Errors)))
		}
	} else {
		log.Info("Security CRDs synced successfully",
			"users", cluster.Status.Security.SyncedUsers,
			"roles", cluster.Status.Security.SyncedRoles,
			"roleMappings", cluster.Status.Security.SyncedRoleMappings,
			"tenants", cluster.Status.Security.SyncedTenants,
			"actionGroups", cluster.Status.Security.SyncedActionGroups)
	}

	// Record OpenSearch security metrics
	metrics.SetOpenSearchUsers(cluster.Name, cluster.Namespace, cluster.Status.Security.SyncedUsers)
	metrics.SetOpenSearchRoles(cluster.Name, cluster.Namespace, cluster.Status.Security.SyncedRoles)

	return nil
}

// DetectIndexerRestart checks if the indexer has restarted since last check
func (r *IndexerReconciler) DetectIndexerRestart(ctx context.Context, cluster *wazuhv1.WazuhCluster) (bool, error) {
	// Get current restart count from pods
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/name":      "opensearch-indexer",
			"app.kubernetes.io/instance":  cluster.Name,
			"app.kubernetes.io/component": "indexer",
		},
	}

	if err := r.List(ctx, podList, listOpts...); err != nil {
		return false, fmt.Errorf("failed to list indexer pods: %w", err)
	}

	// Sum up restart counts
	var totalRestarts int32
	for _, pod := range podList.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			totalRestarts += cs.RestartCount
		}
	}

	// Compare with stored restart count
	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}

	storedRestarts := cluster.Status.Security.IndexerRestartCount
	if totalRestarts > storedRestarts {
		cluster.Status.Security.IndexerRestartCount = totalRestarts
		return true, nil
	}

	return false, nil
}

// CollectOpenSearchMetrics collects and records OpenSearch metrics via API
// This includes cluster health, indices count, and ISM policies count
func (r *IndexerReconciler) CollectOpenSearchMetrics(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	// Ensure we have an OpenSearch client
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		log.V(1).Info("Cannot create OpenSearch client for metrics collection", "error", err)
		return
	}

	// Collect cluster health
	health, err := r.osClient.GetClusterHealth(ctx)
	if err != nil {
		log.V(1).Info("Failed to get cluster health for metrics", "error", err)
	} else {
		var healthStatus metrics.HealthStatus
		switch health.Status {
		case "green":
			healthStatus = metrics.HealthGreen
		case "yellow":
			healthStatus = metrics.HealthYellow
		default:
			healthStatus = metrics.HealthRed
		}
		metrics.SetOpenSearchClusterHealth(cluster.Name, cluster.Namespace, healthStatus)
	}

	// Collect indices count
	indicesCount, err := r.osClient.GetIndicesCount(ctx)
	if err != nil {
		log.V(1).Info("Failed to get indices count for metrics", "error", err)
	} else {
		metrics.SetOpenSearchIndices(cluster.Name, cluster.Namespace, indicesCount)
	}

	// Collect ISM policies count
	ismPoliciesCount, err := r.osClient.GetISMPoliciesCount(ctx)
	if err != nil {
		log.V(1).Info("Failed to get ISM policies count for metrics", "error", err)
	} else {
		metrics.SetOpenSearchISMPolicies(cluster.Name, cluster.Namespace, ismPoliciesCount)
	}
}

// ResolveAndSetDefaultAdmin resolves the default admin user and updates cluster status
func (r *IndexerReconciler) ResolveAndSetDefaultAdmin(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	credManager := security.NewCredentialManager(r.Client, r.Recorder)
	creds, err := credManager.GetAdminCredentials(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get admin credentials: %w", err)
	}

	// Update status
	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}
	cluster.Status.Security.DefaultAdminUser = creds.Username
	cluster.Status.Security.DefaultAdminSource = creds.Source

	log.V(1).Info("Resolved default admin user",
		"username", creds.Username,
		"source", creds.Source)

	return nil
}

// reconcileVolumeExpansion handles PVC volume expansion for indexer pods
func (r *IndexerReconciler) reconcileVolumeExpansion(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get requested storage size from spec
	requestedSize := constants.DefaultIndexerStorageSize
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.StorageSize != "" {
		requestedSize = cluster.Spec.Indexer.StorageSize
	}

	// List all indexer PVCs
	pvcList, err := r.getIndexerPVCs(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to list indexer PVCs: %w", err)
	}

	// If no PVCs found, nothing to expand
	if len(pvcList.Items) == 0 {
		log.V(1).Info("No indexer PVCs found, skipping volume expansion check")
		return nil
	}

	// Track expansion progress
	var pvcsExpanded []string
	var pvcsPending []string
	var expansionNeeded bool
	var expansionError error

	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]

		// Validate expansion
		validationResult, err := storage.ValidateExpansion(ctx, r.Client, pvc, requestedSize)
		if err != nil {
			log.Error(err, "Failed to validate expansion for PVC", "pvc", pvc.Name)
			expansionError = err
			continue
		}

		// Handle validation failures
		if !validationResult.Valid {
			if validationResult.ErrorMessage != "" {
				// Check if this is a shrink request
				isShrink, _ := storage.IsShrinkRequest(validationResult.CurrentSize.String(), requestedSize)
				if isShrink {
					// Emit shrink rejected event
					if r.Recorder != nil {
						r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageSizeDecreaseRejected,
							fmt.Sprintf("Cannot decrease storage size for PVC %s: Kubernetes does not support shrinking PVCs", pvc.Name))
					}
					log.Info("Storage size decrease rejected",
						"pvc", pvc.Name,
						"currentSize", validationResult.CurrentSize.String(),
						"requestedSize", requestedSize)
					continue
				}

				// Check if StorageClass doesn't support expansion
				if !validationResult.StorageClassSupportsExpansion && validationResult.NeedsExpansion {
					if r.Recorder != nil {
						r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageClassNotExpandable,
							fmt.Sprintf("StorageClass for PVC %s does not support volume expansion", pvc.Name))
					}
					log.Info("StorageClass does not support volume expansion",
						"pvc", pvc.Name,
						"error", validationResult.ErrorMessage)
					expansionError = fmt.Errorf("storage class does not support expansion: %s", validationResult.ErrorMessage)
					continue
				}
			}
			continue
		}

		// Check if expansion is needed
		if !validationResult.NeedsExpansion {
			// Already at requested size
			pvcsExpanded = append(pvcsExpanded, pvc.Name)
			continue
		}

		// Expansion is needed
		expansionNeeded = true
		pvcsPending = append(pvcsPending, pvc.Name)

		// Check current expansion state
		condition := storage.GetPVCExpansionCondition(pvc)
		if !condition.IsComplete {
			log.V(1).Info("PVC expansion already in progress",
				"pvc", pvc.Name,
				"phase", condition.Phase,
				"message", condition.Message)
			continue
		}

		// Emit expansion started event (only once at the start)
		if len(pvcsPending) == 1 && len(pvcsExpanded) == 0 {
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionStarted,
					fmt.Sprintf("Starting volume expansion for indexer PVCs to %s", requestedSize))
			}
		}

		// Perform expansion
		log.Info("Expanding indexer PVC",
			"pvc", pvc.Name,
			"currentSize", validationResult.CurrentSize.String(),
			"requestedSize", requestedSize)

		if err := storage.ExpandPVC(ctx, r.Client, pvc, requestedSize); err != nil {
			log.Error(err, "Failed to expand PVC", "pvc", pvc.Name)
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonVolumeExpansionFailed,
					fmt.Sprintf("Failed to expand PVC %s: %v", pvc.Name, err))
			}
			expansionError = err
			continue
		}

		log.Info("PVC expansion initiated",
			"pvc", pvc.Name,
			"newSize", requestedSize)
	}

	// Update expansion status
	r.updateIndexerExpansionStatus(ctx, cluster, requestedSize, pvcsExpanded, pvcsPending, expansionError)

	// Emit completion event if all PVCs are expanded
	if len(pvcsPending) == 0 && len(pvcsExpanded) > 0 && expansionNeeded {
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionCompleted,
				fmt.Sprintf("All indexer PVCs expanded successfully to %s", requestedSize))
		}
	}

	return nil
}

// getIndexerPVCs lists all PVCs belonging to the indexer StatefulSet
func (r *IndexerReconciler) getIndexerPVCs(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*corev1.PersistentVolumeClaimList, error) {
	pvcList := &corev1.PersistentVolumeClaimList{}

	// Indexer PVCs are labeled with app.kubernetes.io/component=indexer
	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			constants.LabelInstance:  cluster.Name,
			constants.LabelComponent: constants.ComponentIndexer,
		},
	}

	if err := r.List(ctx, pvcList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list indexer PVCs: %w", err)
	}

	return pvcList, nil
}

// updateIndexerExpansionStatus updates the indexer expansion status in the cluster status
func (r *IndexerReconciler) updateIndexerExpansionStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster, requestedSize string, pvcsExpanded, pvcsPending []string, expansionError error) {
	log := logf.FromContext(ctx)

	// Initialize VolumeExpansion status if needed
	if cluster.Status.VolumeExpansion == nil {
		cluster.Status.VolumeExpansion = &wazuhv1.VolumeExpansionStatus{}
	}

	var update storage.ExpansionStatusUpdate

	// Determine current size from first expanded PVC or use requested size
	currentSize := requestedSize
	if len(pvcsExpanded) == 0 && len(pvcsPending) > 0 {
		// Try to get current size from a pending PVC
		pvcList, err := r.getIndexerPVCs(ctx, cluster)
		if err == nil && len(pvcList.Items) > 0 {
			currentSize = storage.GetPVCStorageSize(&pvcList.Items[0])
		}
	}

	// Determine the phase and create status update
	if expansionError != nil {
		update = storage.CreateFailedStatus(requestedSize, currentSize, expansionError.Error(), pvcsExpanded, pvcsPending)
	} else if len(pvcsPending) > 0 {
		if len(pvcsExpanded) > 0 {
			update = storage.CreateInProgressStatus(requestedSize, currentSize, pvcsExpanded, pvcsPending)
		} else {
			update = storage.CreatePendingStatus(requestedSize, currentSize, pvcsPending)
		}
	} else if len(pvcsExpanded) > 0 {
		update = storage.CreateCompletedStatus(requestedSize, pvcsExpanded)
	} else {
		// No PVCs found or no expansion needed - clear the status
		cluster.Status.VolumeExpansion.IndexerExpansion = nil
		return
	}

	// Update the status
	cluster.Status.VolumeExpansion.IndexerExpansion = storage.UpdateComponentExpansionStatus(
		cluster.Status.VolumeExpansion.IndexerExpansion,
		update,
	)

	log.V(1).Info("Updated indexer expansion status",
		"phase", update.Phase,
		"pvcsExpanded", len(pvcsExpanded),
		"pvcsPending", len(pvcsPending))
}

// =============================================================================
// Advanced Topology Mode (NodePools)
// =============================================================================

// reconcileAdvancedMode reconciles the indexer in advanced topology mode
// This creates separate StatefulSets, Services, and ConfigMaps for each nodePool
func (r *IndexerReconciler) reconcileAdvancedMode(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Initialize nodePool statuses if needed
	if cluster.Status.Indexer.NodePoolStatuses == nil {
		cluster.Status.Indexer.NodePoolStatuses = make(map[string]wazuhv1.NodePoolStatus)
	}

	// Build discovery hosts and initial master nodes (pointing to cluster_manager pools)
	discoveryHosts, initialMasterNodes := r.buildDiscoveryConfig(cluster)

	// Reconcile each nodePool
	for _, pool := range cluster.Spec.Indexer.NodePools {
		log.V(1).Info("Reconciling nodePool", "pool", pool.Name, "replicas", pool.Replicas)

		// Update status to indicate reconciliation in progress
		r.updateNodePoolStatus(cluster, pool.Name, wazuhv1.NodePoolPhaseCreating, "Reconciling nodePool")

		if err := r.reconcileSingleNodePool(ctx, cluster, &pool, discoveryHosts, initialMasterNodes); err != nil {
			r.updateNodePoolStatus(cluster, pool.Name, wazuhv1.NodePoolPhaseFailed, err.Error())
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, "NodePoolReconcileFailed",
					fmt.Sprintf("Failed to reconcile nodePool %s: %v", pool.Name, err))
			}
			return fmt.Errorf("failed to reconcile nodePool %s: %w", pool.Name, err)
		}

		// Get StatefulSet status for this pool
		stsName := constants.IndexerNodePoolName(cluster.Name, pool.Name)
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err == nil {
			phase := r.getNodePoolPhase(sts)
			r.updateNodePoolStatusFromSts(cluster, pool.Name, sts, phase)
		}
	}

	// Cleanup orphaned resources from removed nodePools
	if err := r.cleanupOrphanedNodePools(ctx, cluster); err != nil {
		log.Error(err, "Failed to cleanup orphaned nodePool resources")
		// Don't fail reconciliation for cleanup errors
	}

	// Update overall indexer status
	r.updateIndexerStatusFromNodePools(cluster)

	log.Info("Advanced mode indexer reconciliation completed",
		"nodePools", len(cluster.Spec.Indexer.NodePools))
	return nil
}

// reconcileSingleNodePool reconciles a single nodePool's resources
func (r *IndexerReconciler) reconcileSingleNodePool(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	pool *wazuhv1.IndexerNodePoolSpec,
	discoveryHosts []string,
	initialMasterNodes []string,
) error {
	log := logf.FromContext(ctx)

	// 1. Reconcile ConfigMap for this nodePool
	if err := r.reconcileNodePoolConfigMap(ctx, cluster, pool, discoveryHosts, initialMasterNodes); err != nil {
		return fmt.Errorf("failed to reconcile configmap: %w", err)
	}

	// 2. Reconcile headless Service for this nodePool
	if err := r.reconcileNodePoolService(ctx, cluster, pool); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	// 3. Reconcile StatefulSet for this nodePool
	if err := r.reconcileNodePoolStatefulSet(ctx, cluster, pool); err != nil {
		return fmt.Errorf("failed to reconcile statefulset: %w", err)
	}

	log.V(1).Info("NodePool resources reconciled", "pool", pool.Name)
	return nil
}

// reconcileNodePoolConfigMap creates/updates the ConfigMap for a nodePool
func (r *IndexerReconciler) reconcileNodePoolConfigMap(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	pool *wazuhv1.IndexerNodePoolSpec,
	discoveryHosts []string,
	initialMasterNodes []string,
) error {
	// Build opensearch.yml with role-specific configuration
	params := config.NodePoolConfigParams{
		ClusterName:        cluster.Name,
		Namespace:          cluster.Namespace,
		PoolName:           pool.Name,
		Roles:              pool.GetRolesAsStrings(),
		Attributes:         pool.Attributes,
		DiscoverySeedHosts: discoveryHosts,
		InitialMasterNodes: initialMasterNodes,
		WazuhVersion:       cluster.Spec.Version,
	}
	opensearchYML := config.BuildNodePoolConfig(params)

	// Build ConfigMap
	configBuilder := configmaps.NewNodePoolConfigMapBuilder(cluster.Name, cluster.Namespace, pool.Name)
	configBuilder.WithOpenSearchYML(opensearchYML)
	if cluster.Spec.Version != "" {
		configBuilder.WithVersion(cluster.Spec.Version)
	}
	configMap := configBuilder.Build()

	// Set controller reference
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// reconcileNodePoolService creates/updates the headless Service for a nodePool
func (r *IndexerReconciler) reconcileNodePoolService(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	pool *wazuhv1.IndexerNodePoolSpec,
) error {
	// Build headless service
	serviceBuilder := services.NewNodePoolServiceBuilder(cluster.Name, cluster.Namespace, pool.Name)
	if cluster.Spec.Version != "" {
		serviceBuilder.WithVersion(cluster.Spec.Version)
	}
	service := serviceBuilder.Build()

	// Set controller reference
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, service)
}

// reconcileNodePoolStatefulSet creates/updates the StatefulSet for a nodePool
func (r *IndexerReconciler) reconcileNodePoolStatefulSet(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	pool *wazuhv1.IndexerNodePoolSpec,
) error {
	log := logf.FromContext(ctx)

	// Build StatefulSet
	stsBuilder := deployments.NewNodePoolStatefulSetBuilder(cluster.Name, cluster.Namespace, pool.Name)
	stsBuilder.WithReplicas(pool.Replicas).
		WithRoles(pool.GetRolesAsStrings()).
		WithCluster(cluster)

	// Set version
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}

	// Set per-pool configurations
	if pool.Resources != nil {
		stsBuilder.WithResources(pool.Resources)
	}
	if pool.StorageSize != "" {
		stsBuilder.WithStorageSize(pool.StorageSize)
	}
	if pool.StorageClass != nil && *pool.StorageClass != "" {
		stsBuilder.WithStorageClassName(*pool.StorageClass)
	} else if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.StorageClass != nil && *cluster.Spec.Indexer.StorageClass != "" {
		stsBuilder.WithStorageClassName(*cluster.Spec.Indexer.StorageClass)
	} else if cluster.Spec.StorageClassName != nil && *cluster.Spec.StorageClassName != "" {
		stsBuilder.WithStorageClassName(*cluster.Spec.StorageClassName)
	}
	if pool.JavaOpts != "" {
		stsBuilder.WithJavaOpts(pool.JavaOpts)
	}
	if pool.NodeSelector != nil {
		stsBuilder.WithNodeSelector(pool.NodeSelector)
	}
	if pool.Tolerations != nil {
		stsBuilder.WithTolerations(pool.Tolerations)
	}
	if pool.Affinity != nil {
		stsBuilder.WithAffinity(pool.Affinity)
	}
	if len(pool.TopologySpreadConstraints) > 0 {
		stsBuilder.WithTopologySpreadConstraints(pool.TopologySpreadConstraints)
	}
	if len(pool.Annotations) > 0 {
		stsBuilder.WithAnnotations(pool.Annotations)
	}
	if len(pool.PodAnnotations) > 0 {
		stsBuilder.WithPodAnnotations(pool.PodAnnotations)
	}

	// Wire extra volumes, init containers, and sidecar containers from nodePool spec
	if len(pool.ExtraVolumes) > 0 {
		stsBuilder.WithVolumes(pool.ExtraVolumes)
	}
	if len(pool.ExtraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(pool.ExtraVolumeMounts)
	}
	if len(pool.ExtraInitContainers) > 0 {
		stsBuilder.WithExtraInitContainers(pool.ExtraInitContainers)
	}
	if len(pool.ExtraContainers) > 0 {
		stsBuilder.WithExtraContainers(pool.ExtraContainers)
	}

	// Apply cluster-level imagePullSecrets
	if len(cluster.Spec.ImagePullSecrets) > 0 {
		stsBuilder.WithImagePullSecrets(cluster.Spec.ImagePullSecrets)
	}

	// Compute config hash for change detection
	configMapName := constants.IndexerNodePoolConfigName(cluster.Name, pool.Name)
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap); err == nil {
		configHash := patch.ComputeConfigHash(configMap.Data)
		stsBuilder.WithConfigHash(configHash)
	}

	// Set termination grace period (default + user override from indexer spec)
	terminationGracePeriod := constants.DefaultIndexerTerminationGracePeriod
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.TerminationGracePeriodSeconds != nil {
		terminationGracePeriod = *cluster.Spec.Indexer.TerminationGracePeriodSeconds
	}
	stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)

	// Reconcile ServiceAccount for nodePool (inherit from indexer if pool SA is nil)
	saCfg := pool.ServiceAccount
	if saCfg == nil && cluster.Spec.Indexer != nil {
		saCfg = cluster.Spec.Indexer.ServiceAccount
	}
	if saCfg != nil {
		poolSAName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, cluster,
			saCfg, cluster.Name, cluster.Namespace, fmt.Sprintf("indexer-%s", pool.Name))
		if err != nil {
			return fmt.Errorf("failed to reconcile nodePool %s ServiceAccount: %w", pool.Name, err)
		}
		if poolSAName != "" {
			stsBuilder.WithServiceAccountName(poolSAName)
		}
	}

	sts := stsBuilder.Build()

	// Set controller reference
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if StatefulSet exists
	found := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating nodePool StatefulSet", "name", sts.Name, "pool", pool.Name, "replicas", pool.Replicas)
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create statefulset: %w", err)
		}

		// Emit event
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "NodePoolCreated",
				fmt.Sprintf("Created nodePool %s with %d replicas", pool.Name, pool.Replicas))
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Check if update is needed
	needsUpdate := false
	updateReason := ""

	// Check replicas change
	currentReplicas := *found.Spec.Replicas
	isScaleDown := pool.Replicas < currentReplicas

	if currentReplicas != pool.Replicas {
		log.Info("NodePool replicas changed",
			"pool", pool.Name,
			"oldReplicas", currentReplicas,
			"newReplicas", pool.Replicas,
			"isScaleDown", isScaleDown)

		// Record scale operation metric
		direction := "up"
		if isScaleDown {
			direction = "down"
		}
		metrics.RecordScaleOperation(cluster.Name, cluster.Namespace, "indexer-"+pool.Name, direction)

		// Handle scale-down with drain integration
		if isScaleDown {
			// Check if drain is enabled and if it's needed for this nodePool
			drainNeeded, err := r.checkNodePoolScaleDownDrain(ctx, cluster, pool, currentReplicas)
			if err != nil {
				return fmt.Errorf("failed to check scale-down drain: %w", err)
			}
			if drainNeeded {
				// Drain is in progress or waiting, don't update replicas yet
				log.Info("Scale-down drain in progress, deferring replica update",
					"pool", pool.Name)
				return nil
			}
			// Drain complete or not needed, proceed with scale-down
		}

		needsUpdate = true
		updateReason = fmt.Sprintf("replicas: %d->%d", currentReplicas, pool.Replicas)
	}

	// Check config hash change
	existingConfigHash := ""
	if found.Spec.Template.Annotations != nil {
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	newConfigHash := ""
	if sts.Spec.Template.Annotations != nil {
		newConfigHash = sts.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	if newConfigHash != "" && newConfigHash != existingConfigHash {
		needsUpdate = true
		if updateReason != "" {
			updateReason += ", "
		}
		updateReason += "config changed"
	}
	if utils.HashMap(sts.Annotations) != utils.HashMap(found.Annotations) {
		needsUpdate = true
		if updateReason != "" {
			updateReason += ", "
		}
		updateReason += "annotations changed"
	}
	if utils.HashMap(sts.Spec.Template.Annotations) != utils.HashMap(found.Spec.Template.Annotations) {
		needsUpdate = true
		if updateReason != "" {
			updateReason += ", "
		}
		updateReason += "pod annotations changed"
	}

	if needsUpdate {
		log.Info("Updating nodePool StatefulSet",
			"pool", pool.Name,
			"reason", updateReason)

		if err := r.updateStatefulSetWithRetry(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, r.Recorder, sts, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update statefulset: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}

		// Emit event
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "NodePoolUpdated",
				fmt.Sprintf("Updated nodePool %s: %s", pool.Name, updateReason))
		}
	}

	return nil
}

// checkNodePoolScaleDownDrain checks if drain is needed and handles it for nodePool scale-down
// Returns true if drain is in progress and scale-down should be deferred
func (r *IndexerReconciler) checkNodePoolScaleDownDrain(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	pool *wazuhv1.IndexerNodePoolSpec,
	currentReplicas int32,
) (bool, error) {
	log := logf.FromContext(ctx)

	// Check if drain is enabled
	if cluster.Spec.Drain == nil || cluster.Spec.Drain.Indexer == nil ||
		cluster.Spec.Drain.Indexer.Enabled == nil || !*cluster.Spec.Drain.Indexer.Enabled {
		log.Info("Indexer drain is not enabled, proceeding with scale-down without drain",
			"pool", pool.Name)
		return false, nil
	}

	// Calculate total cluster_manager count for quorum check
	totalClusterManagers := r.getTotalClusterManagers(cluster)

	// Build scale-down info
	targetPods := drain.GetNodePoolScaleDownTargets(cluster.Name, pool.Name, currentReplicas, pool.Replicas)
	scaleDownInfo := &drain.NodePoolScaleDownInfo{
		PoolName:        pool.Name,
		Roles:           pool.GetRolesAsStrings(),
		CurrentReplicas: currentReplicas,
		DesiredReplicas: pool.Replicas,
		TargetPodNames:  targetPods,
	}

	// Initialize drainer if needed
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		log.Error(err, "Failed to create OpenSearch client for drain check")
		// If we can't connect, emit warning but allow scale-down
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "DrainCheckFailed",
				fmt.Sprintf("Cannot check drain for nodePool %s: %v", pool.Name, err))
		}
		return false, nil
	}

	if r.drainer == nil {
		var drainConfig *wazuhv1.IndexerDrainConfig
		if cluster.Spec.Drain != nil {
			drainConfig = cluster.Spec.Drain.Indexer
		}
		r.drainer = drain.NewIndexerDrainer(r.osClient, log, drainConfig)
	}

	// Evaluate if drain is needed
	drainResult, err := r.drainer.EvaluateNodePoolScaleDown(ctx, scaleDownInfo, totalClusterManagers)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate scale-down drain: %w", err)
	}

	// Check for blockers (quorum violation, etc.)
	if !drainResult.Feasible {
		for _, blocker := range drainResult.Blockers {
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, "ScaleDownBlocked",
					fmt.Sprintf("NodePool %s scale-down blocked: %s", pool.Name, blocker))
			}
		}
		// Return error to prevent scale-down
		return false, fmt.Errorf("scale-down blocked: %s", drainResult.Blockers[0])
	}

	// If drain not needed (coordinating-only, no data role), proceed
	if !drainResult.NeedsDrain {
		log.Info("Drain not needed for nodePool scale-down",
			"pool", pool.Name,
			"reason", drainResult.SkipReason)
		return false, nil
	}

	// Drain is needed - check/manage drain status
	drainStatus := r.getOrInitNodePoolDrainStatus(cluster, pool.Name)

	switch drainStatus.Phase {
	case wazuhv1.DrainPhaseIdle, "":
		// Start new drain
		log.Info("Starting nodePool drain for scale-down",
			"pool", pool.Name,
			"targetPods", targetPods)

		if err := r.drainer.StartNodePoolDrain(ctx, targetPods); err != nil {
			drainStatus.Phase = wazuhv1.DrainPhaseFailed
			drainStatus.Message = err.Error()
			return false, fmt.Errorf("failed to start drain: %w", err)
		}

		drainStatus.Phase = wazuhv1.DrainPhaseDraining
		drainStatus.Message = fmt.Sprintf("Draining %d pods", len(targetPods))
		drainStatus.StartTime = &metav1.Time{Time: time.Now()}
		drainStatus.LastTransitionTime = &metav1.Time{Time: time.Now()}

		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "NodePoolDrainStarted",
				fmt.Sprintf("Started drain for nodePool %s: %d pods", pool.Name, len(targetPods)))
		}
		return true, nil

	case wazuhv1.DrainPhaseDraining:
		// Monitor progress
		progress, err := r.drainer.MonitorNodePoolDrainProgress(ctx, targetPods)
		if err != nil {
			log.Error(err, "Error monitoring nodePool drain progress", "pool", pool.Name)
			return true, nil // Keep waiting
		}

		drainStatus.Progress = progress.Percent
		drainStatus.Message = progress.Message

		if progress.IsComplete {
			drainStatus.Phase = wazuhv1.DrainPhaseVerifying
			log.Info("NodePool drain appears complete, verifying", "pool", pool.Name)
		}
		return true, nil

	case wazuhv1.DrainPhaseVerifying:
		// Verify completion
		complete, err := r.drainer.VerifyNodePoolDrainComplete(ctx, targetPods)
		if err != nil {
			log.Error(err, "Error verifying nodePool drain", "pool", pool.Name)
			return true, nil
		}

		if complete {
			drainStatus.Phase = wazuhv1.DrainPhaseComplete
			drainStatus.LastTransitionTime = &metav1.Time{Time: time.Now()}
			drainStatus.Message = "Drain complete, proceeding with scale-down"

			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "NodePoolDrainComplete",
					fmt.Sprintf("Drain complete for nodePool %s", pool.Name))
			}

			// Clear allocation exclusion
			if err := r.drainer.CancelDrain(ctx); err != nil {
				log.Error(err, "Failed to clear allocation exclusion after drain")
			}

			return false, nil // Drain complete, proceed with scale-down
		}
		return true, nil

	case wazuhv1.DrainPhaseComplete:
		// Already complete, proceed
		log.Info("NodePool drain already complete, proceeding with scale-down", "pool", pool.Name)
		// Reset status for next operation
		drainStatus.Phase = wazuhv1.DrainPhaseIdle
		return false, nil

	case wazuhv1.DrainPhaseFailed:
		// Failed - check if we should retry
		log.Info("Previous nodePool drain failed", "pool", pool.Name, "message", drainStatus.Message)
		// Reset and allow retry on next reconcile
		drainStatus.Phase = wazuhv1.DrainPhaseIdle
		return true, nil
	}

	return false, nil
}

// getOrInitNodePoolDrainStatus returns or initializes drain status for a nodePool
func (r *IndexerReconciler) getOrInitNodePoolDrainStatus(cluster *wazuhv1.WazuhCluster, _ string) *wazuhv1.ComponentDrainStatus {
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1.DrainStatus{}
	}

	// Use a map in NodePoolDrainStatuses (we'll need to check if this exists in the API)
	// For now, use the single Indexer status with pool name in message
	if cluster.Status.Drain.Indexer == nil {
		cluster.Status.Drain.Indexer = &wazuhv1.ComponentDrainStatus{
			Phase: wazuhv1.DrainPhaseIdle,
		}
	}
	return cluster.Status.Drain.Indexer
}

// getTotalClusterManagers returns the total number of cluster_manager nodes across all nodePools
func (r *IndexerReconciler) getTotalClusterManagers(cluster *wazuhv1.WazuhCluster) int32 {
	var total int32
	for _, pool := range cluster.Spec.Indexer.NodePools {
		if pool.HasClusterManagerRole() {
			total += pool.Replicas
		}
	}
	return total
}

// buildDiscoveryConfig builds discovery hosts and initial master nodes for advanced mode
// Discovery hosts point to cluster_manager nodePool pods for all nodes to find the cluster
func (r *IndexerReconciler) buildDiscoveryConfig(cluster *wazuhv1.WazuhCluster) ([]string, []string) {
	var clusterManagerPools []struct {
		Name     string
		Replicas int32
	}

	// Find all nodePools with cluster_manager role
	for _, pool := range cluster.Spec.Indexer.NodePools {
		if pool.HasClusterManagerRole() {
			clusterManagerPools = append(clusterManagerPools, struct {
				Name     string
				Replicas int32
			}{
				Name:     pool.Name,
				Replicas: pool.Replicas,
			})
		}
	}

	// If no cluster_manager pools found, use all pools for discovery
	// (this shouldn't happen with validation, but be safe)
	if len(clusterManagerPools) == 0 {
		for _, pool := range cluster.Spec.Indexer.NodePools {
			clusterManagerPools = append(clusterManagerPools, struct {
				Name     string
				Replicas int32
			}{
				Name:     pool.Name,
				Replicas: pool.Replicas,
			})
		}
	}

	discoveryHosts := config.GenerateDiscoveryHostsForNodePools(cluster.Name, cluster.Namespace, clusterManagerPools)
	initialMasterNodes := config.GenerateInitialMasterNodesForNodePools(cluster.Name, clusterManagerPools)

	return discoveryHosts, initialMasterNodes
}

// cleanupOrphanedNodePools removes resources from nodePools that no longer exist in spec
func (r *IndexerReconciler) cleanupOrphanedNodePools(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Build set of current nodePool names
	currentPools := make(map[string]bool)
	for _, pool := range cluster.Spec.Indexer.NodePools {
		currentPools[pool.Name] = true
	}

	// List all StatefulSets with nodePool label
	stsList := &appsv1.StatefulSetList{}
	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			constants.LabelInstance:  cluster.Name,
			constants.LabelComponent: constants.ComponentIndexer,
		},
	}

	if err := r.List(ctx, stsList, listOpts...); err != nil {
		return fmt.Errorf("failed to list statefulsets: %w", err)
	}

	// Find orphaned StatefulSets (have nodePool label but pool doesn't exist)
	for _, sts := range stsList.Items {
		poolName, hasPoolLabel := sts.Labels[constants.LabelNodePool]
		if !hasPoolLabel {
			// Not a nodePool StatefulSet, skip
			continue
		}

		if !currentPools[poolName] {
			// This nodePool no longer exists, delete its resources
			log.Info("Cleaning up orphaned nodePool resources", "pool", poolName)

			// Delete StatefulSet
			if err := r.Delete(ctx, &sts); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete orphaned StatefulSet", "name", sts.Name)
			}

			// Delete Service
			svcName := constants.IndexerNodePoolHeadlessName(cluster.Name, poolName)
			svc := &corev1.Service{}
			if err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cluster.Namespace}, svc); err == nil {
				if err := r.Delete(ctx, svc); err != nil && !errors.IsNotFound(err) {
					log.Error(err, "Failed to delete orphaned Service", "name", svcName)
				}
			}

			// Delete ConfigMap
			cmName := constants.IndexerNodePoolConfigName(cluster.Name, poolName)
			cm := &corev1.ConfigMap{}
			if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm); err == nil {
				if err := r.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
					log.Error(err, "Failed to delete orphaned ConfigMap", "name", cmName)
				}
			}

			// Remove from status
			delete(cluster.Status.Indexer.NodePoolStatuses, poolName)

			// Emit event
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "NodePoolDeleted",
					fmt.Sprintf("Deleted orphaned nodePool %s", poolName))
			}
		}
	}

	return nil
}

// updateNodePoolStatus updates the status for a specific nodePool
func (r *IndexerReconciler) updateNodePoolStatus(cluster *wazuhv1.WazuhCluster, poolName string, phase wazuhv1.NodePoolPhase, message string) {
	if cluster.Status.Indexer.NodePoolStatuses == nil {
		cluster.Status.Indexer.NodePoolStatuses = make(map[string]wazuhv1.NodePoolStatus)
	}

	status := cluster.Status.Indexer.NodePoolStatuses[poolName]
	status.Name = poolName
	status.Phase = phase
	status.Message = message
	status.StatefulSetName = constants.IndexerNodePoolName(cluster.Name, poolName)
	now := metav1.Now()
	status.LastTransitionTime = &now

	cluster.Status.Indexer.NodePoolStatuses[poolName] = status
}

// updateNodePoolStatusFromSts updates nodePool status from StatefulSet state
func (r *IndexerReconciler) updateNodePoolStatusFromSts(cluster *wazuhv1.WazuhCluster, poolName string, sts *appsv1.StatefulSet, phase wazuhv1.NodePoolPhase) {
	if cluster.Status.Indexer.NodePoolStatuses == nil {
		cluster.Status.Indexer.NodePoolStatuses = make(map[string]wazuhv1.NodePoolStatus)
	}

	status := cluster.Status.Indexer.NodePoolStatuses[poolName]
	status.Name = poolName
	status.Replicas = *sts.Spec.Replicas
	status.ReadyReplicas = sts.Status.ReadyReplicas
	status.Phase = phase
	status.StatefulSetName = sts.Name

	// Only update transition time if phase changed
	existing, exists := cluster.Status.Indexer.NodePoolStatuses[poolName]
	if !exists || existing.Phase != phase {
		now := metav1.Now()
		status.LastTransitionTime = &now
	} else {
		status.LastTransitionTime = existing.LastTransitionTime
	}

	cluster.Status.Indexer.NodePoolStatuses[poolName] = status
}

// getNodePoolPhase determines the phase of a nodePool from its StatefulSet
func (r *IndexerReconciler) getNodePoolPhase(sts *appsv1.StatefulSet) wazuhv1.NodePoolPhase {
	if sts.Status.ReadyReplicas == 0 {
		return wazuhv1.NodePoolPhaseCreating
	}
	if sts.Status.ReadyReplicas < *sts.Spec.Replicas {
		return wazuhv1.NodePoolPhaseScaling
	}
	if sts.Status.UpdatedReplicas < *sts.Spec.Replicas {
		return wazuhv1.NodePoolPhaseScaling
	}
	return wazuhv1.NodePoolPhaseRunning
}

// updateIndexerStatusFromNodePools aggregates nodePool statuses into overall indexer status
func (r *IndexerReconciler) updateIndexerStatusFromNodePools(cluster *wazuhv1.WazuhCluster) {
	var totalReplicas int32
	var totalReady int32
	allRunning := true
	var phases []string

	for _, status := range cluster.Status.Indexer.NodePoolStatuses {
		totalReplicas += status.Replicas
		totalReady += status.ReadyReplicas
		if status.Phase != wazuhv1.NodePoolPhaseRunning {
			allRunning = false
		}
		phases = append(phases, fmt.Sprintf("%s:%s", status.Name, status.Phase))
	}

	cluster.Status.Indexer.Replicas = totalReplicas
	cluster.Status.Indexer.ReadyReplicas = totalReady
	cluster.Status.Indexer.TopologyMode = constants.TopologyModeAdvanced

	// Determine overall phase
	if totalReady == 0 {
		cluster.Status.Indexer.Phase = wazuhv1.ComponentStatusPhaseStarting
	} else if allRunning && totalReady == totalReplicas {
		cluster.Status.Indexer.Phase = wazuhv1.ComponentStatusPhaseReady
	} else if totalReady < totalReplicas {
		cluster.Status.Indexer.Phase = wazuhv1.ComponentStatusPhaseScaling
	} else {
		cluster.Status.Indexer.Phase = wazuhv1.ComponentStatusPhaseDegraded
	}

	// Sort phases for consistent output
	sort.Strings(phases)
}

// reconcileClusterSettings applies cluster-level settings via the OpenSearch Cluster Settings API
// This is called after the cluster is healthy to ensure settings can be applied
func (r *IndexerReconciler) reconcileClusterSettings(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if cluster settings are defined
	if cluster.Spec.Indexer == nil || cluster.Spec.Indexer.ClusterSettings == nil {
		log.V(1).Info("No cluster settings defined, skipping")
		return nil
	}

	settings := cluster.Spec.Indexer.ClusterSettings

	// Skip if no settings are specified
	if len(settings.Persistent) == 0 && len(settings.Transient) == 0 {
		log.V(1).Info("Cluster settings are empty, skipping")
		return nil
	}

	// Compute hash of desired settings for change detection
	desiredHash := computeClusterSettingsHash(settings)

	// Compare with applied settings hash
	if cluster.Status.Indexer != nil && cluster.Status.Indexer.AppliedSettingsHash == desiredHash {
		log.V(1).Info("Cluster settings unchanged, skipping", "hash", utils.ShortHash(desiredHash))
		return nil
	}

	previousHash := ""
	if cluster.Status.Indexer != nil {
		previousHash = cluster.Status.Indexer.AppliedSettingsHash
	}
	log.Info("Cluster settings changed, applying",
		"previousHash", utils.ShortHash(previousHash),
		"newHash", utils.ShortHash(desiredHash))

	// Ensure OpenSearch client is available
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	// Check cluster health before applying settings
	health, err := r.osClient.GetClusterHealth(ctx)
	if err != nil {
		log.V(1).Info("Cannot get cluster health, deferring settings application", "error", err)
		return nil // Don't fail the reconciliation, retry later
	}

	if health.Status == "red" {
		log.Info("Cluster health is red, deferring settings application until healthy")
		return nil
	}

	// Apply settings via the API
	_, err = r.osClient.PutClusterSettingsFromMap(ctx, settings.Persistent, settings.Transient)
	if err != nil {
		// Emit warning event but don't fail reconciliation
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "ClusterSettingsFailed",
				fmt.Sprintf("Failed to apply cluster settings: %v", err))
		}
		return fmt.Errorf("failed to apply cluster settings: %w", err)
	}

	// Update status with applied settings hash
	if cluster.Status.Indexer == nil {
		cluster.Status.Indexer = &wazuhv1.ComponentStatus{}
	}
	cluster.Status.Indexer.AppliedSettingsHash = desiredHash

	// Emit success event
	if r.Recorder != nil {
		settingsCount := len(settings.Persistent) + len(settings.Transient)
		r.Recorder.Event(cluster, corev1.EventTypeNormal, "ClusterSettingsApplied",
			fmt.Sprintf("Successfully applied %d cluster settings", settingsCount))
	}

	log.Info("Cluster settings applied successfully",
		"persistent", len(settings.Persistent),
		"transient", len(settings.Transient))

	return nil
}

// computeClusterSettingsHash computes a deterministic hash of cluster settings
func computeClusterSettingsHash(settings *wazuhv1.ClusterSettingsSpec) string {
	if settings == nil {
		return ""
	}

	// Build a map combining both persistent and transient for hashing
	// Use map[string]string for patch.ComputeConfigHash compatibility
	combined := make(map[string]string)

	// Add persistent settings with "p:" prefix to distinguish from transient
	for k, v := range settings.Persistent {
		combined["p:"+k] = v
	}

	// Add transient settings with "t:" prefix
	for k, v := range settings.Transient {
		combined["t:"+k] = v
	}

	return patch.ComputeConfigHash(combined)
}

// reconcileIndexerPDB reconciles the PodDisruptionBudget for indexer pods
func (r *IndexerReconciler) reconcileIndexerPDB(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	pdbName := pdb.GetIndexerPDBName(cluster.Name)

	// Check if PDB should exist
	if !pdb.ShouldCreateIndexerPDB(cluster) {
		// If PDB should not exist, delete it if it does
		existing := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Indexer PDB (no longer needed)", "name", pdbName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete indexer PDB: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get indexer PDB: %w", err)
		}
		return nil
	}

	// Build the PDB
	builder := pdb.NewIndexerPDBBuilder(cluster)
	indexerPDB := builder.Build()

	// Warn if minAvailable >= total replicas (will block all disruptions)
	totalReplicas := cluster.Spec.Indexer.GetTotalReplicas()
	if indexerPDB.Spec.MinAvailable != nil && indexerPDB.Spec.MinAvailable.IntVal >= totalReplicas {
		log.Info("WARNING: Indexer PDB minAvailable >= total replicas - all voluntary disruptions will be blocked",
			"minAvailable", indexerPDB.Spec.MinAvailable.IntVal,
			"totalReplicas", totalReplicas,
			"pdbName", pdbName)
	}

	if err := controllerutil.SetControllerReference(cluster, indexerPDB, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer PDB: %w", err)
	}

	// Check if PDB exists
	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Indexer PDB", "name", pdbName)
		if err := r.Create(ctx, indexerPDB); err != nil {
			return fmt.Errorf("failed to create indexer PDB: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get indexer PDB: %w", err)
	}

	// Update PDB if needed
	indexerPDB.SetResourceVersion(existing.GetResourceVersion())
	log.Info("Updating Indexer PDB", "name", pdbName)
	if err := r.Update(ctx, indexerPDB); err != nil {
		return fmt.Errorf("failed to update indexer PDB: %w", err)
	}

	return nil
}

// reconcileHPA reconciles the HorizontalPodAutoscaler for indexer
// Note: HPA for StatefulSet requires careful consideration as OpenSearch
// needs shard rebalancing after scaling
func (r *IndexerReconciler) reconcileHPA(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	hpaName := cluster.Name + "-indexer"

	// Check if HPA should be enabled
	hpaEnabled := cluster.Spec.Indexer != nil &&
		cluster.Spec.Indexer.HPA != nil &&
		cluster.Spec.Indexer.HPA.Enabled

	if !hpaEnabled {
		// If HPA should not exist, delete it if it does
		existing := &autoscalingv2.HorizontalPodAutoscaler{}
		err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Indexer HPA (no longer needed)", "name", hpaName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete indexer HPA: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get indexer HPA: %w", err)
		}
		return nil
	}

	// Build the HPA
	builder := hpa.NewIndexerHPABuilder(cluster.Name, cluster.Namespace).
		WithSpec(cluster.Spec.Indexer.HPA)

	indexerHPA := builder.Build()
	if indexerHPA == nil {
		return nil
	}

	if err := controllerutil.SetControllerReference(cluster, indexerHPA, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer HPA: %w", err)
	}

	// Warn about StatefulSet HPA
	log.Info("WARNING: Enabling HPA for Indexer StatefulSet - ensure you have a shard rebalancing strategy",
		"name", hpaName,
		"minReplicas", *indexerHPA.Spec.MinReplicas,
		"maxReplicas", indexerHPA.Spec.MaxReplicas)

	// Check if HPA exists
	existing := &autoscalingv2.HorizontalPodAutoscaler{}
	err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Indexer HPA", "name", hpaName)
		if err := r.Create(ctx, indexerHPA); err != nil {
			return fmt.Errorf("failed to create indexer HPA: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get indexer HPA: %w", err)
	}

	// Update HPA if needed
	indexerHPA.SetResourceVersion(existing.GetResourceVersion())
	log.V(1).Info("Updating Indexer HPA", "name", hpaName)
	if err := r.Update(ctx, indexerHPA); err != nil {
		return fmt.Errorf("failed to update indexer HPA: %w", err)
	}

	return nil
}
