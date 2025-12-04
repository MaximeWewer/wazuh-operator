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

// Package reconciler provides helper reconcilers for OpenSearch components
package reconciler

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/bcrypt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/secrets"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/drain"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/storage"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	drainstate "github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerReconciler handles reconciliation of OpenSearch Indexer
type IndexerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

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

// WithRecorder sets the event recorder
func (r *IndexerReconciler) WithRecorder(recorder record.EventRecorder) *IndexerReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the OpenSearch Indexer
func (r *IndexerReconciler) Reconcile(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
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

	// Reconcile StatefulSet
	if err := r.reconcileStatefulSet(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer statefulset: %w", err)
	}

	// Reconcile Volume Expansion (after StatefulSet to ensure PVCs exist)
	if err := r.reconcileVolumeExpansion(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer volume expansion: %w", err)
	}

	log.Info("Indexer reconciliation completed")
	return nil
}

// reconcileSecrets reconciles indexer secrets (certs, credentials, security config)
func (r *IndexerReconciler) reconcileSecrets(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
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

		certsBuilder := secrets.NewIndexerCertsSecretBuilder(cluster.Name, cluster.Namespace)
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
			adminPassword = config.GenerateRandomPassword(24)
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
	} else {
		// Get existing password from credentials secret (but prefer external if specified)
		if adminPassword == "" {
			adminPassword = string(existingCreds.Data[constants.SecretKeyAdminPassword])
		}
	}

	// Security config secret with default configurations
	// Uses the same password as credentials secret
	securitySecretName := fmt.Sprintf("%s-indexer-security", cluster.Name)
	err = r.Get(ctx, types.NamespacedName{Name: securitySecretName, Namespace: cluster.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		securityBuilder := secrets.NewIndexerSecuritySecretBuilder(cluster.Name, cluster.Namespace)
		// Add default security configuration files with the SAME password as credentials
		securityBuilder.WithInternalUsers(generateDefaultInternalUsers(adminPassword))
		securityBuilder.WithRoles(generateDefaultRoles())
		securityBuilder.WithRolesMapping(generateDefaultRolesMapping())
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
func (r *IndexerReconciler) generateIndexerCertificates(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*indexerCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate CA
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-indexer-ca", cluster.Name))
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

	// Generate node certificate with SANs
	nodeConfig := certificates.DefaultNodeCertConfig(fmt.Sprintf("%s-indexer", cluster.Name))
	nodeConfig.DNSNames = certificates.GenerateIndexerNodeSANs(cluster.Name, cluster.Namespace, replicas)
	nodeConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	nodeCert, err := certificates.GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node certificate: %w", err)
	}
	log.V(1).Info("Generated node certificate", "sans", nodeConfig.DNSNames)

	// Generate admin certificate
	adminConfig := certificates.DefaultAdminCertConfig()
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
func (r *IndexerReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	// Determine replicas
	replicas := int32(1)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		replicas = cluster.Spec.Indexer.Replicas
	}

	// Build opensearch.yml content (version-aware configuration)
	opensearchYML := config.BuildIndexerConfig(cluster.Name, cluster.Namespace, replicas, cluster.Spec.Version)

	configBuilder := configmaps.NewIndexerConfigMapBuilder(cluster.Name, cluster.Namespace)
	configBuilder.WithOpenSearchYML(opensearchYML)
	configMap := configBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer configmap: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// getConfigHash retrieves the current config hash from the indexer ConfigMap
func (r *IndexerReconciler) getConfigHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) string {
	configMapName := fmt.Sprintf("%s-indexer-config", cluster.Name)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// reconcileServices reconciles indexer services
func (r *IndexerReconciler) reconcileServices(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	serviceBuilder := services.NewIndexerServiceBuilder(cluster.Name, cluster.Namespace)

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
func (r *IndexerReconciler) reconcileStatefulSet(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	return r.reconcileStatefulSetWithCertHash(ctx, cluster, "")
}

// reconcileStatefulSetWithCertHash reconciles the indexer StatefulSet with an optional certificate hash
// When the cert hash changes, the StatefulSet will be updated which triggers a pod rollout
func (r *IndexerReconciler) reconcileStatefulSetWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
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
		if cluster.Spec.StorageClassName != nil && *cluster.Spec.StorageClassName != "" {
			stsBuilder.WithStorageClassName(*cluster.Spec.StorageClassName)
		}
		if cluster.Spec.Indexer.JavaOpts != "" {
			stsBuilder.WithJavaOpts(cluster.Spec.Indexer.JavaOpts)
		}
	}

	// Set cert hash to trigger pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	// Set cluster reference for monitoring (Prometheus plugin and metrics)
	stsBuilder.WithCluster(cluster)

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

	// Check if update is needed (cert hash changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Indexer StatefulSet due to certificate hash change",
				"name", sts.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
		}
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update indexer statefulset: %w", err)
		}

		// Wait for the StatefulSet to be ready after update (graceful rollout)
		// This ensures new pods are healthy before the reconcile completes
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

	return nil
}

// ReconcileWithCertHash reconciles the OpenSearch Indexer with certificate hash for pod restart
// DEPRECATED: Use ReconcileNonBlocking for non-blocking rollouts
func (r *IndexerReconciler) ReconcileWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
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
func (r *IndexerReconciler) ReconcileNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) IndexerReconcileResult {
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

	log.Info("Indexer reconciliation completed (non-blocking)", "hasPendingRollout", pendingRollout != nil)
	return IndexerReconcileResult{PendingRollout: pendingRollout}
}

// reconcileStatefulSetNonBlocking reconciles the indexer StatefulSet without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *IndexerReconciler) reconcileStatefulSetNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	var (
		replicas     int32 = constants.DefaultIndexerReplicas
		resources    *corev1.ResourceRequirements
		storageSize  = constants.DefaultIndexerStorageSize
		javaOpts     = constants.DefaultIndexerJavaOpts
		image        string
		nodeSelector map[string]string
		tolerations  []corev1.Toleration
		affinity     *corev1.Affinity
		env          []corev1.EnvVar
		envFrom      []corev1.EnvFromSource
		annotations  map[string]string
	)
	version := cluster.Spec.Version

	// Check if monitoring is enabled
	monitoringEnabled := cluster.Spec.Monitoring != nil && cluster.Spec.Monitoring.Enabled

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
		env = cluster.Spec.Indexer.Env
		envFrom = cluster.Spec.Indexer.EnvFrom
		annotations = cluster.Spec.Indexer.Annotations
	}

	// Compute spec hash for change detection (includes all configurable fields)
	specHash, err := patch.ComputeIndexerSpecHashFull(patch.IndexerSpecInput{
		Replicas:          replicas,
		Version:           version,
		Resources:         resources,
		StorageSize:       storageSize,
		JavaOpts:          javaOpts,
		Image:             image,
		NodeSelector:      nodeSelector,
		Tolerations:       tolerations,
		Affinity:          affinity,
		Env:               env,
		EnvFrom:           envFrom,
		Annotations:       annotations,
		MonitoringEnabled: monitoringEnabled,
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
		if cluster.Spec.StorageClassName != nil && *cluster.Spec.StorageClassName != "" {
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
		if len(env) > 0 {
			stsBuilder.WithEnv(env)
		}
		if len(envFrom) > 0 {
			stsBuilder.WithEnvFrom(envFrom)
		}
		if len(annotations) > 0 {
			stsBuilder.WithAnnotations(annotations)
		}
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
		log.Info("Creating Indexer StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash), "specHash", patch.ShortHash(specHash))
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
			"oldSpecHash", patch.ShortHash(existingSpecHash),
			"newSpecHash", patch.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Emit event for spec change detection
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Indexer spec changed, updating StatefulSet %s", sts.Name))
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
			updateReason = updateReason + ",certificate-renewal"
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
			"oldConfigHash", patch.ShortHash(existingConfigHash),
			"newConfigHash", patch.ShortHash(configHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "config-change"
		} else {
			updateReason = updateReason + ",config-change"
		}

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

		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to update indexer statefulset: %w", err)
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
func (r *IndexerReconciler) GetStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*wazuhv1alpha1.ComponentStatus, error) {
	sts := &appsv1.StatefulSet{}
	name := fmt.Sprintf("%s-indexer", cluster.Name)

	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return &wazuhv1alpha1.ComponentStatus{
		Replicas:      sts.Status.Replicas,
		ReadyReplicas: sts.Status.ReadyReplicas,
		Phase:         getStatefulSetPhase(sts),
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
func (r *IndexerReconciler) CheckScaleDownDrain(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, desiredReplicas int32) (*DrainCheckResult, error) {
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
	case wazuhv1alpha1.DrainPhaseIdle, "":
		// Start new drain
		log.Info("Starting indexer drain for scale-down", "targetPod", scaleInfo.TargetPodName)
		if err := r.startDrain(ctx, cluster, scaleInfo, drainStatus); err != nil {
			result.Error = err
			return result, err
		}
		result.DrainInProgress = true
		return result, nil

	case wazuhv1alpha1.DrainPhasePending, wazuhv1alpha1.DrainPhaseDraining:
		// Drain in progress, check status
		result.DrainInProgress = true
		progress, err := r.monitorDrainProgress(ctx, cluster, scaleInfo.TargetPodName, drainStatus)
		if err != nil {
			result.Error = err
			return result, nil // Continue reconciliation, don't fail
		}
		result.Progress = progress
		return result, nil

	case wazuhv1alpha1.DrainPhaseVerifying:
		// Verify completion
		complete, err := r.verifyDrainComplete(ctx, cluster, scaleInfo.TargetPodName, drainStatus)
		if err != nil {
			result.Error = err
			return result, nil
		}
		if complete {
			result.DrainComplete = true
			result.DrainInProgress = false
		} else {
			result.DrainInProgress = true
		}
		return result, nil

	case wazuhv1alpha1.DrainPhaseComplete:
		// Drain complete, proceed with scale-down
		log.Info("Indexer drain complete, proceeding with scale-down")
		result.DrainComplete = true
		return result, nil

	case wazuhv1alpha1.DrainPhaseFailed:
		// Drain failed - check if we should retry or skip
		log.Info("Previous drain failed", "message", drainStatus.Message)
		result.Error = fmt.Errorf("drain failed: %s", drainStatus.Message)
		return result, nil

	default:
		log.Info("Unknown drain phase", "phase", drainStatus.Phase)
		return result, nil
	}
}

// getOrInitDrainStatus returns the current drain status or initializes a new one
func (r *IndexerReconciler) getOrInitDrainStatus(cluster *wazuhv1alpha1.WazuhCluster) *wazuhv1alpha1.ComponentDrainStatus {
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
	}
	if cluster.Status.Drain.Indexer == nil {
		cluster.Status.Drain.Indexer = &wazuhv1alpha1.ComponentDrainStatus{
			Phase: wazuhv1alpha1.DrainPhaseIdle,
		}
	}
	return cluster.Status.Drain.Indexer
}

// startDrain initiates the drain process for an indexer node
func (r *IndexerReconciler) startDrain(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, scaleInfo drainstate.ScaleDownInfo, status *wazuhv1alpha1.ComponentDrainStatus) error {
	log := logf.FromContext(ctx)

	// Initialize OpenSearch client if needed
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	// Get drain configuration
	var drainConfig *wazuhv1alpha1.IndexerDrainConfig
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
		drainstate.MarkFailed(status, fmt.Sprintf("Failed to start drain: %v", err))
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.DrainEventReasonFailed,
				fmt.Sprintf("Failed to start indexer drain: %v", err))
		}
		return err
	}

	// Transition to draining phase
	if err := drainstate.TransitionTo(status, wazuhv1alpha1.DrainPhaseDraining, "Relocating shards from node"); err != nil {
		log.Error(err, "Failed to transition to draining phase")
	}

	log.Info("Indexer drain started successfully", "node", nodeName)
	return nil
}

// monitorDrainProgress checks the current drain progress
func (r *IndexerReconciler) monitorDrainProgress(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string, status *wazuhv1alpha1.ComponentDrainStatus) (*drain.DrainProgress, error) {
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
		if err := drainstate.TransitionTo(status, wazuhv1alpha1.DrainPhaseVerifying, "Verifying drain completion"); err != nil {
			log.Error(err, "Failed to transition to verifying phase")
		}
	}

	return &progress, nil
}

// verifyDrainComplete verifies that drain is fully complete
func (r *IndexerReconciler) verifyDrainComplete(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string, status *wazuhv1alpha1.ComponentDrainStatus) (bool, error) {
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
func (r *IndexerReconciler) ensureOpenSearchClient(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	if r.osClient != nil {
		return nil
	}

	clientFactory := security.NewOpenSearchClientFactory(r.Client)
	client, err := clientFactory.GetClientForCluster(ctx, cluster)
	if err != nil {
		return err
	}

	r.osClient = client
	return nil
}

// ResetDrainState resets the drain state after a successful scale-down
func (r *IndexerReconciler) ResetDrainState(cluster *wazuhv1alpha1.WazuhCluster) {
	if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
		drainstate.Reset(cluster.Status.Drain.Indexer)
	}
	// Clear cached drainer for next operation
	r.drainer = nil
}

// EvaluateDrainFeasibility evaluates if drain is feasible (for dry-run mode)
func (r *IndexerReconciler) EvaluateDrainFeasibility(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string) (*wazuhv1alpha1.DryRunResult, error) {
	// Initialize OpenSearch client if needed
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return &wazuhv1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentIndexer,
			Blockers:    []string{fmt.Sprintf("Cannot connect to OpenSearch: %v", err)},
		}, nil
	}

	// Get drain configuration
	var drainConfig *wazuhv1alpha1.IndexerDrainConfig
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

		existing := obj.DeepCopyObject().(client.Object)

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
			existingSvc := existing.(*corev1.Service)
			svc.Spec.ClusterIP = existingSvc.Spec.ClusterIP
			svc.Spec.ClusterIPs = existingSvc.Spec.ClusterIPs
		}

		log.V(1).Info("Updating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		obj.SetResourceVersion(existing.GetResourceVersion())
		return r.Update(ctx, obj)
	})
}

// getStatefulSetPhase returns the phase of a StatefulSet
func getStatefulSetPhase(sts *appsv1.StatefulSet) string {
	if sts.Status.ReadyReplicas == 0 {
		return "Starting"
	}
	if sts.Status.ReadyReplicas < sts.Status.Replicas {
		return "Degraded"
	}
	if sts.Status.UpdatedReplicas < sts.Status.Replicas {
		return "Updating"
	}
	return "Ready"
}

// ReconcileStandalone reconciles a standalone OpenSearchIndexer resource
func (r *IndexerReconciler) ReconcileStandalone(ctx context.Context, indexer *wazuhv1alpha1.OpenSearchIndexer) error {
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

		certsBuilder := secrets.NewIndexerCertsSecretBuilder(indexer.Name, indexer.Namespace)
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
	}

	log.Info("Standalone indexer reconciliation completed", "name", indexer.Name)
	return nil
}

// generateStandaloneIndexerCertificates generates certificates for standalone indexer
func (r *IndexerReconciler) generateStandaloneIndexerCertificates(ctx context.Context, indexer *wazuhv1alpha1.OpenSearchIndexer) (*indexerCertificates, error) {
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
func generateDefaultRolesMapping() []byte {
	return []byte(`---
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
    - "CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"
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
`)
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

// CheckSecurityInitialization checks if OpenSearch security is initialized
// and updates the cluster status accordingly
func (r *IndexerReconciler) CheckSecurityInitialization(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (bool, error) {
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

	// Create OpenSearch client factory and get a client
	clientFactory := security.NewOpenSearchClientFactory(r.Client)
	osClient, err := clientFactory.GetClientForCluster(ctx, cluster)
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
		cluster.Status.Security = &wazuhv1alpha1.SecurityStatus{}
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
func (r *IndexerReconciler) SyncSecurityCRDs(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if security is initialized
	if cluster.Status.Security == nil || !cluster.Status.Security.Initialized {
		log.V(1).Info("Security not initialized, skipping CRD sync")
		return nil
	}

	// Create client factory and synchronizer
	clientFactory := security.NewOpenSearchClientFactory(r.Client)
	synchronizer := security.NewSecurityConfigSynchronizer(r.Client, clientFactory, r.Recorder)

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

	return nil
}

// DetectIndexerRestart checks if the indexer has restarted since last check
func (r *IndexerReconciler) DetectIndexerRestart(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (bool, error) {
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
		cluster.Status.Security = &wazuhv1alpha1.SecurityStatus{}
	}

	storedRestarts := cluster.Status.Security.IndexerRestartCount
	if totalRestarts > storedRestarts {
		cluster.Status.Security.IndexerRestartCount = totalRestarts
		return true, nil
	}

	return false, nil
}

// ResolveAndSetDefaultAdmin resolves the default admin user and updates cluster status
func (r *IndexerReconciler) ResolveAndSetDefaultAdmin(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	credManager := security.NewCredentialManager(r.Client, r.Recorder)
	creds, err := credManager.GetAdminCredentials(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get admin credentials: %w", err)
	}

	// Update status
	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1alpha1.SecurityStatus{}
	}
	cluster.Status.Security.DefaultAdminUser = creds.Username
	cluster.Status.Security.DefaultAdminSource = creds.Source

	log.V(1).Info("Resolved default admin user",
		"username", creds.Username,
		"source", creds.Source)

	return nil
}

// reconcileVolumeExpansion handles PVC volume expansion for indexer pods
func (r *IndexerReconciler) reconcileVolumeExpansion(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
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
func (r *IndexerReconciler) getIndexerPVCs(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*corev1.PersistentVolumeClaimList, error) {
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
func (r *IndexerReconciler) updateIndexerExpansionStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, requestedSize string, pvcsExpanded, pvcsPending []string, expansionError error) {
	log := logf.FromContext(ctx)

	// Initialize VolumeExpansion status if needed
	if cluster.Status.VolumeExpansion == nil {
		cluster.Status.VolumeExpansion = &wazuhv1alpha1.VolumeExpansionStatus{}
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
