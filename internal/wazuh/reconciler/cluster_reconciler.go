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

// Package reconciler provides helper reconcilers for Wazuh components
package reconciler

import (
	"context"
	"fmt"
	"net"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/cronjobs"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/secrets"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ClusterReconciler handles reconciliation of Wazuh cluster components
type ClusterReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	requeueInterval time.Duration
}

// NewClusterReconciler creates a new ClusterReconciler
func NewClusterReconciler(c client.Client, scheme *runtime.Scheme) *ClusterReconciler {
	return &ClusterReconciler{
		Client:          c,
		Scheme:          scheme,
		requeueInterval: constants.DefaultRequeueAfter,
	}
}

// RequeueInterval returns the requeue interval
func (r *ClusterReconciler) RequeueInterval() time.Duration {
	return r.requeueInterval
}

// ReconcileCertificates reconciles TLS certificates for the cluster
func (r *ClusterReconciler) ReconcileCertificates(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if certificates already exist
	certsSecretName := fmt.Sprintf("%s-manager-certs", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Generate new certificates
		certs, err := r.generateManagerCertificates(ctx, cluster)
		if err != nil {
			return fmt.Errorf("failed to generate manager certificates: %w", err)
		}

		certsBuilder := secrets.NewManagerCertsSecretBuilder(cluster.Name, cluster.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithNodeCert(certs.nodeCert).
			WithNodeKey(certs.nodeKey).
			WithFilebeatCert(certs.filebeatCert).
			WithFilebeatKey(certs.filebeatKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(cluster, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for certs secret: %w", err)
		}

		log.Info("Creating Manager certificates secret", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get certs secret: %w", err)
	}

	// Build cluster key secret
	clusterKeySecretName := fmt.Sprintf("%s-cluster-key", cluster.Name)
	err = r.Get(ctx, types.NamespacedName{Name: clusterKeySecretName, Namespace: cluster.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		clusterKeyBuilder := secrets.NewClusterKeySecretBuilder(cluster.Name, cluster.Namespace)
		clusterKey, err := config.GenerateClusterKey()
		if err != nil {
			return fmt.Errorf("failed to generate cluster key: %w", err)
		}
		clusterKeySecret := clusterKeyBuilder.WithClusterKey(clusterKey).Build()

		if err := controllerutil.SetControllerReference(cluster, clusterKeySecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for cluster key secret: %w", err)
		}

		log.Info("Creating cluster key secret", "name", clusterKeySecret.Name)
		if err := r.Create(ctx, clusterKeySecret); err != nil {
			return fmt.Errorf("failed to create cluster key secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get cluster key secret: %w", err)
	}

	return nil
}

// managerCertificates holds all generated certificates for the manager
type managerCertificates struct {
	caCert       []byte
	nodeCert     []byte
	nodeKey      []byte
	filebeatCert []byte
	filebeatKey  []byte
}

// generateManagerCertificates generates all certificates needed for the manager
func (r *ClusterReconciler) generateManagerCertificates(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*managerCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate CA
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-manager-ca", cluster.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for manager")

	// Determine worker replicas for SANs
	var workerReplicas int32 = 0
	if cluster.Spec.Manager != nil {
		workerReplicas = cluster.Spec.Manager.Workers.GetReplicas()
	}

	// Generate node certificate with SANs
	nodeConfig := certificates.DefaultNodeCertConfig(fmt.Sprintf("%s-manager", cluster.Name))
	nodeConfig.DNSNames = certificates.GenerateManagerNodeSANs(cluster.Name, cluster.Namespace, workerReplicas)
	nodeConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	nodeCert, err := certificates.GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node certificate: %w", err)
	}
	log.V(1).Info("Generated node certificate", "sans", nodeConfig.DNSNames)

	// Generate filebeat certificate for OpenSearch communication
	filebeatConfig := certificates.DefaultFilebeatCertConfig()
	filebeatConfig.DNSNames = certificates.GenerateFilebeatSANs(cluster.Name, cluster.Namespace, workerReplicas)
	filebeatConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	filebeatCert, err := certificates.GenerateFilebeatCert(filebeatConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate filebeat certificate: %w", err)
	}
	log.V(1).Info("Generated filebeat certificate", "sans", filebeatConfig.DNSNames)

	return &managerCertificates{
		caCert:       ca.CertificatePEM,
		nodeCert:     nodeCert.CertificatePEM,
		nodeKey:      nodeCert.PrivateKeyPEM,
		filebeatCert: filebeatCert.CertificatePEM,
		filebeatKey:  filebeatCert.PrivateKeyPEM,
	}, nil
}

// ManagerReconcileResult contains the result of manager reconciliation
type ManagerReconcileResult struct {
	// PendingRollouts contains rollouts that were initiated but not yet complete
	PendingRollouts []utils.PendingRollout
	// Error if any occurred during reconciliation
	Error error
}

// ReconcileManager reconciles the Wazuh Manager (master and workers)
func (r *ClusterReconciler) ReconcileManager(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	return r.ReconcileManagerWithCertHashes(ctx, cluster, "", "")
}

// ReconcileManagerWithCertHashes reconciles the Wazuh Manager with certificate hashes for pod restart
// DEPRECATED: Use ReconcileManagerNonBlocking for non-blocking rollouts
func (r *ClusterReconciler) ReconcileManagerWithCertHashes(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, masterCertHash, workerCertHash string) error {
	log := logf.FromContext(ctx)

	// Ensure cluster key secret exists (needed for manager cluster communication)
	if err := r.ensureClusterKeySecret(ctx, cluster); err != nil {
		return fmt.Errorf("failed to ensure cluster key secret: %w", err)
	}

	// Ensure API credentials secret exists (needed for Wazuh exporter sidecar)
	if err := r.ensureAPICredentialsSecret(ctx, cluster); err != nil {
		return fmt.Errorf("failed to ensure API credentials secret: %w", err)
	}

	// Reconcile Master
	if err := r.reconcileMasterWithCertHash(ctx, cluster, masterCertHash); err != nil {
		return fmt.Errorf("failed to reconcile master: %w", err)
	}

	// Reconcile Workers
	if err := r.reconcileWorkersWithCertHash(ctx, cluster, workerCertHash); err != nil {
		return fmt.Errorf("failed to reconcile workers: %w", err)
	}

	log.Info("Manager reconciliation completed")
	return nil
}

// ReconcileManagerNonBlocking reconciles the Wazuh Manager without blocking on rollouts
// Returns pending rollouts that should be tracked and monitored by the caller
func (r *ClusterReconciler) ReconcileManagerNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, masterCertHash, workerCertHash string) ManagerReconcileResult {
	log := logf.FromContext(ctx)
	var pendingRollouts []utils.PendingRollout

	// Ensure cluster key secret exists (needed for manager cluster communication)
	if err := r.ensureClusterKeySecret(ctx, cluster); err != nil {
		return ManagerReconcileResult{Error: fmt.Errorf("failed to ensure cluster key secret: %w", err)}
	}

	// Ensure API credentials secret exists (needed for Wazuh exporter sidecar)
	if err := r.ensureAPICredentialsSecret(ctx, cluster); err != nil {
		return ManagerReconcileResult{Error: fmt.Errorf("failed to ensure API credentials secret: %w", err)}
	}

	// Reconcile Master (non-blocking)
	masterRollout, err := r.reconcileMasterNonBlocking(ctx, cluster, masterCertHash)
	if err != nil {
		return ManagerReconcileResult{Error: fmt.Errorf("failed to reconcile master: %w", err)}
	}
	if masterRollout != nil {
		pendingRollouts = append(pendingRollouts, *masterRollout)
	}

	// Reconcile Workers (non-blocking)
	workerRollout, err := r.reconcileWorkersNonBlocking(ctx, cluster, workerCertHash)
	if err != nil {
		return ManagerReconcileResult{Error: fmt.Errorf("failed to reconcile workers: %w", err)}
	}
	if workerRollout != nil {
		pendingRollouts = append(pendingRollouts, *workerRollout)
	}

	log.Info("Manager reconciliation completed (non-blocking)", "pendingRollouts", len(pendingRollouts))
	return ManagerReconcileResult{PendingRollouts: pendingRollouts}
}

// reconcileMasterNonBlocking reconciles the master without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *ClusterReconciler) reconcileMasterNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Build ConfigMap (same as blocking version)
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "master")

	ossecConf, err := config.BuildMasterConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-master", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to build ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	sslVerificationMode := "full"
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.FilebeatSSLVerificationMode != "" {
		sslVerificationMode = cluster.Spec.Manager.FilebeatSSLVerificationMode
	}

	indexerUsername, indexerPassword := r.resolveIndexerCredentials(ctx, cluster)

	filebeatConf, err := config.BuildFilebeatConfigWithCredentials(
		cluster.Name,
		cluster.Namespace,
		indexerService,
		sslVerificationMode,
		indexerUsername,
		indexerPassword,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return nil, fmt.Errorf("failed to reconcile master configmap: %w", err)
	}

	// Build Services (same as blocking version)
	serviceBuilder := services.NewManagerServiceBuilder(cluster.Name, cluster.Namespace, "master")
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return nil, fmt.Errorf("failed to reconcile master service: %w", err)
	}

	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master headless service: %w", err)
	}
	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return nil, fmt.Errorf("failed to reconcile master headless service: %w", err)
	}

	// Build StatefulSet
	stsBuilder := deployments.NewManagerStatefulSetBuilder(cluster.Name, cluster.Namespace, "master")
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Resources != nil {
		stsBuilder.WithResources(cluster.Spec.Manager.Master.Resources)
	}
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	// Set cluster reference for monitoring sidecar
	stsBuilder.WithCluster(cluster)

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Master StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create master statefulset: %w", err)
		}
		// New StatefulSet - return pending rollout to track initial readiness
		return &utils.PendingRollout{
			Component: "manager-master",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "initial-creation",
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get master statefulset: %w", err)
	}

	// Check if update is needed (cert hash changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	if certHash != "" && certHash != existingCertHash {
		log.Info("Updating Master StatefulSet due to certificate hash change (non-blocking)",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))

		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to update master statefulset: %w", err)
		}

		// Return pending rollout instead of waiting
		return &utils.PendingRollout{
			Component: "manager-master",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "certificate-renewal",
		}, nil
	}

	return nil, nil
}

// reconcileWorkersNonBlocking reconciles the workers without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *ClusterReconciler) reconcileWorkersNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "worker")

	masterAddr := config.GetMasterServiceAddress(cluster.Name, cluster.Namespace)
	ossecConf, err := config.BuildWorkerConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-worker", "", masterAddr, int(constants.PortManagerCluster), "")
	if err != nil {
		return nil, fmt.Errorf("failed to build worker ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	sslVerificationMode := "full"
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.FilebeatSSLVerificationMode != "" {
		sslVerificationMode = cluster.Spec.Manager.FilebeatSSLVerificationMode
	}

	indexerUsername, indexerPassword := r.resolveIndexerCredentials(ctx, cluster)

	filebeatConf, err := config.BuildFilebeatConfigWithCredentials(
		cluster.Name,
		cluster.Namespace,
		indexerService,
		sslVerificationMode,
		indexerUsername,
		indexerPassword,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return nil, fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	// Build Services
	serviceBuilder := services.NewWorkerServiceBuilder(cluster.Name, cluster.Namespace)
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return nil, fmt.Errorf("failed to reconcile worker service: %w", err)
	}

	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker headless service: %w", err)
	}
	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return nil, fmt.Errorf("failed to reconcile worker headless service: %w", err)
	}

	// Build StatefulSet
	stsBuilder := deployments.NewWorkerStatefulSetBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	// Always set replicas from spec (including 0 for no workers)
	var workerReplicas int32 = 0
	if cluster.Spec.Manager != nil {
		workerReplicas = cluster.Spec.Manager.Workers.GetReplicas()
		if cluster.Spec.Manager.Workers.Resources != nil {
			stsBuilder.WithResources(cluster.Spec.Manager.Workers.Resources)
		}
	}
	stsBuilder.WithReplicas(workerReplicas)
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Worker StatefulSet", "name", sts.Name, "replicas", workerReplicas, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create worker statefulset: %w", err)
		}
		return &utils.PendingRollout{
			Component: "manager-worker",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "initial-creation",
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get worker statefulset: %w", err)
	}

	// Check if update is needed (cert hash changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	if certHash != "" && certHash != existingCertHash {
		log.Info("Updating Worker StatefulSet due to certificate hash change (non-blocking)",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))

		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to update worker statefulset: %w", err)
		}

		return &utils.PendingRollout{
			Component: "manager-worker",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "certificate-renewal",
		}, nil
	}

	return nil, nil
}

// resolveIndexerCredentials resolves indexer credentials from secret
func (r *ClusterReconciler) resolveIndexerCredentials(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (string, string) {
	log := logf.FromContext(ctx)
	indexerUsername := ""
	indexerPassword := ""

	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Credentials != nil && cluster.Spec.Indexer.Credentials.SecretName != "" {
		usernameKey := "username"
		if cluster.Spec.Indexer.Credentials.UsernameKey != "" {
			usernameKey = cluster.Spec.Indexer.Credentials.UsernameKey
		}
		username, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, usernameKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer username from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerUsername = username
		}

		passwordKey := "password"
		if cluster.Spec.Indexer.Credentials.PasswordKey != "" {
			passwordKey = cluster.Spec.Indexer.Credentials.PasswordKey
		}
		password, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, passwordKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer password from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerPassword = password
		}
	}

	return indexerUsername, indexerPassword
}

// reconcileMaster reconciles the master manager node
func (r *ClusterReconciler) reconcileMaster(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	return r.reconcileMasterWithCertHash(ctx, cluster, "")
}

// reconcileMasterWithCertHash reconciles the master manager node with certificate hash for pod restart
func (r *ClusterReconciler) reconcileMasterWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "master")

	// Generate ossec.conf
	ossecConf, err := config.BuildMasterConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-master", "", "")
	if err != nil {
		return fmt.Errorf("failed to build ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	// Generate filebeat.yml with correct indexer host and credentials
	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	sslVerificationMode := "full"
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.FilebeatSSLVerificationMode != "" {
		sslVerificationMode = cluster.Spec.Manager.FilebeatSSLVerificationMode
	}

	// Resolve indexer credentials from secret
	indexerUsername := ""
	indexerPassword := ""
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Credentials != nil && cluster.Spec.Indexer.Credentials.SecretName != "" {
		// Resolve username
		usernameKey := "username"
		if cluster.Spec.Indexer.Credentials.UsernameKey != "" {
			usernameKey = cluster.Spec.Indexer.Credentials.UsernameKey
		}
		username, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, usernameKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer username from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerUsername = username
		}

		// Resolve password
		passwordKey := "password"
		if cluster.Spec.Indexer.Credentials.PasswordKey != "" {
			passwordKey = cluster.Spec.Indexer.Credentials.PasswordKey
		}
		password, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, passwordKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer password from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerPassword = password
		}
	}

	filebeatConf, err := config.BuildFilebeatConfigWithCredentials(
		cluster.Name,
		cluster.Namespace,
		indexerService,
		sslVerificationMode,
		indexerUsername,
		indexerPassword,
	)
	if err != nil {
		return fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for master configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile master configmap: %w", err)
	}

	// Build Service
	serviceBuilder := services.NewManagerServiceBuilder(cluster.Name, cluster.Namespace, "master")
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for master service: %w", err)
	}

	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile master service: %w", err)
	}

	// Build Headless Service
	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for master headless service: %w", err)
	}

	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return fmt.Errorf("failed to reconcile master headless service: %w", err)
	}

	// Build StatefulSet
	stsBuilder := deployments.NewManagerStatefulSetBuilder(cluster.Name, cluster.Namespace, "master")
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Resources != nil {
		stsBuilder.WithResources(cluster.Spec.Manager.Master.Resources)
	}
	// Set cert hash for pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	// Set cluster reference for monitoring sidecar
	stsBuilder.WithCluster(cluster)

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for master statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Master StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create master statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get master statefulset: %w", err)
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
			log.Info("Updating Master StatefulSet due to certificate hash change",
				"name", sts.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
		}
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update master statefulset: %w", err)
		}

		// Wait for the StatefulSet to be ready after update (graceful rollout)
		// This ensures new pods are healthy before the reconcile completes
		log.Info("Waiting for Master StatefulSet to be ready after certificate renewal",
			"name", sts.Name,
			"timeout", utils.DefaultRolloutTimeout)

		waiter := utils.NewRolloutWaiter(r.Client)
		result := waiter.WaitForStatefulSetReadyWithResult(ctx, sts.Namespace, sts.Name)
		if result.TimedOut {
			log.Error(result.Error, "Timeout waiting for Master StatefulSet to be ready",
				"name", sts.Name,
				"timeout", utils.DefaultRolloutTimeout)
			// Don't fail the reconcile on timeout - the StatefulSet strategy ensures
			// OrderedReady policy, so old pods are kept until new ones are ready
			return nil
		}
		if result.Error != nil {
			return fmt.Errorf("error waiting for master statefulset to be ready: %w", result.Error)
		}

		log.Info("Master StatefulSet is ready after certificate renewal", "name", sts.Name)
	}

	return nil
}

// reconcileWorkers reconciles the worker manager nodes
func (r *ClusterReconciler) reconcileWorkers(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	return r.reconcileWorkersWithCertHash(ctx, cluster, "")
}

// reconcileWorkersWithCertHash reconciles the worker manager nodes with certificate hash for pod restart
func (r *ClusterReconciler) reconcileWorkersWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "worker")

	masterAddr := config.GetMasterServiceAddress(cluster.Name, cluster.Namespace)
	ossecConf, err := config.BuildWorkerConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-worker", "", masterAddr, int(constants.PortManagerCluster), "")
	if err != nil {
		return fmt.Errorf("failed to build worker ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	// Generate filebeat.yml with correct indexer host and credentials
	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	sslVerificationMode := "full"
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.FilebeatSSLVerificationMode != "" {
		sslVerificationMode = cluster.Spec.Manager.FilebeatSSLVerificationMode
	}

	// Resolve indexer credentials from secret
	indexerUsername := ""
	indexerPassword := ""
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Credentials != nil && cluster.Spec.Indexer.Credentials.SecretName != "" {
		// Resolve username
		usernameKey := "username"
		if cluster.Spec.Indexer.Credentials.UsernameKey != "" {
			usernameKey = cluster.Spec.Indexer.Credentials.UsernameKey
		}
		username, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, usernameKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer username from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerUsername = username
		}

		// Resolve password
		passwordKey := "password"
		if cluster.Spec.Indexer.Credentials.PasswordKey != "" {
			passwordKey = cluster.Spec.Indexer.Credentials.PasswordKey
		}
		password, err := r.resolveSecretKey(ctx, cluster.Namespace, cluster.Spec.Indexer.Credentials.SecretName, passwordKey)
		if err != nil {
			log.Error(err, "Failed to resolve indexer password from secret", "secret", cluster.Spec.Indexer.Credentials.SecretName)
		} else {
			indexerPassword = password
		}
	}

	filebeatConf, err := config.BuildFilebeatConfigWithCredentials(
		cluster.Name,
		cluster.Namespace,
		indexerService,
		sslVerificationMode,
		indexerUsername,
		indexerPassword,
	)
	if err != nil {
		return fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for worker configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	// Build Service
	serviceBuilder := services.NewWorkerServiceBuilder(cluster.Name, cluster.Namespace)
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for worker service: %w", err)
	}

	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile worker service: %w", err)
	}

	// Build Headless Service for StatefulSet
	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for worker headless service: %w", err)
	}

	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return fmt.Errorf("failed to reconcile worker headless service: %w", err)
	}

	// Build StatefulSet
	stsBuilder := deployments.NewWorkerStatefulSetBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	// Always set replicas from spec (including 0 for no workers)
	var workerReplicas2 int32 = 0
	if cluster.Spec.Manager != nil {
		workerReplicas2 = cluster.Spec.Manager.Workers.GetReplicas()
		if cluster.Spec.Manager.Workers.Resources != nil {
			stsBuilder.WithResources(cluster.Spec.Manager.Workers.Resources)
		}
	}
	stsBuilder.WithReplicas(workerReplicas2)
	// Set cert hash for pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for worker statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Worker StatefulSet", "name", sts.Name, "replicas", workerReplicas2, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create worker statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get worker statefulset: %w", err)
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
			log.Info("Updating Worker StatefulSet due to certificate hash change",
				"name", sts.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
		}
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update worker statefulset: %w", err)
		}

		// Wait for the StatefulSet to be ready after update (graceful rollout)
		// This ensures new pods are healthy before the reconcile completes
		log.Info("Waiting for Worker StatefulSet to be ready after certificate renewal",
			"name", sts.Name,
			"timeout", utils.DefaultRolloutTimeout)

		waiter := utils.NewRolloutWaiter(r.Client)
		result := waiter.WaitForStatefulSetReadyWithResult(ctx, sts.Namespace, sts.Name)
		if result.TimedOut {
			log.Error(result.Error, "Timeout waiting for Worker StatefulSet to be ready",
				"name", sts.Name,
				"timeout", utils.DefaultRolloutTimeout)
			// Don't fail the reconcile on timeout - the StatefulSet strategy ensures
			// OrderedReady policy, so old pods are kept until new ones are ready
			return nil
		}
		if result.Error != nil {
			return fmt.Errorf("error waiting for worker statefulset to be ready: %w", result.Error)
		}

		log.Info("Worker StatefulSet is ready after certificate renewal", "name", sts.Name)
	}

	return nil
}

// GetManagerStatus gets the manager status
func (r *ClusterReconciler) GetManagerStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*wazuhv1alpha1.ComponentStatus, error) {
	// Get master status
	masterSts := &appsv1.StatefulSet{}
	masterName := fmt.Sprintf("%s-manager-master", cluster.Name)
	if err := r.Get(ctx, types.NamespacedName{Name: masterName, Namespace: cluster.Namespace}, masterSts); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// Get worker status
	workerSts := &appsv1.StatefulSet{}
	workerName := fmt.Sprintf("%s-manager-worker", cluster.Name)
	workerReady := int32(0)
	workerTotal := int32(0)
	if err := r.Get(ctx, types.NamespacedName{Name: workerName, Namespace: cluster.Namespace}, workerSts); err == nil {
		workerReady = workerSts.Status.ReadyReplicas
		workerTotal = workerSts.Status.Replicas
	}

	return &wazuhv1alpha1.ComponentStatus{
		Replicas:      masterSts.Status.Replicas + workerTotal,
		ReadyReplicas: masterSts.Status.ReadyReplicas + workerReady,
		Phase:         getStatefulSetPhase(masterSts),
	}, nil
}

// createOrUpdate creates or updates a resource with retry on conflict
func (r *ClusterReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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

// resolveSecretKey reads a key from a secret
func (r *ClusterReconciler) resolveSecretKey(ctx context.Context, namespace, secretName, key string) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, secretName)
	}
	return string(value), nil
}

// ensureClusterKeySecret ensures the cluster key secret exists
func (r *ClusterReconciler) ensureClusterKeySecret(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	secretName := fmt.Sprintf("%s-cluster-key", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Create cluster key secret
		clusterKeyBuilder := secrets.NewClusterKeySecretBuilder(cluster.Name, cluster.Namespace)
		clusterKey, err := config.GenerateClusterKey()
		if err != nil {
			return fmt.Errorf("failed to generate cluster key: %w", err)
		}
		clusterKeySecret := clusterKeyBuilder.WithClusterKey(clusterKey).Build()

		if err := controllerutil.SetControllerReference(cluster, clusterKeySecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for cluster key secret: %w", err)
		}

		log.Info("Creating cluster key secret", "name", clusterKeySecret.Name)
		if err := r.Create(ctx, clusterKeySecret); err != nil {
			return fmt.Errorf("failed to create cluster key secret: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get cluster key secret: %w", err)
	}

	return nil
}

// ensureAPICredentialsSecret ensures the API credentials secret exists when monitoring is enabled
// This secret is required by the Wazuh Prometheus exporter sidecar
func (r *ClusterReconciler) ensureAPICredentialsSecret(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Only create if monitoring with Wazuh exporter is enabled
	if cluster.Spec.Monitoring == nil || !cluster.Spec.Monitoring.Enabled {
		return nil
	}
	if cluster.Spec.Monitoring.WazuhExporter == nil || !cluster.Spec.Monitoring.WazuhExporter.Enabled {
		return nil
	}

	secretName := fmt.Sprintf("%s-api-credentials", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	if errors.IsNotFound(err) {
		// Create API credentials secret with default Wazuh credentials
		apiCredentialsBuilder := secrets.NewAPICredentialsSecretBuilder(cluster.Name, cluster.Namespace)
		if cluster.Spec.Version != "" {
			apiCredentialsBuilder.WithVersion(cluster.Spec.Version)
		}
		apiCredentialsSecret := apiCredentialsBuilder.Build()

		if err := controllerutil.SetControllerReference(cluster, apiCredentialsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for API credentials secret: %w", err)
		}

		log.Info("Creating API credentials secret for Wazuh exporter", "name", apiCredentialsSecret.Name)
		if err := r.Create(ctx, apiCredentialsSecret); err != nil {
			return fmt.Errorf("failed to create API credentials secret: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get API credentials secret: %w", err)
	}

	return nil
}

// ReconcileLogRotation reconciles log rotation CronJob and RBAC resources
// Creates or updates the CronJob, ServiceAccount, Role, and RoleBinding when log rotation is enabled
// Deletes all log rotation resources when disabled
func (r *ClusterReconciler) ReconcileLogRotation(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if log rotation is enabled
	if cluster.Spec.Manager == nil || cluster.Spec.Manager.LogRotation == nil || !cluster.Spec.Manager.LogRotation.Enabled {
		// Log rotation is disabled - clean up any existing resources
		return r.cleanupLogRotationResources(ctx, cluster)
	}

	log.Info("Reconciling log rotation resources")

	// Build the CronJob builder with configuration from spec
	builder := cronjobs.NewLogRotationCronJobBuilder(cluster.Name, cluster.Namespace)

	// Apply configuration from spec
	logRotation := cluster.Spec.Manager.LogRotation
	builder.WithSchedule(logRotation.Schedule)
	if logRotation.RetentionDays != nil {
		builder.WithRetentionDays(*logRotation.RetentionDays)
	}
	if logRotation.MaxFileSizeMB != nil {
		builder.WithMaxFileSizeMB(*logRotation.MaxFileSizeMB)
	}
	builder.WithCombinationMode(logRotation.CombinationMode)
	builder.WithPaths(logRotation.Paths)
	builder.WithImage(logRotation.Image)
	if cluster.Spec.Version != "" {
		builder.WithVersion(cluster.Spec.Version)
	}

	// Reconcile ServiceAccount
	sa := builder.BuildServiceAccount()
	if err := controllerutil.SetControllerReference(cluster, sa, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for log rotation service account: %w", err)
	}
	if err := r.createOrUpdate(ctx, sa); err != nil {
		return fmt.Errorf("failed to reconcile log rotation service account: %w", err)
	}

	// Reconcile Role
	role := builder.BuildRole()
	if err := controllerutil.SetControllerReference(cluster, role, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for log rotation role: %w", err)
	}
	if err := r.createOrUpdateRole(ctx, role); err != nil {
		return fmt.Errorf("failed to reconcile log rotation role: %w", err)
	}

	// Reconcile RoleBinding
	roleBinding := builder.BuildRoleBinding()
	if err := controllerutil.SetControllerReference(cluster, roleBinding, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for log rotation role binding: %w", err)
	}
	if err := r.createOrUpdateRoleBinding(ctx, roleBinding); err != nil {
		return fmt.Errorf("failed to reconcile log rotation role binding: %w", err)
	}

	// Reconcile CronJob
	cronJob := builder.Build()
	if err := controllerutil.SetControllerReference(cluster, cronJob, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for log rotation cronjob: %w", err)
	}
	if err := r.createOrUpdateCronJob(ctx, cronJob); err != nil {
		return fmt.Errorf("failed to reconcile log rotation cronjob: %w", err)
	}

	log.Info("Log rotation resources reconciled successfully")
	return nil
}

// cleanupLogRotationResources removes all log rotation resources when feature is disabled
func (r *ClusterReconciler) cleanupLogRotationResources(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	builder := cronjobs.NewLogRotationCronJobBuilder(cluster.Name, cluster.Namespace)
	cronJobName, saName, roleName, roleBindingName := builder.GetResourceNames()

	// Delete CronJob if exists
	cronJob := &batchv1.CronJob{}
	if err := r.Get(ctx, types.NamespacedName{Name: cronJobName, Namespace: cluster.Namespace}, cronJob); err == nil {
		log.Info("Deleting log rotation CronJob", "name", cronJobName)
		if err := r.Delete(ctx, cronJob); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete log rotation cronjob: %w", err)
		}
	}

	// Delete RoleBinding if exists
	roleBinding := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: cluster.Namespace}, roleBinding); err == nil {
		log.Info("Deleting log rotation RoleBinding", "name", roleBindingName)
		if err := r.Delete(ctx, roleBinding); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete log rotation role binding: %w", err)
		}
	}

	// Delete Role if exists
	role := &rbacv1.Role{}
	if err := r.Get(ctx, types.NamespacedName{Name: roleName, Namespace: cluster.Namespace}, role); err == nil {
		log.Info("Deleting log rotation Role", "name", roleName)
		if err := r.Delete(ctx, role); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete log rotation role: %w", err)
		}
	}

	// Delete ServiceAccount if exists
	sa := &corev1.ServiceAccount{}
	if err := r.Get(ctx, types.NamespacedName{Name: saName, Namespace: cluster.Namespace}, sa); err == nil {
		log.Info("Deleting log rotation ServiceAccount", "name", saName)
		if err := r.Delete(ctx, sa); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete log rotation service account: %w", err)
		}
	}

	return nil
}

// createOrUpdateRole creates or updates a Role resource
func (r *ClusterReconciler) createOrUpdateRole(ctx context.Context, role *rbacv1.Role) error {
	log := logf.FromContext(ctx)

	existing := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Role", "name", role.Name)
		return r.Create(ctx, role)
	} else if err != nil {
		return err
	}

	log.V(1).Info("Updating Role", "name", role.Name)
	role.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, role)
}

// createOrUpdateRoleBinding creates or updates a RoleBinding resource
func (r *ClusterReconciler) createOrUpdateRoleBinding(ctx context.Context, roleBinding *rbacv1.RoleBinding) error {
	log := logf.FromContext(ctx)

	existing := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Name: roleBinding.Name, Namespace: roleBinding.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating RoleBinding", "name", roleBinding.Name)
		return r.Create(ctx, roleBinding)
	} else if err != nil {
		return err
	}

	log.V(1).Info("Updating RoleBinding", "name", roleBinding.Name)
	roleBinding.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, roleBinding)
}

// createOrUpdateCronJob creates or updates a CronJob resource
func (r *ClusterReconciler) createOrUpdateCronJob(ctx context.Context, cronJob *batchv1.CronJob) error {
	log := logf.FromContext(ctx)

	existing := &batchv1.CronJob{}
	err := r.Get(ctx, types.NamespacedName{Name: cronJob.Name, Namespace: cronJob.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating CronJob", "name", cronJob.Name)
		return r.Create(ctx, cronJob)
	} else if err != nil {
		return err
	}

	log.V(1).Info("Updating CronJob", "name", cronJob.Name)
	cronJob.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, cronJob)
}
