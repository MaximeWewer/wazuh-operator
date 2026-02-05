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
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	wazuhcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/wazuh"
	affinityutil "github.com/MaximeWewer/wazuh-operator/internal/shared/affinity"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/validation"
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
	Recorder        record.EventRecorder
	requeueInterval time.Duration
	// RuleReconciler handles WazuhRule resources for mounting rules to manager pods
	RuleReconciler *RuleReconciler
	// DecoderReconciler handles WazuhDecoder resources for mounting decoders to manager pods
	DecoderReconciler *DecoderReconciler
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

// WithRuleReconciler sets the rule reconciler for mounting rule ConfigMaps to manager pods
func (r *ClusterReconciler) WithRuleReconciler(rr *RuleReconciler) *ClusterReconciler {
	r.RuleReconciler = rr
	return r
}

// WithDecoderReconciler sets the decoder reconciler for mounting decoder ConfigMaps to manager pods
func (r *ClusterReconciler) WithDecoderReconciler(dr *DecoderReconciler) *ClusterReconciler {
	r.DecoderReconciler = dr
	return r
}

// ReconcileCertificates reconciles TLS certificates for the cluster
func (r *ClusterReconciler) ReconcileCertificates(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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

		certsBuilder := wazuhcerts.NewManagerCertsSecretBuilder(cluster.Name, cluster.Namespace)
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
func (r *ClusterReconciler) generateManagerCertificates(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*managerCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate CA
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-manager-ca", cluster.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for manager")

	// Determine worker replicas for SANs
	var workerReplicas int32
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
func (r *ClusterReconciler) ReconcileManager(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	return r.ReconcileManagerWithCertHashes(ctx, cluster, "", "")
}

// ReconcileManagerWithCertHashes reconciles the Wazuh Manager with certificate hashes for pod restart.
//
// Deprecated: Use ReconcileManagerNonBlocking for non-blocking rollouts.
func (r *ClusterReconciler) ReconcileManagerWithCertHashes(ctx context.Context, cluster *wazuhv1.WazuhCluster, masterCertHash, workerCertHash string) error {
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

	// Reconcile Manager PDB
	if err := r.reconcileManagerPDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager PDB: %w", err)
	}

	log.Info("Manager reconciliation completed")
	return nil
}

// ReconcileManagerNonBlocking reconciles the Wazuh Manager without blocking on rollouts
// Returns pending rollouts that should be tracked and monitored by the caller
func (r *ClusterReconciler) ReconcileManagerNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, masterCertHash, workerCertHash string) ManagerReconcileResult {
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

	// Reconcile Manager PDB
	if err := r.reconcileManagerPDB(ctx, cluster); err != nil {
		return ManagerReconcileResult{Error: fmt.Errorf("failed to reconcile manager PDB: %w", err)}
	}

	log.Info("Manager reconciliation completed (non-blocking)", "pendingRollouts", len(pendingRollouts))
	return ManagerReconcileResult{PendingRollouts: pendingRollouts}
}

// reconcileMasterNonBlocking reconciles the master without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *ClusterReconciler) reconcileMasterNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract master spec fields with defaults
	var (
		version           = cluster.Spec.Version
		resources         *corev1.ResourceRequirements
		storageSize       = constants.DefaultManagerStorageSize
		nodeSelector      map[string]string
		tolerations       []corev1.Toleration
		affinity          *corev1.Affinity
		extraVolumes      []corev1.Volume
		extraVolumeMounts []corev1.VolumeMount
		extraConfig       string
		annotations       map[string]string
		podAnnotations    map[string]string
	)

	var env []corev1.EnvVar
	var envFrom []corev1.EnvFromSource

	if cluster.Spec.Manager != nil {
		if cluster.Spec.Manager.Master.Resources != nil {
			resources = cluster.Spec.Manager.Master.Resources
		}
		if cluster.Spec.Manager.Master.StorageSize != "" {
			storageSize = cluster.Spec.Manager.Master.StorageSize
		}
		nodeSelector = cluster.Spec.Manager.Master.NodeSelector
		tolerations = cluster.Spec.Manager.Master.Tolerations
		affinity = cluster.Spec.Manager.Master.Affinity
		env = cluster.Spec.Manager.Master.Env
		envFrom = cluster.Spec.Manager.Master.EnvFrom
		extraVolumes = cluster.Spec.Manager.Master.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Manager.Master.ExtraVolumeMounts
		extraConfig = cluster.Spec.Manager.Master.ExtraConfig
		annotations = cluster.Spec.Manager.Master.Annotations
		podAnnotations = cluster.Spec.Manager.Master.PodAnnotations

		// Apply cluster-level anti-affinity if enabled
		if affinityutil.ShouldApplyAntiAffinity(cluster) {
			clusterAntiAffinity := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)
			affinity = affinityutil.MergeAntiAffinity(clusterAntiAffinity, affinity)
		}
	}

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "master")

	ossecConf, err := config.BuildMasterConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-master", "", extraConfig)
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return nil, fmt.Errorf("failed to reconcile master configmap: %w", err)
	}

	// Compute configHash for change detection (ossec.conf + filebeat.yml + wazuh-template.json)
	configHash := patch.ComputeConfigHash(configMap.Data)

	// Build Services
	serviceBuilder := services.NewManagerServiceBuilder(cluster.Name, cluster.Namespace, "master")
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Service != nil && len(cluster.Spec.Manager.Master.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(cluster.Spec.Manager.Master.Service.Annotations)
	}
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

	// Compute specHash for change detection (version is included in image tag)
	specHash, err := patch.ComputeManagerMasterSpecHashFull(patch.ManagerMasterSpecInput{
		Version:           version,
		Resources:         resources,
		StorageSize:       storageSize,
		NodeSelector:      nodeSelector,
		Tolerations:       tolerations,
		Affinity:          affinity,
		Env:               env,
		EnvFrom:           envFrom,
		Annotations:       annotations,
		PodAnnotations:    podAnnotations,
		ExtraConfig:       extraConfig,
		ExtraVolumes:      extraVolumes,
		ExtraVolumeMounts: extraVolumeMounts,
		MonitoringEnabled: cluster.Spec.Monitoring != nil && cluster.Spec.Monitoring.Enabled,
	})
	if err != nil {
		log.Error(err, "Failed to compute master spec hash, continuing without spec hash")
		specHash = ""
	}

	// Build StatefulSet with all fields
	stsBuilder := deployments.NewManagerStatefulSetBuilder(cluster.Name, cluster.Namespace, "master")
	if version != "" {
		stsBuilder.WithVersion(version)
	}
	if resources != nil {
		stsBuilder.WithResources(resources)
	}
	if storageSize != "" {
		stsBuilder.WithStorageSize(storageSize)
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
	if len(extraVolumes) > 0 {
		stsBuilder.WithVolumes(extraVolumes)
	}
	if len(extraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(extraVolumeMounts)
	}
	if len(annotations) > 0 {
		stsBuilder.WithAnnotations(annotations)
	}
	if len(podAnnotations) > 0 {
		stsBuilder.WithPodAnnotations(podAnnotations)
	}
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
	}
	// Set cluster reference for monitoring sidecar
	stsBuilder.WithCluster(cluster)

	// Mount rule ConfigMaps if RuleReconciler is configured
	var ruleHash string
	if r.RuleReconciler != nil {
		ruleConfigMaps, hash, err := r.RuleReconciler.GetRuleConfigMapsForCluster(ctx, cluster.Name, cluster.Namespace)
		if err != nil {
			log.Error(err, "Failed to get rule ConfigMaps for cluster, continuing without rules")
		} else if len(ruleConfigMaps) > 0 {
			stsBuilder.WithRuleConfigMaps(convertRuleConfigMaps(ruleConfigMaps))
			stsBuilder.WithRuleHash(hash)
			ruleHash = hash
			log.V(1).Info("Mounting rule ConfigMaps to master", "count", len(ruleConfigMaps), "hash", utils.ShortHash(hash))
		}
	}

	// Mount decoder ConfigMaps if DecoderReconciler is configured
	var decoderHash string
	if r.DecoderReconciler != nil {
		decoderConfigMaps, hash, err := r.DecoderReconciler.GetDecoderConfigMapsForCluster(ctx, cluster.Name, cluster.Namespace)
		if err != nil {
			log.Error(err, "Failed to get decoder ConfigMaps for cluster, continuing without decoders")
		} else if len(decoderConfigMaps) > 0 {
			stsBuilder.WithDecoderConfigMaps(convertDecoderConfigMaps(decoderConfigMaps))
			stsBuilder.WithDecoderHash(hash)
			decoderHash = hash
			log.V(1).Info("Mounting decoder ConfigMaps to master", "count", len(decoderConfigMaps), "hash", utils.ShortHash(hash))
		}
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for master statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Master StatefulSet", "name", sts.Name, "certHash", utils.ShortHash(certHash), "configHash", utils.ShortHash(configHash), "specHash", utils.ShortHash(specHash), "ruleHash", utils.ShortHash(ruleHash), "decoderHash", utils.ShortHash(decoderHash))
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create master statefulset: %w", err)
		}
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

	// Check if recreation is needed due to immutable field changes (SecurityContext, PodManagementPolicy)
	needsRecreation, recreationReason := patch.NeedsStatefulSetRecreation(found, sts)
	if needsRecreation {
		log.Info("Master StatefulSet requires recreation due to immutable field change",
			"name", sts.Name,
			"reason", recreationReason)

		if err := r.Delete(ctx, found); err != nil && !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to delete master statefulset for recreation: %w", err)
		}
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create master statefulset after recreation: %w", err)
		}
		return &utils.PendingRollout{
			Component: "manager-master",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "recreation-" + recreationReason,
		}, nil
	}

	// Check if update is needed (any hash changed: cert, config, or spec)
	existingCertHash := ""
	existingConfigHash := ""
	existingSpecHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	needsUpdate := false
	var updateReason string

	if certHash != "" && certHash != existingCertHash {
		needsUpdate = true
		updateReason = "certificate-change"
		log.Info("Master StatefulSet needs update due to certificate hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))
	}
	if configHash != "" && configHash != existingConfigHash {
		needsUpdate = true
		if updateReason != "" {
			updateReason += "+config-change"
		} else {
			updateReason = "config-change"
		}
		log.Info("Master StatefulSet needs update due to config hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingConfigHash),
			"newHash", utils.ShortHash(configHash))
	}
	if specHash != "" && specHash != existingSpecHash {
		needsUpdate = true
		if updateReason != "" {
			updateReason += "+spec-change"
		} else {
			updateReason = "spec-change"
		}
		log.Info("Master StatefulSet needs update due to spec hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingSpecHash),
			"newHash", utils.ShortHash(specHash))
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, sts, found, err)
			if recErr != nil {
				return nil, fmt.Errorf("failed to update master statefulset: %w", recErr)
			}
			if !recreated {
				return nil, fmt.Errorf("failed to update master statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return nil, fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}
		return &utils.PendingRollout{
			Component: "manager-master",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    updateReason,
		}, nil
	}

	return nil, nil
}

// reconcileWorkersNonBlocking reconciles the workers without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *ClusterReconciler) reconcileWorkersNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract worker spec fields with defaults
	var (
		replicas          int32
		version           = cluster.Spec.Version
		resources         *corev1.ResourceRequirements
		storageSize       = constants.DefaultManagerStorageSize
		nodeSelector      map[string]string
		tolerations       []corev1.Toleration
		affinity          *corev1.Affinity
		extraVolumes      []corev1.Volume
		extraVolumeMounts []corev1.VolumeMount
		extraConfig       string
		annotations       map[string]string
		podAnnotations    map[string]string
	)

	if cluster.Spec.Manager != nil {
		replicas = cluster.Spec.Manager.Workers.GetReplicas()
		if cluster.Spec.Manager.Workers.Resources != nil {
			resources = cluster.Spec.Manager.Workers.Resources
		}
		if cluster.Spec.Manager.Workers.StorageSize != "" {
			storageSize = cluster.Spec.Manager.Workers.StorageSize
		}
		nodeSelector = cluster.Spec.Manager.Workers.NodeSelector
		tolerations = cluster.Spec.Manager.Workers.Tolerations
		affinity = cluster.Spec.Manager.Workers.Affinity
		extraVolumes = cluster.Spec.Manager.Workers.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Manager.Workers.ExtraVolumeMounts
		extraConfig = cluster.Spec.Manager.Workers.ExtraConfig
		annotations = cluster.Spec.Manager.Workers.Annotations
		podAnnotations = cluster.Spec.Manager.Workers.PodAnnotations

		// Apply cluster-level anti-affinity if enabled
		if affinityutil.ShouldApplyAntiAffinity(cluster) {
			clusterAntiAffinity := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)
			affinity = affinityutil.MergeAntiAffinity(clusterAntiAffinity, affinity)
		}
	}

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "worker")

	// Build ossec.conf for workers - master service name is computed from cluster name
	ossecConf, err := config.BuildWorkerConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-worker", "", int(constants.PortManagerCluster), extraConfig)
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return nil, fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	// Compute configHash for change detection (ossec.conf + filebeat.yml + wazuh-template.json)
	configHash := patch.ComputeConfigHash(configMap.Data)

	// Build Services
	serviceBuilder := services.NewWorkerServiceBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Service != nil && len(cluster.Spec.Manager.Workers.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(cluster.Spec.Manager.Workers.Service.Annotations)
	}
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

	// Extract additional fields for hash computation
	var workerPodAnnotations map[string]string
	var workerExtraConfig string
	var workerExtraVolumes []corev1.Volume
	var workerExtraVolumeMounts []corev1.VolumeMount
	var workerEnv []corev1.EnvVar
	var workerEnvFrom []corev1.EnvFromSource
	if cluster.Spec.Manager != nil {
		workerPodAnnotations = cluster.Spec.Manager.Workers.PodAnnotations
		workerExtraConfig = cluster.Spec.Manager.Workers.ExtraConfig
		workerExtraVolumes = cluster.Spec.Manager.Workers.ExtraVolumes
		workerExtraVolumeMounts = cluster.Spec.Manager.Workers.ExtraVolumeMounts
		workerEnv = cluster.Spec.Manager.Workers.Env
		workerEnvFrom = cluster.Spec.Manager.Workers.EnvFrom
	}

	// Compute specHash for change detection (version is included in image tag)
	specHash, err := patch.ComputeManagerWorkersSpecHashFull(patch.ManagerWorkersSpecInput{
		Replicas:          replicas,
		Version:           version,
		Resources:         resources,
		StorageSize:       storageSize,
		NodeSelector:      nodeSelector,
		Tolerations:       tolerations,
		Affinity:          affinity,
		Env:               workerEnv,
		EnvFrom:           workerEnvFrom,
		Annotations:       annotations,
		PodAnnotations:    workerPodAnnotations,
		ExtraConfig:       workerExtraConfig,
		ExtraVolumes:      workerExtraVolumes,
		ExtraVolumeMounts: workerExtraVolumeMounts,
	})
	if err != nil {
		log.Error(err, "Failed to compute worker spec hash, continuing without spec hash")
		specHash = ""
	}

	// Build StatefulSet with all fields
	stsBuilder := deployments.NewWorkerStatefulSetBuilder(cluster.Name, cluster.Namespace)
	stsBuilder.WithReplicas(replicas)
	if version != "" {
		stsBuilder.WithVersion(version)
	}
	if resources != nil {
		stsBuilder.WithResources(resources)
	}
	if storageSize != "" {
		stsBuilder.WithStorageSize(storageSize)
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
	if len(extraVolumes) > 0 {
		stsBuilder.WithVolumes(extraVolumes)
	}
	if len(extraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(extraVolumeMounts)
	}
	if len(annotations) > 0 {
		stsBuilder.WithAnnotations(annotations)
	}
	if len(podAnnotations) > 0 {
		stsBuilder.WithPodAnnotations(podAnnotations)
	}
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
	}

	// Mount rule ConfigMaps if RuleReconciler is configured
	var ruleHash string
	if r.RuleReconciler != nil {
		ruleConfigMaps, hash, err := r.RuleReconciler.GetRuleConfigMapsForCluster(ctx, cluster.Name, cluster.Namespace)
		if err != nil {
			log.Error(err, "Failed to get rule ConfigMaps for cluster, continuing without rules")
		} else if len(ruleConfigMaps) > 0 {
			stsBuilder.WithRuleConfigMaps(convertRuleConfigMaps(ruleConfigMaps))
			stsBuilder.WithRuleHash(hash)
			ruleHash = hash
			log.V(1).Info("Mounting rule ConfigMaps to workers", "count", len(ruleConfigMaps), "hash", utils.ShortHash(hash))
		}
	}

	// Mount decoder ConfigMaps if DecoderReconciler is configured
	var decoderHash string
	if r.DecoderReconciler != nil {
		decoderConfigMaps, hash, err := r.DecoderReconciler.GetDecoderConfigMapsForCluster(ctx, cluster.Name, cluster.Namespace)
		if err != nil {
			log.Error(err, "Failed to get decoder ConfigMaps for cluster, continuing without decoders")
		} else if len(decoderConfigMaps) > 0 {
			stsBuilder.WithDecoderConfigMaps(convertDecoderConfigMaps(decoderConfigMaps))
			stsBuilder.WithDecoderHash(hash)
			decoderHash = hash
			log.V(1).Info("Mounting decoder ConfigMaps to workers", "count", len(decoderConfigMaps), "hash", utils.ShortHash(hash))
		}
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for worker statefulset: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Worker StatefulSet", "name", sts.Name, "replicas", replicas, "certHash", utils.ShortHash(certHash), "configHash", utils.ShortHash(configHash), "specHash", utils.ShortHash(specHash), "ruleHash", utils.ShortHash(ruleHash), "decoderHash", utils.ShortHash(decoderHash))
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

	// Check if recreation is needed due to immutable field changes (SecurityContext, PodManagementPolicy)
	needsRecreation, recreationReason := patch.NeedsStatefulSetRecreation(found, sts)
	if needsRecreation {
		log.Info("Worker StatefulSet requires recreation due to immutable field change",
			"name", sts.Name,
			"reason", recreationReason)

		// Delete the old StatefulSet (PVCs will be preserved)
		if err := r.Delete(ctx, found); err != nil && !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to delete worker statefulset for recreation: %w", err)
		}

		// Create the new StatefulSet
		if err := r.Create(ctx, sts); err != nil {
			return nil, fmt.Errorf("failed to create worker statefulset after recreation: %w", err)
		}

		return &utils.PendingRollout{
			Component: "manager-worker",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    "recreation-" + recreationReason,
		}, nil
	}

	// Check if update is needed (any hash changed: cert, config, or spec)
	existingCertHash := ""
	existingConfigHash := ""
	existingSpecHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	needsUpdate := false
	var updateReason string

	if certHash != "" && certHash != existingCertHash {
		needsUpdate = true
		updateReason = "certificate-change"
		log.Info("Worker StatefulSet needs update due to certificate hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))
	}
	if configHash != "" && configHash != existingConfigHash {
		needsUpdate = true
		if updateReason != "" {
			updateReason += "+config-change"
		} else {
			updateReason = "config-change"
		}
		log.Info("Worker StatefulSet needs update due to config hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingConfigHash),
			"newHash", utils.ShortHash(configHash))
	}
	if specHash != "" && specHash != existingSpecHash {
		needsUpdate = true
		if updateReason != "" {
			updateReason += "+spec-change"
		} else {
			updateReason = "spec-change"
		}
		log.Info("Worker StatefulSet needs update due to spec hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingSpecHash),
			"newHash", utils.ShortHash(specHash))
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, sts, found, err)
			if recErr != nil {
				return nil, fmt.Errorf("failed to update worker statefulset: %w", recErr)
			}
			if !recreated {
				return nil, fmt.Errorf("failed to update worker statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return nil, fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}
		return &utils.PendingRollout{
			Component: "manager-worker",
			Namespace: sts.Namespace,
			Name:      sts.Name,
			Type:      utils.RolloutTypeStatefulSet,
			StartTime: time.Now(),
			Reason:    updateReason,
		}, nil
	}

	return nil, nil
}

// resolveIndexerCredentials resolves indexer credentials from secret
// It first checks for custom credentials in cluster.Spec.Indexer.Credentials
// If not specified, it falls back to the default auto-generated secret: <cluster>-indexer-credentials
func (r *ClusterReconciler) resolveIndexerCredentials(ctx context.Context, cluster *wazuhv1.WazuhCluster) (string, string) {
	log := logf.FromContext(ctx)
	indexerUsername := ""
	indexerPassword := ""

	// Check if custom credentials secret is specified in the CRD
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
	} else {
		// Fall back to the default auto-generated indexer credentials secret
		defaultSecretName := fmt.Sprintf("%s-indexer-credentials", cluster.Name)
		username, err := r.resolveSecretKey(ctx, cluster.Namespace, defaultSecretName, constants.SecretKeyAdminUsername)
		if err != nil {
			log.V(1).Info("Default indexer credentials secret not found, will use defaults", "secret", defaultSecretName)
		} else {
			indexerUsername = username
		}

		password, err := r.resolveSecretKey(ctx, cluster.Namespace, defaultSecretName, constants.SecretKeyAdminPassword)
		if err != nil {
			log.V(1).Info("Default indexer credentials password not found in secret", "secret", defaultSecretName)
		} else {
			indexerPassword = password
		}
	}

	return indexerUsername, indexerPassword
}

// reconcileMasterWithCertHash reconciles the master manager node with certificate hash for pod restart
func (r *ClusterReconciler) reconcileMasterWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	extraConfig := ""
	var extraVolumes []corev1.Volume
	var extraVolumeMounts []corev1.VolumeMount
	if cluster.Spec.Manager != nil {
		extraConfig = cluster.Spec.Manager.Master.ExtraConfig
		extraVolumes = cluster.Spec.Manager.Master.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Manager.Master.ExtraVolumeMounts
	}

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "master")

	// Generate ossec.conf
	ossecConf, err := config.BuildMasterConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-master", "", extraConfig)
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for master configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile master configmap: %w", err)
	}

	configHash := patch.ComputeConfigHash(configMap.Data)

	// Build Service
	serviceBuilder := services.NewManagerServiceBuilder(cluster.Name, cluster.Namespace, "master")
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Service != nil && len(cluster.Spec.Manager.Master.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(cluster.Spec.Manager.Master.Service.Annotations)
	}
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
	if len(extraVolumes) > 0 {
		stsBuilder.WithVolumes(extraVolumes)
	}
	if len(extraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(extraVolumeMounts)
	}
	if cluster.Spec.Manager != nil {
		if len(cluster.Spec.Manager.Master.Annotations) > 0 {
			stsBuilder.WithAnnotations(cluster.Spec.Manager.Master.Annotations)
		}
		if len(cluster.Spec.Manager.Master.PodAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(cluster.Spec.Manager.Master.PodAnnotations)
		}
	}
	// Set cert hash for pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}
	// Set cluster reference for monitoring sidecar
	stsBuilder.WithCluster(cluster)

	specHash, err := patch.ComputeManagerMasterSpecHashFull(patch.ManagerMasterSpecInput{
		Version:           cluster.Spec.Version,
		Resources:         cluster.Spec.Manager.Master.Resources,
		StorageSize:       cluster.Spec.Manager.Master.StorageSize,
		Image:             "",
		NodeSelector:      cluster.Spec.Manager.Master.NodeSelector,
		Tolerations:       cluster.Spec.Manager.Master.Tolerations,
		Affinity:          cluster.Spec.Manager.Master.Affinity,
		ExtraVolumes:      extraVolumes,
		ExtraVolumeMounts: extraVolumeMounts,
		ExtraConfig:       extraConfig,
		Env:               cluster.Spec.Manager.Master.Env,
		EnvFrom:           cluster.Spec.Manager.Master.EnvFrom,
		Annotations:       cluster.Spec.Manager.Master.Annotations,
		PodAnnotations:    cluster.Spec.Manager.Master.PodAnnotations,
		MonitoringEnabled: cluster.Spec.Monitoring != nil && cluster.Spec.Monitoring.Enabled,
	})
	if err != nil {
		log.Error(err, "Failed to compute master spec hash, continuing without spec hash")
		specHash = ""
	}
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
	}

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
	existingConfigHash := ""
	existingSpecHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
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
	if configHash != "" && configHash != existingConfigHash {
		log.Info("Updating Master StatefulSet due to config hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingConfigHash),
			"newHash", utils.ShortHash(configHash))
		needsUpdate = true
	}
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Updating Master StatefulSet due to spec hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingSpecHash),
			"newHash", utils.ShortHash(specHash))
		needsUpdate = true
	}
	if utils.HashMap(sts.Annotations) != utils.HashMap(found.Annotations) {
		log.Info("Updating Master StatefulSet due to annotation change", "name", sts.Name)
		needsUpdate = true
	}
	if utils.HashMap(sts.Spec.Template.Annotations) != utils.HashMap(found.Spec.Template.Annotations) {
		log.Info("Updating Master StatefulSet due to pod annotation change", "name", sts.Name)
		needsUpdate = true
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, sts, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update master statefulset: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update master statefulset: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
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

// reconcileWorkersWithCertHash reconciles the worker manager nodes with certificate hash for pod restart
func (r *ClusterReconciler) reconcileWorkersWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	extraConfig := ""
	var extraVolumes []corev1.Volume
	var extraVolumeMounts []corev1.VolumeMount
	if cluster.Spec.Manager != nil {
		extraConfig = cluster.Spec.Manager.Workers.ExtraConfig
		extraVolumes = cluster.Spec.Manager.Workers.ExtraVolumes
		extraVolumeMounts = cluster.Spec.Manager.Workers.ExtraVolumeMounts
	}

	// Build ConfigMap
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "worker")

	// Build ossec.conf for workers - master service name is computed from cluster name
	ossecConf, err := config.BuildWorkerConfig(cluster.Name, cluster.Namespace, cluster.Name+"-manager-worker", "", int(constants.PortManagerCluster), extraConfig)
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for worker configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	configHash := patch.ComputeConfigHash(configMap.Data)

	// Build Service
	serviceBuilder := services.NewWorkerServiceBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Service != nil && len(cluster.Spec.Manager.Workers.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(cluster.Spec.Manager.Workers.Service.Annotations)
	}
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
	var workerReplicas2 int32
	if cluster.Spec.Manager != nil {
		workerReplicas2 = cluster.Spec.Manager.Workers.GetReplicas()
		if cluster.Spec.Manager.Workers.Resources != nil {
			stsBuilder.WithResources(cluster.Spec.Manager.Workers.Resources)
		}
		if len(extraVolumes) > 0 {
			stsBuilder.WithVolumes(extraVolumes)
		}
		if len(extraVolumeMounts) > 0 {
			stsBuilder.WithVolumeMounts(extraVolumeMounts)
		}
		if len(cluster.Spec.Manager.Workers.Annotations) > 0 {
			stsBuilder.WithAnnotations(cluster.Spec.Manager.Workers.Annotations)
		}
		if len(cluster.Spec.Manager.Workers.PodAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(cluster.Spec.Manager.Workers.PodAnnotations)
		}
	}
	stsBuilder.WithReplicas(workerReplicas2)
	// Set cert hash for pod restart on cert renewal
	if certHash != "" {
		stsBuilder.WithCertHash(certHash)
	}
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}

	specHash, err := patch.ComputeManagerWorkersSpecHashFull(patch.ManagerWorkersSpecInput{
		Replicas:          workerReplicas2,
		Version:           cluster.Spec.Version,
		Resources:         cluster.Spec.Manager.Workers.Resources,
		StorageSize:       cluster.Spec.Manager.Workers.StorageSize,
		Image:             "",
		NodeSelector:      cluster.Spec.Manager.Workers.NodeSelector,
		Tolerations:       cluster.Spec.Manager.Workers.Tolerations,
		Affinity:          cluster.Spec.Manager.Workers.Affinity,
		ExtraVolumes:      extraVolumes,
		ExtraVolumeMounts: extraVolumeMounts,
		ExtraConfig:       extraConfig,
		Env:               cluster.Spec.Manager.Workers.Env,
		EnvFrom:           cluster.Spec.Manager.Workers.EnvFrom,
		Annotations:       cluster.Spec.Manager.Workers.Annotations,
		PodAnnotations:    cluster.Spec.Manager.Workers.PodAnnotations,
	})
	if err != nil {
		log.Error(err, "Failed to compute worker spec hash, continuing without spec hash")
		specHash = ""
	}
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
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

	// Check if update is needed (cert hash changed or replicas changed)
	existingCertHash := ""
	existingConfigHash := ""
	existingSpecHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	certHashChanged := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Worker StatefulSet due to certificate hash change",
				"name", sts.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
			certHashChanged = true
		}
	}

	// Check if replicas changed
	if found.Spec.Replicas != nil && *found.Spec.Replicas != workerReplicas2 {
		log.Info("Updating Worker StatefulSet due to replica count change",
			"name", sts.Name,
			"oldReplicas", *found.Spec.Replicas,
			"newReplicas", workerReplicas2)
		needsUpdate = true
	}
	if configHash != "" && configHash != existingConfigHash {
		log.Info("Updating Worker StatefulSet due to config hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingConfigHash),
			"newHash", utils.ShortHash(configHash))
		needsUpdate = true
	}
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Updating Worker StatefulSet due to spec hash change",
			"name", sts.Name,
			"oldHash", utils.ShortHash(existingSpecHash),
			"newHash", utils.ShortHash(specHash))
		needsUpdate = true
	}
	if utils.HashMap(sts.Annotations) != utils.HashMap(found.Annotations) {
		log.Info("Updating Worker StatefulSet due to annotation change", "name", sts.Name)
		needsUpdate = true
	}
	if utils.HashMap(sts.Spec.Template.Annotations) != utils.HashMap(found.Spec.Template.Annotations) {
		log.Info("Updating Worker StatefulSet due to pod annotation change", "name", sts.Name)
		needsUpdate = true
	}

	if needsUpdate {
		sts.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, sts); err != nil {
			recreated, recErr := utils.RecreateStatefulSetOnError(ctx, r.Client, sts, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update worker statefulset: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update worker statefulset: %w", err)
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
	}

	return nil
}

// GetManagerStatus gets the manager status
func (r *ClusterReconciler) GetManagerStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.ComponentStatus, error) {
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

	// Get desired replicas from the spec
	desiredReplicas := int32(0)
	if cluster.Spec.Manager != nil {
		desiredReplicas = cluster.Spec.Manager.GetTotalReplicas()
	}

	return &wazuhv1.ComponentStatus{
		Replicas:        masterSts.Status.Replicas + workerTotal,
		ReadyReplicas:   masterSts.Status.ReadyReplicas + workerReady,
		DesiredReplicas: desiredReplicas,
		Phase:           getStatefulSetPhase(masterSts),
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

		existing, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("failed to deep copy object")
		}

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
func (r *ClusterReconciler) ensureClusterKeySecret(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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
// This secret is required by the Wazuh Manager (API_USERNAME/API_PASSWORD env vars)
// and optionally by the Wazuh Prometheus exporter sidecar
// It also validates that the password meets Wazuh's security requirements
func (r *ClusterReconciler) ensureAPICredentialsSecret(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if user provided a custom API credentials secret
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil && cluster.Spec.Manager.APICredentials.SecretName != "" {
		// User-provided secret - validate password meets Wazuh requirements
		userSecretName := cluster.Spec.Manager.APICredentials.SecretName
		passwordKey := cluster.Spec.Manager.APICredentials.PasswordKey
		if passwordKey == "" {
			passwordKey = "password" // default key
		}

		userSecret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Name: userSecretName, Namespace: cluster.Namespace}, userSecret)
		if err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("API credentials secret '%s' not found. Please create it with username and password keys", userSecretName)
			}
			return fmt.Errorf("failed to get API credentials secret '%s': %w", userSecretName, err)
		}

		password := string(userSecret.Data[passwordKey])
		if password == "" {
			return fmt.Errorf("API credentials secret '%s' does not contain password key '%s'", userSecretName, passwordKey)
		}

		// Validate password meets Wazuh security requirements
		if err := validation.ValidateWazuhPassword(password); err != nil {
			log.Error(err, "API credentials password does not meet Wazuh security requirements",
				"secret", userSecretName,
				"requirements", validation.FormatPasswordRequirements())
			return fmt.Errorf("API credentials secret '%s' contains an insecure password: %w. %s",
				userSecretName, err, validation.FormatPasswordRequirements())
		}
		log.V(1).Info("User-provided API credentials password validated successfully", "secret", userSecretName)
		return nil
	}

	// No user-provided secret - use auto-generated secret
	secretName := fmt.Sprintf("%s-api-credentials", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	if errors.IsNotFound(err) {
		// Create API credentials secret with generated password
		// Password is generated with special characters required by Wazuh API
		generatedPassword := utils.GenerateWazuhAPIPassword(20)
		apiCredentialsBuilder := secrets.NewAPICredentialsSecretBuilder(cluster.Name, cluster.Namespace)
		apiCredentialsBuilder.WithCredentials(constants.DefaultWazuhAPIUsername, generatedPassword)
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

	// Secret exists - validate that the password meets Wazuh security requirements
	// This prevents deployment failures due to Wazuh Error 5007 (Insecure user password)
	password := string(found.Data[constants.SecretKeyAPIPassword])

	if password != "" {
		if err := validation.ValidateWazuhPassword(password); err != nil {
			log.Error(err, "API credentials password does not meet Wazuh security requirements",
				"secret", secretName,
				"requirements", validation.FormatPasswordRequirements())
			return fmt.Errorf("API credentials secret '%s' contains an insecure password: %w. %s",
				secretName, err, validation.FormatPasswordRequirements())
		}
		log.V(1).Info("API credentials password validated successfully", "secret", secretName)
	}

	return nil
}

// ReconcileLogRotation reconciles log rotation CronJob and RBAC resources
// Creates or updates the CronJob, ServiceAccount, Role, and RoleBinding when log rotation is enabled
// Deletes all log rotation resources when disabled
func (r *ClusterReconciler) ReconcileLogRotation(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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
func (r *ClusterReconciler) cleanupLogRotationResources(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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

// convertRuleConfigMaps converts RuleConfigMapInfo from the rule reconciler to RuleConfigMapRef for the builder
func convertRuleConfigMaps(infos []RuleConfigMapInfo) []deployments.RuleConfigMapRef {
	refs := make([]deployments.RuleConfigMapRef, len(infos))
	for i, info := range infos {
		refs[i] = deployments.RuleConfigMapRef{
			Name:     info.ConfigMapName,
			FileName: info.FileName,
		}
	}
	return refs
}

// convertDecoderConfigMaps converts DecoderConfigMapInfo from the decoder reconciler to DecoderConfigMapRef for the builder
func convertDecoderConfigMaps(infos []DecoderConfigMapInfo) []deployments.DecoderConfigMapRef {
	refs := make([]deployments.DecoderConfigMapRef, len(infos))
	for i, info := range infos {
		refs[i] = deployments.DecoderConfigMapRef{
			Name:     info.ConfigMapName,
			FileName: info.FileName,
		}
	}
	return refs
}

// reconcileManagerPDB reconciles the PodDisruptionBudget for manager pods
func (r *ClusterReconciler) reconcileManagerPDB(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	pdbName := pdb.GetManagerPDBName(cluster.Name)

	// Check if PDB should exist
	if !pdb.ShouldCreateManagerPDB(cluster) {
		// If PDB should not exist, delete it if it does
		existing := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Manager PDB (no longer needed)", "name", pdbName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete manager PDB: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get manager PDB: %w", err)
		}
		return nil
	}

	// Build the PDB
	builder := pdb.NewManagerPDBBuilder(cluster)
	managerPDB := builder.Build()

	if err := controllerutil.SetControllerReference(cluster, managerPDB, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for manager PDB: %w", err)
	}

	// Check if PDB exists
	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Manager PDB", "name", pdbName)
		if err := r.Create(ctx, managerPDB); err != nil {
			return fmt.Errorf("failed to create manager PDB: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get manager PDB: %w", err)
	}

	// Update PDB if needed
	if err := utils.RetryOnConflict(ctx, func() error {
		latest := &policyv1.PodDisruptionBudget{}
		if err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, latest); err != nil {
			return err
		}
		managerPDB.SetResourceVersion(latest.GetResourceVersion())
		log.V(1).Info("Updating Manager PDB", "name", pdbName)
		return r.Update(ctx, managerPDB)
	}); err != nil {
		return fmt.Errorf("failed to update manager PDB: %w", err)
	}

	return nil
}
