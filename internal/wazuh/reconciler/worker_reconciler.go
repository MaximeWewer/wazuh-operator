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
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/storage"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WorkerReconciler handles reconciliation of Wazuh Worker nodes
type WorkerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// drainer handles manager drain operations for safe scale-down
	drainer *drain.ManagerDrainerImpl
	// wazuhClient is the Wazuh API client for drain operations
	wazuhClient *adapters.WazuhAPIAdapter
}

// NewWorkerReconciler creates a new WorkerReconciler
func NewWorkerReconciler(c client.Client, scheme *runtime.Scheme) *WorkerReconciler {
	return &WorkerReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithRecorder sets the event recorder for the reconciler
func (r *WorkerReconciler) WithRecorder(recorder record.EventRecorder) *WorkerReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the Wazuh Worker nodes
func (r *WorkerReconciler) Reconcile(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Skip if no workers configured
	if cluster.Spec.Manager.Workers.GetReplicas() == 0 {
		log.V(1).Info("No workers configured, skipping worker reconciliation")
		return nil
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	// Reconcile Services
	if err := r.reconcileServices(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile worker services: %w", err)
	}

	// Reconcile StatefulSet
	if err := r.reconcileStatefulSet(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile worker statefulset: %w", err)
	}

	// Reconcile volume expansion for workers
	if err := r.reconcileVolumeExpansion(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile worker volume expansion: %w", err)
	}

	log.Info("Worker reconciliation completed")
	return nil
}

// reconcileConfigMap reconciles the worker ConfigMap
func (r *WorkerReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "worker")

	// Convert CRD config spec to internal config structs
	var configSpec *wazuhv1alpha1.WazuhConfigSpec
	if cluster.Spec.Manager != nil {
		configSpec = cluster.Spec.Manager.Config
	}
	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg := config.WazuhConfigFromSpec(configSpec)

	// Resolve authd password from secret if configured
	// Note: For workers with EnabledOnMasterOnly=true, auth will be disabled anyway
	authdPassword := ""
	if authCfg.UsePassword && authCfg.PasswordSecretRef != nil {
		password, err := r.resolveSecretKey(ctx, cluster.Namespace, authCfg.PasswordSecretRef.Name, authCfg.PasswordSecretRef.Key)
		if err != nil {
			log.Error(err, "Failed to resolve authd password from secret", "secret", authCfg.PasswordSecretRef.Name)
		} else {
			authdPassword = password
		}
	}

	// Get extra config for worker nodes
	extraConfig := ""
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.ExtraConfig != "" {
		extraConfig = cluster.Spec.Manager.Workers.ExtraConfig
	}

	// Build ossec.conf using the config builder with CRD values
	// NodeType = worker ensures auth section respects EnabledOnMasterOnly
	masterAddr := config.GetMasterServiceAddress(cluster.Name, cluster.Namespace)
	ossecConfig := config.DefaultOSSECConfig(cluster.Name, cluster.Name+"-manager-worker")
	ossecConfig.NodeType = config.NodeTypeWorker
	ossecConfig.Namespace = cluster.Namespace
	ossecConfig.MasterAddress = masterAddr
	ossecConfig.MasterPort = int(constants.PortManagerCluster)
	ossecConfig.Global = globalCfg
	ossecConfig.Alerts = alertsCfg
	ossecConfig.Logging = loggingCfg
	ossecConfig.Remote = remoteCfg
	ossecConfig.Auth = authCfg
	ossecConfig.AuthdPassword = authdPassword
	ossecConfig.ExtraConfig = extraConfig

	ossecConfBuilder := config.NewOSSECConfigBuilder(ossecConfig)
	ossecConf, err := ossecConfBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	// Generate filebeat.yml with credentials from indexer spec
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
			// Password will fall back to env var INDEXER_PASSWORD
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

	// Generate per-pod configs for workers with overrides
	if cluster.Spec.Manager != nil && len(cluster.Spec.Manager.Workers.Overrides) > 0 {
		for _, override := range cluster.Spec.Manager.Workers.Overrides {
			if override.ExtraConfig == "" {
				continue // Skip overrides without extra config
			}

			// Build ossec.conf for this specific worker
			// Merge base extraConfig with per-pod override
			mergedExtraConfig := extraConfig
			if mergedExtraConfig != "" && override.ExtraConfig != "" {
				mergedExtraConfig = mergedExtraConfig + "\n" + override.ExtraConfig
			} else if override.ExtraConfig != "" {
				mergedExtraConfig = override.ExtraConfig
			}

			// Create per-pod config
			podOssecConfig := config.DefaultOSSECConfig(cluster.Name, fmt.Sprintf("%s-manager-worker-%d", cluster.Name, override.Index))
			podOssecConfig.NodeType = config.NodeTypeWorker
			podOssecConfig.Namespace = cluster.Namespace
			podOssecConfig.MasterAddress = masterAddr
			podOssecConfig.MasterPort = int(constants.PortManagerCluster)
			podOssecConfig.Global = globalCfg
			podOssecConfig.Alerts = alertsCfg
			podOssecConfig.Logging = loggingCfg
			podOssecConfig.Remote = remoteCfg
			podOssecConfig.Auth = authCfg
			podOssecConfig.AuthdPassword = authdPassword
			podOssecConfig.ExtraConfig = mergedExtraConfig

			podOssecConfBuilder := config.NewOSSECConfigBuilder(podOssecConfig)
			podOssecConf, err := podOssecConfBuilder.Build()
			if err != nil {
				log.Error(err, "Failed to build per-pod ossec.conf", "workerIndex", override.Index)
				continue
			}

			// Add to ConfigMap with indexed key
			configBuilder.WithIndexedOSSECConfig(override.Index, podOssecConf)
			log.V(1).Info("Generated per-pod config for worker override", "index", override.Index, "description", override.Description)
		}
	}

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// resolveSecretKey reads a key from a secret
func (r *WorkerReconciler) resolveSecretKey(ctx context.Context, namespace, secretName, key string) (string, error) {
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

// getConfigHash retrieves the current config hash from the worker ConfigMap
func (r *WorkerReconciler) getConfigHash(ctx context.Context, clusterName, namespace string) string {
	configMapName := fmt.Sprintf("%s-manager-worker-config", clusterName)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// reconcileServices reconciles worker services
func (r *WorkerReconciler) reconcileServices(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	serviceBuilder := services.NewWorkerServiceBuilder(cluster.Name, cluster.Namespace)

	// Regular ClusterIP service
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	// Headless service for StatefulSet
	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(cluster, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for headless service: %w", err)
	}
	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	log.V(1).Info("Worker services reconciled")
	return nil
}

// reconcileStatefulSet reconciles the worker StatefulSet
func (r *WorkerReconciler) reconcileStatefulSet(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	replicas := cluster.Spec.Manager.Workers.GetReplicas()
	version := cluster.Spec.Version
	resources := cluster.Spec.Manager.Workers.Resources
	storageSize := cluster.Spec.Manager.Workers.StorageSize
	nodeSelector := cluster.Spec.Manager.Workers.NodeSelector
	tolerations := cluster.Spec.Manager.Workers.Tolerations
	affinity := cluster.Spec.Manager.Workers.Affinity

	// Compute spec hash for change detection (includes scheduling options)
	specHash, err := patch.ComputeManagerWorkersSpecHash(replicas, version, resources, storageSize, "", nodeSelector, tolerations, affinity)
	if err != nil {
		log.Error(err, "Failed to compute worker spec hash, continuing without spec tracking")
		specHash = ""
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster.Name, cluster.Namespace)

	stsBuilder := deployments.NewWorkerStatefulSetBuilder(cluster.Name, cluster.Namespace)

	// Apply spec from cluster
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	// Always set replicas from spec (including 0 for no workers)
	stsBuilder.WithReplicas(cluster.Spec.Manager.Workers.GetReplicas())
	if cluster.Spec.Manager.Workers.Resources != nil {
		stsBuilder.WithResources(cluster.Spec.Manager.Workers.Resources)
	}
	if cluster.Spec.Manager.Workers.NodeSelector != nil {
		stsBuilder.WithNodeSelector(cluster.Spec.Manager.Workers.NodeSelector)
	}

	// Set spec hash for change detection
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
	}

	// Set config hash to trigger pod restart on config changes
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if StatefulSet exists
	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Worker StatefulSet", "name", sts.Name, "specHash", patch.ShortHash(specHash))
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Check if update is needed using spec hash comparison
	needsUpdate := false
	updateReason := ""

	// Get existing spec hash
	existingSpecHash := ""
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	// Check spec hash (version, resources, replicas changes)
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Worker spec changed",
			"name", sts.Name,
			"oldSpecHash", patch.ShortHash(existingSpecHash),
			"newSpecHash", patch.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Emit Kubernetes event for spec change
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Worker spec changed (version=%s, replicas=%d)", version, replicas))
		}
	}

	// Check config hash (ConfigMap content changes)
	existingConfigHash := ""
	if found.Spec.Template.Annotations != nil {
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}

	if configHash != "" && configHash != existingConfigHash {
		log.Info("Worker ConfigMap hash changed",
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
				fmt.Sprintf("Worker ConfigMap changed, pods will restart (StatefulSet %s)", sts.Name))
		}
	}

	if needsUpdate {
		// Preserve immutable fields
		sts.Spec.Selector = found.Spec.Selector
		sts.Spec.ServiceName = found.Spec.ServiceName
		sts.Spec.PodManagementPolicy = found.Spec.PodManagementPolicy
		sts.SetResourceVersion(found.GetResourceVersion())

		log.Info("Updating Worker StatefulSet", "name", sts.Name, "reason", updateReason)
		if err := r.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update statefulset: %w", err)
		}
	}

	return nil
}

// GetStatus returns the worker status
func (r *WorkerReconciler) GetStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*wazuhv1alpha1.ComponentStatus, error) {
	sts := &appsv1.StatefulSet{}
	name := fmt.Sprintf("%s-manager-worker", cluster.Name)

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

// ReconcileStandalone reconciles a standalone WazuhWorker resource
func (r *WorkerReconciler) ReconcileStandalone(ctx context.Context, worker *wazuhv1alpha1.WazuhWorker) error {
	log := logf.FromContext(ctx)

	// Skip if no replicas configured
	if worker.Spec.Replicas == 0 {
		log.V(1).Info("No replicas configured, skipping worker reconciliation")
		return nil
	}

	// Reconcile ConfigMap
	if err := r.reconcileStandaloneConfigMap(ctx, worker); err != nil {
		return fmt.Errorf("failed to reconcile worker configmap: %w", err)
	}

	// Reconcile Services
	if err := r.reconcileStandaloneServices(ctx, worker); err != nil {
		return fmt.Errorf("failed to reconcile worker services: %w", err)
	}

	// Reconcile StatefulSet
	if err := r.reconcileStandaloneStatefulSet(ctx, worker); err != nil {
		return fmt.Errorf("failed to reconcile worker statefulset: %w", err)
	}

	log.Info("Standalone worker reconciliation completed", "name", worker.Name)
	return nil
}

// reconcileStandaloneConfigMap reconciles a ConfigMap for standalone worker
func (r *WorkerReconciler) reconcileStandaloneConfigMap(ctx context.Context, worker *wazuhv1alpha1.WazuhWorker) error {
	configBuilder := configmaps.NewManagerConfigMapBuilder(worker.Name, worker.Namespace, "worker")

	// Build configuration based on manager reference
	// Master service name is computed from worker.Spec.ManagerRef (the cluster name)
	ossecConf, err := config.BuildWorkerConfig(
		worker.Spec.ManagerRef, // Use manager ref as cluster name for correct service name
		worker.Namespace,
		worker.Name+"-manager-worker",
		"",
		int(constants.PortManagerCluster),
		worker.Spec.ExtraConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to build ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	// Generate filebeat.yml with correct indexer host
	indexerService := fmt.Sprintf("%s-indexer", worker.Spec.ManagerRef)
	filebeatConf, err := config.BuildFilebeatConfig(
		worker.Name,
		worker.Namespace,
		indexerService,
		"full", // SSL verification mode
	)
	if err != nil {
		return fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(worker, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// reconcileStandaloneServices reconciles services for standalone worker
func (r *WorkerReconciler) reconcileStandaloneServices(ctx context.Context, worker *wazuhv1alpha1.WazuhWorker) error {
	serviceBuilder := services.NewWorkerServiceBuilder(worker.Name, worker.Namespace)

	// Regular ClusterIP service
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(worker, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	// Headless service for StatefulSet
	headlessService := serviceBuilder.BuildHeadless()
	if err := controllerutil.SetControllerReference(worker, headlessService, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for headless service: %w", err)
	}
	if err := r.createOrUpdate(ctx, headlessService); err != nil {
		return fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	return nil
}

// reconcileStandaloneStatefulSet reconciles a StatefulSet for standalone worker
func (r *WorkerReconciler) reconcileStandaloneStatefulSet(ctx context.Context, worker *wazuhv1alpha1.WazuhWorker) error {
	log := logf.FromContext(ctx)

	stsBuilder := deployments.NewWorkerStatefulSetBuilder(worker.Name, worker.Namespace)

	// Apply spec from worker CRD
	if worker.Spec.Image != nil && worker.Spec.Image.Tag != "" {
		stsBuilder.WithVersion(worker.Spec.Image.Tag)
	}
	if worker.Spec.Replicas > 0 {
		stsBuilder.WithReplicas(worker.Spec.Replicas)
	}
	if worker.Spec.Resources != nil {
		stsBuilder.WithResources(worker.Spec.Resources)
	}
	if worker.Spec.NodeSelector != nil {
		stsBuilder.WithNodeSelector(worker.Spec.NodeSelector)
	}

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(worker, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if StatefulSet exists
	found := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Worker StatefulSet", "name", sts.Name)
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Update replicas if changed
	if *found.Spec.Replicas != *sts.Spec.Replicas {
		log.Info("Updating Worker StatefulSet replicas", "name", sts.Name, "replicas", *sts.Spec.Replicas)
		found.Spec.Replicas = sts.Spec.Replicas
		if err := r.Update(ctx, found); err != nil {
			return fmt.Errorf("failed to update statefulset replicas: %w", err)
		}
	}

	return nil
}

// reconcileVolumeExpansion handles volume expansion for worker PVCs
func (r *WorkerReconciler) reconcileVolumeExpansion(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get requested storage size from spec
	requestedSize := cluster.Spec.Manager.Workers.StorageSize
	if requestedSize == "" {
		// No storage size specified, clear any expansion status
		if cluster.Status.VolumeExpansion != nil && cluster.Status.VolumeExpansion.ManagerWorkersExpansion != nil {
			r.updateManagerWorkersExpansionStatus(ctx, cluster, nil)
		}
		return nil
	}

	// Get all worker PVCs
	pvcList, err := r.getManagerWorkerPVCs(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get worker PVCs: %w", err)
	}

	if len(pvcList.Items) == 0 {
		log.V(1).Info("No worker PVCs found, skipping volume expansion")
		return nil
	}

	// Track expansion progress
	var pvcsExpanded []string
	var pvcsPending []string
	var expansionError error

	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]

		// Validate expansion for this PVC
		validationResult, err := storage.ValidateExpansion(ctx, r.Client, pvc, requestedSize)
		if err != nil {
			log.Error(err, "Failed to validate expansion for PVC", "pvc", pvc.Name)
			expansionError = err
			pvcsPending = append(pvcsPending, pvc.Name)
			continue
		}

		// Handle validation result
		if !validationResult.NeedsExpansion {
			if validationResult.Valid {
				// Size already matches or is larger
				pvcsExpanded = append(pvcsExpanded, pvc.Name)
			} else {
				// Check if this is a shrink request (not supported)
				isShrink, _ := storage.IsShrinkRequest(validationResult.CurrentSize.String(), requestedSize)
				if isShrink {
					if r.Recorder != nil {
						r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageSizeDecreaseRejected,
							fmt.Sprintf("Storage size decrease not supported for worker PVC %s: cannot shrink from %s to %s",
								pvc.Name, validationResult.CurrentSize.String(), requestedSize))
					}
				}
				pvcsPending = append(pvcsPending, pvc.Name)
			}
			continue
		}

		// Check if validation passed (storage class supports expansion)
		if !validationResult.Valid {
			if !validationResult.StorageClassSupportsExpansion {
				if r.Recorder != nil {
					r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageClassNotExpandable,
						fmt.Sprintf("StorageClass for worker PVC %s does not support volume expansion", pvc.Name))
				}
			}
			pvcsPending = append(pvcsPending, pvc.Name)
			continue
		}

		// Check if expansion is already in progress
		condition := storage.GetPVCExpansionCondition(pvc)
		if !condition.IsComplete {
			log.V(1).Info("PVC expansion already in progress",
				"pvc", pvc.Name,
				"phase", condition.Phase,
				"message", condition.Message)
			pvcsPending = append(pvcsPending, pvc.Name)
			continue
		}

		// Initiate expansion
		log.Info("Expanding worker PVC", "pvc", pvc.Name, "from", validationResult.CurrentSize.String(), "to", requestedSize)
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionStarted,
				fmt.Sprintf("Starting volume expansion for worker PVC %s from %s to %s",
					pvc.Name, validationResult.CurrentSize.String(), requestedSize))
		}

		if err := storage.ExpandPVC(ctx, r.Client, pvc, requestedSize); err != nil {
			log.Error(err, "Failed to expand PVC", "pvc", pvc.Name)
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonVolumeExpansionFailed,
					fmt.Sprintf("Failed to expand worker PVC %s: %v", pvc.Name, err))
			}
			expansionError = err
			pvcsPending = append(pvcsPending, pvc.Name)
			continue
		}

		// PVC patch submitted, mark as pending until complete
		pvcsPending = append(pvcsPending, pvc.Name)
	}

	// Update expansion status
	var update storage.ExpansionStatusUpdate
	currentSize := requestedSize
	if len(pvcList.Items) > 0 {
		currentSize = storage.GetPVCStorageSize(&pvcList.Items[0])
	}

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
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionCompleted,
				fmt.Sprintf("All %d worker PVC(s) expanded successfully to %s", len(pvcsExpanded), requestedSize))
		}
	} else {
		// No PVCs found or no expansion needed - clear the status
		cluster.Status.VolumeExpansion.ManagerWorkersExpansion = nil
		return nil
	}

	r.updateManagerWorkersExpansionStatus(ctx, cluster, &update)
	return nil
}

// getManagerWorkerPVCs returns all PVCs associated with the manager worker StatefulSet
func (r *WorkerReconciler) getManagerWorkerPVCs(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*corev1.PersistentVolumeClaimList, error) {
	pvcList := &corev1.PersistentVolumeClaimList{}

	// List PVCs with labels matching worker StatefulSet
	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			constants.LabelInstance:  cluster.Name,
			constants.LabelComponent: "manager-worker",
		},
	}

	if err := r.List(ctx, pvcList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list worker PVCs: %w", err)
	}

	return pvcList, nil
}

// updateManagerWorkersExpansionStatus updates the manager workers expansion status in the cluster
func (r *WorkerReconciler) updateManagerWorkersExpansionStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, update *storage.ExpansionStatusUpdate) {
	log := logf.FromContext(ctx)

	if cluster.Status.VolumeExpansion == nil {
		cluster.Status.VolumeExpansion = &wazuhv1alpha1.VolumeExpansionStatus{}
	}

	if update == nil {
		cluster.Status.VolumeExpansion.ManagerWorkersExpansion = nil
	} else {
		cluster.Status.VolumeExpansion.ManagerWorkersExpansion = storage.UpdateComponentExpansionStatus(
			cluster.Status.VolumeExpansion.ManagerWorkersExpansion,
			*update,
		)
	}

	// Note: The actual status update will be handled by the main controller
	// This just updates the in-memory status object
	log.V(1).Info("Updated manager workers volume expansion status",
		"phase", func() string {
			if update != nil {
				return update.Phase
			}
			return "cleared"
		}())
}

// createOrUpdate creates or updates a resource with retry on conflict
func (r *WorkerReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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

// ManagerDrainCheckResult represents the result of a manager drain check
type ManagerDrainCheckResult struct {
	// NeedsDrain indicates if drain is required before scale-down
	NeedsDrain bool
	// DrainInProgress indicates if drain is currently running
	DrainInProgress bool
	// DrainComplete indicates if drain has completed successfully
	DrainComplete bool
	// TargetPod is the pod to be drained
	TargetPod string
	// Progress is the current drain progress (if in progress)
	Progress *drain.ManagerDrainProgress
	// Error if any occurred
	Error error
}

// CheckScaleDownDrain checks if a manager worker scale-down requires drain and handles it
// Returns a result indicating drain status and whether scale-down should proceed
func (r *WorkerReconciler) CheckScaleDownDrain(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, desiredReplicas int32) (*ManagerDrainCheckResult, error) {
	log := logf.FromContext(ctx)
	result := &ManagerDrainCheckResult{}

	// Get the current StatefulSet
	sts := &appsv1.StatefulSet{}
	stsName := fmt.Sprintf("%s-manager-worker", cluster.Name)
	if err := r.Get(ctx, types.NamespacedName{Name: stsName, Namespace: cluster.Namespace}, sts); err != nil {
		if errors.IsNotFound(err) {
			// No StatefulSet yet, no drain needed
			return result, nil
		}
		return nil, fmt.Errorf("failed to get worker StatefulSet: %w", err)
	}

	// Detect scale-down
	scaleInfo := drain.DetectStatefulSetScaleDown(sts, desiredReplicas)
	if !scaleInfo.Detected {
		// No scale-down detected
		return result, nil
	}

	log.Info("Scale-down detected for manager worker",
		"currentReplicas", scaleInfo.CurrentReplicas,
		"desiredReplicas", scaleInfo.TargetReplicas,
		"targetPod", scaleInfo.TargetPodName)

	result.NeedsDrain = true
	result.TargetPod = scaleInfo.TargetPodName

	// Check if drain configuration is enabled
	if cluster.Spec.Drain == nil || cluster.Spec.Drain.Manager == nil ||
		cluster.Spec.Drain.Manager.Enabled == nil || !*cluster.Spec.Drain.Manager.Enabled {
		log.Info("Manager drain is not enabled, proceeding with scale-down without drain")
		result.NeedsDrain = false
		return result, nil
	}

	// Initialize or get drain status
	drainStatus := r.getOrInitDrainStatus(cluster)

	// Check current drain phase
	switch drainStatus.Phase {
	case wazuhv1alpha1.DrainPhaseIdle, "":
		// Start new drain
		log.Info("Starting manager drain for scale-down", "targetPod", scaleInfo.TargetPodName)
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
		log.Info("Manager drain complete, proceeding with scale-down")
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
func (r *WorkerReconciler) getOrInitDrainStatus(cluster *wazuhv1alpha1.WazuhCluster) *wazuhv1alpha1.ComponentDrainStatus {
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
	}
	if cluster.Status.Drain.Manager == nil {
		cluster.Status.Drain.Manager = &wazuhv1alpha1.ComponentDrainStatus{
			Phase: wazuhv1alpha1.DrainPhaseIdle,
		}
	}
	return cluster.Status.Drain.Manager
}

// startDrain initiates the drain process for a manager worker node
func (r *WorkerReconciler) startDrain(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, scaleInfo drain.ScaleDownInfo, status *wazuhv1alpha1.ComponentDrainStatus) error {
	log := logf.FromContext(ctx)

	// Initialize Wazuh client if needed
	if err := r.ensureWazuhClient(ctx, cluster); err != nil {
		return fmt.Errorf("failed to create Wazuh client: %w", err)
	}

	// Get drain configuration
	var drainConfig *wazuhv1alpha1.ManagerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Manager
	}

	// Create drainer if not exists
	if r.drainer == nil {
		r.drainer = drain.NewManagerDrainer(r.wazuhClient, log, drainConfig)
	}

	// Get the node name from the pod name
	nodeName := scaleInfo.TargetPodName

	// Update status to pending
	if err := drain.StartDrain(status, nodeName, scaleInfo.CurrentReplicas, scaleInfo.TargetReplicas); err != nil {
		return fmt.Errorf("failed to transition drain state: %w", err)
	}

	// Emit event
	if r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.DrainEventReasonStarted,
			fmt.Sprintf("Starting manager queue drain for worker %s before scale-down", nodeName))
	}

	// Start the actual drain
	if err := r.drainer.StartDrain(ctx, nodeName); err != nil {
		// Mark as failed
		drain.MarkFailed(status, fmt.Sprintf("Failed to start drain: %v", err))
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.DrainEventReasonFailed,
				fmt.Sprintf("Failed to start manager drain: %v", err))
		}
		return err
	}

	// Transition to draining phase
	if err := drain.TransitionTo(status, wazuhv1alpha1.DrainPhaseDraining, "Draining event queue on worker"); err != nil {
		log.Error(err, "Failed to transition to draining phase")
	}

	log.Info("Manager drain started successfully", "node", nodeName)
	return nil
}

// monitorDrainProgress checks the current drain progress
func (r *WorkerReconciler) monitorDrainProgress(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string, status *wazuhv1alpha1.ComponentDrainStatus) (*drain.ManagerDrainProgress, error) {
	log := logf.FromContext(ctx)

	if r.drainer == nil {
		return nil, fmt.Errorf("drainer not initialized")
	}

	progress, err := r.drainer.MonitorQueueDepth(ctx, nodeName)
	if err != nil {
		log.Error(err, "Failed to monitor drain progress")
		return nil, err
	}

	// Update status
	drain.UpdateProgress(status, progress.Percent, progress.Message)
	drain.UpdateQueueDepth(status, progress.QueueDepth)

	log.V(1).Info("Manager drain progress",
		"node", nodeName,
		"percent", progress.Percent,
		"queueDepth", progress.QueueDepth,
		"complete", progress.IsComplete)

	// Check for completion
	if progress.IsComplete {
		if err := drain.TransitionTo(status, wazuhv1alpha1.DrainPhaseVerifying, "Verifying queue drain completion"); err != nil {
			log.Error(err, "Failed to transition to verifying phase")
		}
	}

	return &progress, nil
}

// verifyDrainComplete verifies that drain is fully complete
func (r *WorkerReconciler) verifyDrainComplete(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string, status *wazuhv1alpha1.ComponentDrainStatus) (bool, error) {
	log := logf.FromContext(ctx)

	if r.drainer == nil {
		return false, fmt.Errorf("drainer not initialized")
	}

	complete, err := r.drainer.VerifyQueueEmpty(ctx, nodeName)
	if err != nil {
		log.Error(err, "Failed to verify drain completion")
		return false, err
	}

	if complete {
		// Mark as complete
		if err := drain.MarkComplete(status); err != nil {
			log.Error(err, "Failed to mark drain as complete")
		}

		// Cancel drain (reset state)
		if err := r.drainer.CancelDrain(ctx); err != nil {
			log.Error(err, "Failed to clean up after drain")
			// Don't fail, drain is still complete
		}

		// Emit event
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.DrainEventReasonCompleted,
				fmt.Sprintf("Manager drain completed for worker %s", nodeName))
		}

		log.Info("Manager drain verified complete", "node", nodeName)
	}

	return complete, nil
}

// ensureWazuhClient creates or reuses a Wazuh API client
func (r *WorkerReconciler) ensureWazuhClient(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	if r.wazuhClient != nil {
		return nil
	}

	// Build the Wazuh API URL from the cluster name
	// The master service is typically named {cluster-name}-manager-master
	masterServiceName := fmt.Sprintf("%s-manager-master", cluster.Name)
	baseURL := fmt.Sprintf("https://%s.%s.svc.cluster.local:%d",
		masterServiceName, cluster.Namespace, constants.PortManagerAPI)

	// Get API credentials from secret
	username, password, err := r.getWazuhAPICredentials(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get Wazuh API credentials: %w", err)
	}

	r.wazuhClient = adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Insecure: true, // Use insecure for internal cluster communication
	})

	return nil
}

// getWazuhAPICredentials retrieves the Wazuh API credentials from the cluster
func (r *WorkerReconciler) getWazuhAPICredentials(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (string, string, error) {
	// Check if credentials are specified in the cluster spec
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil {
		secretName := cluster.Spec.Manager.APICredentials.SecretName
		if secretName != "" {
			secret := &corev1.Secret{}
			if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
				return "", "", fmt.Errorf("failed to get API credentials secret: %w", err)
			}

			usernameKey := cluster.Spec.Manager.APICredentials.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			passwordKey := cluster.Spec.Manager.APICredentials.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}

			username := string(secret.Data[usernameKey])
			password := string(secret.Data[passwordKey])
			return username, password, nil
		}
	}

	// Default: try to get from default credentials secret
	defaultSecretName := fmt.Sprintf("%s-wazuh-api-credentials", cluster.Name)
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: defaultSecretName, Namespace: cluster.Namespace}, secret); err != nil {
		if errors.IsNotFound(err) {
			// Use default credentials
			return "wazuh", "wazuh", nil
		}
		return "", "", fmt.Errorf("failed to get default API credentials secret: %w", err)
	}

	return string(secret.Data["username"]), string(secret.Data["password"]), nil
}

// ResetDrainState resets the drain state after a successful scale-down
func (r *WorkerReconciler) ResetDrainState(cluster *wazuhv1alpha1.WazuhCluster) {
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		drain.Reset(cluster.Status.Drain.Manager)
	}
	// Clear cached drainer for next operation
	r.drainer = nil
}

// EvaluateDrainFeasibility evaluates if drain is feasible (for dry-run mode)
func (r *WorkerReconciler) EvaluateDrainFeasibility(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, nodeName string) (*wazuhv1alpha1.DryRunResult, error) {
	// Initialize Wazuh client if needed
	if err := r.ensureWazuhClient(ctx, cluster); err != nil {
		return &wazuhv1alpha1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentManager,
			Blockers:    []string{fmt.Sprintf("Cannot connect to Wazuh API: %v", err)},
		}, nil
	}

	// Get drain configuration
	var drainConfig *wazuhv1alpha1.ManagerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Manager
	}

	// Create drainer for evaluation
	drainer := drain.NewManagerDrainer(r.wazuhClient, logf.FromContext(ctx), drainConfig)
	return drainer.EvaluateFeasibility(ctx, nodeName)
}
