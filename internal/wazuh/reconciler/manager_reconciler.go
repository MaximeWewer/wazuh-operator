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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerReconciler handles reconciliation of Wazuh Manager (master node)
type ManagerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewManagerReconciler creates a new ManagerReconciler
func NewManagerReconciler(c client.Client, scheme *runtime.Scheme) *ManagerReconciler {
	return &ManagerReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithRecorder sets the event recorder for the reconciler
func (r *ManagerReconciler) WithRecorder(recorder record.EventRecorder) *ManagerReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the Wazuh Manager (master node)
func (r *ManagerReconciler) Reconcile(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager configmap: %w", err)
	}

	// Reconcile Services
	if err := r.reconcileServices(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager services: %w", err)
	}

	// Reconcile StatefulSet
	if err := r.reconcileStatefulSet(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager statefulset: %w", err)
	}

	log.Info("Manager (master) reconciliation completed")
	return nil
}

// reconcileConfigMap reconciles the manager ConfigMap
func (r *ManagerReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	configBuilder := configmaps.NewManagerConfigMapBuilder(cluster.Name, cluster.Namespace, "master")

	// Convert CRD config spec to internal config structs
	var configSpec *wazuhv1alpha1.WazuhConfigSpec
	if cluster.Spec.Manager != nil {
		configSpec = cluster.Spec.Manager.Config
	}
	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg := config.WazuhConfigFromSpec(configSpec)

	// Resolve authd password from secret if configured
	authdPassword := ""
	if authCfg.UsePassword && authCfg.PasswordSecretRef != nil {
		password, err := r.resolveSecretKey(ctx, cluster.Namespace, authCfg.PasswordSecretRef.Name, authCfg.PasswordSecretRef.Key)
		if err != nil {
			log.Error(err, "Failed to resolve authd password from secret", "secret", authCfg.PasswordSecretRef.Name)
			// Don't fail - continue with empty password, operator can retry
		} else {
			authdPassword = password
		}
	}

	// Get extra config for master node
	extraConfig := ""
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.ExtraConfig != "" {
		extraConfig = cluster.Spec.Manager.Master.ExtraConfig
	}

	// Build ossec.conf using the config builder with CRD values
	ossecConfig := config.DefaultOSSECConfig(cluster.Name, cluster.Name+"-manager-master")
	ossecConfig.NodeType = config.NodeTypeMaster
	ossecConfig.Namespace = cluster.Namespace
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
			// Fall back to default admin
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

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// resolveSecretKey reads a key from a secret
func (r *ManagerReconciler) resolveSecretKey(ctx context.Context, namespace, secretName, key string) (string, error) {
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

// getConfigHash retrieves the current config hash from the manager ConfigMap
func (r *ManagerReconciler) getConfigHash(ctx context.Context, clusterName, namespace, nodeType string) string {
	configMapName := fmt.Sprintf("%s-manager-%s-config", clusterName, nodeType)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// reconcileServices reconciles manager services
func (r *ManagerReconciler) reconcileServices(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	serviceBuilder := services.NewManagerServiceBuilder(cluster.Name, cluster.Namespace, "master")

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

	log.V(1).Info("Manager services reconciled")
	return nil
}

// reconcileStatefulSet reconciles the manager StatefulSet
func (r *ManagerReconciler) reconcileStatefulSet(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	version := cluster.Spec.Version
	resources := cluster.Spec.Manager.Master.Resources
	storageSize := cluster.Spec.Manager.Master.StorageSize
	nodeSelector := cluster.Spec.Manager.Master.NodeSelector
	tolerations := cluster.Spec.Manager.Master.Tolerations
	affinity := cluster.Spec.Manager.Master.Affinity

	// Compute spec hash for change detection (includes scheduling options)
	specHash, err := patch.ComputeManagerMasterSpecHash(version, resources, storageSize, "", nodeSelector, tolerations, affinity)
	if err != nil {
		log.Error(err, "Failed to compute manager master spec hash, continuing without spec tracking")
		specHash = ""
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster.Name, cluster.Namespace, "master")

	stsBuilder := deployments.NewManagerStatefulSetBuilder(cluster.Name, cluster.Namespace, "master")

	// Apply spec from cluster
	if cluster.Spec.Version != "" {
		stsBuilder.WithVersion(cluster.Spec.Version)
	}
	if cluster.Spec.Manager.Master.Resources != nil {
		stsBuilder.WithResources(cluster.Spec.Manager.Master.Resources)
	}
	if cluster.Spec.Manager.Master.NodeSelector != nil {
		stsBuilder.WithNodeSelector(cluster.Spec.Manager.Master.NodeSelector)
	}

	// Set spec hash for change detection
	if specHash != "" {
		stsBuilder.WithSpecHash(specHash)
	}

	// Set config hash to trigger pod restart on config changes
	if configHash != "" {
		stsBuilder.WithConfigHash(configHash)
	}
	// Set cluster reference for monitoring sidecar
	stsBuilder.WithCluster(cluster)

	sts := stsBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if StatefulSet exists
	found := &appsv1.StatefulSet{}
	err = r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Manager StatefulSet", "name", sts.Name, "specHash", patch.ShortHash(specHash))
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

	// Check spec hash (version, resources changes)
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Manager master spec changed",
			"name", sts.Name,
			"oldSpecHash", patch.ShortHash(existingSpecHash),
			"newSpecHash", patch.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Emit Kubernetes event for spec change
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Manager master spec changed (version=%s)", version))
		}
	}

	// Check config hash (ConfigMap content changes)
	existingConfigHash := ""
	if found.Spec.Template.Annotations != nil {
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}

	if configHash != "" && configHash != existingConfigHash {
		log.Info("Manager ConfigMap hash changed",
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
				fmt.Sprintf("Manager ConfigMap changed, pods will restart (StatefulSet %s)", sts.Name))
		}
	}

	if needsUpdate {
		// Preserve immutable fields
		sts.Spec.Selector = found.Spec.Selector
		sts.Spec.ServiceName = found.Spec.ServiceName
		sts.Spec.PodManagementPolicy = found.Spec.PodManagementPolicy
		sts.SetResourceVersion(found.GetResourceVersion())

		log.Info("Updating Manager StatefulSet", "name", sts.Name, "reason", updateReason)
		if err := r.Update(ctx, sts); err != nil {
			return fmt.Errorf("failed to update statefulset: %w", err)
		}
	}

	return nil
}

// GetStatus returns the manager status
func (r *ManagerReconciler) GetStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*wazuhv1alpha1.ComponentStatus, error) {
	sts := &appsv1.StatefulSet{}
	name := fmt.Sprintf("%s-manager-master", cluster.Name)

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

// ReconcileStandalone reconciles a standalone WazuhManager resource
func (r *ManagerReconciler) ReconcileStandalone(ctx context.Context, manager *wazuhv1alpha1.WazuhManager) error {
	log := logf.FromContext(ctx)

	// Reconcile Master node ConfigMap
	if err := r.reconcileStandaloneConfigMap(ctx, manager, "master"); err != nil {
		return fmt.Errorf("failed to reconcile master configmap: %w", err)
	}

	// Reconcile Master Services
	if err := r.reconcileStandaloneServices(ctx, manager, "master"); err != nil {
		return fmt.Errorf("failed to reconcile master services: %w", err)
	}

	// Reconcile Master StatefulSet
	if err := r.reconcileStandaloneStatefulSet(ctx, manager, "master"); err != nil {
		return fmt.Errorf("failed to reconcile master statefulset: %w", err)
	}

	// Reconcile Workers if configured
	if manager.Spec.Workers.GetReplicas() > 0 {
		if err := r.reconcileStandaloneConfigMap(ctx, manager, "worker"); err != nil {
			return fmt.Errorf("failed to reconcile worker configmap: %w", err)
		}
		if err := r.reconcileStandaloneServices(ctx, manager, "worker"); err != nil {
			return fmt.Errorf("failed to reconcile worker services: %w", err)
		}
		if err := r.reconcileStandaloneStatefulSet(ctx, manager, "worker"); err != nil {
			return fmt.Errorf("failed to reconcile worker statefulset: %w", err)
		}
	}

	log.Info("Standalone manager reconciliation completed", "name", manager.Name)
	return nil
}

// reconcileStandaloneConfigMap reconciles a ConfigMap for standalone manager
func (r *ManagerReconciler) reconcileStandaloneConfigMap(ctx context.Context, manager *wazuhv1alpha1.WazuhManager, nodeType string) error {
	log := logf.FromContext(ctx)
	configBuilder := configmaps.NewManagerConfigMapBuilder(manager.Name, manager.Namespace, nodeType)

	// Convert CRD config spec to internal config structs
	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg := config.WazuhConfigFromSpec(manager.Spec.Config)

	// Resolve authd password from secret if configured
	authdPassword := ""
	if authCfg.UsePassword && authCfg.PasswordSecretRef != nil {
		password, err := r.resolveSecretKey(ctx, manager.Namespace, authCfg.PasswordSecretRef.Name, authCfg.PasswordSecretRef.Key)
		if err != nil {
			log.Error(err, "Failed to resolve authd password from secret", "secret", authCfg.PasswordSecretRef.Name)
		} else {
			authdPassword = password
		}
	}

	// Get extra config based on node type
	extraConfig := ""
	if nodeType == "master" && manager.Spec.Master.ExtraConfig != "" {
		extraConfig = manager.Spec.Master.ExtraConfig
	} else if nodeType == "worker" && manager.Spec.Workers.ExtraConfig != "" {
		extraConfig = manager.Spec.Workers.ExtraConfig
	}

	// Build ossec.conf using the config builder with CRD values
	nodeName := fmt.Sprintf("%s-manager-%s", manager.Name, nodeType)
	ossecConfig := config.DefaultOSSECConfig(manager.Name, nodeName)
	ossecConfig.Namespace = manager.Namespace
	ossecConfig.Global = globalCfg
	ossecConfig.Alerts = alertsCfg
	ossecConfig.Logging = loggingCfg
	ossecConfig.Remote = remoteCfg
	ossecConfig.Auth = authCfg
	ossecConfig.AuthdPassword = authdPassword
	ossecConfig.ExtraConfig = extraConfig

	if nodeType == "master" {
		ossecConfig.NodeType = config.NodeTypeMaster
	} else {
		ossecConfig.NodeType = config.NodeTypeWorker
		ossecConfig.MasterAddress = config.GetMasterServiceAddress(manager.Name, manager.Namespace)
		ossecConfig.MasterPort = int(constants.PortManagerCluster)
	}

	ossecConfBuilder := config.NewOSSECConfigBuilder(ossecConfig)
	ossecConf, err := ossecConfBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build ossec.conf: %w", err)
	}
	configBuilder.WithOSSECConfig(ossecConf)

	// Generate filebeat.yml with correct indexer host
	indexerService := fmt.Sprintf("%s-indexer", manager.Name)
	sslVerificationMode := "full"
	if manager.Spec.FilebeatSSLVerificationMode != "" {
		sslVerificationMode = manager.Spec.FilebeatSSLVerificationMode
	}

	// Note: For standalone manager, indexer credentials would need to be resolved
	// from a separate indexer CRD or cluster reference - using empty for now
	filebeatConf, err := config.BuildFilebeatConfigWithCredentials(
		manager.Name,
		manager.Namespace,
		indexerService,
		sslVerificationMode,
		"", // Will use default "admin"
		"", // Password via env var
	)
	if err != nil {
		return fmt.Errorf("failed to build filebeat.yml: %w", err)
	}
	configBuilder.WithFilebeatConfig(filebeatConf)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(manager, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// reconcileStandaloneServices reconciles services for standalone manager
func (r *ManagerReconciler) reconcileStandaloneServices(ctx context.Context, manager *wazuhv1alpha1.WazuhManager, nodeType string) error {
	if nodeType == "master" {
		serviceBuilder := services.NewManagerServiceBuilder(manager.Name, manager.Namespace, "master")

		service := serviceBuilder.Build()
		if err := controllerutil.SetControllerReference(manager, service, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.createOrUpdate(ctx, service); err != nil {
			return fmt.Errorf("failed to reconcile service: %w", err)
		}

		headlessService := serviceBuilder.BuildHeadless()
		if err := controllerutil.SetControllerReference(manager, headlessService, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.createOrUpdate(ctx, headlessService); err != nil {
			return fmt.Errorf("failed to reconcile headless service: %w", err)
		}
	} else {
		serviceBuilder := services.NewWorkerServiceBuilder(manager.Name, manager.Namespace)

		service := serviceBuilder.Build()
		if err := controllerutil.SetControllerReference(manager, service, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.createOrUpdate(ctx, service); err != nil {
			return fmt.Errorf("failed to reconcile service: %w", err)
		}

		headlessService := serviceBuilder.BuildHeadless()
		if err := controllerutil.SetControllerReference(manager, headlessService, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.createOrUpdate(ctx, headlessService); err != nil {
			return fmt.Errorf("failed to reconcile headless service: %w", err)
		}
	}

	return nil
}

// reconcileStandaloneStatefulSet reconciles a StatefulSet for standalone manager
func (r *ManagerReconciler) reconcileStandaloneStatefulSet(ctx context.Context, manager *wazuhv1alpha1.WazuhManager, nodeType string) error {
	log := logf.FromContext(ctx)

	var sts *appsv1.StatefulSet
	if nodeType == "master" {
		stsBuilder := deployments.NewManagerStatefulSetBuilder(manager.Name, manager.Namespace, "master")
		if manager.Spec.Version != "" {
			stsBuilder.WithVersion(manager.Spec.Version)
		}
		if manager.Spec.Master.Resources != nil {
			stsBuilder.WithResources(manager.Spec.Master.Resources)
		}
		if manager.Spec.Master.NodeSelector != nil {
			stsBuilder.WithNodeSelector(manager.Spec.Master.NodeSelector)
		}
		sts = stsBuilder.Build()
	} else {
		stsBuilder := deployments.NewWorkerStatefulSetBuilder(manager.Name, manager.Namespace)
		if manager.Spec.Version != "" {
			stsBuilder.WithVersion(manager.Spec.Version)
		}
		// Always set replicas from spec (including 0 for no workers)
		stsBuilder.WithReplicas(manager.Spec.Workers.GetReplicas())
		if manager.Spec.Workers.Resources != nil {
			stsBuilder.WithResources(manager.Spec.Workers.Resources)
		}
		if manager.Spec.Workers.NodeSelector != nil {
			stsBuilder.WithNodeSelector(manager.Spec.Workers.NodeSelector)
		}
		sts = stsBuilder.Build()
	}

	if err := controllerutil.SetControllerReference(manager, sts, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	found := &appsv1.StatefulSet{}
	err := r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Manager StatefulSet", "name", sts.Name, "type", nodeType)
		if err := r.Create(ctx, sts); err != nil {
			return fmt.Errorf("failed to create statefulset: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Update if replicas changed (for workers)
	if nodeType == "worker" && *found.Spec.Replicas != *sts.Spec.Replicas {
		log.Info("Updating StatefulSet replicas", "name", sts.Name, "replicas", *sts.Spec.Replicas)
		found.Spec.Replicas = sts.Spec.Replicas
		if err := r.Update(ctx, found); err != nil {
			return fmt.Errorf("failed to update statefulset replicas: %w", err)
		}
	}

	return nil
}

// createOrUpdate creates or updates a resource with retry on conflict
func (r *ManagerReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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
