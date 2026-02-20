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
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/serviceaccount"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
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

// ReconcileStandalone reconciles a standalone WazuhManager resource
func (r *ManagerReconciler) ReconcileStandalone(ctx context.Context, manager *wazuhv1.WazuhManager) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ManagerReconciler.ReconcileStandalone",
		telemetry.WithAttributes(
			attribute.String("resource.name", manager.Name),
			attribute.String("resource.namespace", manager.Namespace),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

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
func (r *ManagerReconciler) reconcileStandaloneConfigMap(ctx context.Context, manager *wazuhv1.WazuhManager, nodeType string) error {
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(manager, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// reconcileStandaloneServices reconciles services for standalone manager
func (r *ManagerReconciler) reconcileStandaloneServices(ctx context.Context, manager *wazuhv1.WazuhManager, nodeType string) error {
	if nodeType == "master" {
		serviceBuilder := services.NewManagerServiceBuilder(manager.Name, manager.Namespace, "master")
		if manager.Spec.Master.Service != nil && len(manager.Spec.Master.Service.Annotations) > 0 {
			serviceBuilder.WithAnnotations(manager.Spec.Master.Service.Annotations)
		}

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
		if manager.Spec.Workers.Service != nil && len(manager.Spec.Workers.Service.Annotations) > 0 {
			serviceBuilder.WithAnnotations(manager.Spec.Workers.Service.Annotations)
		}

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
func (r *ManagerReconciler) reconcileStandaloneStatefulSet(ctx context.Context, manager *wazuhv1.WazuhManager, nodeType string) error {
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
		if len(manager.Spec.Master.ExtraVolumes) > 0 {
			stsBuilder.WithVolumes(manager.Spec.Master.ExtraVolumes)
		}
		if len(manager.Spec.Master.ExtraVolumeMounts) > 0 {
			stsBuilder.WithVolumeMounts(manager.Spec.Master.ExtraVolumeMounts)
		}
		if len(manager.Spec.Master.ExtraInitContainers) > 0 {
			stsBuilder.WithExtraInitContainers(manager.Spec.Master.ExtraInitContainers)
		}
		if len(manager.Spec.Master.ExtraContainers) > 0 {
			stsBuilder.WithExtraContainers(manager.Spec.Master.ExtraContainers)
		}
		if len(manager.Spec.Master.Annotations) > 0 {
			stsBuilder.WithAnnotations(manager.Spec.Master.Annotations)
		}
		if len(manager.Spec.Master.PodAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(manager.Spec.Master.PodAnnotations)
		}
		if manager.Spec.Master.NodeSelector != nil {
			stsBuilder.WithNodeSelector(manager.Spec.Master.NodeSelector)
		}
		if manager.Spec.Master.Tolerations != nil {
			stsBuilder.WithTolerations(manager.Spec.Master.Tolerations)
		}
		if manager.Spec.Master.Affinity != nil {
			stsBuilder.WithAffinity(manager.Spec.Master.Affinity)
		}
		// Set termination grace period (default + user override)
		terminationGracePeriod := constants.DefaultManagerTerminationGracePeriod
		if manager.Spec.Master.TerminationGracePeriodSeconds != nil {
			terminationGracePeriod = *manager.Spec.Master.TerminationGracePeriodSeconds
		}
		stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)
		// Reconcile and set ServiceAccount if configured
		if manager.Spec.Master.ServiceAccount != nil {
			saName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, manager,
				manager.Spec.Master.ServiceAccount, manager.Name, manager.Namespace, "master")
			if err != nil {
				return fmt.Errorf("failed to reconcile master ServiceAccount: %w", err)
			}
			if saName != "" {
				stsBuilder.WithServiceAccountName(saName)
			}
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
		if len(manager.Spec.Workers.ExtraVolumes) > 0 {
			stsBuilder.WithVolumes(manager.Spec.Workers.ExtraVolumes)
		}
		if len(manager.Spec.Workers.ExtraVolumeMounts) > 0 {
			stsBuilder.WithVolumeMounts(manager.Spec.Workers.ExtraVolumeMounts)
		}
		if len(manager.Spec.Workers.ExtraInitContainers) > 0 {
			stsBuilder.WithExtraInitContainers(manager.Spec.Workers.ExtraInitContainers)
		}
		if len(manager.Spec.Workers.ExtraContainers) > 0 {
			stsBuilder.WithExtraContainers(manager.Spec.Workers.ExtraContainers)
		}
		if len(manager.Spec.Workers.Annotations) > 0 {
			stsBuilder.WithAnnotations(manager.Spec.Workers.Annotations)
		}
		if len(manager.Spec.Workers.PodAnnotations) > 0 {
			stsBuilder.WithPodAnnotations(manager.Spec.Workers.PodAnnotations)
		}
		if manager.Spec.Workers.NodeSelector != nil {
			stsBuilder.WithNodeSelector(manager.Spec.Workers.NodeSelector)
		}
		if manager.Spec.Workers.Tolerations != nil {
			stsBuilder.WithTolerations(manager.Spec.Workers.Tolerations)
		}
		if manager.Spec.Workers.Affinity != nil {
			stsBuilder.WithAffinity(manager.Spec.Workers.Affinity)
		}
		// Set termination grace period (default + user override)
		terminationGracePeriod := constants.DefaultManagerTerminationGracePeriod
		if manager.Spec.Workers.TerminationGracePeriodSeconds != nil {
			terminationGracePeriod = *manager.Spec.Workers.TerminationGracePeriodSeconds
		}
		stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)
		// Reconcile and set ServiceAccount if configured
		if manager.Spec.Workers.ServiceAccount != nil {
			saName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, manager,
				manager.Spec.Workers.ServiceAccount, manager.Name, manager.Namespace, "worker")
			if err != nil {
				return fmt.Errorf("failed to reconcile worker ServiceAccount: %w", err)
			}
			if saName != "" {
				stsBuilder.WithServiceAccountName(saName)
			}
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

	needsUpdate := false
	if nodeType == "worker" && *found.Spec.Replicas != *sts.Spec.Replicas {
		log.Info("Updating StatefulSet replicas", "name", sts.Name, "replicas", *sts.Spec.Replicas)
		needsUpdate = true
	}
	if utils.HashMap(sts.Annotations) != utils.HashMap(found.Annotations) {
		log.Info("Updating StatefulSet due to annotation change", "name", sts.Name)
		needsUpdate = true
	}
	if utils.HashMap(sts.Spec.Template.Annotations) != utils.HashMap(found.Spec.Template.Annotations) {
		log.Info("Updating StatefulSet due to pod annotation change", "name", sts.Name)
		needsUpdate = true
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Tolerations, found.Spec.Template.Spec.Tolerations) {
		log.Info("Updating StatefulSet due to tolerations change", "name", sts.Name)
		needsUpdate = true
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Affinity, found.Spec.Template.Spec.Affinity) {
		log.Info("Updating StatefulSet due to affinity change", "name", sts.Name)
		needsUpdate = true
	}
	if needsUpdate {
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
				r.Recorder.Event(manager, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
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

// updateStatefulSetWithRetry updates a StatefulSet with retry-on-conflict.
// It merges mutable fields from desired into the current server object rather than
// doing a full PUT replacement, which avoids issues with server-defaulted immutable
// fields (e.g. VolumeClaimTemplates) causing silent update failures.
func (r *ManagerReconciler) updateStatefulSetWithRetry(ctx context.Context, desired *appsv1.StatefulSet) error {
	return utils.RetryOnConflict(ctx, func() error {
		current := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, current); err != nil {
			return err
		}
		patch.MergeStatefulSetUpdate(current, desired)
		return r.Update(ctx, current)
	})
}
