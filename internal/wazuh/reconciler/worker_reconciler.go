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
	"time"

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

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	shareddrain "github.com/MaximeWewer/wazuh-operator/internal/shared/drain"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/serviceaccount"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
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

// ReconcileStandalone reconciles a standalone WazuhWorker resource
func (r *WorkerReconciler) ReconcileStandalone(ctx context.Context, worker *wazuhv1.WazuhWorker) error {
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
func (r *WorkerReconciler) reconcileStandaloneConfigMap(ctx context.Context, worker *wazuhv1.WazuhWorker) error {
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

	// Generate wazuh-template.json for filebeat index template
	templateBuilder := config.NewFilebeatTemplateBuilder()
	filebeatTemplate, err := templateBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build wazuh-template.json: %w", err)
	}
	configBuilder.WithFilebeatTemplate(filebeatTemplate)

	configMap := configBuilder.Build()
	if err := controllerutil.SetControllerReference(worker, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// reconcileStandaloneServices reconciles services for standalone worker
func (r *WorkerReconciler) reconcileStandaloneServices(ctx context.Context, worker *wazuhv1.WazuhWorker) error {
	serviceBuilder := services.NewWorkerServiceBuilder(worker.Name, worker.Namespace)
	if worker.Spec.Service != nil && len(worker.Spec.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(worker.Spec.Service.Annotations)
	}

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
func (r *WorkerReconciler) reconcileStandaloneStatefulSet(ctx context.Context, worker *wazuhv1.WazuhWorker) error {
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
	if len(worker.Spec.Annotations) > 0 {
		stsBuilder.WithAnnotations(worker.Spec.Annotations)
	}
	if len(worker.Spec.PodAnnotations) > 0 {
		stsBuilder.WithPodAnnotations(worker.Spec.PodAnnotations)
	}
	if worker.Spec.NodeSelector != nil {
		stsBuilder.WithNodeSelector(worker.Spec.NodeSelector)
	}
	if len(worker.Spec.ExtraVolumes) > 0 {
		stsBuilder.WithVolumes(worker.Spec.ExtraVolumes)
	}
	if len(worker.Spec.ExtraVolumeMounts) > 0 {
		stsBuilder.WithVolumeMounts(worker.Spec.ExtraVolumeMounts)
	}
	if len(worker.Spec.ExtraInitContainers) > 0 {
		stsBuilder.WithExtraInitContainers(worker.Spec.ExtraInitContainers)
	}
	if len(worker.Spec.ExtraContainers) > 0 {
		stsBuilder.WithExtraContainers(worker.Spec.ExtraContainers)
	}
	if worker.Spec.Tolerations != nil {
		stsBuilder.WithTolerations(worker.Spec.Tolerations)
	}
	if worker.Spec.Affinity != nil {
		stsBuilder.WithAffinity(worker.Spec.Affinity)
	}

	// Set termination grace period default
	terminationGracePeriod := constants.DefaultManagerTerminationGracePeriod
	stsBuilder.WithTerminationGracePeriodSeconds(&terminationGracePeriod)

	// Reconcile and set ServiceAccount if configured
	if worker.Spec.ServiceAccount != nil {
		saName, err := serviceaccount.ReconcileServiceAccount(ctx, r.Client, r.Scheme, worker,
			worker.Spec.ServiceAccount, worker.Name, worker.Namespace, "worker")
		if err != nil {
			return fmt.Errorf("failed to reconcile worker ServiceAccount: %w", err)
		}
		if saName != "" {
			stsBuilder.WithServiceAccountName(saName)
		}
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

	// Update replicas or annotations if changed
	needsUpdate := false
	if *found.Spec.Replicas != *sts.Spec.Replicas {
		log.Info("Updating Worker StatefulSet replicas", "name", sts.Name, "replicas", *sts.Spec.Replicas)
		direction := "up"
		if *sts.Spec.Replicas < *found.Spec.Replicas {
			direction = "down"
		}
		metrics.RecordScaleOperation(worker.Name, worker.Namespace, "worker", direction)
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
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Tolerations, found.Spec.Template.Spec.Tolerations) {
		log.Info("Updating Worker StatefulSet due to tolerations change", "name", sts.Name)
		needsUpdate = true
	}
	if !reflect.DeepEqual(sts.Spec.Template.Spec.Affinity, found.Spec.Template.Spec.Affinity) {
		log.Info("Updating Worker StatefulSet due to affinity change", "name", sts.Name)
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
				r.Recorder.Event(worker, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted StatefulSet %s/%s due to immutable field change; re-creation on next reconciliation", sts.Namespace, sts.Name))
			}
			return fmt.Errorf("statefulset %s/%s deleted for immutable field recreation", sts.Namespace, sts.Name)
		}
	}

	return nil
}

// createOrUpdate creates or updates a resource with retry on conflict
func (r *WorkerReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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

// updateStatefulSetWithRetry updates a StatefulSet with retry-on-conflict, always using the latest resourceVersion.
func (r *WorkerReconciler) updateStatefulSetWithRetry(ctx context.Context, desired *appsv1.StatefulSet) error {
	return utils.RetryOnConflict(ctx, func() error {
		current := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, current); err != nil {
			return err
		}
		desired.SetResourceVersion(current.GetResourceVersion())
		return r.Update(ctx, desired)
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
func (r *WorkerReconciler) CheckScaleDownDrain(ctx context.Context, cluster *wazuhv1.WazuhCluster, desiredReplicas int32) (*ManagerDrainCheckResult, error) {
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
	scaleInfo := shareddrain.DetectStatefulSetScaleDown(sts, desiredReplicas)
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
	case wazuhv1.DrainPhaseIdle, "":
		// Start new drain
		log.Info("Starting manager drain for scale-down", "targetPod", scaleInfo.TargetPodName)
		metrics.RecordDrainStarted(cluster.Name, cluster.Namespace, "manager")
		if err := r.startDrain(ctx, cluster, scaleInfo, drainStatus); err != nil {
			metrics.RecordDrainFailed(cluster.Name, cluster.Namespace, "manager")
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
			metrics.RecordDrainProgress(cluster.Name, cluster.Namespace, "manager", float64(progress.Percent))
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
			metrics.RecordDrainCompleted(cluster.Name, cluster.Namespace, "manager")
			metrics.RecordDrainOperation(cluster.Name, cluster.Namespace, "manager", "success", durationSeconds)
			metrics.QueueDrainDuration.WithLabelValues(cluster.Name, cluster.Namespace).Observe(durationSeconds)
			result.DrainComplete = true
			result.DrainInProgress = false
		} else {
			result.DrainInProgress = true
		}
		return result, nil

	case wazuhv1.DrainPhaseComplete:
		// Drain complete, proceed with scale-down
		log.Info("Manager drain complete, proceeding with scale-down")
		metrics.ResetDrainMetrics(cluster.Name, cluster.Namespace, "manager")
		result.DrainComplete = true
		return result, nil

	case wazuhv1.DrainPhaseFailed:
		// Drain failed - check if we should retry or skip
		log.Info("Previous drain failed", "message", drainStatus.Message)
		metrics.RecordDrainFailed(cluster.Name, cluster.Namespace, "manager")
		var durationSeconds float64
		if drainStatus.StartTime != nil {
			durationSeconds = time.Since(drainStatus.StartTime.Time).Seconds()
		}
		metrics.RecordDrainOperation(cluster.Name, cluster.Namespace, "manager", "failure", durationSeconds)
		result.Error = fmt.Errorf("drain failed: %s", drainStatus.Message)
		return result, nil

	default:
		log.Info("Unknown drain phase", "phase", drainStatus.Phase)
		return result, nil
	}
}

// getOrInitDrainStatus returns the current drain status or initializes a new one
func (r *WorkerReconciler) getOrInitDrainStatus(cluster *wazuhv1.WazuhCluster) *wazuhv1.ComponentDrainStatus {
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1.DrainStatus{}
	}
	if cluster.Status.Drain.Manager == nil {
		cluster.Status.Drain.Manager = &wazuhv1.ComponentDrainStatus{
			Phase: wazuhv1.DrainPhaseIdle,
		}
	}
	return cluster.Status.Drain.Manager
}

// startDrain initiates the drain process for a manager worker node
func (r *WorkerReconciler) startDrain(ctx context.Context, cluster *wazuhv1.WazuhCluster, scaleInfo shareddrain.ScaleDownInfo, status *wazuhv1.ComponentDrainStatus) error {
	log := logf.FromContext(ctx)

	// Initialize Wazuh client if needed
	if err := r.ensureWazuhClient(ctx, cluster); err != nil {
		return fmt.Errorf("failed to create Wazuh client: %w", err)
	}

	// Get drain configuration
	var drainConfig *wazuhv1.ManagerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Manager
	}

	// Create drainer if not exists
	if r.drainer == nil {
		r.drainer = drain.NewManagerDrainer(r.wazuhClient, log, drainConfig, cluster.Name, cluster.Namespace)
	}

	// Get the node name from the pod name
	nodeName := scaleInfo.TargetPodName

	// Update status to pending
	if err := shareddrain.StartDrain(status, nodeName, scaleInfo.CurrentReplicas, scaleInfo.TargetReplicas); err != nil {
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
		_ = shareddrain.MarkFailed(status, fmt.Sprintf("Failed to start drain: %v", err))
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.DrainEventReasonFailed,
				fmt.Sprintf("Failed to start manager drain: %v", err))
		}
		return err
	}

	// Transition to draining phase
	if err := shareddrain.TransitionTo(status, wazuhv1.DrainPhaseDraining, "Draining event queue on worker"); err != nil {
		log.Error(err, "Failed to transition to draining phase")
	}

	log.Info("Manager drain started successfully", "node", nodeName)
	return nil
}

// monitorDrainProgress checks the current drain progress
//
//nolint:unparam // cluster param kept for consistency with other reconcilers
func (r *WorkerReconciler) monitorDrainProgress(ctx context.Context, _ *wazuhv1.WazuhCluster, nodeName string, status *wazuhv1.ComponentDrainStatus) (*drain.ManagerDrainProgress, error) {
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
	shareddrain.UpdateProgress(status, progress.Percent, progress.Message)
	shareddrain.UpdateQueueDepth(status, progress.QueueDepth)

	log.V(1).Info("Manager drain progress",
		"node", nodeName,
		"percent", progress.Percent,
		"queueDepth", progress.QueueDepth,
		"complete", progress.IsComplete)

	// Check for completion
	if progress.IsComplete {
		if err := shareddrain.TransitionTo(status, wazuhv1.DrainPhaseVerifying, "Verifying queue drain completion"); err != nil {
			log.Error(err, "Failed to transition to verifying phase")
		}
	}

	return &progress, nil
}

// verifyDrainComplete verifies that drain is fully complete
func (r *WorkerReconciler) verifyDrainComplete(ctx context.Context, cluster *wazuhv1.WazuhCluster, nodeName string, status *wazuhv1.ComponentDrainStatus) (bool, error) {
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
		if err := shareddrain.MarkComplete(status); err != nil {
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
func (r *WorkerReconciler) ensureWazuhClient(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	if r.wazuhClient != nil {
		return nil
	}

	// Build the Wazuh API URL from the cluster name
	// The master service is typically named {cluster-name}-manager-master
	masterServiceName := cluster.Name + "-manager-master"
	baseURL := fmt.Sprintf("https://%s:%d",
		dns.ServiceFQDN(masterServiceName, cluster.Namespace), constants.PortManagerAPI)

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
func (r *WorkerReconciler) getWazuhAPICredentials(ctx context.Context, cluster *wazuhv1.WazuhCluster) (string, string, error) {
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
func (r *WorkerReconciler) ResetDrainState(cluster *wazuhv1.WazuhCluster) {
	if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
		shareddrain.Reset(cluster.Status.Drain.Manager)
	}
	// Clear cached drainer for next operation
	r.drainer = nil
}

// EvaluateDrainFeasibility evaluates if drain is feasible (for dry-run mode)
func (r *WorkerReconciler) EvaluateDrainFeasibility(ctx context.Context, cluster *wazuhv1.WazuhCluster, nodeName string) (*wazuhv1.DryRunResult, error) {
	// Initialize Wazuh client if needed
	if err := r.ensureWazuhClient(ctx, cluster); err != nil {
		return &wazuhv1.DryRunResult{
			Feasible:    false,
			EvaluatedAt: metav1.Now(),
			Component:   constants.DrainComponentManager,
			Blockers:    []string{fmt.Sprintf("Cannot connect to Wazuh API: %v", err)},
		}, nil
	}

	// Get drain configuration
	var drainConfig *wazuhv1.ManagerDrainConfig
	if cluster.Spec.Drain != nil {
		drainConfig = cluster.Spec.Drain.Manager
	}

	// Create drainer for evaluation
	drainer := drain.NewManagerDrainer(r.wazuhClient, logf.FromContext(ctx), drainConfig, cluster.Name, cluster.Namespace)
	return drainer.EvaluateFeasibility(ctx, nodeName)
}
