/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// FilebeatReconciler handles reconciliation of WazuhFilebeat resources
type FilebeatReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewFilebeatReconciler creates a new FilebeatReconciler
func NewFilebeatReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *FilebeatReconciler {
	return &FilebeatReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// Reconcile reconciles the WazuhFilebeat resource across all target clusters.
func (r *FilebeatReconciler) Reconcile(ctx context.Context, filebeat *wazuhv1.WazuhFilebeat) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "FilebeatReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", filebeat.Name),
			attribute.String("resource.namespace", filebeat.Namespace),
			attribute.Int("resource.clusterRefs", len(filebeat.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)
	log.Info("Reconciling WazuhFilebeat", "name", filebeat.Name, "namespace", filebeat.Namespace)

	existingByKey := make(map[string]wazuhv1.FilebeatClusterStatus, len(filebeat.Status.ClusterStatuses))
	for _, s := range filebeat.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.FilebeatClusterStatus, 0, len(filebeat.Spec.ClusterRefs))
	anyFailed := false
	anyPending := false
	allReady := true

	for _, ref := range filebeat.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileForCluster(ctx, filebeat, ref, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile filebeat on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		switch st.Phase {
		case wazuhv1.FilebeatPhaseReady:
			// ok
		case wazuhv1.FilebeatPhasePending:
			anyPending = true
			allReady = false
		default:
			allReady = false
		}
		newStatuses = append(newStatuses, st)
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	filebeat.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		r.setCondition(filebeat, constants.ConditionTypeReconciled, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply filebeat config")
		_ = r.updateStatus(ctx, filebeat, wazuhv1.FilebeatPhaseFailed,
			"One or more target clusters failed to apply filebeat config")
		return fmt.Errorf("one or more target clusters failed to apply filebeat config")
	case allReady:
		r.setCondition(filebeat, constants.ConditionTypeReconciled, metav1.ConditionTrue, "Reconciled",
			"Reconciliation successful on all target clusters")
		r.setCondition(filebeat, constants.ConditionTypeConfigMapReady, metav1.ConditionTrue, "ConfigMapReady",
			"All cluster ConfigMaps reconciled")
		r.setCondition(filebeat, constants.ConditionTypeTemplateApplied, metav1.ConditionTrue, "TemplateApplied",
			"Index templates configured")
		r.setCondition(filebeat, constants.ConditionTypePipelineApplied, metav1.ConditionTrue, "PipelineApplied",
			"Ingest pipelines configured")
		_ = r.updateStatus(ctx, filebeat, wazuhv1.FilebeatPhaseReady, "")
	case anyPending:
		_ = r.updateStatus(ctx, filebeat, wazuhv1.FilebeatPhasePending,
			"Waiting on one or more target clusters to become Ready")
	default:
		_ = r.updateStatus(ctx, filebeat, wazuhv1.FilebeatPhasePending, "")
	}

	log.Info("WazuhFilebeat reconciliation completed", "name", filebeat.Name)
	return nil
}

// reconcileForCluster reconciles the filebeat config on a single target cluster.
func (r *FilebeatReconciler) reconcileForCluster(
	ctx context.Context,
	filebeat *wazuhv1.WazuhFilebeat,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.FilebeatClusterStatus,
) error {
	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.FilebeatPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonClusterNotFound, st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.FilebeatPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	if cluster.Status.Phase != "Ready" && cluster.Status.Phase != "Running" {
		st.Phase = wazuhv1.FilebeatPhasePending
		st.Message = fmt.Sprintf("WazuhCluster %s is not ready (phase: %s)", cluster.Name, cluster.Status.Phase)
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonClusterNotReady, st.Message)
		}
		return nil
	}

	filebeatConfig, err := r.buildFilebeatConfig(ctx, filebeat, cluster)
	if err != nil {
		st.Phase = wazuhv1.FilebeatPhaseFailed
		st.Message = fmt.Sprintf("Failed to build filebeat config: %v", err)
		return err
	}

	indexTemplate, templateVersion, err := r.buildIndexTemplate(ctx, filebeat)
	if err != nil {
		st.Phase = wazuhv1.FilebeatPhaseFailed
		st.Message = fmt.Sprintf("Failed to build index template: %v", err)
		return err
	}

	pipeline, pipelineVersion, err := r.buildIngestPipeline(ctx, filebeat)
	if err != nil {
		st.Phase = wazuhv1.FilebeatPhaseFailed
		st.Message = fmt.Sprintf("Failed to build ingest pipeline: %v", err)
		return err
	}

	configHash := r.calculateConfigHash(filebeatConfig, indexTemplate, pipeline)

	if err := r.reconcileConfigMap(ctx, filebeat, cluster, filebeatConfig, indexTemplate, pipeline); err != nil {
		st.Phase = wazuhv1.FilebeatPhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonFilebeatConfigFailed, err.Error())
		}
		return err
	}

	st.TemplateVersion = templateVersion
	st.PipelineVersion = pipelineVersion
	st.ConfigHash = configHash
	st.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      configmaps.GetConfigMapName(cluster.Name),
		Namespace: cluster.Namespace,
	}

	wasReady := st.Phase == wazuhv1.FilebeatPhaseReady
	st.Phase = wazuhv1.FilebeatPhaseReady
	st.Message = ""
	if !wasReady {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonFilebeatConfigUpdated,
				fmt.Sprintf("Filebeat configuration applied to %s/%s", ref.Namespace, ref.Name))
		}
	}
	return nil
}

// buildFilebeatConfig generates the filebeat.yml content for a target cluster.
func (r *FilebeatReconciler) buildFilebeatConfig(_ context.Context, filebeat *wazuhv1.WazuhFilebeat, cluster *wazuhv1.WazuhCluster) (string, error) {
	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	builder := config.NewFilebeatConfigBuilderFromSpec(&filebeat.Spec, cluster.Name, cluster.Namespace, indexerService)
	return builder.Build()
}

// buildIndexTemplate generates the wazuh-template.json content.
// Custom-template ConfigMap is loaded from the CR's own namespace.
func (r *FilebeatReconciler) buildIndexTemplate(ctx context.Context, filebeat *wazuhv1.WazuhFilebeat) (string, string, error) {
	if filebeat.Spec.Template != nil && filebeat.Spec.Template.CustomTemplateRef != nil {
		ref := filebeat.Spec.Template.CustomTemplateRef
		template, err := config.LoadCustomTemplate(ctx, r.Client, filebeat.Namespace, ref.Name, ref.Key)
		if err != nil {
			return "", "", err
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonCustomTemplateLoaded,
				fmt.Sprintf("Custom template loaded from ConfigMap %s", ref.Name))
		}
		return template, "custom", nil
	}

	builder := config.NewFilebeatTemplateBuilder()
	if filebeat.Spec.Template != nil {
		if filebeat.Spec.Template.Shards != nil {
			builder.WithShards(*filebeat.Spec.Template.Shards)
		}
		if filebeat.Spec.Template.Replicas != nil {
			builder.WithReplicas(*filebeat.Spec.Template.Replicas)
		}
		if filebeat.Spec.Template.RefreshInterval != "" {
			builder.WithRefreshInterval(filebeat.Spec.Template.RefreshInterval)
		}
		if filebeat.Spec.Template.FieldLimit != nil {
			builder.WithFieldLimit(*filebeat.Spec.Template.FieldLimit)
		}
		if filebeat.Spec.Template.AdditionalMappings != nil {
			builder.WithAdditionalMappings(filebeat.Spec.Template.AdditionalMappings.Raw)
		}
	}

	template, err := builder.Build()
	if err != nil {
		return "", "", err
	}
	return template, config.GetDefaultTemplateVersion(), nil
}

// buildIngestPipeline generates the pipeline.json content.
func (r *FilebeatReconciler) buildIngestPipeline(ctx context.Context, filebeat *wazuhv1.WazuhFilebeat) (string, string, error) {
	if filebeat.Spec.Pipeline != nil && filebeat.Spec.Pipeline.CustomPipelineRef != nil {
		ref := filebeat.Spec.Pipeline.CustomPipelineRef
		pipeline, err := config.LoadCustomPipeline(ctx, r.Client, filebeat.Namespace, ref.Name, ref.Key)
		if err != nil {
			return "", "", err
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonCustomPipelineLoaded,
				fmt.Sprintf("Custom pipeline loaded from ConfigMap %s", ref.Name))
		}
		return pipeline, "custom", nil
	}

	builder := config.NewFilebeatPipelineBuilder()
	if filebeat.Spec.Pipeline != nil {
		if filebeat.Spec.Pipeline.GeoIPEnabled != nil {
			builder.WithGeoIPEnabled(*filebeat.Spec.Pipeline.GeoIPEnabled)
		}
		if filebeat.Spec.Pipeline.IndexPrefix != "" {
			builder.WithIndexPrefix(filebeat.Spec.Pipeline.IndexPrefix)
		}
		if len(filebeat.Spec.Pipeline.AdditionalRemoveFields) > 0 {
			builder.WithAdditionalRemoveFields(filebeat.Spec.Pipeline.AdditionalRemoveFields)
		}
		if filebeat.Spec.Pipeline.TimestampFormat != "" {
			builder.WithTimestampFormat(filebeat.Spec.Pipeline.TimestampFormat)
		}
	}

	pipeline, err := builder.Build()
	if err != nil {
		return "", "", err
	}
	return pipeline, config.GetDefaultPipelineVersion(), nil
}

// reconcileConfigMap creates or updates the Filebeat ConfigMap in the target cluster's namespace.
// No cross-namespace owner reference: cleanup is handled in Delete via finalizer + label match.
func (r *FilebeatReconciler) reconcileConfigMap(
	ctx context.Context,
	filebeat *wazuhv1.WazuhFilebeat,
	cluster *wazuhv1.WazuhCluster,
	filebeatConfig, indexTemplate, pipeline string,
) error {
	log := logf.FromContext(ctx)

	cm := configmaps.NewFilebeatConfigMapBuilder(cluster.Name, cluster.Namespace).
		WithConfig(filebeatConfig).
		WithIndexTemplate(indexTemplate).
		WithIngestPipeline(pipeline).
		Build()

	// Tag with CR identity so Delete() can find and remove this CM cross-NS.
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	cm.Labels["resources.wazuh.com/filebeat-cr"] = filebeat.Name
	cm.Labels["resources.wazuh.com/filebeat-cr-namespace"] = filebeat.Namespace

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Filebeat ConfigMap", "name", cm.Name, "namespace", cm.Namespace)
		if err := r.Create(ctx, cm); err != nil {
			return fmt.Errorf("failed to create configmap: %w", err)
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonFilebeatConfigCreated,
				fmt.Sprintf("ConfigMap %s/%s created", cm.Namespace, cm.Name))
		}
		return nil
	} else if err != nil {
		return err
	}

	if !mapsEqual(existing.Data, cm.Data) || !mapsEqual(existing.Labels, cm.Labels) {
		existing.Data = cm.Data
		existing.Labels = cm.Labels
		log.V(1).Info("Updating Filebeat ConfigMap", "name", cm.Name, "namespace", cm.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update configmap: %w", err)
		}
	}
	return nil
}

// calculateConfigHash calculates a hash of all configuration content
func (r *FilebeatReconciler) calculateConfigHash(filebeatConfig, indexTemplate, pipeline string) string {
	h := sha256.New()
	h.Write([]byte(filebeatConfig))
	h.Write([]byte(indexTemplate))
	h.Write([]byte(pipeline))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// setCondition sets a condition on the WazuhFilebeat aggregate status.
func (r *FilebeatReconciler) setCondition(filebeat *wazuhv1.WazuhFilebeat, conditionType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}
	for i, c := range filebeat.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != status {
				condition.LastTransitionTime = now
			} else {
				condition.LastTransitionTime = c.LastTransitionTime
			}
			filebeat.Status.Conditions[i] = condition
			return
		}
	}
	filebeat.Status.Conditions = append(filebeat.Status.Conditions, condition)
}

// updateStatus updates the WazuhFilebeat aggregate status with retry on conflict.
func (r *FilebeatReconciler) updateStatus(ctx context.Context, filebeat *wazuhv1.WazuhFilebeat, phase wazuhv1.FilebeatPhase, message string) error {
	filebeat.Status.Phase = phase
	filebeat.Status.Message = message
	filebeat.Status.ObservedGeneration = filebeat.Generation

	desiredStatus := filebeat.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhFilebeat{}
		if err := r.Get(ctx, types.NamespacedName{Name: filebeat.Name, Namespace: filebeat.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		filebeat.Status = latest.Status
		return nil
	})
}

// Delete handles cleanup when a WazuhFilebeat is deleted.
// Deletes the per-cluster ConfigMaps in each target cluster's namespace.
func (r *FilebeatReconciler) Delete(ctx context.Context, filebeat *wazuhv1.WazuhFilebeat) error {
	log := logf.FromContext(ctx)

	for _, ref := range filebeat.Spec.ClusterRefs {
		cmName := configmaps.GetConfigMapName(ref.Name)
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			// Only delete if labelled as ours, to avoid stomping on a CM owned by the cluster.
			if cm.Labels["resources.wazuh.com/filebeat-cr"] == filebeat.Name &&
				cm.Labels["resources.wazuh.com/filebeat-cr-namespace"] == filebeat.Namespace {
				if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
					log.Error(err, "Failed to delete filebeat ConfigMap",
						"configMap", cmName, "namespace", ref.Namespace)
				}
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup filebeat ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}
	log.Info("WazuhFilebeat deletion handled", "name", filebeat.Name)
	return nil
}
