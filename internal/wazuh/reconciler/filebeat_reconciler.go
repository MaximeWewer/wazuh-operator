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
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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

// Reconcile reconciles the WazuhFilebeat resource
func (r *FilebeatReconciler) Reconcile(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat) error {
	log := logf.FromContext(ctx)
	log.Info("Reconciling WazuhFilebeat", "name", filebeat.Name, "namespace", filebeat.Namespace)

	// Validate cluster reference
	cluster, err := r.getCluster(ctx, filebeat)
	if err != nil {
		r.setCondition(filebeat, constants.ConditionTypeReconciled, metav1.ConditionFalse, "ClusterNotFound", err.Error())
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseFailed, err.Error()); err != nil {
			log.Error(err, "Failed to update status")
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonClusterNotFound, err.Error())
		}
		return err
	}

	// Check if cluster is ready
	if cluster.Status.Phase != "Ready" && cluster.Status.Phase != "Running" {
		msg := fmt.Sprintf("WazuhCluster %s is not ready (phase: %s)", cluster.Name, cluster.Status.Phase)
		r.setCondition(filebeat, constants.ConditionTypeReconciled, metav1.ConditionFalse, "ClusterNotReady", msg)
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhasePending, msg); err != nil {
			log.Error(err, "Failed to update status")
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonClusterNotReady, msg)
		}
		return nil // Requeue after default interval
	}

	// Generate configurations
	filebeatConfig, err := r.buildFilebeatConfig(ctx, filebeat, cluster)
	if err != nil {
		r.setCondition(filebeat, constants.ConditionTypeConfigMapReady, metav1.ConditionFalse, "ConfigGenerationFailed", err.Error())
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseFailed, err.Error()); err != nil {
			log.Error(err, "Failed to update status")
		}
		return fmt.Errorf("failed to build filebeat config: %w", err)
	}

	indexTemplate, templateVersion, err := r.buildIndexTemplate(ctx, filebeat)
	if err != nil {
		r.setCondition(filebeat, constants.ConditionTypeTemplateApplied, metav1.ConditionFalse, "TemplateGenerationFailed", err.Error())
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseFailed, err.Error()); err != nil {
			log.Error(err, "Failed to update status")
		}
		return fmt.Errorf("failed to build index template: %w", err)
	}

	pipeline, pipelineVersion, err := r.buildIngestPipeline(ctx, filebeat)
	if err != nil {
		r.setCondition(filebeat, constants.ConditionTypePipelineApplied, metav1.ConditionFalse, "PipelineGenerationFailed", err.Error())
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseFailed, err.Error()); err != nil {
			log.Error(err, "Failed to update status")
		}
		return fmt.Errorf("failed to build ingest pipeline: %w", err)
	}

	// Calculate config hash for change detection
	configHash := r.calculateConfigHash(filebeatConfig, indexTemplate, pipeline)

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, filebeat, cluster, filebeatConfig, indexTemplate, pipeline); err != nil {
		r.setCondition(filebeat, constants.ConditionTypeConfigMapReady, metav1.ConditionFalse, "ConfigMapFailed", err.Error())
		if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseFailed, err.Error()); err != nil {
			log.Error(err, "Failed to update status")
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeWarning, constants.EventReasonFilebeatConfigFailed, err.Error())
		}
		return fmt.Errorf("failed to reconcile configmap: %w", err)
	}

	// Update status with success
	r.setCondition(filebeat, constants.ConditionTypeConfigMapReady, metav1.ConditionTrue, "ConfigMapReady", "ConfigMap created/updated successfully")
	r.setCondition(filebeat, constants.ConditionTypeTemplateApplied, metav1.ConditionTrue, "TemplateApplied", "Index template configured")
	r.setCondition(filebeat, constants.ConditionTypePipelineApplied, metav1.ConditionTrue, "PipelineApplied", "Ingest pipeline configured")
	r.setCondition(filebeat, constants.ConditionTypeReconciled, metav1.ConditionTrue, "Reconciled", "Reconciliation successful")

	filebeat.Status.TemplateVersion = templateVersion
	filebeat.Status.PipelineVersion = pipelineVersion
	filebeat.Status.ConfigHash = configHash
	filebeat.Status.ConfigMapRef = &wazuhv1alpha1.ConfigMapReference{
		Name: configmaps.GetConfigMapName(cluster.Name),
	}

	if err := r.updateStatus(ctx, filebeat, wazuhv1alpha1.FilebeatPhaseReady, "Configuration applied successfully"); err != nil {
		log.Error(err, "Failed to update status")
		return err
	}

	if r.Recorder != nil {
		r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonFilebeatConfigUpdated, "Filebeat configuration updated successfully")
	}

	log.Info("WazuhFilebeat reconciliation completed", "name", filebeat.Name)
	return nil
}

// getCluster retrieves the referenced WazuhCluster
func (r *FilebeatReconciler) getCluster(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat) (*wazuhv1alpha1.WazuhCluster, error) {
	cluster := &wazuhv1alpha1.WazuhCluster{}
	namespace := filebeat.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = filebeat.Namespace
	}

	if err := r.Get(ctx, types.NamespacedName{
		Name:      filebeat.Spec.ClusterRef.Name,
		Namespace: namespace,
	}, cluster); err != nil {
		return nil, fmt.Errorf("failed to get WazuhCluster %s/%s: %w", namespace, filebeat.Spec.ClusterRef.Name, err)
	}

	return cluster, nil
}

// buildFilebeatConfig generates the filebeat.yml content
func (r *FilebeatReconciler) buildFilebeatConfig(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat, cluster *wazuhv1alpha1.WazuhCluster) (string, error) {
	indexerService := fmt.Sprintf("%s-indexer", cluster.Name)
	builder := config.NewFilebeatConfigBuilderFromSpec(&filebeat.Spec, cluster.Name, cluster.Namespace, indexerService)

	return builder.Build()
}

// buildIndexTemplate generates the wazuh-template.json content
func (r *FilebeatReconciler) buildIndexTemplate(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat) (string, string, error) {
	// Check for custom template reference
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

	// Build template from spec
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

// buildIngestPipeline generates the pipeline.json content
func (r *FilebeatReconciler) buildIngestPipeline(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat) (string, string, error) {
	// Check for custom pipeline reference
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

	// Build pipeline from spec
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

// reconcileConfigMap creates or updates the Filebeat ConfigMap
func (r *FilebeatReconciler) reconcileConfigMap(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat, cluster *wazuhv1alpha1.WazuhCluster, filebeatConfig, indexTemplate, pipeline string) error {
	log := logf.FromContext(ctx)

	cm := configmaps.NewFilebeatConfigMapBuilder(cluster.Name, cluster.Namespace).
		WithConfig(filebeatConfig).
		WithIndexTemplate(indexTemplate).
		WithIngestPipeline(pipeline).
		Build()

	// Set owner reference to WazuhFilebeat for garbage collection
	if err := controllerutil.SetControllerReference(filebeat, cm, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Filebeat ConfigMap", "name", cm.Name)
		if err := r.Create(ctx, cm); err != nil {
			return fmt.Errorf("failed to create configmap: %w", err)
		}
		if r.Recorder != nil {
			r.Recorder.Event(filebeat, corev1.EventTypeNormal, constants.EventReasonFilebeatConfigCreated, "ConfigMap created")
		}
		return nil
	} else if err != nil {
		return err
	}

	// Update existing ConfigMap
	existing.Data = cm.Data
	existing.Labels = cm.Labels
	log.V(1).Info("Updating Filebeat ConfigMap", "name", cm.Name)
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update configmap: %w", err)
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

// setCondition sets a condition on the WazuhFilebeat status
func (r *FilebeatReconciler) setCondition(filebeat *wazuhv1alpha1.WazuhFilebeat, conditionType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	// Find existing condition
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

	// Add new condition
	filebeat.Status.Conditions = append(filebeat.Status.Conditions, condition)
}

// updateStatus updates the WazuhFilebeat status
func (r *FilebeatReconciler) updateStatus(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat, phase wazuhv1alpha1.FilebeatPhase, message string) error {
	filebeat.Status.Phase = phase
	filebeat.Status.Message = message
	filebeat.Status.ObservedGeneration = filebeat.Generation
	now := metav1.Now()
	filebeat.Status.LastAppliedTime = &now

	return r.Status().Update(ctx, filebeat)
}

// Delete handles cleanup when a WazuhFilebeat is deleted
func (r *FilebeatReconciler) Delete(ctx context.Context, filebeat *wazuhv1alpha1.WazuhFilebeat) error {
	log := logf.FromContext(ctx)
	// The ConfigMap will be garbage collected due to owner reference
	log.Info("WazuhFilebeat deletion handled", "name", filebeat.Name)
	return nil
}
