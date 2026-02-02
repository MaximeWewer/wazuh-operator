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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/validation"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// DecoderFinalizer is the finalizer for WazuhDecoder resources
	DecoderFinalizer = "wazuhdecoder.resources.wazuh.com/finalizer"

	// Decoder condition types
	DecoderConditionTypeReady            = "Ready"
	DecoderConditionTypeConfigMapCreated = "ConfigMapCreated"
	DecoderConditionTypeValidated        = "Validated"
)

// DecoderReconciler handles reconciliation of Wazuh Decoders
type DecoderReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Validator *validation.DecoderValidator
}

// NewDecoderReconciler creates a new DecoderReconciler
func NewDecoderReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *DecoderReconciler {
	return &DecoderReconciler{
		Client:    c,
		Scheme:    scheme,
		Recorder:  recorder,
		Validator: validation.NewDecoderValidator(c),
	}
}

// Reconcile reconciles the Wazuh Decoder
func (r *DecoderReconciler) Reconcile(ctx context.Context, decoder *wazuhv1.WazuhDecoder) error {
	log := logf.FromContext(ctx)

	// Initialize status if needed
	if decoder.Status.Phase == "" {
		decoder.Status.Phase = wazuhv1.DecoderPhasePending
	}

	// Validate the decoder
	validationResult := r.Validator.Validate(ctx, decoder)
	if !validationResult.Valid {
		log.Info("Decoder validation failed", "errors", validationResult.Errors)
		decoder.Status.ValidationErrors = validationResult.Errors
		r.setCondition(decoder, DecoderConditionTypeValidated, metav1.ConditionFalse, "ValidationFailed",
			validation.FormatValidationErrors(validationResult.Errors))
		r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionFalse, "ValidationFailed",
			"Decoder validation failed")
		decoder.Status.Phase = wazuhv1.DecoderPhaseFailed
		if r.Recorder != nil {
			r.Recorder.Event(decoder, corev1.EventTypeWarning, "ValidationFailed",
				validation.FormatValidationErrors(validationResult.Errors))
		}
		return r.updateStatus(ctx, decoder)
	}

	// Clear validation errors and set validated condition
	decoder.Status.ValidationErrors = nil
	r.setCondition(decoder, DecoderConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Decoder content is valid")

	// Verify referenced cluster exists
	cluster := &wazuhv1.WazuhCluster{}
	clusterNamespace := decoder.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = decoder.Namespace
	}
	clusterKey := types.NamespacedName{Name: decoder.Spec.ClusterRef.Name, Namespace: clusterNamespace}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Referenced WazuhCluster not found", "cluster", clusterKey)
			r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionFalse, "ClusterNotFound",
				fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			decoder.Status.Phase = wazuhv1.DecoderPhasePending
			if r.Recorder != nil {
				r.Recorder.Event(decoder, corev1.EventTypeWarning, "ClusterNotFound",
					fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			}
			return r.updateStatus(ctx, decoder)
		}
		return fmt.Errorf("failed to get referenced WazuhCluster %s: %w", clusterKey, err)
	}

	// Create ConfigMap for the decoder
	configMapName, err := r.reconcileConfigMap(ctx, decoder)
	if err != nil {
		decoder.Status.Phase = wazuhv1.DecoderPhaseFailed
		r.setCondition(decoder, DecoderConditionTypeConfigMapCreated, metav1.ConditionFalse, "ConfigMapFailed",
			fmt.Sprintf("Failed to create ConfigMap: %v", err))
		r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionFalse, "ConfigMapFailed",
			"Failed to create decoder ConfigMap")
		if r.Recorder != nil {
			r.Recorder.Event(decoder, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return fmt.Errorf("failed to reconcile decoder configmap: %w", err)
	}

	// Update status with ConfigMap reference
	decoder.Status.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      configMapName,
		Namespace: decoder.Namespace,
	}
	r.setCondition(decoder, DecoderConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
		fmt.Sprintf("ConfigMap %s created successfully", configMapName))

	// Determine which nodes the decoder is applied to based on targetNodes
	appliedNodes := r.determineAppliedNodes(decoder, cluster)
	decoder.Status.AppliedToNodes = appliedNodes

	// Set ready condition and phase
	decoder.Status.Phase = wazuhv1.DecoderPhaseApplied
	r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionTrue, "DecoderApplied",
		fmt.Sprintf("Decoder applied to %d node(s)", len(appliedNodes)))

	// Update observed generation
	decoder.Status.ObservedGeneration = decoder.Generation

	// Update timestamp
	now := metav1.Now()
	decoder.Status.LastAppliedTime = &now

	// Record success event
	if r.Recorder != nil {
		r.Recorder.Event(decoder, corev1.EventTypeNormal, "DecoderApplied",
			fmt.Sprintf("Decoder %s applied successfully", decoder.Name))
	}

	// Update status
	if err := r.updateStatus(ctx, decoder); err != nil {
		return fmt.Errorf("failed to update decoder status: %w", err)
	}

	// Record decoders metric for the cluster
	decodersCount, err := r.countDecodersForCluster(ctx, clusterNamespace, decoder.Spec.ClusterRef.Name)
	if err == nil {
		metrics.SetWazuhDecodersTotal(decoder.Spec.ClusterRef.Name, clusterNamespace, decodersCount)
	}

	log.Info("Decoder reconciliation completed", "name", decoder.Name, "configMap", configMapName)
	return nil
}

// reconcileConfigMap reconciles the ConfigMap for the decoder
func (r *DecoderReconciler) reconcileConfigMap(ctx context.Context, decoder *wazuhv1.WazuhDecoder) (string, error) {
	log := logf.FromContext(ctx)

	configMapName := fmt.Sprintf("%s-decoder", decoder.Name)
	fileName := fmt.Sprintf("%s.xml", decoder.Spec.DecoderName)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: decoder.Namespace,
			Labels: map[string]string{
				constants.LabelName:      "wazuh-decoder",
				constants.LabelInstance:  decoder.Name,
				constants.LabelManagedBy: constants.OperatorName,
				constants.LabelComponent: "decoder",
				// Add cluster reference label for easy filtering
				"wazuh.com/cluster": decoder.Spec.ClusterRef.Name,
			},
		},
		Data: map[string]string{
			fileName: decoder.Spec.Decoders,
		},
	}

	if err := controllerutil.SetControllerReference(decoder, cm, r.Scheme); err != nil {
		return "", fmt.Errorf("failed to set controller reference: %w", err)
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating decoder ConfigMap", "name", cm.Name)
		if err := r.Create(ctx, cm); err != nil {
			return "", err
		}
		return configMapName, nil
	} else if err != nil {
		return "", err
	}

	// Update existing
	existing.Data = cm.Data
	existing.Labels = cm.Labels
	log.V(1).Info("Updating decoder ConfigMap", "name", cm.Name)
	if err := r.Update(ctx, existing); err != nil {
		return "", err
	}

	return configMapName, nil
}

// setCondition sets a status condition on the decoder
func (r *DecoderReconciler) setCondition(decoder *wazuhv1.WazuhDecoder, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&decoder.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: decoder.Generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// updateStatus updates the decoder status
func (r *DecoderReconciler) updateStatus(ctx context.Context, decoder *wazuhv1.WazuhDecoder) error {
	return r.Status().Update(ctx, decoder)
}

// determineAppliedNodes determines which manager nodes the decoder applies to
func (r *DecoderReconciler) determineAppliedNodes(decoder *wazuhv1.WazuhDecoder, cluster *wazuhv1.WazuhCluster) []string {
	var nodes []string
	targetNodes := decoder.Spec.TargetNodes
	if targetNodes == "" {
		targetNodes = "all"
	}

	// Build node names based on cluster configuration
	clusterName := cluster.Name

	switch targetNodes {
	case "master":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
	case "workers":
		// Get worker count from cluster spec
		workerCount := int32(0)
		if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
			workerCount = *cluster.Spec.Manager.Workers.Replicas
		}
		for i := int32(0); i < workerCount; i++ {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	case "all":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
		workerCount := int32(0)
		if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
			workerCount = *cluster.Spec.Manager.Workers.Replicas
		}
		for i := int32(0); i < workerCount; i++ {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	}

	return nodes
}

// Delete handles cleanup when a decoder is deleted
func (r *DecoderReconciler) Delete(ctx context.Context, decoder *wazuhv1.WazuhDecoder) error {
	log := logf.FromContext(ctx)

	// Record deletion event
	if r.Recorder != nil {
		r.Recorder.Event(decoder, corev1.EventTypeNormal, "DecoderDeleted",
			fmt.Sprintf("Decoder %s deleted, ConfigMap will be garbage collected", decoder.Name))
	}

	// The ConfigMap will be garbage collected due to owner reference
	log.Info("Decoder deletion handled", "name", decoder.Name)
	return nil
}

// ListDecodersForCluster lists all WazuhDecoders referencing a specific cluster
func (r *DecoderReconciler) ListDecodersForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhDecoder, error) {
	decoderList := &wazuhv1.WazuhDecoderList{}
	if err := r.List(ctx, decoderList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list WazuhDecoders: %w", err)
	}

	var matchingDecoders []wazuhv1.WazuhDecoder
	for _, decoder := range decoderList.Items {
		if decoder.Spec.ClusterRef.Name == clusterName {
			matchingDecoders = append(matchingDecoders, decoder)
		}
	}

	return matchingDecoders, nil
}

// GetDecoderConfigMapsForCluster returns ConfigMap references for all decoders in a cluster
// This is used by the WazuhCluster reconciler to mount decoder ConfigMaps to manager pods
func (r *DecoderReconciler) GetDecoderConfigMapsForCluster(ctx context.Context, clusterName, namespace string) ([]DecoderConfigMapInfo, string, error) {
	decoders, err := r.ListDecodersForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, "", err
	}

	configMaps := make([]DecoderConfigMapInfo, 0, len(decoders))
	decoderContents := make([]string, 0, len(decoders))

	for _, decoder := range decoders {
		// Only include decoders that are successfully applied
		if decoder.Status.Phase != wazuhv1.DecoderPhaseApplied {
			continue
		}
		if decoder.Status.ConfigMapRef == nil {
			continue
		}

		configMaps = append(configMaps, DecoderConfigMapInfo{
			ConfigMapName: decoder.Status.ConfigMapRef.Name,
			FileName:      fmt.Sprintf("%s.xml", decoder.Spec.DecoderName),
			DecoderName:   decoder.Name,
		})
		decoderContents = append(decoderContents, decoder.Spec.Decoders)
	}

	// Sort for consistent ordering
	sort.Slice(configMaps, func(i, j int) bool {
		return configMaps[i].DecoderName < configMaps[j].DecoderName
	})
	sort.Strings(decoderContents)

	// Compute hash of all decoder contents for change detection
	hash := computeDecodersHash(decoderContents)

	return configMaps, hash, nil
}

// DecoderConfigMapInfo holds information about a decoder ConfigMap for mounting
type DecoderConfigMapInfo struct {
	ConfigMapName string
	FileName      string
	DecoderName   string
}

// computeDecodersHash computes a hash of all decoder contents for change detection
func computeDecodersHash(contents []string) string {
	h := sha256.New()
	for _, content := range contents {
		h.Write([]byte(content))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// countDecodersForCluster counts the total number of decoders for a cluster
func (r *DecoderReconciler) countDecodersForCluster(ctx context.Context, namespace, clusterName string) (int, error) {
	decoders, err := r.ListDecodersForCluster(ctx, clusterName, namespace)
	if err != nil {
		return 0, err
	}
	return len(decoders), nil
}
