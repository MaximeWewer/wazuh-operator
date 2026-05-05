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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
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

	// Labels used to identify decoder ConfigMaps owned by a WazuhDecoder CR.
	labelDecoderCROwnerName      = "resources.wazuh.com/decoder-cr"
	labelDecoderCROwnerNamespace = "resources.wazuh.com/decoder-cr-namespace"
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

// Reconcile reconciles the Wazuh Decoder across all target clusters.
func (r *DecoderReconciler) Reconcile(ctx context.Context, decoder *wazuhv1.WazuhDecoder) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "DecoderReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", decoder.Name),
			attribute.String("resource.namespace", decoder.Namespace),
			attribute.Int("resource.clusterRefs", len(decoder.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if decoder.Status.Phase == "" {
		decoder.Status.Phase = wazuhv1.DecoderPhasePending
	}

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
	decoder.Status.ValidationErrors = nil
	r.setCondition(decoder, DecoderConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Decoder content is valid")

	existingByKey := make(map[string]wazuhv1.DecoderClusterStatus, len(decoder.Status.ClusterStatuses))
	for _, s := range decoder.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.DecoderClusterStatus, 0, len(decoder.Spec.ClusterRefs))
	anyFailed := false
	allApplied := true

	for _, ref := range decoder.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileDecoderForCluster(ctx, decoder, ref, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile decoder on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.DecoderPhaseApplied {
			allApplied = false
		}
		newStatuses = append(newStatuses, st)

		decodersCount, mErr := r.countDecodersForCluster(ctx, ref.Namespace, ref.Name)
		if mErr == nil {
			metrics.SetWazuhDecodersTotal(ref.Name, ref.Namespace, decodersCount)
		}
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	decoder.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		decoder.Status.Phase = wazuhv1.DecoderPhaseFailed
		r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply the decoder")
		decoder.Status.Message = "One or more target clusters failed to apply the decoder"
	case allApplied:
		decoder.Status.Phase = wazuhv1.DecoderPhaseApplied
		r.setCondition(decoder, DecoderConditionTypeReady, metav1.ConditionTrue, "DecoderApplied",
			"Decoder applied to all target clusters")
		r.setCondition(decoder, DecoderConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
			"All cluster ConfigMaps reconciled")
		decoder.Status.Message = ""
	default:
		decoder.Status.Phase = wazuhv1.DecoderPhasePending
	}

	decoder.Status.ObservedGeneration = decoder.Generation

	if err := r.updateStatus(ctx, decoder); err != nil {
		return fmt.Errorf("failed to update decoder status: %w", err)
	}

	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to apply the decoder")
	}
	log.Info("Decoder reconciliation completed", "name", decoder.Name)
	return nil
}

// reconcileDecoderForCluster reconciles the decoder on a single target cluster.
func (r *DecoderReconciler) reconcileDecoderForCluster(
	ctx context.Context,
	decoder *wazuhv1.WazuhDecoder,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.DecoderClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.DecoderPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(decoder, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.DecoderPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	cmName, err := r.reconcileConfigMap(ctx, decoder, ref)
	if err != nil {
		st.Phase = wazuhv1.DecoderPhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(decoder, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return err
	}

	st.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      cmName,
		Namespace: ref.Namespace,
	}
	st.AppliedToNodes = r.determineAppliedNodes(decoder, cluster)

	wasApplied := st.Phase == wazuhv1.DecoderPhaseApplied
	st.Phase = wazuhv1.DecoderPhaseApplied
	st.Message = ""
	if !wasApplied {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(decoder, corev1.EventTypeNormal, "DecoderApplied",
				fmt.Sprintf("Decoder %s applied to %s/%s", decoder.Name, ref.Namespace, ref.Name))
		}
	}
	log.V(1).Info("Decoder applied", "configMap", cmName)
	return nil
}

// decoderConfigMapName returns the cross-namespace-safe ConfigMap name.
func decoderConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-decoder", crNamespace, crName)
}

// reconcileConfigMap creates/updates the decoder ConfigMap in the target cluster's namespace.
func (r *DecoderReconciler) reconcileConfigMap(
	ctx context.Context,
	decoder *wazuhv1.WazuhDecoder,
	ref wazuhv1.WazuhClusterRef,
) (string, error) {
	log := logf.FromContext(ctx)
	cmName := decoderConfigMapName(decoder.Namespace, decoder.Name)
	fileName := fmt.Sprintf("%s.xml", decoder.Spec.DecoderName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelName:          "wazuh-decoder",
				constants.LabelInstance:      decoder.Name,
				constants.LabelManagedBy:     constants.OperatorName,
				constants.LabelComponent:     "decoder",
				"wazuh.com/cluster":          ref.Name,
				labelDecoderCROwnerName:      decoder.Name,
				labelDecoderCROwnerNamespace: decoder.Namespace,
			},
		},
		Data: map[string]string{
			fileName: decoder.Spec.Decoders,
		},
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating decoder ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Create(ctx, desired); err != nil {
			return "", err
		}
		return cmName, nil
	} else if err != nil {
		return "", err
	}

	if !mapsEqual(existing.Data, desired.Data) || !mapsEqual(existing.Labels, desired.Labels) {
		existing.Data = desired.Data
		existing.Labels = desired.Labels
		log.V(1).Info("Updating decoder ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return "", err
		}
	}
	return cmName, nil
}

// setCondition sets a status condition on the decoder.
func (r *DecoderReconciler) setCondition(decoder *wazuhv1.WazuhDecoder, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&decoder.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: decoder.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the decoder status with retry on conflict.
func (r *DecoderReconciler) updateStatus(ctx context.Context, decoder *wazuhv1.WazuhDecoder) error {
	desiredStatus := decoder.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhDecoder{}
		if err := r.Get(ctx, types.NamespacedName{Name: decoder.Name, Namespace: decoder.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		decoder.Status = latest.Status
		return nil
	})
}

// determineAppliedNodes determines which manager nodes the decoder applies to
func (r *DecoderReconciler) determineAppliedNodes(decoder *wazuhv1.WazuhDecoder, cluster *wazuhv1.WazuhCluster) []string {
	var nodes []string
	targetNodes := decoder.Spec.TargetNodes
	if targetNodes == "" {
		targetNodes = "all"
	}
	clusterName := cluster.Name

	switch targetNodes {
	case "master":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
	case "workers":
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

// Delete handles cleanup when a decoder is deleted.
func (r *DecoderReconciler) Delete(ctx context.Context, decoder *wazuhv1.WazuhDecoder) error {
	log := logf.FromContext(ctx)
	cmName := decoderConfigMapName(decoder.Namespace, decoder.Name)

	for _, ref := range decoder.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete decoder ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup decoder ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if r.Recorder != nil {
		r.Recorder.Event(decoder, corev1.EventTypeNormal, "DecoderDeleted",
			fmt.Sprintf("Decoder %s deleted on all target clusters", decoder.Name))
	}
	return nil
}

// ListDecodersForCluster lists all WazuhDecoders targeting a specific cluster (cross-NS).
func (r *DecoderReconciler) ListDecodersForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhDecoder, error) {
	decoderList := &wazuhv1.WazuhDecoderList{}
	if err := r.List(ctx, decoderList); err != nil {
		return nil, fmt.Errorf("failed to list WazuhDecoders: %w", err)
	}

	var matching []wazuhv1.WazuhDecoder
	for _, decoder := range decoderList.Items {
		for _, ref := range decoder.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matching = append(matching, decoder)
				break
			}
		}
	}
	return matching, nil
}

// GetDecoderConfigMapsForCluster returns ConfigMap references for all decoders on a cluster.
func (r *DecoderReconciler) GetDecoderConfigMapsForCluster(ctx context.Context, clusterName, namespace string) ([]DecoderConfigMapInfo, string, error) {
	decoders, err := r.ListDecodersForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, "", err
	}

	configMaps := make([]DecoderConfigMapInfo, 0, len(decoders))
	decoderContents := make([]string, 0, len(decoders))

	for _, decoder := range decoders {
		applied := false
		for _, st := range decoder.Status.ClusterStatuses {
			if st.Name == clusterName && st.Namespace == namespace && st.Phase == wazuhv1.DecoderPhaseApplied && st.ConfigMapRef != nil {
				applied = true
				break
			}
		}
		if !applied {
			continue
		}

		configMaps = append(configMaps, DecoderConfigMapInfo{
			ConfigMapName: decoderConfigMapName(decoder.Namespace, decoder.Name),
			FileName:      fmt.Sprintf("%s.xml", decoder.Spec.DecoderName),
			DecoderName:   decoder.Name,
		})
		decoderContents = append(decoderContents, decoder.Spec.Decoders)
	}

	sort.Slice(configMaps, func(i, j int) bool {
		return configMaps[i].DecoderName < configMaps[j].DecoderName
	})
	sort.Strings(decoderContents)

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
