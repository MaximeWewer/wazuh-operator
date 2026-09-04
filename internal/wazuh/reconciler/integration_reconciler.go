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
	"strings"

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
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/validation"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// IntegrationFinalizer is the finalizer for WazuhIntegration resources.
	IntegrationFinalizer = "wazuhintegration.resources.wazuh.com/finalizer"

	// Integration condition types.
	IntegrationConditionTypeReady            = "Ready"
	IntegrationConditionTypeConfigMapCreated = "ConfigMapCreated"
	IntegrationConditionTypeValidated        = "Validated"

	// Labels used to identify integration ConfigMaps owned by a WazuhIntegration CR.
	labelIntegrationCROwnerName      = "resources.wazuh.com/integration-cr"
	labelIntegrationCROwnerNamespace = "resources.wazuh.com/integration-cr-namespace"
)

// IntegrationReconciler handles reconciliation of Wazuh custom integrations.
type IntegrationReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Validator *validation.IntegrationValidator
}

// NewIntegrationReconciler creates a new IntegrationReconciler.
func NewIntegrationReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *IntegrationReconciler {
	return &IntegrationReconciler{
		Client:    c,
		Scheme:    scheme,
		Recorder:  recorder,
		Validator: validation.NewIntegrationValidator(c),
	}
}

// Reconcile reconciles the Wazuh integration across all target clusters.
func (r *IntegrationReconciler) Reconcile(ctx context.Context, integration *wazuhv1.WazuhIntegration) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "IntegrationReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", integration.Name),
			attribute.String("resource.namespace", integration.Namespace),
			attribute.Int("resource.clusterRefs", len(integration.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if integration.Status.Phase == "" {
		integration.Status.Phase = wazuhv1.IntegrationPhasePending
	}

	validationResult := r.Validator.Validate(ctx, integration)
	if !validationResult.Valid {
		log.Info("Integration validation failed", "errors", validationResult.Errors)
		integration.Status.ValidationErrors = validationResult.Errors
		r.setCondition(integration, IntegrationConditionTypeValidated, metav1.ConditionFalse, "ValidationFailed",
			validation.FormatValidationErrors(validationResult.Errors))
		r.setCondition(integration, IntegrationConditionTypeReady, metav1.ConditionFalse, "ValidationFailed",
			"Integration validation failed")
		integration.Status.Phase = wazuhv1.IntegrationPhaseFailed
		if r.Recorder != nil {
			r.Recorder.Event(integration, corev1.EventTypeWarning, "ValidationFailed",
				validation.FormatValidationErrors(validationResult.Errors))
		}
		return r.updateStatus(ctx, integration)
	}
	integration.Status.ValidationErrors = nil
	r.setCondition(integration, IntegrationConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Integration content is valid")

	existingByKey := make(map[string]wazuhv1.IntegrationClusterStatus, len(integration.Status.ClusterStatuses))
	for _, s := range integration.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.IntegrationClusterStatus, 0, len(integration.Spec.ClusterRefs))
	anyFailed := false
	allApplied := true

	for _, ref := range integration.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileIntegrationForCluster(ctx, integration, ref, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile integration on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.IntegrationPhaseApplied {
			allApplied = false
		}
		newStatuses = append(newStatuses, st)
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	integration.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		integration.Status.Phase = wazuhv1.IntegrationPhaseFailed
		r.setCondition(integration, IntegrationConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply the integration")
		integration.Status.Message = "One or more target clusters failed to apply the integration"
	case allApplied:
		integration.Status.Phase = wazuhv1.IntegrationPhaseApplied
		r.setCondition(integration, IntegrationConditionTypeReady, metav1.ConditionTrue, "IntegrationApplied",
			"Integration applied to all target clusters")
		r.setCondition(integration, IntegrationConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
			"All cluster ConfigMaps reconciled")
		integration.Status.Message = ""
	default:
		integration.Status.Phase = wazuhv1.IntegrationPhasePending
	}

	integration.Status.ObservedGeneration = integration.Generation

	if err := r.updateStatus(ctx, integration); err != nil {
		return fmt.Errorf("failed to update integration status: %w", err)
	}

	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to apply the integration")
	}
	log.Info("Integration reconciliation completed", "name", integration.Name)
	return nil
}

// reconcileIntegrationForCluster reconciles the integration on a single target cluster.
func (r *IntegrationReconciler) reconcileIntegrationForCluster(
	ctx context.Context,
	integration *wazuhv1.WazuhIntegration,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.IntegrationClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.IntegrationPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(integration, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.IntegrationPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	cmName, err := r.reconcileConfigMap(ctx, integration, ref)
	if err != nil {
		st.Phase = wazuhv1.IntegrationPhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(integration, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return err
	}

	// Resolve secret-backed values to validate they exist before marking Applied.
	// The resolved <integration> block is injected into ossec.conf by the cluster reconciler.
	if _, err := r.buildBlock(ctx, integration, ref.Namespace); err != nil {
		st.Phase = wazuhv1.IntegrationPhaseFailed
		st.Message = fmt.Sprintf("Failed to resolve integration secrets: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(integration, corev1.EventTypeWarning, "SecretResolutionFailed", err.Error())
		}
		return err
	}

	st.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      cmName,
		Namespace: ref.Namespace,
	}
	st.AppliedToNodes = r.determineAppliedNodes(integration, cluster)

	wasApplied := st.Phase == wazuhv1.IntegrationPhaseApplied
	st.Phase = wazuhv1.IntegrationPhaseApplied
	st.Message = ""
	if !wasApplied {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(integration, corev1.EventTypeNormal, "IntegrationApplied",
				fmt.Sprintf("Integration %s applied to %s/%s", integration.Name, ref.Namespace, ref.Name))
		}
	}
	log.V(1).Info("Integration applied", "configMap", cmName)
	return nil
}

// integrationConfigMapName returns the cross-namespace-safe ConfigMap name.
func integrationConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-integration", crNamespace, crName)
}

// reconcileConfigMap creates/updates the integration script ConfigMap in the target cluster's namespace.
func (r *IntegrationReconciler) reconcileConfigMap(
	ctx context.Context,
	integration *wazuhv1.WazuhIntegration,
	ref wazuhv1.WazuhClusterRef,
) (string, error) {
	log := logf.FromContext(ctx)
	cmName := integrationConfigMapName(integration.Namespace, integration.Name)
	fileName := integration.Spec.ScriptName()

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelName:              "wazuh-integration",
				constants.LabelInstance:          integration.Name,
				constants.LabelManagedBy:         constants.OperatorName,
				constants.LabelComponent:         "integration",
				"wazuh.com/cluster":              ref.Name,
				labelIntegrationCROwnerName:      integration.Name,
				labelIntegrationCROwnerNamespace: integration.Namespace,
			},
		},
		Data: map[string]string{
			fileName: integration.Spec.Script,
		},
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating integration ConfigMap", "name", cmName, "namespace", ref.Namespace)
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
		log.V(1).Info("Updating integration ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return "", err
		}
	}
	return cmName, nil
}

// setCondition sets a status condition on the integration.
func (r *IntegrationReconciler) setCondition(integration *wazuhv1.WazuhIntegration, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&integration.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: integration.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the integration status with retry on conflict.
func (r *IntegrationReconciler) updateStatus(ctx context.Context, integration *wazuhv1.WazuhIntegration) error {
	desiredStatus := integration.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhIntegration{}
		if err := r.Get(ctx, types.NamespacedName{Name: integration.Name, Namespace: integration.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		integration.Status = latest.Status
		return nil
	})
}

// determineAppliedNodes determines which manager nodes the integration applies to.
func (r *IntegrationReconciler) determineAppliedNodes(integration *wazuhv1.WazuhIntegration, cluster *wazuhv1.WazuhCluster) []string {
	var nodes []string
	targetNodes := integration.Spec.TargetNodes
	if targetNodes == "" {
		targetNodes = "all"
	}
	clusterName := cluster.Name

	workerCount := int32(0)
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
		workerCount = *cluster.Spec.Manager.Workers.Replicas
	}

	switch targetNodes {
	case "master":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
	case "workers":
		for i := range workerCount {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	case "all":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
		for i := range workerCount {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	}
	return nodes
}

// Delete handles cleanup when an integration is deleted.
func (r *IntegrationReconciler) Delete(ctx context.Context, integration *wazuhv1.WazuhIntegration) error {
	log := logf.FromContext(ctx)
	cmName := integrationConfigMapName(integration.Namespace, integration.Name)

	for _, ref := range integration.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete integration ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup integration ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if r.Recorder != nil {
		r.Recorder.Event(integration, corev1.EventTypeNormal, "IntegrationDeleted",
			fmt.Sprintf("Integration %s deleted on all target clusters", integration.Name))
	}
	return nil
}

// ListIntegrationsForCluster lists all WazuhIntegrations targeting a specific cluster (cross-NS).
func (r *IntegrationReconciler) ListIntegrationsForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhIntegration, error) {
	list := &wazuhv1.WazuhIntegrationList{}
	if err := r.List(ctx, list); err != nil {
		return nil, fmt.Errorf("failed to list WazuhIntegrations: %w", err)
	}

	var matching []wazuhv1.WazuhIntegration
	for _, integration := range list.Items {
		for _, ref := range integration.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matching = append(matching, integration)
				break
			}
		}
	}
	return matching, nil
}

// IntegrationConfigMapInfo holds information about an integration script ConfigMap for mounting.
type IntegrationConfigMapInfo struct {
	ConfigMapName   string
	FileName        string // script filename (e.g. "custom-jira")
	IntegrationName string // CR name, used for stable ordering
}

// integrationForNode bundles a resolved integration applicable to a node type.
type integrationForNode struct {
	info  IntegrationConfigMapInfo
	block string // resolved <integration> ossec.conf block
	hash  string // per-integration hash input (script + block)
}

// collectForCluster returns the applied integrations that target the given node type,
// resolving their secret-backed <integration> blocks. Results are sorted by CR name.
func (r *IntegrationReconciler) collectForCluster(ctx context.Context, clusterName, namespace, nodeType string) ([]integrationForNode, error) {
	log := logf.FromContext(ctx)
	integrations, err := r.ListIntegrationsForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, err
	}

	out := make([]integrationForNode, 0, len(integrations))
	for i := range integrations {
		ig := integrations[i]
		if !matchesIntegrationNodeType(ig.Spec.TargetNodes, nodeType) {
			continue
		}

		applied := false
		for _, st := range ig.Status.ClusterStatuses {
			if st.Name == clusterName && st.Namespace == namespace && st.Phase == wazuhv1.IntegrationPhaseApplied && st.ConfigMapRef != nil {
				applied = true
				break
			}
		}
		if !applied {
			continue
		}

		block, err := r.buildBlock(ctx, &ig, namespace)
		if err != nil {
			// Skip integrations whose secrets cannot be resolved; their CR status
			// already reflects the failure.
			log.Error(err, "Skipping integration with unresolved secrets",
				"integration", ig.Name, "namespace", ig.Namespace)
			continue
		}

		out = append(out, integrationForNode{
			info: IntegrationConfigMapInfo{
				ConfigMapName:   integrationConfigMapName(ig.Namespace, ig.Name),
				FileName:        ig.Spec.ScriptName(),
				IntegrationName: ig.Name,
			},
			block: block,
			hash:  ig.Spec.ScriptName() + "\x00" + ig.Spec.Script + "\x00" + block,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].info.IntegrationName < out[j].info.IntegrationName
	})
	return out, nil
}

// GetIntegrationConfigMapsForCluster returns the script ConfigMap mounts for a node type
// ("master" or "worker") plus a content hash used to trigger pod restarts on change.
func (r *IntegrationReconciler) GetIntegrationConfigMapsForCluster(ctx context.Context, clusterName, namespace, nodeType string) ([]IntegrationConfigMapInfo, string, error) {
	items, err := r.collectForCluster(ctx, clusterName, namespace, nodeType)
	if err != nil {
		return nil, "", err
	}

	configMaps := make([]IntegrationConfigMapInfo, 0, len(items))
	hashInputs := make([]string, 0, len(items))
	for _, it := range items {
		configMaps = append(configMaps, it.info)
		hashInputs = append(hashInputs, it.hash)
	}

	return configMaps, computeIntegrationsHash(hashInputs), nil
}

// GetIntegrationOSSECBlocks returns the concatenated <integration> blocks for a node type,
// ready to be appended to ossec.conf.
func (r *IntegrationReconciler) GetIntegrationOSSECBlocks(ctx context.Context, clusterName, namespace, nodeType string) (string, error) {
	items, err := r.collectForCluster(ctx, clusterName, namespace, nodeType)
	if err != nil {
		return "", err
	}

	blocks := make([]string, 0, len(items))
	for _, it := range items {
		blocks = append(blocks, it.block)
	}
	return joinNonEmpty(blocks, "\n"), nil
}

// buildBlock resolves secret-backed values and renders the <integration> block for a CR.
func (r *IntegrationReconciler) buildBlock(ctx context.Context, integration *wazuhv1.WazuhIntegration, namespace string) (string, error) {
	hookURL := integration.Spec.HookURL
	if integration.Spec.HookURLSecretRef != nil {
		v, err := r.resolveSecretValue(ctx, namespace, integration.Spec.HookURLSecretRef)
		if err != nil {
			return "", err
		}
		if v != "" {
			hookURL = v
		}
	}

	apiKey := ""
	if integration.Spec.APIKeySecretRef != nil {
		v, err := r.resolveSecretValue(ctx, namespace, integration.Spec.APIKeySecretRef)
		if err != nil {
			return "", err
		}
		apiKey = v
	}

	return config.BuildIntegrationBlock(config.IntegrationBlockOptions{
		Name:          integration.Spec.ScriptName(),
		HookURL:       hookURL,
		APIKey:        apiKey,
		Level:         integration.Spec.Level,
		RuleID:        integration.Spec.RuleID,
		Group:         integration.Spec.Group,
		EventLocation: integration.Spec.EventLocation,
		AlertFormat:   integration.Spec.AlertFormat,
		Options:       integration.Spec.Options,
	}), nil
}

// resolveSecretValue reads a value from a Secret in the given namespace.
func (r *IntegrationReconciler) resolveSecretValue(ctx context.Context, namespace string, sel *corev1.SecretKeySelector) (string, error) {
	if sel == nil {
		return "", nil
	}
	optional := sel.Optional != nil && *sel.Optional

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: sel.Name, Namespace: namespace}, secret); err != nil {
		if optional && errors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read secret %s/%s: %w", namespace, sel.Name, err)
	}

	val, ok := secret.Data[sel.Key]
	if !ok {
		if optional {
			return "", nil
		}
		return "", fmt.Errorf("key %q not found in secret %s/%s", sel.Key, namespace, sel.Name)
	}
	return string(val), nil
}

// matchesIntegrationNodeType reports whether an integration with the given targetNodes
// applies to the supplied node type ("master" or "worker").
func matchesIntegrationNodeType(targetNodes, nodeType string) bool {
	if targetNodes == "" || targetNodes == "all" {
		return true
	}
	switch nodeType {
	case config.NodeTypeMaster:
		return targetNodes == "master"
	case config.NodeTypeWorker:
		return targetNodes == "workers"
	}
	return false
}

// computeIntegrationsHash computes a hash of all integration contents for change detection.
func computeIntegrationsHash(inputs []string) string {
	if len(inputs) == 0 {
		return ""
	}
	h := sha256.New()
	for _, in := range inputs {
		h.Write([]byte(in))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// joinNonEmpty joins the non-empty elements of parts with sep.
func joinNonEmpty(parts []string, sep string) string {
	filtered := parts[:0]
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	var result strings.Builder
	for i, p := range filtered {
		if i > 0 {
			result.WriteString(sep)
		}
		result.WriteString(p)
	}
	return result.String()
}
