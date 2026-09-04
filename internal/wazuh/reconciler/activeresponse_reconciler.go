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
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/validation"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// ActiveResponseFinalizer is the finalizer for WazuhActiveResponse resources.
	ActiveResponseFinalizer = "wazuhactiveresponse.resources.wazuh.com/finalizer"

	// Labels used to identify active response ConfigMaps owned by a WazuhActiveResponse CR.
	labelActiveResponseCROwnerName      = "resources.wazuh.com/activeresponse-cr"
	labelActiveResponseCROwnerNamespace = "resources.wazuh.com/activeresponse-cr-namespace"
)

// ActiveResponseReconciler handles reconciliation of Wazuh custom active responses.
type ActiveResponseReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Validator *validation.ActiveResponseValidator
}

// NewActiveResponseReconciler creates a new ActiveResponseReconciler.
func NewActiveResponseReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *ActiveResponseReconciler {
	return &ActiveResponseReconciler{
		Client:    c,
		Scheme:    scheme,
		Recorder:  recorder,
		Validator: validation.NewActiveResponseValidator(c),
	}
}

// Reconcile reconciles the Wazuh active response across all target clusters.
func (r *ActiveResponseReconciler) Reconcile(ctx context.Context, ar *wazuhv1.WazuhActiveResponse) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "ActiveResponseReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", ar.Name),
			attribute.String("resource.namespace", ar.Namespace),
			attribute.Int("resource.clusterRefs", len(ar.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if ar.Status.Phase == "" {
		ar.Status.Phase = wazuhv1.ActiveResponsePhasePending
	}

	validationResult := r.Validator.Validate(ctx, ar)
	if !validationResult.Valid {
		log.Info("Active response validation failed", "errors", validationResult.Errors)
		ar.Status.ValidationErrors = validationResult.Errors
		r.setCondition(ar, ConditionTypeValidated, metav1.ConditionFalse, "ValidationFailed",
			validation.FormatValidationErrors(validationResult.Errors))
		r.setCondition(ar, ConditionTypeReady, metav1.ConditionFalse, "ValidationFailed",
			"Active response validation failed")
		ar.Status.Phase = wazuhv1.ActiveResponsePhaseFailed
		if r.Recorder != nil {
			r.Recorder.Event(ar, corev1.EventTypeWarning, "ValidationFailed",
				validation.FormatValidationErrors(validationResult.Errors))
		}
		return r.updateStatus(ctx, ar)
	}
	ar.Status.ValidationErrors = nil
	r.setCondition(ar, ConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Active response content is valid")

	existingByKey := make(map[string]wazuhv1.ActiveResponseClusterStatus, len(ar.Status.ClusterStatuses))
	for _, s := range ar.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.ActiveResponseClusterStatus, 0, len(ar.Spec.ClusterRefs))
	anyFailed := false
	allApplied := true

	for _, ref := range ar.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileForCluster(ctx, ar, ref, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile active response on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.ActiveResponsePhaseApplied {
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
	ar.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		ar.Status.Phase = wazuhv1.ActiveResponsePhaseFailed
		r.setCondition(ar, ConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply the active response")
		ar.Status.Message = "One or more target clusters failed to apply the active response"
	case allApplied:
		ar.Status.Phase = wazuhv1.ActiveResponsePhaseApplied
		r.setCondition(ar, ConditionTypeReady, metav1.ConditionTrue, "ActiveResponseApplied",
			"Active response applied to all target clusters")
		r.setCondition(ar, ConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
			"All cluster ConfigMaps reconciled")
		ar.Status.Message = ""
	default:
		ar.Status.Phase = wazuhv1.ActiveResponsePhasePending
	}

	ar.Status.ObservedGeneration = ar.Generation

	if err := r.updateStatus(ctx, ar); err != nil {
		return fmt.Errorf("failed to update active response status: %w", err)
	}

	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to apply the active response")
	}
	log.Info("Active response reconciliation completed", "name", ar.Name)
	return nil
}

// reconcileForCluster reconciles the active response on a single target cluster.
func (r *ActiveResponseReconciler) reconcileForCluster(
	ctx context.Context,
	ar *wazuhv1.WazuhActiveResponse,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.ActiveResponseClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.ActiveResponsePhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(ar, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.ActiveResponsePhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	cmName, err := r.reconcileConfigMap(ctx, ar, ref)
	if err != nil {
		st.Phase = wazuhv1.ActiveResponsePhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(ar, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return err
	}

	st.ConfigMapRef = &wazuhv1.ConfigMapReference{Name: cmName, Namespace: ref.Namespace}
	st.AppliedToNodes = r.determineAppliedNodes(ar, cluster)

	wasApplied := st.Phase == wazuhv1.ActiveResponsePhaseApplied
	st.Phase = wazuhv1.ActiveResponsePhaseApplied
	st.Message = ""
	if !wasApplied {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(ar, corev1.EventTypeNormal, "ActiveResponseApplied",
				fmt.Sprintf("Active response %s applied to %s/%s", ar.Name, ref.Namespace, ref.Name))
		}
	}
	log.V(1).Info("Active response applied", "configMap", cmName)
	return nil
}

// activeResponseConfigMapName returns the cross-namespace-safe ConfigMap name.
func activeResponseConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-activeresponse", crNamespace, crName)
}

// reconcileConfigMap creates/updates the script ConfigMap in the target cluster's namespace.
func (r *ActiveResponseReconciler) reconcileConfigMap(
	ctx context.Context,
	ar *wazuhv1.WazuhActiveResponse,
	ref wazuhv1.WazuhClusterRef,
) (string, error) {
	log := logf.FromContext(ctx)
	cmName := activeResponseConfigMapName(ar.Namespace, ar.Name)
	fileName := ar.Spec.ScriptName()

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelName:                 "wazuh-activeresponse",
				constants.LabelInstance:             ar.Name,
				constants.LabelManagedBy:            constants.OperatorName,
				constants.LabelComponent:            "activeresponse",
				"wazuh.com/cluster":                 ref.Name,
				labelActiveResponseCROwnerName:      ar.Name,
				labelActiveResponseCROwnerNamespace: ar.Namespace,
			},
		},
		Data: map[string]string{
			fileName: ar.Spec.Script,
		},
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating active response ConfigMap", "name", cmName, "namespace", ref.Namespace)
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
		log.V(1).Info("Updating active response ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return "", err
		}
	}
	return cmName, nil
}

// setCondition sets a status condition on the active response.
func (r *ActiveResponseReconciler) setCondition(ar *wazuhv1.WazuhActiveResponse, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&ar.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: ar.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the active response status with retry on conflict.
func (r *ActiveResponseReconciler) updateStatus(ctx context.Context, ar *wazuhv1.WazuhActiveResponse) error {
	desiredStatus := ar.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhActiveResponse{}
		if err := r.Get(ctx, types.NamespacedName{Name: ar.Name, Namespace: ar.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		ar.Status = latest.Status
		return nil
	})
}

// determineAppliedNodes determines which manager nodes the active response applies to.
func (r *ActiveResponseReconciler) determineAppliedNodes(ar *wazuhv1.WazuhActiveResponse, cluster *wazuhv1.WazuhCluster) []string {
	targetNodes := ar.Spec.TargetNodes
	if targetNodes == "" {
		targetNodes = "all"
	}

	workerCount := int32(0)
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
		workerCount = *cluster.Spec.Manager.Workers.Replicas
	}

	var nodes []string
	if targetNodes == "master" || targetNodes == "all" {
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", cluster.Name))
	}
	if targetNodes == "workers" || targetNodes == "all" {
		for i := range workerCount {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", cluster.Name, i))
		}
	}
	return nodes
}

// Delete handles cleanup when an active response is deleted.
func (r *ActiveResponseReconciler) Delete(ctx context.Context, ar *wazuhv1.WazuhActiveResponse) error {
	log := logf.FromContext(ctx)
	cmName := activeResponseConfigMapName(ar.Namespace, ar.Name)

	for _, ref := range ar.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete active response ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup active response ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if r.Recorder != nil {
		r.Recorder.Event(ar, corev1.EventTypeNormal, "ActiveResponseDeleted",
			fmt.Sprintf("Active response %s deleted on all target clusters", ar.Name))
	}
	return nil
}

// ListActiveResponsesForCluster lists all WazuhActiveResponses targeting a specific cluster (cross-NS).
func (r *ActiveResponseReconciler) ListActiveResponsesForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhActiveResponse, error) {
	list := &wazuhv1.WazuhActiveResponseList{}
	if err := r.List(ctx, list); err != nil {
		return nil, fmt.Errorf("failed to list WazuhActiveResponses: %w", err)
	}

	var matching []wazuhv1.WazuhActiveResponse
	for _, ar := range list.Items {
		for _, ref := range ar.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matching = append(matching, ar)
				break
			}
		}
	}
	return matching, nil
}

// ActiveResponseConfigMapInfo holds information about a script ConfigMap for mounting.
type ActiveResponseConfigMapInfo struct {
	ConfigMapName string
	FileName      string // script filename (e.g. "firewall-drop.sh")
	CRName        string // CR name, used for stable ordering
}

// activeResponseForNode bundles a resolved active response applicable to a node type.
type activeResponseForNode struct {
	info  ActiveResponseConfigMapInfo
	block string // resolved <command> + <active-response> ossec.conf block
	hash  string // per-AR hash input (script + block)
}

// collectForCluster returns the applied active responses that target the given node type.
func (r *ActiveResponseReconciler) collectForCluster(ctx context.Context, clusterName, namespace, nodeType string) ([]activeResponseForNode, error) {
	responses, err := r.ListActiveResponsesForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, err
	}

	out := make([]activeResponseForNode, 0, len(responses))
	for i := range responses {
		ar := responses[i]
		if !matchesIntegrationNodeType(ar.Spec.TargetNodes, nodeType) {
			continue
		}

		applied := false
		for _, st := range ar.Status.ClusterStatuses {
			if st.Name == clusterName && st.Namespace == namespace && st.Phase == wazuhv1.ActiveResponsePhaseApplied && st.ConfigMapRef != nil {
				applied = true
				break
			}
		}
		if !applied {
			continue
		}

		block := config.BuildActiveResponseBlock(config.ActiveResponseBlockOptions{
			Name:              ar.Spec.Name,
			Executable:        ar.Spec.ScriptName(),
			TimeoutAllowed:    ar.Spec.TimeoutAllowed,
			ExtraArgs:         ar.Spec.ExtraArgs,
			Disabled:          ar.Spec.Disabled,
			Location:          ar.Spec.Location,
			AgentID:           ar.Spec.AgentID,
			Level:             ar.Spec.Level,
			RulesID:           ar.Spec.RulesID,
			RulesGroup:        ar.Spec.RulesGroup,
			Timeout:           ar.Spec.Timeout,
			RepeatedOffenders: ar.Spec.RepeatedOffenders,
		})

		out = append(out, activeResponseForNode{
			info: ActiveResponseConfigMapInfo{
				ConfigMapName: activeResponseConfigMapName(ar.Namespace, ar.Name),
				FileName:      ar.Spec.ScriptName(),
				CRName:        ar.Name,
			},
			block: block,
			hash:  ar.Spec.ScriptName() + "\x00" + ar.Spec.Script + "\x00" + block,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].info.CRName < out[j].info.CRName
	})
	return out, nil
}

// GetActiveResponseConfigMapsForCluster returns the script ConfigMap mounts for a node
// type ("master" or "worker") plus a content hash used to trigger pod restarts on change.
func (r *ActiveResponseReconciler) GetActiveResponseConfigMapsForCluster(ctx context.Context, clusterName, namespace, nodeType string) ([]ActiveResponseConfigMapInfo, string, error) {
	items, err := r.collectForCluster(ctx, clusterName, namespace, nodeType)
	if err != nil {
		return nil, "", err
	}

	configMaps := make([]ActiveResponseConfigMapInfo, 0, len(items))
	hashInputs := make([]string, 0, len(items))
	for _, it := range items {
		configMaps = append(configMaps, it.info)
		hashInputs = append(hashInputs, it.hash)
	}

	return configMaps, computeIntegrationsHash(hashInputs), nil
}

// GetActiveResponseOSSECBlocks returns the concatenated <command> + <active-response>
// blocks for a node type, ready to be appended to ossec.conf.
func (r *ActiveResponseReconciler) GetActiveResponseOSSECBlocks(ctx context.Context, clusterName, namespace, nodeType string) (string, error) {
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
