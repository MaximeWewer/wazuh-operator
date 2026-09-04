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
	// RuleFinalizer is the finalizer for WazuhRule resources
	RuleFinalizer = "wazuhrule.resources.wazuh.com/finalizer"

	// Condition types
	ConditionTypeReady            = "Ready"
	ConditionTypeConfigMapCreated = "ConfigMapCreated"
	ConditionTypeValidated        = "Validated"

	// Labels used to identify rule ConfigMaps owned by a WazuhRule CR.
	// Cross-namespace owner references are forbidden, so cleanup is finalizer-driven.
	labelRuleCROwnerName      = "resources.wazuh.com/rule-cr"
	labelRuleCROwnerNamespace = "resources.wazuh.com/rule-cr-namespace"
)

// RuleReconciler handles reconciliation of Wazuh Rules
type RuleReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Validator *validation.RuleValidator
}

// NewRuleReconciler creates a new RuleReconciler
func NewRuleReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *RuleReconciler {
	return &RuleReconciler{
		Client:    c,
		Scheme:    scheme,
		Recorder:  recorder,
		Validator: validation.NewRuleValidator(c),
	}
}

// Reconcile reconciles the Wazuh Rule across all target clusters.
func (r *RuleReconciler) Reconcile(ctx context.Context, rule *wazuhv1.WazuhRule) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "RuleReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", rule.Name),
			attribute.String("resource.namespace", rule.Namespace),
			attribute.Int("resource.clusterRefs", len(rule.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if rule.Status.Phase == "" {
		rule.Status.Phase = wazuhv1.RulePhasePending
	}

	// Content validation is cluster-independent
	validationResult := r.Validator.Validate(ctx, rule)
	if !validationResult.Valid {
		log.Info("Rule validation failed", "errors", validationResult.Errors)
		rule.Status.ValidationErrors = validationResult.Errors
		r.setCondition(rule, ConditionTypeValidated, metav1.ConditionFalse, "ValidationFailed",
			validation.FormatValidationErrors(validationResult.Errors))
		r.setCondition(rule, ConditionTypeReady, metav1.ConditionFalse, "ValidationFailed",
			"Rule validation failed")
		rule.Status.Phase = wazuhv1.RulePhaseFailed
		if r.Recorder != nil {
			r.Recorder.Event(rule, corev1.EventTypeWarning, "ValidationFailed",
				validation.FormatValidationErrors(validationResult.Errors))
		}
		return r.updateStatus(ctx, rule)
	}
	rule.Status.ValidationErrors = nil
	r.setCondition(rule, ConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Rule content is valid")

	existingByKey := make(map[string]wazuhv1.RuleClusterStatus, len(rule.Status.ClusterStatuses))
	for _, s := range rule.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.RuleClusterStatus, 0, len(rule.Spec.ClusterRefs))
	anyFailed := false
	allApplied := true

	for _, ref := range rule.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileRuleForCluster(ctx, rule, ref, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile rule on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.RulePhaseApplied {
			allApplied = false
		}
		newStatuses = append(newStatuses, st)

		// metrics per cluster
		rulesCount, mErr := r.countRulesForCluster(ctx, ref.Namespace, ref.Name)
		if mErr == nil {
			metrics.SetWazuhRulesTotal(ref.Name, ref.Namespace, rulesCount)
		}
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	rule.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		rule.Status.Phase = wazuhv1.RulePhaseFailed
		r.setCondition(rule, ConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply the rule")
		rule.Status.Message = "One or more target clusters failed to apply the rule"
	case allApplied:
		rule.Status.Phase = wazuhv1.RulePhaseApplied
		r.setCondition(rule, ConditionTypeReady, metav1.ConditionTrue, "RuleApplied",
			"Rule applied to all target clusters")
		r.setCondition(rule, ConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
			"All cluster ConfigMaps reconciled")
		rule.Status.Message = ""
	default:
		rule.Status.Phase = wazuhv1.RulePhasePending
	}

	rule.Status.ObservedGeneration = rule.Generation

	if err := r.updateStatus(ctx, rule); err != nil {
		return fmt.Errorf("failed to update rule status: %w", err)
	}

	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to apply the rule")
	}
	log.Info("Rule reconciliation completed", "name", rule.Name)
	return nil
}

// reconcileRuleForCluster reconciles the rule on a single target cluster.
func (r *RuleReconciler) reconcileRuleForCluster(
	ctx context.Context,
	rule *wazuhv1.WazuhRule,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.RuleClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.RulePhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(rule, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.RulePhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	cmName, err := r.reconcileConfigMap(ctx, rule, ref)
	if err != nil {
		st.Phase = wazuhv1.RulePhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(rule, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return err
	}

	st.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      cmName,
		Namespace: ref.Namespace,
	}
	st.AppliedToNodes = r.determineAppliedNodes(rule, cluster)

	wasApplied := st.Phase == wazuhv1.RulePhaseApplied
	st.Phase = wazuhv1.RulePhaseApplied
	st.Message = ""
	if !wasApplied {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(rule, corev1.EventTypeNormal, "RuleApplied",
				fmt.Sprintf("Rule %s applied to %s/%s", rule.Name, ref.Namespace, ref.Name))
		}
	}
	log.V(1).Info("Rule applied", "configMap", cmName)
	return nil
}

// ruleConfigMapName returns the cross-namespace-safe ConfigMap name for the rule on a given cluster.
func ruleConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-rule", crNamespace, crName)
}

// reconcileConfigMap creates/updates the rule ConfigMap in the target cluster's namespace.
func (r *RuleReconciler) reconcileConfigMap(
	ctx context.Context,
	rule *wazuhv1.WazuhRule,
	ref wazuhv1.WazuhClusterRef,
) (string, error) {
	log := logf.FromContext(ctx)
	cmName := ruleConfigMapName(rule.Namespace, rule.Name)
	fileName := fmt.Sprintf("%s.xml", rule.Spec.RuleName)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelName:       "wazuh-rule",
				constants.LabelInstance:   rule.Name,
				constants.LabelManagedBy:  constants.OperatorName,
				constants.LabelComponent:  "rule",
				"wazuh.com/cluster":       ref.Name,
				labelRuleCROwnerName:      rule.Name,
				labelRuleCROwnerNamespace: rule.Namespace,
			},
		},
		Data: map[string]string{
			fileName: rule.Spec.Rules,
		},
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating rule ConfigMap", "name", cmName, "namespace", ref.Namespace)
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
		log.V(1).Info("Updating rule ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return "", err
		}
	}
	return cmName, nil
}

// setCondition sets a status condition on the rule.
func (r *RuleReconciler) setCondition(rule *wazuhv1.WazuhRule, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: rule.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the rule status with retry on conflict.
func (r *RuleReconciler) updateStatus(ctx context.Context, rule *wazuhv1.WazuhRule) error {
	desiredStatus := rule.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhRule{}
		if err := r.Get(ctx, types.NamespacedName{Name: rule.Name, Namespace: rule.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		rule.Status = latest.Status
		return nil
	})
}

// determineAppliedNodes determines which manager nodes the rule applies to
func (r *RuleReconciler) determineAppliedNodes(rule *wazuhv1.WazuhRule, cluster *wazuhv1.WazuhCluster) []string {
	var nodes []string
	targetNodes := rule.Spec.TargetNodes
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
		for i := range workerCount {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	case "all":
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", clusterName))
		workerCount := int32(0)
		if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
			workerCount = *cluster.Spec.Manager.Workers.Replicas
		}
		for i := range workerCount {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", clusterName, i))
		}
	}

	return nodes
}

// Delete handles cleanup when a rule is deleted.
// Deletes the rule ConfigMap from each target cluster's namespace (cross-NS, no ownerRef).
func (r *RuleReconciler) Delete(ctx context.Context, rule *wazuhv1.WazuhRule) error {
	log := logf.FromContext(ctx)
	cmName := ruleConfigMapName(rule.Namespace, rule.Name)

	for _, ref := range rule.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete rule ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup rule ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if r.Recorder != nil {
		r.Recorder.Event(rule, corev1.EventTypeNormal, "RuleDeleted",
			fmt.Sprintf("Rule %s deleted on all target clusters", rule.Name))
	}
	return nil
}

// ListRulesForCluster lists all WazuhRules targeting a specific cluster (cross-NS).
func (r *RuleReconciler) ListRulesForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhRule, error) {
	ruleList := &wazuhv1.WazuhRuleList{}
	if err := r.List(ctx, ruleList); err != nil {
		return nil, fmt.Errorf("failed to list WazuhRules: %w", err)
	}

	var matching []wazuhv1.WazuhRule
	for _, rule := range ruleList.Items {
		for _, ref := range rule.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matching = append(matching, rule)
				break
			}
		}
	}
	return matching, nil
}

// GetRuleConfigMapsForCluster returns ConfigMap references for all rules on a cluster.
func (r *RuleReconciler) GetRuleConfigMapsForCluster(ctx context.Context, clusterName, namespace string) ([]RuleConfigMapInfo, string, error) {
	rules, err := r.ListRulesForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, "", err
	}

	var configMaps []RuleConfigMapInfo
	var ruleContents []string

	for _, rule := range rules {
		// Find the per-cluster status to confirm the rule is applied on this cluster
		applied := false
		for _, st := range rule.Status.ClusterStatuses {
			if st.Name == clusterName && st.Namespace == namespace && st.Phase == wazuhv1.RulePhaseApplied && st.ConfigMapRef != nil {
				applied = true
				break
			}
		}
		if !applied {
			continue
		}

		configMaps = append(configMaps, RuleConfigMapInfo{
			ConfigMapName: ruleConfigMapName(rule.Namespace, rule.Name),
			FileName:      fmt.Sprintf("%s.xml", rule.Spec.RuleName),
			RuleName:      rule.Name,
		})
		ruleContents = append(ruleContents, rule.Spec.Rules)
	}

	sort.Slice(configMaps, func(i, j int) bool {
		return configMaps[i].RuleName < configMaps[j].RuleName
	})
	sort.Strings(ruleContents)

	hash := computeRulesHash(ruleContents)
	return configMaps, hash, nil
}

// RuleConfigMapInfo holds information about a rule ConfigMap for mounting
type RuleConfigMapInfo struct {
	ConfigMapName string
	FileName      string
	RuleName      string
}

// computeRulesHash computes a hash of all rule contents for change detection
func computeRulesHash(contents []string) string {
	h := sha256.New()
	for _, content := range contents {
		h.Write([]byte(content))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// countRulesForCluster counts the total number of rules for a cluster
func (r *RuleReconciler) countRulesForCluster(ctx context.Context, namespace, clusterName string) (int, error) {
	rules, err := r.ListRulesForCluster(ctx, clusterName, namespace)
	if err != nil {
		return 0, err
	}
	return len(rules), nil
}
