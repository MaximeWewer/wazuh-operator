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

// Reconcile reconciles the Wazuh Rule
func (r *RuleReconciler) Reconcile(ctx context.Context, rule *wazuhv1.WazuhRule) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "RuleReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", rule.Name),
			attribute.String("resource.namespace", rule.Namespace),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	// Initialize status if needed
	if rule.Status.Phase == "" {
		rule.Status.Phase = wazuhv1.RulePhasePending
	}

	// Validate the rule
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

	// Clear validation errors and set validated condition
	rule.Status.ValidationErrors = nil
	r.setCondition(rule, ConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"Rule content is valid")

	// Verify referenced cluster exists
	cluster := &wazuhv1.WazuhCluster{}
	clusterNamespace := rule.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = rule.Namespace
	}
	clusterKey := types.NamespacedName{Name: rule.Spec.ClusterRef.Name, Namespace: clusterNamespace}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Referenced WazuhCluster not found", "cluster", clusterKey)
			r.setCondition(rule, ConditionTypeReady, metav1.ConditionFalse, "ClusterNotFound",
				fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			rule.Status.Phase = wazuhv1.RulePhasePending
			if r.Recorder != nil {
				r.Recorder.Event(rule, corev1.EventTypeWarning, "ClusterNotFound",
					fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			}
			return r.updateStatus(ctx, rule)
		}
		return fmt.Errorf("failed to get referenced WazuhCluster %s: %w", clusterKey, err)
	}

	// Create ConfigMap for the rule
	configMapName, err := r.reconcileConfigMap(ctx, rule)
	if err != nil {
		rule.Status.Phase = wazuhv1.RulePhaseFailed
		r.setCondition(rule, ConditionTypeConfigMapCreated, metav1.ConditionFalse, "ConfigMapFailed",
			fmt.Sprintf("Failed to create ConfigMap: %v", err))
		r.setCondition(rule, ConditionTypeReady, metav1.ConditionFalse, "ConfigMapFailed",
			"Failed to create rule ConfigMap")
		if r.Recorder != nil {
			r.Recorder.Event(rule, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return fmt.Errorf("failed to reconcile rule configmap: %w", err)
	}

	// Update status with ConfigMap reference
	rule.Status.ConfigMapRef = &wazuhv1.ConfigMapReference{
		Name:      configMapName,
		Namespace: rule.Namespace,
	}
	r.setCondition(rule, ConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
		fmt.Sprintf("ConfigMap %s created successfully", configMapName))

	// Determine which nodes the rule is applied to based on targetNodes
	appliedNodes := r.determineAppliedNodes(rule, cluster)
	rule.Status.AppliedToNodes = appliedNodes

	// Set ready condition and phase
	rule.Status.Phase = wazuhv1.RulePhaseApplied
	r.setCondition(rule, ConditionTypeReady, metav1.ConditionTrue, "RuleApplied",
		fmt.Sprintf("Rule applied to %d node(s)", len(appliedNodes)))

	// Update observed generation
	rule.Status.ObservedGeneration = rule.Generation

	// Update timestamp
	now := metav1.Now()
	rule.Status.LastAppliedTime = &now

	// Record success event
	if r.Recorder != nil {
		r.Recorder.Event(rule, corev1.EventTypeNormal, "RuleApplied",
			fmt.Sprintf("Rule %s applied successfully", rule.Name))
	}

	// Update status
	if err := r.updateStatus(ctx, rule); err != nil {
		return fmt.Errorf("failed to update rule status: %w", err)
	}

	// Record rules metric for the cluster
	rulesCount, err := r.countRulesForCluster(ctx, clusterNamespace, rule.Spec.ClusterRef.Name)
	if err == nil {
		metrics.SetWazuhRulesTotal(rule.Spec.ClusterRef.Name, clusterNamespace, rulesCount)
	}

	log.Info("Rule reconciliation completed", "name", rule.Name, "configMap", configMapName)
	return nil
}

// reconcileConfigMap reconciles the ConfigMap for the rule
func (r *RuleReconciler) reconcileConfigMap(ctx context.Context, rule *wazuhv1.WazuhRule) (string, error) {
	log := logf.FromContext(ctx)

	configMapName := fmt.Sprintf("%s-rule", rule.Name)
	fileName := fmt.Sprintf("%s.xml", rule.Spec.RuleName)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: rule.Namespace,
			Labels: map[string]string{
				constants.LabelName:      "wazuh-rule",
				constants.LabelInstance:  rule.Name,
				constants.LabelManagedBy: constants.OperatorName,
				constants.LabelComponent: "rule",
				// Add cluster reference label for easy filtering
				"wazuh.com/cluster": rule.Spec.ClusterRef.Name,
			},
		},
		Data: map[string]string{
			fileName: rule.Spec.Rules,
		},
	}

	if err := controllerutil.SetControllerReference(rule, cm, r.Scheme); err != nil {
		return "", fmt.Errorf("failed to set controller reference: %w", err)
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating rule ConfigMap", "name", cm.Name)
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
	log.V(1).Info("Updating rule ConfigMap", "name", cm.Name)
	if err := r.Update(ctx, existing); err != nil {
		return "", err
	}

	return configMapName, nil
}

// setCondition sets a status condition on the rule
func (r *RuleReconciler) setCondition(rule *wazuhv1.WazuhRule, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: rule.Generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// updateStatus updates the rule status with retry on conflict
func (r *RuleReconciler) updateStatus(ctx context.Context, rule *wazuhv1.WazuhRule) error {
	desiredStatus := rule.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhRule{}
		if err := r.Get(ctx, types.NamespacedName{Name: rule.Name, Namespace: rule.Namespace}, latest); err != nil {
			return err
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

// Delete handles cleanup when a rule is deleted
func (r *RuleReconciler) Delete(ctx context.Context, rule *wazuhv1.WazuhRule) error {
	log := logf.FromContext(ctx)

	// Record deletion event
	if r.Recorder != nil {
		r.Recorder.Event(rule, corev1.EventTypeNormal, "RuleDeleted",
			fmt.Sprintf("Rule %s deleted, ConfigMap will be garbage collected", rule.Name))
	}

	// The ConfigMap will be garbage collected due to owner reference
	log.Info("Rule deletion handled", "name", rule.Name)
	return nil
}

// ListRulesForCluster lists all WazuhRules referencing a specific cluster
func (r *RuleReconciler) ListRulesForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhRule, error) {
	ruleList := &wazuhv1.WazuhRuleList{}
	if err := r.List(ctx, ruleList, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("failed to list WazuhRules: %w", err)
	}

	var matchingRules []wazuhv1.WazuhRule
	for _, rule := range ruleList.Items {
		if rule.Spec.ClusterRef.Name == clusterName {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}

// GetRuleConfigMapsForCluster returns ConfigMap references for all rules in a cluster
// This is used by the WazuhCluster reconciler to mount rule ConfigMaps to manager pods
func (r *RuleReconciler) GetRuleConfigMapsForCluster(ctx context.Context, clusterName, namespace string) ([]RuleConfigMapInfo, string, error) {
	rules, err := r.ListRulesForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, "", err
	}

	var configMaps []RuleConfigMapInfo
	var ruleContents []string

	for _, rule := range rules {
		// Only include rules that are successfully applied
		if rule.Status.Phase != wazuhv1.RulePhaseApplied {
			continue
		}
		if rule.Status.ConfigMapRef == nil {
			continue
		}

		configMaps = append(configMaps, RuleConfigMapInfo{
			ConfigMapName: rule.Status.ConfigMapRef.Name,
			FileName:      fmt.Sprintf("%s.xml", rule.Spec.RuleName),
			RuleName:      rule.Name,
		})
		ruleContents = append(ruleContents, rule.Spec.Rules)
	}

	// Sort for consistent ordering
	sort.Slice(configMaps, func(i, j int) bool {
		return configMaps[i].RuleName < configMaps[j].RuleName
	})
	sort.Strings(ruleContents)

	// Compute hash of all rule contents for change detection
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
