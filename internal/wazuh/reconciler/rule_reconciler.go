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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RuleReconciler handles reconciliation of Wazuh Rules
type RuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewRuleReconciler creates a new RuleReconciler
func NewRuleReconciler(c client.Client, scheme *runtime.Scheme) *RuleReconciler {
	return &RuleReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles the Wazuh Rule
func (r *RuleReconciler) Reconcile(ctx context.Context, rule *wazuhv1alpha1.WazuhRule) error {
	log := logf.FromContext(ctx)

	// Create ConfigMap for the rule
	if err := r.reconcileConfigMap(ctx, rule); err != nil {
		return fmt.Errorf("failed to reconcile rule configmap: %w", err)
	}

	// Update status
	if err := r.updateStatus(ctx, rule); err != nil {
		return fmt.Errorf("failed to update rule status: %w", err)
	}

	log.Info("Rule reconciliation completed", "name", rule.Name)
	return nil
}

// reconcileConfigMap reconciles the ConfigMap for the rule
func (r *RuleReconciler) reconcileConfigMap(ctx context.Context, rule *wazuhv1alpha1.WazuhRule) error {
	log := logf.FromContext(ctx)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-rule", rule.Name),
			Namespace: rule.Namespace,
			Labels: map[string]string{
				constants.LabelName:      "wazuh-rule",
				constants.LabelInstance:  rule.Name,
				constants.LabelManagedBy: "wazuh-operator",
				constants.LabelComponent: "rule",
			},
		},
		Data: map[string]string{
			fmt.Sprintf("%s.xml", rule.Spec.RuleName): rule.Spec.Rules,
		},
	}

	if err := controllerutil.SetControllerReference(rule, cm, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating rule ConfigMap", "name", cm.Name)
		return r.Create(ctx, cm)
	} else if err != nil {
		return err
	}

	// Update existing
	existing.Data = cm.Data
	existing.Labels = cm.Labels
	log.V(1).Info("Updating rule ConfigMap", "name", cm.Name)
	return r.Update(ctx, existing)
}

// updateStatus updates the rule status
func (r *RuleReconciler) updateStatus(ctx context.Context, rule *wazuhv1alpha1.WazuhRule) error {
	rule.Status.Phase = wazuhv1alpha1.RulePhaseApplied
	rule.Status.Message = "Rule ConfigMap created successfully"
	now := metav1.Now()
	rule.Status.LastAppliedTime = &now

	return r.Status().Update(ctx, rule)
}

// Delete handles cleanup when a rule is deleted
func (r *RuleReconciler) Delete(ctx context.Context, rule *wazuhv1alpha1.WazuhRule) error {
	log := logf.FromContext(ctx)

	// The ConfigMap will be garbage collected due to owner reference
	log.Info("Rule deletion handled", "name", rule.Name)
	return nil
}
