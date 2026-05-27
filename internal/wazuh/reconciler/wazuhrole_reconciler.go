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

	"go.opentelemetry.io/otel/attribute"
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

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

const (
	// WazuhRoleFinalizer is the finalizer for WazuhRole resources.
	WazuhRoleFinalizer = "wazuhrole.resources.wazuh.com/finalizer"

	// WazuhRoleConditionTypeReady is the Ready condition type.
	WazuhRoleConditionTypeReady = "Ready"
	// WazuhRoleConditionTypeSynced is the Synced condition type.
	WazuhRoleConditionTypeSynced = "Synced"
)

// WazuhAPIRoleReconciler reconciles WazuhRole resources against the Wazuh
// Manager API on each target cluster.
type WazuhAPIRoleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewWazuhAPIRoleReconciler creates a new WazuhAPIRoleReconciler.
func NewWazuhAPIRoleReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *WazuhAPIRoleReconciler {
	return &WazuhAPIRoleReconciler{Client: c, Scheme: scheme, Recorder: recorder}
}

// Reconcile reconciles a WazuhRole across all target clusters. Each ClusterRef
// is processed independently; the aggregate Status.Phase reflects the worst case.
func (r *WazuhAPIRoleReconciler) Reconcile(ctx context.Context, role *wazuhv1.WazuhRole) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhAPIRoleReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", role.Name),
			attribute.String("resource.namespace", role.Namespace),
			attribute.Int("resource.clusterRefs", len(role.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)
	roleName := role.ResolveRoleName()

	if role.Status.Phase == "" {
		role.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	existingByKey := make(map[string]wazuhv1.WazuhRBACClusterStatus, len(role.Status.ClusterStatuses))
	for _, s := range role.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.WazuhRBACClusterStatus, 0, len(role.Spec.ClusterRefs))
	anyAPIUnavailable := false
	anyFailed := false
	allReady := true

	for _, ref := range role.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		clusterErr := r.reconcileForCluster(ctx, role, roleName, ref, &st)
		if clusterErr != nil {
			if IsAPIUnavailable(clusterErr) {
				anyAPIUnavailable = true
			} else {
				anyFailed = true
			}
			log.Error(clusterErr, "Failed to reconcile WazuhRole on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.WazuhRBACPhaseReady {
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
	role.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		role.Status.Phase = wazuhv1.WazuhRBACPhaseFailed
		r.setCondition(role, WazuhRoleConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to sync")
		role.Status.Message = "One or more target clusters failed to sync"
	case anyAPIUnavailable:
		role.Status.Phase = wazuhv1.WazuhRBACPhasePending
		r.setCondition(role, WazuhRoleConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			"One or more Wazuh APIs are unavailable")
		role.Status.Message = "Waiting for Wazuh API availability on one or more clusters"
	case allReady:
		role.Status.Phase = wazuhv1.WazuhRBACPhaseReady
		r.setCondition(role, WazuhRoleConditionTypeSynced, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("Role %s synced on all target clusters", roleName))
		r.setCondition(role, WazuhRoleConditionTypeReady, metav1.ConditionTrue, "Ready",
			fmt.Sprintf("Role %s is ready on all target clusters", roleName))
		role.Status.Message = ""
	default:
		role.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	role.Status.ObservedGeneration = role.Generation

	if err := r.updateStatus(ctx, role); err != nil {
		return fmt.Errorf("failed to update WazuhRole status: %w", err)
	}

	metrics.RecordReconciliation("WazuhRole", role.Namespace, "success", 0)

	if anyAPIUnavailable && !anyFailed {
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("one or more wazuh APIs unavailable")}
	}
	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to sync")
	}
	log.Info("WazuhRole reconciliation completed", "name", role.Name, "role", roleName)
	return nil
}

// reconcileForCluster ensures the role, its policies and rules exist on one
// cluster and are linked together. Per-cluster status is mutated in place.
func (r *WazuhAPIRoleReconciler) reconcileForCluster(
	ctx context.Context,
	role *wazuhv1.WazuhRole,
	roleName string,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.WazuhRBACClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.WazuhRBACPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterNN)
			r.event(role, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			return nil
		}
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	apiClient, err := buildWazuhAPIClient(ctx, r.Client, cluster)
	if err != nil {
		st.Phase = wazuhv1.WazuhRBACPhasePending
		st.Message = fmt.Sprintf("Wazuh API unavailable: %v", err)
		return &WazuhAPIUnavailableError{Err: err}
	}
	if !apiClient.IsHealthy(ctx) {
		st.Phase = wazuhv1.WazuhRBACPhasePending
		st.Message = "Wazuh API is not healthy"
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("wazuh API health check failed")}
	}

	specHash := computeRoleSpecHash(role, roleName)
	if specHash == st.LastAppliedHash && st.RoleID != 0 && st.Phase == wazuhv1.WazuhRBACPhaseReady {
		return nil // already synced, nothing to do
	}

	// Capture previously-owned children so we can prune ones removed from spec.
	prevPolicyIDs := st.PolicyIDs
	prevRuleIDs := st.RuleIDs
	newPolicyIDs := make(map[string]int, len(role.Spec.Policies))
	newRuleIDs := make(map[string]int, len(role.Spec.Rules))

	// Ensure policies first.
	for _, p := range role.Spec.Policies {
		effect := p.Effect
		if effect == "" {
			effect = "allow"
		}
		id, err := apiClient.EnsurePolicy(ctx, p.Name, p.Actions, p.Resources, effect)
		if err != nil {
			return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("policy %s: %v", p.Name, err), "PolicyFailed", err)
		}
		if id == 0 {
			return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("policy %s not resolved", p.Name), "PolicyFailed",
				fmt.Errorf("policy %s could not be resolved", p.Name))
		}
		if id < adapters.ReservedRBACIDThreshold {
			return r.fail(role, st, newPolicyIDs, newRuleIDs,
				fmt.Sprintf("policy name %q collides with a reserved Wazuh policy", p.Name), "ReservedCollision",
				fmt.Errorf("policy %s collides with reserved object (id %d)", p.Name, id))
		}
		newPolicyIDs[p.Name] = id
	}

	// Ensure rules.
	for _, ru := range role.Spec.Rules {
		if ru.Body == nil || len(ru.Body.Raw) == 0 {
			return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("rule %s has empty body", ru.Name), "RuleFailed",
				fmt.Errorf("rule %s body is empty", ru.Name))
		}
		id, err := apiClient.EnsureRule(ctx, ru.Name, ru.Body.Raw)
		if err != nil {
			return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("rule %s: %v", ru.Name, err), "RuleFailed", err)
		}
		if id < adapters.ReservedRBACIDThreshold {
			return r.fail(role, st, newPolicyIDs, newRuleIDs,
				fmt.Sprintf("rule name %q collides with a reserved Wazuh rule", ru.Name), "ReservedCollision",
				fmt.Errorf("rule %s collides with reserved object (id %d)", ru.Name, id))
		}
		newRuleIDs[ru.Name] = id
	}

	// Ensure the role.
	roleID, err := apiClient.EnsureRole(ctx, roleName)
	if err != nil {
		return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("role %s: %v", roleName, err), "RoleFailed", err)
	}
	if roleID < adapters.ReservedRBACIDThreshold {
		return r.fail(role, st, newPolicyIDs, newRuleIDs,
			fmt.Sprintf("role name %q collides with a reserved Wazuh role", roleName), "ReservedCollision",
			fmt.Errorf("role %s collides with reserved object (id %d)", roleName, roleID))
	}
	st.RoleID = roleID

	// Link children to the role.
	if err := apiClient.LinkRolePolicies(ctx, roleID, mapValues(newPolicyIDs)); err != nil {
		return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("link policies: %v", err), "LinkFailed", err)
	}
	if err := apiClient.LinkRoleRules(ctx, roleID, mapValues(newRuleIDs)); err != nil {
		return r.fail(role, st, newPolicyIDs, newRuleIDs, fmt.Sprintf("link rules: %v", err), "LinkFailed", err)
	}

	// Persist resolved IDs before pruning so cleanup is never lost.
	st.PolicyIDs = newPolicyIDs
	st.RuleIDs = newRuleIDs

	// Prune policies/rules removed from spec (best-effort).
	for name, id := range prevPolicyIDs {
		if _, keep := newPolicyIDs[name]; !keep && id >= adapters.ReservedRBACIDThreshold {
			_ = apiClient.UnlinkRolePolicies(ctx, roleID, []int{id})
			if err := apiClient.DeletePolicies(ctx, id); err != nil {
				log.Error(err, "Failed to prune removed policy", "policy", name, "id", id)
			}
		}
	}
	for name, id := range prevRuleIDs {
		if _, keep := newRuleIDs[name]; !keep && id >= adapters.ReservedRBACIDThreshold {
			_ = apiClient.UnlinkRoleRules(ctx, roleID, []int{id})
			if err := apiClient.DeleteRules(ctx, id); err != nil {
				log.Error(err, "Failed to prune removed rule", "rule", name, "id", id)
			}
		}
	}

	wasReady := st.Phase == wazuhv1.WazuhRBACPhaseReady
	st.Phase = wazuhv1.WazuhRBACPhaseReady
	st.Message = ""
	st.LastAppliedHash = specHash
	if !wasReady {
		now := metav1.Now()
		st.LastSyncTime = &now
		r.event(role, corev1.EventTypeNormal, "Synced",
			fmt.Sprintf("Role %s synced on %s/%s", roleName, ref.Namespace, ref.Name))
	}
	return nil
}

// fail records a per-cluster failure, persists any IDs resolved so far (so they
// can be cleaned up later), and returns the underlying error.
func (r *WazuhAPIRoleReconciler) fail(
	role *wazuhv1.WazuhRole,
	st *wazuhv1.WazuhRBACClusterStatus,
	policyIDs, ruleIDs map[string]int,
	msg, reason string,
	err error,
) error {
	st.Phase = wazuhv1.WazuhRBACPhaseFailed
	st.Message = msg
	// Merge resolved IDs into status so partial progress is recoverable.
	st.PolicyIDs = mergeIDMaps(st.PolicyIDs, policyIDs)
	st.RuleIDs = mergeIDMaps(st.RuleIDs, ruleIDs)
	r.event(role, corev1.EventTypeWarning, reason, msg)
	return err
}

// Delete cleans up all Wazuh API objects owned by the role across clusters
// (reverse order: unlink, then delete role, then delete policies/rules).
func (r *WazuhAPIRoleReconciler) Delete(ctx context.Context, role *wazuhv1.WazuhRole) error {
	log := logf.FromContext(ctx)

	byKey := make(map[string]wazuhv1.WazuhRBACClusterStatus, len(role.Status.ClusterStatuses))
	for _, s := range role.Status.ClusterStatuses {
		byKey[clusterKey(s.Name, s.Namespace)] = s
	}

	for _, ref := range role.Spec.ClusterRefs {
		st := byKey[clusterKey(ref.Name, ref.Namespace)]
		cluster := &wazuhv1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, cluster); err != nil {
			log.Info("Cluster not found during delete, skipping API cleanup", "cluster", ref.Name)
			continue
		}
		apiClient, err := buildWazuhAPIClient(ctx, r.Client, cluster)
		if err != nil {
			log.Info("Wazuh API unavailable during delete, skipping API cleanup", "cluster", ref.Name, "error", err)
			continue
		}

		if st.RoleID >= adapters.ReservedRBACIDThreshold {
			_ = apiClient.UnlinkRoleRules(ctx, st.RoleID, mapValues(st.RuleIDs))
			_ = apiClient.UnlinkRolePolicies(ctx, st.RoleID, mapValues(st.PolicyIDs))
			if err := apiClient.DeleteRoles(ctx, st.RoleID); err != nil {
				log.Error(err, "Failed to delete role from Wazuh API, continuing", "cluster", ref.Name)
			}
		}
		for name, id := range st.PolicyIDs {
			if id >= adapters.ReservedRBACIDThreshold {
				if err := apiClient.DeletePolicies(ctx, id); err != nil {
					log.Error(err, "Failed to delete policy from Wazuh API, continuing", "policy", name, "id", id)
				}
			}
		}
		for name, id := range st.RuleIDs {
			if id >= adapters.ReservedRBACIDThreshold {
				if err := apiClient.DeleteRules(ctx, id); err != nil {
					log.Error(err, "Failed to delete rule from Wazuh API, continuing", "rule", name, "id", id)
				}
			}
		}
	}

	r.event(role, corev1.EventTypeNormal, "Deleted",
		fmt.Sprintf("Role %s cleaned up on all target clusters", role.ResolveRoleName()))
	return nil
}

func (r *WazuhAPIRoleReconciler) setCondition(role *wazuhv1.WazuhRole, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: role.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *WazuhAPIRoleReconciler) event(role *wazuhv1.WazuhRole, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(role, eventType, reason, message)
	}
}

func (r *WazuhAPIRoleReconciler) updateStatus(ctx context.Context, role *wazuhv1.WazuhRole) error {
	desiredStatus := role.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhRole{}
		if err := r.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		role.Status = latest.Status
		return nil
	})
}

// computeRoleSpecHash hashes the role spec for drift detection.
func computeRoleSpecHash(role *wazuhv1.WazuhRole, roleName string) string {
	h := sha256.New()
	h.Write([]byte(roleName))

	policies := append([]wazuhv1.WazuhRolePolicy(nil), role.Spec.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	for _, p := range policies {
		h.Write([]byte(p.Name))
		for _, a := range p.Actions {
			h.Write([]byte(a))
		}
		for _, res := range p.Resources {
			h.Write([]byte(res))
		}
		h.Write([]byte(p.Effect))
	}

	rules := append([]wazuhv1.WazuhRoleRule(nil), role.Spec.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	for _, ru := range rules {
		h.Write([]byte(ru.Name))
		if ru.Body != nil {
			h.Write(ru.Body.Raw)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// mapValues returns the values of an id map in a stable (sorted) order.
func mapValues(m map[string]int) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// mergeIDMaps merges src into dst (src wins) and returns the result.
func mergeIDMaps(dst, src map[string]int) map[string]int {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]int, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
