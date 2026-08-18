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
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

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
	// WazuhAgentGroupAssignmentFinalizer is the finalizer for
	// WazuhAgentGroupAssignment resources.
	WazuhAgentGroupAssignmentFinalizer = "wazuhagentgroupassignment.resources.wazuh.com/finalizer"

	// WazuhAgentGroupAssignmentConditionTypeReady is the Ready condition type.
	WazuhAgentGroupAssignmentConditionTypeReady = "Ready"
	// WazuhAgentGroupAssignmentConditionTypeSynced is the Synced condition type.
	WazuhAgentGroupAssignmentConditionTypeSynced = "Synced"

	// managerAgentID is the reserved ID of the Wazuh manager itself; it must
	// never be moved between groups.
	managerAgentID = "000"
)

// agentGroupAPI is the minimal set of Wazuh API operations needed to enforce
// group membership. Satisfied by *adapters.WazuhAPIAdapter and by fakes in tests.
type agentGroupAPI interface {
	AssignAgentToGroup(ctx context.Context, agentID, group string) error
	RemoveAgentFromGroup(ctx context.Context, agentID, group string) error
}

// WazuhAPIAgentGroupAssignmentReconciler reconciles WazuhAgentGroupAssignment
// resources against the Wazuh Manager API on each target cluster.
//
// Reconciliation is cluster-global: every waga reconcile recomputes the whole
// cluster's desired agent->groups state as the UNION of Spec.Groups across all
// CRs whose selector matches each agent. Applies are serialized per cluster so
// concurrent reconciles are idempotent and do not thrash.
type WazuhAPIAgentGroupAssignmentReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	clusterLocksMu sync.Mutex
	clusterLocks   map[string]*sync.Mutex
}

// NewWazuhAPIAgentGroupAssignmentReconciler creates a new reconciler.
func NewWazuhAPIAgentGroupAssignmentReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *WazuhAPIAgentGroupAssignmentReconciler {
	return &WazuhAPIAgentGroupAssignmentReconciler{
		Client:       c,
		Scheme:       scheme,
		Recorder:     recorder,
		clusterLocks: make(map[string]*sync.Mutex),
	}
}

// clusterLock returns the process-wide mutex for a cluster, creating it on first
// use. All global applies for a cluster serialize on this lock.
func (r *WazuhAPIAgentGroupAssignmentReconciler) clusterLock(key string) *sync.Mutex {
	r.clusterLocksMu.Lock()
	defer r.clusterLocksMu.Unlock()
	if r.clusterLocks == nil {
		r.clusterLocks = make(map[string]*sync.Mutex)
	}
	m, ok := r.clusterLocks[key]
	if !ok {
		m = &sync.Mutex{}
		r.clusterLocks[key] = m
	}
	return m
}

// Reconcile reconciles a WazuhAgentGroupAssignment across all target clusters.
// Each ClusterRef is processed independently; the aggregate Status.Phase
// reflects the worst case.
func (r *WazuhAPIAgentGroupAssignmentReconciler) Reconcile(ctx context.Context, assignment *wazuhv1.WazuhAgentGroupAssignment) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhAPIAgentGroupAssignmentReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", assignment.Name),
			attribute.String("resource.namespace", assignment.Namespace),
			attribute.Int("resource.clusterRefs", len(assignment.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if assignment.Status.Phase == "" {
		assignment.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	// Compile this CR's own selector once (used for status + error reporting).
	sel, selErr := compileSelector(assignment.Spec.Selector)

	existingByKey := make(map[string]wazuhv1.AgentGroupAssignmentClusterStatus, len(assignment.Status.ClusterStatuses))
	for _, s := range assignment.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.AgentGroupAssignmentClusterStatus, 0, len(assignment.Spec.ClusterRefs))
	anyAPIUnavailable := false
	anyFailed := false
	allReady := true

	for _, ref := range assignment.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		clusterErr := r.reconcileForCluster(ctx, assignment, ref, sel, selErr, &st)
		if clusterErr != nil {
			if IsAPIUnavailable(clusterErr) {
				anyAPIUnavailable = true
			} else {
				anyFailed = true
			}
			log.Error(clusterErr, "Failed to reconcile WazuhAgentGroupAssignment on cluster",
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
	assignment.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		assignment.Status.Phase = wazuhv1.WazuhRBACPhaseFailed
		r.setCondition(assignment, WazuhAgentGroupAssignmentConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to sync")
		assignment.Status.Message = "One or more target clusters failed to sync"
	case anyAPIUnavailable:
		assignment.Status.Phase = wazuhv1.WazuhRBACPhasePending
		r.setCondition(assignment, WazuhAgentGroupAssignmentConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			"One or more Wazuh APIs are unavailable")
		assignment.Status.Message = "Waiting for Wazuh API availability on one or more clusters"
	case allReady:
		assignment.Status.Phase = wazuhv1.WazuhRBACPhaseReady
		r.setCondition(assignment, WazuhAgentGroupAssignmentConditionTypeSynced, metav1.ConditionTrue, "Synced",
			"Agent group assignment synced on all target clusters")
		r.setCondition(assignment, WazuhAgentGroupAssignmentConditionTypeReady, metav1.ConditionTrue, "Ready",
			"Agent group assignment is ready on all target clusters")
		assignment.Status.Message = ""
	default:
		assignment.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	assignment.Status.ObservedGeneration = assignment.Generation

	if err := r.updateStatus(ctx, assignment); err != nil {
		return fmt.Errorf("failed to update WazuhAgentGroupAssignment status: %w", err)
	}

	metrics.RecordReconciliation("WazuhAgentGroupAssignment", assignment.Namespace, "success", 0)

	if anyAPIUnavailable && !anyFailed {
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("one or more wazuh APIs unavailable")}
	}
	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to sync")
	}
	log.Info("WazuhAgentGroupAssignment reconciliation completed", "name", assignment.Name)
	return nil
}

// reconcileForCluster recomputes and applies the whole cluster's desired
// agent->groups state (union across all matching CRs) on one cluster. Per-cluster
// status of the CURRENT CR is mutated in place.
func (r *WazuhAPIAgentGroupAssignmentReconciler) reconcileForCluster(
	ctx context.Context,
	assignment *wazuhv1.WazuhAgentGroupAssignment,
	ref wazuhv1.WazuhClusterRef,
	sel compiledSelector,
	selErr error,
	st *wazuhv1.AgentGroupAssignmentClusterStatus,
) error {
	cluster := &wazuhv1.WazuhCluster{}
	clusterNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.WazuhRBACPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterNN)
			r.event(assignment, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			return nil
		}
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	// This CR's own selector must compile (spec error, not API error).
	if selErr != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("invalid selector: %v", selErr)
		r.event(assignment, corev1.EventTypeWarning, "InvalidSelector", st.Message)
		return fmt.Errorf("invalid selector: %w", selErr)
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

	// Gather every active waga CR that targets THIS cluster (including the one
	// being reconciled). CRs being deleted are excluded so their groups stop
	// contributing to the union.
	crs, err := r.listAssignmentsForCluster(ctx, ref.Name, ref.Namespace, "")
	if err != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to list assignments: %v", err)
		return err
	}

	// Serialize the global apply per cluster so concurrent waga reconciles
	// (which all compute the same union) do not thrash.
	lock := r.clusterLock(clusterKey(ref.Name, ref.Namespace))
	lock.Lock()
	defer lock.Unlock()

	agents, err := apiClient.ListAgents(ctx)
	if err != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to list agents: %v", err)
		r.event(assignment, corev1.EventTypeWarning, "ListAgentsFailed", st.Message)
		return err
	}

	// Always re-scan (never short-circuit on LastAppliedHash): agents register
	// dynamically and must be picked up without a spec change.
	desired := computeDesiredAgentGroups(agents, crs)
	applyErr := applyDesiredAgentGroups(ctx, apiClient, agents, desired)

	// Status reflects the CURRENT CR's own matches, not the whole cluster.
	managedIDs := matchedAgentIDs(agents, sel)
	st.ManagedAgentIDs = managedIDs
	st.MatchedAgentCount = int32(len(managedIDs))
	st.LastAppliedHash = computeAssignmentSpecHash(dedupStrings(assignment.Spec.Groups), assignment.Spec.Selector)

	if applyErr != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to apply group membership: %v", applyErr)
		r.event(assignment, corev1.EventTypeWarning, "ApplyFailed", st.Message)
		return applyErr
	}

	wasReady := st.Phase == wazuhv1.WazuhRBACPhaseReady
	st.Phase = wazuhv1.WazuhRBACPhaseReady
	st.Message = ""
	now := metav1.Now()
	st.LastSyncTime = &now
	if !wasReady {
		r.event(assignment, corev1.EventTypeNormal, "Synced",
			fmt.Sprintf("Group assignment synced on %s/%s (%d agents matched)", ref.Namespace, ref.Name, len(managedIDs)))
	}
	return nil
}

// Delete reverts this assignment's group contributions on every target cluster
// WITHOUT stripping groups that another CR still wants. For each agent this CR
// matched, only the groups in this CR's Spec.Groups that are NOT in the union of
// the OTHER matching CRs are removed. Best-effort and tolerant; returns a retry
// error only when the API is temporarily unhealthy so a deleted/absent cluster
// never blocks finalizer removal.
func (r *WazuhAPIAgentGroupAssignmentReconciler) Delete(ctx context.Context, assignment *wazuhv1.WazuhAgentGroupAssignment) error {
	log := logf.FromContext(ctx)

	byKey := make(map[string]wazuhv1.AgentGroupAssignmentClusterStatus, len(assignment.Status.ClusterStatuses))
	for _, s := range assignment.Status.ClusterStatuses {
		byKey[clusterKey(s.Name, s.Namespace)] = s
	}

	ownGroups := dedupStrings(assignment.Spec.Groups)
	sel, selErr := compileSelector(assignment.Spec.Selector)
	var retryErr error

	for _, ref := range assignment.Spec.ClusterRefs {
		cluster := &wazuhv1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, cluster); err != nil {
			// Cluster is gone: nothing to clean up, do not block finalizer.
			log.Info("Cluster not found during delete, skipping API cleanup", "cluster", ref.Name)
			continue
		}
		apiClient, err := buildWazuhAPIClient(ctx, r.Client, cluster)
		if err != nil {
			log.Info("Wazuh API unavailable during delete, skipping API cleanup", "cluster", ref.Name, "error", err)
			continue
		}
		if !apiClient.IsHealthy(ctx) {
			// API is merely temporarily down: retry so we do not silently leak
			// group membership.
			log.Info("Wazuh API not healthy during delete, will retry", "cluster", ref.Name)
			retryErr = &WazuhAPIUnavailableError{Err: fmt.Errorf("wazuh API not healthy on %s/%s", ref.Namespace, ref.Name)}
			continue
		}

		// Other active CRs still targeting this cluster (exclude the one being deleted).
		otherCRs, err := r.listAssignmentsForCluster(ctx, ref.Name, ref.Namespace, assignment.UID)
		if err != nil {
			log.Error(err, "Failed to list other assignments during delete, will retry", "cluster", ref.Name)
			retryErr = err
			continue
		}

		lock := r.clusterLock(clusterKey(ref.Name, ref.Namespace))
		lock.Lock()

		agents, err := apiClient.ListAgents(ctx)
		if err != nil {
			lock.Unlock()
			log.Error(err, "Failed to list agents during delete, will retry", "cluster", ref.Name)
			retryErr = err
			continue
		}

		// What the OTHER CRs still want for each agent.
		otherDesired := computeDesiredAgentGroups(agents, otherCRs)

		// Agents this CR matched: recompute via its own selector, falling back to
		// recorded status when the selector no longer compiles.
		var matched []string
		if selErr == nil {
			matched = matchedAgentIDs(agents, sel)
		} else {
			st := byKey[clusterKey(ref.Name, ref.Namespace)]
			matched = st.ManagedAgentIDs
		}

		for _, agentID := range matched {
			if agentID == managerAgentID {
				continue
			}
			keep := toSet(otherDesired[agentID])
			for _, group := range ownGroups {
				if _, wanted := keep[group]; wanted {
					continue // another CR still provides this group
				}
				if err := apiClient.RemoveAgentFromGroup(ctx, agentID, group); err != nil {
					log.Error(err, "Failed to remove agent from group during delete, continuing",
						"cluster", ref.Name, "agent", agentID, "group", group)
				}
			}
		}
		lock.Unlock()
	}

	if retryErr != nil {
		return retryErr
	}

	r.event(assignment, corev1.EventTypeNormal, "Deleted",
		"Agent group assignment reverted on all target clusters")
	return nil
}

// listAssignmentsForCluster returns every WazuhAgentGroupAssignment (across all
// namespaces) that targets the given cluster and is not being deleted. When
// excludeUID is non-empty, the CR with that UID is skipped.
func (r *WazuhAPIAgentGroupAssignmentReconciler) listAssignmentsForCluster(ctx context.Context, clusterName, clusterNamespace string, excludeUID types.UID) ([]wazuhv1.WazuhAgentGroupAssignment, error) {
	list := &wazuhv1.WazuhAgentGroupAssignmentList{}
	if err := r.List(ctx, list); err != nil {
		return nil, err
	}
	var out []wazuhv1.WazuhAgentGroupAssignment
	for i := range list.Items {
		cr := list.Items[i]
		if excludeUID != "" && cr.UID == excludeUID {
			continue
		}
		if !cr.DeletionTimestamp.IsZero() {
			continue // being deleted: no longer contributes to the union
		}
		for _, ref := range cr.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == clusterNamespace {
				out = append(out, cr)
				break
			}
		}
	}
	return out, nil
}

// ---- pure helpers (unit-tested) ----

// compiledMatcher is a compiled set of name/os.platform terms ready for matching.
// It is used both for the positive selector and for its exclusion block.
type compiledMatcher struct {
	exact     map[string]struct{}
	globs     []string
	regexps   []*regexp.Regexp
	platforms map[string]struct{} // normalized lowercase os.platform values
}

// hasNameTerms reports whether any name-based term (exact/glob/regex) is set.
func (m compiledMatcher) hasNameTerms() bool {
	return len(m.exact) > 0 || len(m.globs) > 0 || len(m.regexps) > 0
}

// matchesName reports whether the agent name matches any name-based term.
func (m compiledMatcher) matchesName(name string) bool {
	if _, ok := m.exact[name]; ok {
		return true
	}
	for _, g := range m.globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	for _, re := range m.regexps {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// matchesOS reports whether the agent os.platform is in the platform set. An
// empty os.platform never matches.
func (m compiledMatcher) matchesOS(osPlatform string) bool {
	if len(m.platforms) == 0 || osPlatform == "" {
		return false
	}
	_, ok := m.platforms[normalizePlatform(osPlatform)]
	return ok
}

// compiledSelector is a compiled AgentSelector ready for matching.
type compiledSelector struct {
	include compiledMatcher
	// requireOS makes the platform set a restrictive filter (AND) rather than
	// additive (OR): an agent must match osPlatforms and, if any name term is
	// set, a name term too.
	requireOS bool
	// exclude removes agents from the match; nil when no exclusion is configured.
	exclude *compiledMatcher
}

// normalizePlatform lowercases and applies known aliases (macOS reports as
// "darwin"; "macos"/"osx" are accepted as aliases).
func normalizePlatform(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "macos", "osx":
		return "darwin"
	default:
		return p
	}
}

// compileMatcher validates and compiles a set of name/os.platform terms. Glob
// patterns are validated with path.Match and regexes with regexp.Compile.
func compileMatcher(agentNames, namePatterns, nameRegex, osPlatforms []string) (compiledMatcher, error) {
	m := compiledMatcher{exact: make(map[string]struct{}, len(agentNames))}
	for _, n := range agentNames {
		m.exact[n] = struct{}{}
	}
	for _, p := range namePatterns {
		if _, err := path.Match(p, "probe"); err != nil {
			return compiledMatcher{}, fmt.Errorf("invalid glob pattern %q: %w", p, err)
		}
		m.globs = append(m.globs, p)
	}
	for _, re := range nameRegex {
		compiled, err := regexp.Compile(re)
		if err != nil {
			return compiledMatcher{}, fmt.Errorf("invalid regex %q: %w", re, err)
		}
		m.regexps = append(m.regexps, compiled)
	}
	if len(osPlatforms) > 0 {
		m.platforms = make(map[string]struct{}, len(osPlatforms))
		for _, p := range osPlatforms {
			m.platforms[normalizePlatform(p)] = struct{}{}
		}
	}
	return m, nil
}

// compileSelector validates and compiles an AgentSelector, including its
// optional exclusion block.
func compileSelector(sel wazuhv1.AgentSelector) (compiledSelector, error) {
	include, err := compileMatcher(sel.AgentNames, sel.NamePatterns, sel.NameRegex, sel.OSPlatforms)
	if err != nil {
		return compiledSelector{}, err
	}
	cs := compiledSelector{include: include, requireOS: sel.RequireOSPlatform}
	if sel.Exclude != nil {
		exclude, err := compileMatcher(sel.Exclude.AgentNames, sel.Exclude.NamePatterns, sel.Exclude.NameRegex, sel.Exclude.OSPlatforms)
		if err != nil {
			return compiledSelector{}, fmt.Errorf("exclude: %w", err)
		}
		cs.exclude = &exclude
	}
	return cs, nil
}

// matchAgent reports whether the agent is selected: it must match the positive
// selector and must not match the exclusion block.
//
// Positive match, additive mode (requireOS false): name OR os.platform matches.
// Positive match, restrictive mode (requireOS true): os.platform must match and,
// if any name term is set, a name term must match too.
// An agent with an empty os.platform can still match by name in additive mode.
func matchAgent(name, osPlatform string, sel compiledSelector) bool {
	var included bool
	if sel.requireOS {
		nameOK := !sel.include.hasNameTerms() || sel.include.matchesName(name)
		included = sel.include.matchesOS(osPlatform) && nameOK
	} else {
		included = sel.include.matchesName(name) || sel.include.matchesOS(osPlatform)
	}
	if !included {
		return false
	}
	if sel.exclude != nil {
		if sel.exclude.matchesName(name) || sel.exclude.matchesOS(osPlatform) {
			return false
		}
	}
	return true
}

// matchedAgentIDs returns the sorted IDs of agents matched by sel, skipping the
// manager agent ("000").
func matchedAgentIDs(agents []adapters.WazuhAgent, sel compiledSelector) []string {
	var ids []string
	for _, ag := range agents {
		if ag.ID == managerAgentID {
			continue
		}
		if matchAgent(ag.Name, ag.OSPlatform, sel) {
			ids = append(ids, ag.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// computeDesiredAgentGroups computes the cluster-global desired state: for each
// agent, the UNION of Spec.Groups across every CR whose selector matches it. The
// manager agent ("000") is always excluded, and agents matched by NO CR are
// absent from the map (they are left untouched). Groups per agent are sorted and
// deduped. A CR whose selector fails to compile is skipped defensively (it will
// fail its own reconcile / be rejected by the webhook).
func computeDesiredAgentGroups(agents []adapters.WazuhAgent, crs []wazuhv1.WazuhAgentGroupAssignment) map[string][]string {
	// Pre-compile selectors once.
	type compiledCR struct {
		sel    compiledSelector
		groups []string
	}
	compiled := make([]compiledCR, 0, len(crs))
	for i := range crs {
		sel, err := compileSelector(crs[i].Spec.Selector)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledCR{sel: sel, groups: crs[i].Spec.Groups})
	}

	desired := make(map[string]map[string]struct{})
	for _, ag := range agents {
		if ag.ID == managerAgentID {
			continue
		}
		for _, c := range compiled {
			if !matchAgent(ag.Name, ag.OSPlatform, c.sel) {
				continue
			}
			set, ok := desired[ag.ID]
			if !ok {
				set = make(map[string]struct{})
				desired[ag.ID] = set
			}
			for _, g := range c.groups {
				set[g] = struct{}{}
			}
		}
	}

	out := make(map[string][]string, len(desired))
	for id, set := range desired {
		groups := make([]string, 0, len(set))
		for g := range set {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		out[id] = groups
	}
	return out
}

// applyDesiredAgentGroups reconciles every managed agent to EXACTLY its desired
// group set. Agents absent from desired are left untouched. The manager agent
// ("000") is never touched. For each agent additions are applied (PUT) before
// removals (DELETE) so the agent always retains >=1 desired group. Returns an
// aggregated error (nil when all succeeded).
func applyDesiredAgentGroups(ctx context.Context, api agentGroupAPI, agents []adapters.WazuhAgent, desired map[string][]string) error {
	var errs []string
	for _, ag := range agents {
		if ag.ID == managerAgentID {
			continue
		}
		want, managed := desired[ag.ID]
		if !managed {
			continue // matched by no CR: leave completely untouched
		}
		toAdd, toRemove := computeAddRemove(ag.Groups, want)
		for _, g := range toAdd {
			if err := api.AssignAgentToGroup(ctx, ag.ID, g); err != nil {
				errs = append(errs, fmt.Sprintf("assign agent %s to group %s: %v", ag.ID, g, err))
			}
		}
		for _, g := range toRemove {
			if err := api.RemoveAgentFromGroup(ctx, ag.ID, g); err != nil {
				errs = append(errs, fmt.Sprintf("remove agent %s from group %s: %v", ag.ID, g, err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// computeAddRemove returns the groups to add and remove so that current becomes
// exactly desired. Both inputs are treated as sets; results are sorted.
func computeAddRemove(current, desired []string) (toAdd, toRemove []string) {
	desiredSet := toSet(desired)
	currentSet := toSet(current)
	for d := range desiredSet {
		if _, ok := currentSet[d]; !ok {
			toAdd = append(toAdd, d)
		}
	}
	for c := range currentSet {
		if _, ok := desiredSet[c]; !ok {
			toRemove = append(toRemove, c)
		}
	}
	sort.Strings(toAdd)
	sort.Strings(toRemove)
	return toAdd, toRemove
}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func dedupStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	return out
}

// computeAssignmentSpecHash hashes the desired groups and selector for drift
// detection (informational only).
func computeAssignmentSpecHash(desired []string, sel wazuhv1.AgentSelector) string {
	h := sha256.New()
	writeSorted := func(items []string) {
		s := append([]string(nil), items...)
		sort.Strings(s)
		for _, it := range s {
			h.Write([]byte(it))
			h.Write([]byte{0})
		}
		h.Write([]byte{'|'})
	}
	writeSorted(desired)
	writeSorted(sel.AgentNames)
	writeSorted(sel.NamePatterns)
	writeSorted(sel.NameRegex)
	writeSorted(sel.OSPlatforms)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (r *WazuhAPIAgentGroupAssignmentReconciler) setCondition(assignment *wazuhv1.WazuhAgentGroupAssignment, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&assignment.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: assignment.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *WazuhAPIAgentGroupAssignmentReconciler) event(assignment *wazuhv1.WazuhAgentGroupAssignment, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(assignment, eventType, reason, message)
	}
}

func (r *WazuhAPIAgentGroupAssignmentReconciler) updateStatus(ctx context.Context, assignment *wazuhv1.WazuhAgentGroupAssignment) error {
	desiredStatus := assignment.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhAgentGroupAssignment{}
		if err := r.Get(ctx, types.NamespacedName{Name: assignment.Name, Namespace: assignment.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		assignment.Status = latest.Status
		return nil
	})
}
