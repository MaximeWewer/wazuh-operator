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
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/topology"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// An indexer topology migration replaces the indexer nodes of one topology (simple mode, or
// nodePools) by the nodes of the other one, without downtime and without copying data: the
// target nodes join the running cluster, become its cluster managers, take its shards over
// through OpenSearch shard allocation, and the source nodes are removed. Switching
// spec.indexer between replicas and nodePools starts it, in either direction; switching back
// during a migration reverses it.
//
// Nothing is changed until the preflight checks pass (healthy cluster, enough disk on the
// target data nodes, index replicas and allocation filters the target nodes can satisfy, no
// exclusion set by someone else): until then the migration is Blocked, the reasons are in
// status.indexerMigration.message and a Warning event, and the indexer resources are left as
// they are.

const (
	// migrationCapacityRatio is the share of the target data nodes' disk the data may fill:
	// under OpenSearch's default low disk watermark (85%), above which no shard is allocated
	// to a node.
	migrationCapacityRatio = 0.80
	// migrationRequeue is the reconcile interval of a running migration.
	migrationRequeue = 15 * time.Second
	// migrationBlockedRequeue is how often the preflight checks of a blocked migration run.
	migrationBlockedRequeue = 30 * time.Second
	// migrationJoinWarning is how long the target nodes may take to join before a warning.
	migrationJoinWarning = 15 * time.Minute
	// migrationStallGrace is how long the drain may move no shard before it is reported stalled.
	migrationStallGrace = 2 * time.Minute
	// maxVotingConfigExclusions is OpenSearch's default cluster.max_voting_config_exclusions.
	maxVotingConfigExclusions = 10
)

// MigrationResult tells the cluster reconcile how a topology migration affects it.
type MigrationResult struct {
	// SkipIndexer is set while the migration is blocked: the indexer resources are not
	// reconciled, so the target nodes are not created.
	SkipIndexer bool
	// RequeueAfter, when set, is when the migration needs the next reconcile.
	RequeueAfter time.Duration
}

// indexerTopology returns the topology spec.indexer declares.
func indexerTopology(cluster *wazuhv1.WazuhCluster) wazuhv1.IndexerTopology {
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.IsAdvancedMode() {
		return wazuhv1.IndexerTopologyNodePools
	}
	return wazuhv1.IndexerTopologySimple
}

func otherTopology(t wazuhv1.IndexerTopology) wazuhv1.IndexerTopology {
	if t == wazuhv1.IndexerTopologyNodePools {
		return wazuhv1.IndexerTopologySimple
	}
	return wazuhv1.IndexerTopologyNodePools
}

// joinsExistingCluster reports whether the indexer nodes configured by the ConfigMap cmName
// join the running cluster instead of bootstrapping one: nodes of the target topology of a
// started migration, and the nodes a migration created (their ConfigMap is marked), which
// keep the same configuration afterwards so the end of the migration does not restart them.
func (r *IndexerReconciler) joinsExistingCluster(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	t wazuhv1.IndexerTopology, cmName string) bool {
	m := cluster.Status.IndexerMigration
	if m.Active() && m.Phase != wazuhv1.IndexerMigrationBlocked && m.To == t {
		return true
	}
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm); err != nil {
		return false
	}
	return cm.Annotations[constants.AnnotationIndexerJoinExistingCluster] == "true"
}

// joinDiscovery returns the seed hosts of nodes joining the running cluster: theirs plus the
// cluster-wide headless Service, which resolves to every ready indexer pod of both
// topologies. Joining nodes have no cluster.initial_master_nodes.
func joinDiscovery(cluster *wazuhv1.WazuhCluster, seedHosts []string) []string {
	shared := dns.ServiceFQDN(constants.IndexerHeadlessName(cluster.Name), cluster.Namespace)
	hosts := slices.Clone(seedHosts)
	if !slices.Contains(hosts, shared) {
		hosts = append(hosts, shared)
	}
	return hosts
}

// markJoinsExistingCluster marks an opensearch.yml ConfigMap written for joining nodes.
func markJoinsExistingCluster(cm *corev1.ConfigMap) {
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	cm.Annotations[constants.AnnotationIndexerJoinExistingCluster] = "true"
}

// migrationSources returns the StatefulSets of the topology spec.indexer does not declare
// that still run, or are meant to run, indexer pods.
func (r *IndexerReconciler) migrationSources(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	target wazuhv1.IndexerTopology) ([]appsv1.StatefulSet, error) {
	all, err := r.sourceStatefulSets(ctx, cluster, otherTopology(target))
	if err != nil {
		return nil, err
	}
	var running []appsv1.StatefulSet
	for _, sts := range all {
		if ptr.Deref(sts.Spec.Replicas, 1) > 0 || sts.Status.Replicas > 0 {
			running = append(running, sts)
		}
	}
	return running, nil
}

// sourceStatefulSets returns the indexer StatefulSets of a topology, running or not.
func (r *IndexerReconciler) sourceStatefulSets(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	t wazuhv1.IndexerTopology) ([]appsv1.StatefulSet, error) {
	if t == wazuhv1.IndexerTopologySimple {
		sts := &appsv1.StatefulSet{}
		err := r.Get(ctx, types.NamespacedName{Name: constants.IndexerName(cluster.Name), Namespace: cluster.Namespace}, sts)
		if errors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return []appsv1.StatefulSet{*sts}, nil
	}
	list := &appsv1.StatefulSetList{}
	if err := r.List(ctx, list, client.InNamespace(cluster.Namespace), client.MatchingLabels{
		constants.LabelInstance:  cluster.Name,
		constants.LabelComponent: constants.ComponentIndexer,
	}); err != nil {
		return nil, err
	}
	var pools []appsv1.StatefulSet
	for _, sts := range list.Items {
		if _, ok := sts.Labels[constants.LabelNodePool]; ok {
			pools = append(pools, sts)
		}
	}
	return pools, nil
}

// statefulSetPodNames returns the pod names of StatefulSets, by ordinal.
func statefulSetPodNames(sets []appsv1.StatefulSet) []string {
	var names []string
	for _, sts := range sets {
		n := max(ptr.Deref(sts.Spec.Replicas, 1), sts.Status.Replicas)
		for i := range n {
			names = append(names, fmt.Sprintf("%s-%d", sts.Name, i))
		}
	}
	return names
}

// ReconcileTopologyMigration drives the migration of the indexer between the simple mode and
// the nodePools, one step per call. It runs before the indexer is reconciled and records its
// state in cluster.Status.IndexerMigration, which the caller persists.
func (r *IndexerReconciler) ReconcileTopologyMigration(ctx context.Context, cluster *wazuhv1.WazuhCluster) (MigrationResult, error) {
	if cluster.Spec.Indexer == nil {
		return MigrationResult{}, nil
	}
	target := indexerTopology(cluster)
	sources, err := r.migrationSources(ctx, cluster, target)
	if err != nil {
		return MigrationResult{SkipIndexer: cluster.Status.IndexerMigration.Active(), RequeueAfter: migrationRequeue},
			fmt.Errorf("failed to list the indexer StatefulSets to migrate from: %w", err)
	}

	m := cluster.Status.IndexerMigration
	if len(sources) == 0 {
		if m.Active() {
			return r.finishMigration(ctx, cluster, m)
		}
		return MigrationResult{}, nil
	}

	if !m.Active() || m.To != target {
		if m.Active() {
			// Switched back during the migration: stop moving shards and cluster managers
			// towards the abandoned topology, then migrate back to the declared one.
			if err := r.clearMigrationExclusions(ctx, cluster, m); err != nil {
				return MigrationResult{SkipIndexer: true, RequeueAfter: migrationRequeue}, err
			}
			r.event(cluster, corev1.EventTypeNormal, "IndexerMigrationReversed", fmt.Sprintf(
				"spec.indexer switched back to %s during the migration to %s: the shards and cluster managers are no longer moved, migrating back to %s",
				target, m.To, target))
		}
		now := metav1.Now()
		m = &wazuhv1.IndexerMigrationStatus{
			From: otherTopology(target), To: target, Phase: wazuhv1.IndexerMigrationBlocked,
			StartTime: &now, LastTransitionTime: &now,
		}
		cluster.Status.IndexerMigration = m
	}
	if m.Phase == wazuhv1.IndexerMigrationBlocked {
		m.SourceNodes = statefulSetPodNames(sources)
	}

	if m.Phase != wazuhv1.IndexerMigrationBlocked && m.Phase != wazuhv1.IndexerMigrationRemoving {
		if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
			return r.migrationWait(cluster, m, "Waiting for the OpenSearch API", err), nil //nolint:nilerr // reported in the status, retried
		}
	}

	// Run the steps that are already satisfied in the same reconcile.
	for range 5 {
		phase := m.Phase
		var res MigrationResult
		var err error
		switch phase {
		case wazuhv1.IndexerMigrationBlocked:
			res = r.migrationPreflight(ctx, cluster, m, sources)
		case wazuhv1.IndexerMigrationJoining:
			res = r.migrationJoin(ctx, cluster, m)
		case wazuhv1.IndexerMigrationTransferringClusterManager:
			res = r.migrationTransferClusterManager(ctx, cluster, m)
		case wazuhv1.IndexerMigrationDraining:
			res = r.migrationDrain(ctx, cluster, m)
		case wazuhv1.IndexerMigrationRemoving:
			res, err = r.migrationRemoveSources(ctx, cluster, m, sources)
		default:
			return MigrationResult{}, nil
		}
		if err != nil || m.Phase == phase || m.Phase == wazuhv1.IndexerMigrationJoining {
			// Joining needs the indexer reconcile to create the target nodes first.
			return res, err
		}
	}
	return MigrationResult{RequeueAfter: migrationRequeue}, nil
}

// migrationPreflight checks the migration can run; it starts it (Joining) when all the
// checks pass, and changes nothing otherwise.
func (r *IndexerReconciler) migrationPreflight(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus, sources []appsv1.StatefulSet) MigrationResult {
	blocked := MigrationResult{SkipIndexer: true, RequeueAfter: migrationBlockedRequeue}
	failures := r.preflightFailures(ctx, cluster, m, sources)
	if len(failures) > 0 {
		r.setMigrationMessage(cluster, m, fmt.Sprintf("Migration from %s to %s blocked, nothing was changed: %s",
			m.From, m.To, strings.Join(failures, "; ")), true)
		return blocked
	}
	r.setMigrationPhase(cluster, m, wazuhv1.IndexerMigrationJoining, fmt.Sprintf(
		"Preflight checks passed: creating the %s nodes, which join the running cluster", m.To))
	return MigrationResult{RequeueAfter: migrationRequeue}
}

// preflightFailures returns why the migration cannot start, empty when it can.
func (r *IndexerReconciler) preflightFailures(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus, sources []appsv1.StatefulSet) []string {
	var failures []string
	for _, sts := range sources {
		want := ptr.Deref(sts.Spec.Replicas, 1)
		if sts.Status.ReadyReplicas != want || sts.Status.Replicas != want {
			failures = append(failures, fmt.Sprintf("StatefulSet %s has %d/%d ready pods", sts.Name, sts.Status.ReadyReplicas, want))
		}
	}

	capacity := targetCapacity(cluster)
	if capacity.dataNodes == 0 {
		failures = append(failures, "the declared topology has no data node")
	}
	if capacity.clusterManagers == 0 {
		failures = append(failures, "the declared topology has no cluster_manager node")
	}

	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return append(failures, "OpenSearch API unreachable: "+err.Error())
	}
	osc := r.osClient
	fail := func(what string, err error) []string {
		return append(failures, fmt.Sprintf("cannot %s: %v", what, err))
	}

	health, err := osc.GetClusterHealth(ctx)
	if err != nil {
		return fail("get the cluster health", err)
	}
	if health.Status != constants.OpenSearchHealthGreen || health.RelocatingShards > 0 ||
		health.InitializingShards > 0 || health.UnassignedShards > 0 {
		failures = append(failures, fmt.Sprintf(
			"the cluster must be green with no shard moving (status %s, relocating %d, initializing %d, unassigned %d)",
			health.Status, health.RelocatingShards, health.InitializingShards, health.UnassignedShards))
	}

	nodes, err := osc.ListNodes(ctx)
	if err != nil {
		return fail("list the nodes", err)
	}
	inCluster := map[string]bool{}
	for _, n := range nodes {
		inCluster[n.Name] = true
	}
	var absent []string
	sourceManagers := 0
	for _, name := range m.SourceNodes {
		if !inCluster[name] {
			absent = append(absent, name)
		}
	}
	for _, n := range nodes {
		if slices.Contains(m.SourceNodes, n.Name) && n.IsClusterManagerEligible() {
			sourceManagers++
		}
	}
	// Target nodes already running (a migration switched back, or nodePools an older
	// operator started next to the simple mode) must be part of this cluster: nodes that
	// bootstrapped their own cluster cannot join it with their data.
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(cluster.Namespace), client.MatchingLabels{
		constants.LabelInstance: cluster.Name, constants.LabelComponent: constants.ComponentIndexer,
	}); err != nil {
		return fail("list the indexer pods", err)
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && !slices.Contains(m.SourceNodes, p.Name) && !inCluster[p.Name] {
			absent = append(absent, p.Name)
		}
	}
	if len(absent) > 0 {
		failures = append(failures, fmt.Sprintf(
			"running indexer pods are not part of the cluster the operator reaches (%s): when the %s nodes formed a separate cluster, delete their StatefulSets and volumes first",
			strings.Join(absent, ", "), m.To))
	}
	if sourceManagers > maxVotingConfigExclusions {
		failures = append(failures, fmt.Sprintf("%d cluster_manager nodes to replace, OpenSearch excludes at most %d from voting",
			sourceManagers, maxVotingConfigExclusions))
	}

	if excluded, err := osc.GetVotingConfigExclusions(ctx); err != nil {
		return fail("get the voting configuration exclusions", err)
	} else if len(excluded) > 0 {
		failures = append(failures, fmt.Sprintf("voting configuration exclusions are set (%s): clear them (DELETE _cluster/voting_config_exclusions)",
			strings.Join(excluded, ", ")))
	}
	if excluded, err := osc.GetClusterSetting(ctx, constants.OpenSearchAllocationExcludeNameKey); err != nil {
		return fail("get the allocation exclusions", err)
	} else if excluded != "" {
		failures = append(failures, fmt.Sprintf("%s is set to %q: clear it", constants.OpenSearchAllocationExcludeNameKey, excluded))
	}
	if enable, err := osc.GetClusterSetting(ctx, "cluster.routing.allocation.enable"); err != nil {
		return fail("get the allocation settings", err)
	} else if enable != "" && enable != "all" {
		failures = append(failures, fmt.Sprintf("cluster.routing.allocation.enable is %q: shards could not move", enable))
	}

	placement, err := osc.GetIndexPlacement(ctx)
	if err != nil {
		return fail("get the index settings", err)
	}
	if capacity.dataNodes > 0 && int32(placement.MaxReplicas)+1 > capacity.dataNodes {
		failures = append(failures, fmt.Sprintf("index %s has %d replicas, its copies need %d data nodes and the declared topology has %d",
			placement.MaxReplicasIndex, placement.MaxReplicas, placement.MaxReplicas+1, capacity.dataNodes))
	}
	if len(placement.FilteredIndices) > 0 {
		shown := placement.FilteredIndices[:min(5, len(placement.FilteredIndices))]
		failures = append(failures, fmt.Sprintf(
			"%d indices have index.routing.allocation.require/include filters the new nodes may not match (%s): remove the filters, or move them once the migration is done",
			len(placement.FilteredIndices), strings.Join(shown, ", ")))
	}

	footprint, err := osc.GetDataFootprint(ctx)
	if err != nil {
		return fail("get the data size", err)
	}
	if limit := int64(float64(capacity.totalBytes) * migrationCapacityRatio); capacity.dataNodes > 0 && footprint.TotalBytes > limit {
		failures = append(failures, fmt.Sprintf(
			"not enough disk: the data takes %s (replicas included), the declared data nodes offer %s and may be filled to %d%% (%s)",
			humanBytes(footprint.TotalBytes), humanBytes(capacity.totalBytes), int(migrationCapacityRatio*100), humanBytes(limit)))
	}
	if limit := int64(float64(capacity.largestNodeBytes) * migrationCapacityRatio); capacity.dataNodes > 0 && footprint.LargestShardBytes > limit {
		failures = append(failures, fmt.Sprintf("the largest shard (%s) does not fit on any declared data node (%d%% of %s)",
			humanBytes(footprint.LargestShardBytes), int(migrationCapacityRatio*100), humanBytes(capacity.largestNodeBytes)))
	}
	return failures
}

// topologyCapacity is what the declared indexer topology offers.
type topologyCapacity struct {
	dataNodes        int32
	clusterManagers  int32
	totalBytes       int64
	largestNodeBytes int64
}

// targetCapacity returns the data nodes, cluster-manager nodes and disk spec.indexer declares.
func targetCapacity(cluster *wazuhv1.WazuhCluster) topologyCapacity {
	var c topologyCapacity
	spec := cluster.Spec.Indexer
	add := func(replicas int32, size string, data, manager bool) {
		if manager {
			c.clusterManagers += replicas
		}
		if !data || replicas <= 0 {
			return
		}
		if size == "" {
			size = constants.DefaultIndexerStorageSize
		}
		q, err := resource.ParseQuantity(size)
		if err != nil {
			return
		}
		c.dataNodes += replicas
		c.totalBytes += int64(replicas) * q.Value()
		c.largestNodeBytes = max(c.largestNodeBytes, q.Value())
	}
	if !spec.IsAdvancedMode() {
		add(spec.EffectiveReplicas(), spec.StorageSize, true, true)
		return c
	}
	for i := range spec.NodePools {
		pool := &spec.NodePools[i]
		add(pool.Replicas, pool.StorageSize, pool.HasDataRole(), pool.HasClusterManagerRole())
	}
	return c
}

// migrationJoin waits for every declared node to be part of the cluster.
func (r *IndexerReconciler) migrationJoin(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus) MigrationResult {
	nodes, err := r.osClient.ListNodes(ctx)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot list the cluster nodes", err)
	}
	joined := map[string]bool{}
	for _, n := range nodes {
		joined[n.Name] = true
	}
	var missing []string
	for _, p := range topology.DeclaredPods(cluster) {
		if !joined[p.Name] {
			missing = append(missing, p.Name)
		}
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("Waiting for %d %s nodes to join the cluster: %s", len(missing), m.To, strings.Join(missing, ", "))
		late := m.LastTransitionTime != nil && time.Since(m.LastTransitionTime.Time) > migrationJoinWarning
		if late {
			msg += fmt.Sprintf(" (more than %s: check their pods and logs)", migrationJoinWarning)
		}
		r.setMigrationMessage(cluster, m, msg, late)
		return MigrationResult{RequeueAfter: migrationRequeue}
	}
	r.setMigrationPhase(cluster, m, wazuhv1.IndexerMigrationTransferringClusterManager,
		fmt.Sprintf("All the %s nodes joined: excluding the %s cluster_manager nodes from voting", m.To, m.From))
	return MigrationResult{RequeueAfter: migrationRequeue}
}

// migrationTransferClusterManager excludes the source cluster-manager nodes from voting and
// waits for a target node to be elected cluster manager, so the cluster keeps its quorum
// when the source nodes leave.
func (r *IndexerReconciler) migrationTransferClusterManager(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus) MigrationResult {
	wait := MigrationResult{RequeueAfter: migrationRequeue}
	nodes, err := r.osClient.ListNodes(ctx)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot list the cluster nodes", err)
	}
	excluded, err := r.osClient.GetVotingConfigExclusions(ctx)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot get the voting configuration exclusions", err)
	}
	var toExclude []string
	elected := ""
	for _, n := range nodes {
		if n.IsElectedClusterManager() {
			elected = n.Name
		}
		if slices.Contains(m.SourceNodes, n.Name) && n.IsClusterManagerEligible() && !slices.Contains(excluded, n.Name) {
			toExclude = append(toExclude, n.Name)
		}
	}
	if len(toExclude) > 0 {
		if err := r.osClient.AddVotingConfigExclusions(ctx, toExclude); err != nil {
			return r.migrationWait(cluster, m, "Cannot exclude the source cluster_manager nodes from voting", err)
		}
		r.setMigrationMessage(cluster, m, "Excluded from voting: "+strings.Join(toExclude, ", "), false)
		return wait
	}
	if elected == "" || slices.Contains(m.SourceNodes, elected) {
		r.setMigrationMessage(cluster, m, fmt.Sprintf("Waiting for a %s node to be elected cluster manager (now: %q)", m.To, elected), false)
		return wait
	}
	r.setMigrationPhase(cluster, m, wazuhv1.IndexerMigrationDraining, fmt.Sprintf(
		"%s is the elected cluster manager: moving the shards off the %s nodes", elected, m.From))
	return wait
}

// migrationDrain excludes the source nodes from shard allocation and waits until they hold
// no shard and the cluster is green.
func (r *IndexerReconciler) migrationDrain(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus) MigrationResult {
	wait := MigrationResult{RequeueAfter: migrationRequeue}
	osc := r.osClient
	exclusion := strings.Join(m.SourceNodes, ",")
	current, err := osc.GetClusterSetting(ctx, constants.OpenSearchAllocationExcludeNameKey)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot get the allocation exclusion", err)
	}
	if current != exclusion {
		if err := osc.SetAllocationExclusion(ctx, exclusion); err != nil {
			return r.migrationWait(cluster, m, "Cannot exclude the source nodes from shard allocation", err)
		}
	}
	counts, err := osc.GetShardCountsByNode(ctx)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot count the shards per node", err)
	}
	health, err := osc.GetClusterHealth(ctx)
	if err != nil {
		return r.migrationWait(cluster, m, "Cannot get the cluster health", err)
	}
	remaining := 0
	for _, name := range m.SourceNodes {
		remaining += counts[name]
	}
	if remaining > 0 {
		msg := fmt.Sprintf("%d shard copies left on the %s nodes (%d relocating)", remaining, m.From, health.RelocatingShards)
		stalled := health.RelocatingShards == 0 && health.InitializingShards == 0 &&
			m.LastTransitionTime != nil && time.Since(m.LastTransitionTime.Time) > migrationStallGrace
		if stalled {
			msg += ": no shard is moving, check the disk space of the target nodes (disk watermarks) and GET _cluster/allocation/explain"
		}
		r.setMigrationMessage(cluster, m, msg, stalled)
		return wait
	}
	if health.Status != constants.OpenSearchHealthGreen || health.RelocatingShards > 0 || health.InitializingShards > 0 {
		r.setMigrationMessage(cluster, m, fmt.Sprintf("The %s nodes hold no shard, waiting for a green cluster (%s)", m.From, health.Status), false)
		return wait
	}
	r.setMigrationPhase(cluster, m, wazuhv1.IndexerMigrationRemoving, fmt.Sprintf(
		"The %s nodes hold no shard: stopping them (their volumes are kept)", m.From))
	return wait
}

// migrationRemoveSources scales the drained source StatefulSets down to zero.
func (r *IndexerReconciler) migrationRemoveSources(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus, sources []appsv1.StatefulSet) (MigrationResult, error) {
	var stopping []string
	for i := range sources {
		sts := &sources[i]
		if ptr.Deref(sts.Spec.Replicas, 1) != 0 {
			base := sts.DeepCopy()
			sts.Spec.Replicas = ptr.To[int32](0)
			if err := r.Patch(ctx, sts, client.MergeFrom(base)); err != nil {
				return MigrationResult{RequeueAfter: migrationRequeue}, fmt.Errorf("failed to scale %s down: %w", sts.Name, err)
			}
		}
		stopping = append(stopping, sts.Name)
	}
	r.setMigrationMessage(cluster, m, "Stopping "+strings.Join(stopping, ", "), false)
	return MigrationResult{RequeueAfter: migrationRequeue}, nil
}

// finishMigration runs once no source pod is left: it lifts the exclusions and deletes the
// source StatefulSets (their volumes are kept) and the nodePool Services and ConfigMaps.
func (r *IndexerReconciler) finishMigration(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus) (MigrationResult, error) {
	retry := MigrationResult{RequeueAfter: migrationRequeue}
	if m.Phase == wazuhv1.IndexerMigrationBlocked {
		// The source nodes went away before anything started (e.g. scaled to zero by hand).
		cluster.Status.IndexerMigration = nil
		return MigrationResult{}, nil
	}
	if err := r.clearMigrationExclusions(ctx, cluster, m); err != nil {
		return retry, err
	}
	sets, err := r.sourceStatefulSets(ctx, cluster, m.From)
	if err != nil {
		return retry, err
	}
	for i := range sets {
		sts := &sets[i]
		if err := r.Delete(ctx, sts); err != nil && !errors.IsNotFound(err) {
			return retry, fmt.Errorf("failed to delete %s: %w", sts.Name, err)
		}
		if pool, ok := sts.Labels[constants.LabelNodePool]; ok && m.From == wazuhv1.IndexerTopologyNodePools {
			for _, obj := range []client.Object{
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: constants.IndexerNodePoolHeadlessName(cluster.Name, pool), Namespace: cluster.Namespace}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: constants.IndexerNodePoolConfigName(cluster.Name, pool), Namespace: cluster.Namespace}},
			} {
				if err := r.Delete(ctx, obj); err != nil && !errors.IsNotFound(err) {
					return retry, fmt.Errorf("failed to delete %s: %w", obj.GetName(), err)
				}
			}
			if cluster.Status.Indexer != nil {
				delete(cluster.Status.Indexer.NodePoolStatuses, pool)
			}
		}
	}
	r.setMigrationPhase(cluster, m, wazuhv1.IndexerMigrationCompleted, fmt.Sprintf(
		"Migrated from %s to %s. The volumes (PVCs) of the removed nodes are kept: delete them once their data is no longer needed",
		m.From, m.To))
	logf.FromContext(ctx).Info("Indexer topology migration completed", "from", m.From, "to", m.To)
	return MigrationResult{}, nil
}

// clearMigrationExclusions lifts the voting and allocation exclusions of a migration.
func (r *IndexerReconciler) clearMigrationExclusions(ctx context.Context, cluster *wazuhv1.WazuhCluster,
	m *wazuhv1.IndexerMigrationStatus) error {
	if m.Phase == wazuhv1.IndexerMigrationBlocked || m.Phase == wazuhv1.IndexerMigrationJoining {
		return nil // nothing excluded yet
	}
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return err
	}
	if err := r.osClient.ClearVotingConfigExclusions(ctx); err != nil {
		return err
	}
	current, err := r.osClient.GetClusterSetting(ctx, constants.OpenSearchAllocationExcludeNameKey)
	if err != nil {
		return err
	}
	if current != "" && current == strings.Join(m.SourceNodes, ",") {
		return r.osClient.ClearAllocationExclusion(ctx)
	}
	return nil
}

// setMigrationPhase moves the migration to a phase, with a Normal event.
func (r *IndexerReconciler) setMigrationPhase(cluster *wazuhv1.WazuhCluster, m *wazuhv1.IndexerMigrationStatus,
	phase wazuhv1.IndexerMigrationPhase, message string) {
	now := metav1.Now()
	m.Phase, m.Message, m.LastTransitionTime = phase, message, &now
	r.event(cluster, corev1.EventTypeNormal, "IndexerMigration"+string(phase), message)
}

// setMigrationMessage updates the migration message; a warning is also sent as an event,
// once per distinct message.
func (r *IndexerReconciler) setMigrationMessage(cluster *wazuhv1.WazuhCluster, m *wazuhv1.IndexerMigrationStatus,
	message string, warning bool) {
	if m.Message == message {
		return
	}
	m.Message = message
	if warning {
		reason := "IndexerMigrationStalled"
		if m.Phase == wazuhv1.IndexerMigrationBlocked {
			reason = "IndexerMigrationBlocked"
		}
		r.event(cluster, corev1.EventTypeWarning, reason, message)
	}
}

// migrationWait reports an OpenSearch call a step failed on; the step is retried.
func (r *IndexerReconciler) migrationWait(cluster *wazuhv1.WazuhCluster, m *wazuhv1.IndexerMigrationStatus,
	what string, err error) MigrationResult {
	r.setMigrationMessage(cluster, m, what+": "+err.Error(), false)
	return MigrationResult{RequeueAfter: migrationRequeue}
}

func (r *IndexerReconciler) event(cluster *wazuhv1.WazuhCluster, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(cluster, eventType, reason, message)
	}
}

// humanBytes formats a byte count in binary units.
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
