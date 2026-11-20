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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// cleanupOrphanedNodePools removes the nodePools no longer declared in spec.indexer.nodePools
// without losing their data: their nodes are excluded from shard allocation and from voting,
// their StatefulSets are scaled down once they hold no shard and the cluster is green, and
// their StatefulSet, headless Service and ConfigMap are deleted once their pods are gone (the
// volumes are kept). Nothing is moved while the remaining nodePools could not take the data
// (see poolRemovalFailures): the pools keep running and a warning event says why. One step per
// reconcile.
func (r *IndexerReconciler) cleanupOrphanedNodePools(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	if cluster.Status.IndexerMigration.Active() {
		return nil // a topology migration owns the exclusions
	}
	sets, err := r.sourceStatefulSets(ctx, cluster, wazuhv1.IndexerTopologyNodePools)
	if err != nil {
		return fmt.Errorf("failed to list the nodePool StatefulSets: %w", err)
	}
	var orphans []appsv1.StatefulSet
	for _, sts := range sets {
		pool := sts.Labels[constants.LabelNodePool]
		if !slices.ContainsFunc(cluster.Spec.Indexer.NodePools, func(p wazuhv1.IndexerNodePoolSpec) bool { return p.Name == pool }) {
			orphans = append(orphans, sts)
		}
	}
	if len(orphans) == 0 {
		return nil
	}

	running, scalingDown := false, true
	for _, sts := range orphans {
		if ptr.Deref(sts.Spec.Replicas, 1) > 0 {
			running, scalingDown = true, false
		}
		if sts.Status.Replicas > 0 {
			running = true
		}
	}
	if !running {
		return r.deleteOrphanedNodePools(ctx, cluster, orphans)
	}
	if scalingDown {
		logf.FromContext(ctx).Info("Waiting for the pods of the removed nodePools to stop")
		return nil
	}
	return r.drainOrphanedNodePools(ctx, cluster, orphans)
}

// drainOrphanedNodePools moves the shards and the cluster-manager role off the nodes of
// removed nodePools, then scales them down.
func (r *IndexerReconciler) drainOrphanedNodePools(ctx context.Context, cluster *wazuhv1.WazuhCluster, orphans []appsv1.StatefulSet) error {
	log := logf.FromContext(ctx)
	nodes := statefulSetPodNames(orphans)
	pools := orphanPoolNames(orphans)
	if err := r.ensureOpenSearchClient(ctx, cluster); err != nil {
		return fmt.Errorf("cannot drain the removed nodePools %v: %w", pools, err)
	}
	osc := r.osClient

	current, err := osc.GetClusterSetting(ctx, constants.OpenSearchAllocationExcludeNameKey)
	if err != nil {
		return err
	}
	want := strings.Join(nodes, ",")
	if current != want {
		if current != "" && !ownedByStatefulSets(strings.Split(current, ","), orphans) {
			r.event(cluster, corev1.EventTypeWarning, "NodePoolRemovalBlocked", fmt.Sprintf(
				"The removed nodePools %v keep running: %s is set to %q by another operation; their data is moved once it is cleared",
				pools, constants.OpenSearchAllocationExcludeNameKey, current))
			return nil
		}
		if failures := r.poolRemovalFailures(ctx, cluster); len(failures) > 0 {
			r.event(cluster, corev1.EventTypeWarning, "NodePoolRemovalBlocked", fmt.Sprintf(
				"The removed nodePools %v keep running, nothing was moved: %s", pools, strings.Join(failures, "; ")))
			return nil
		}
		if err := osc.SetAllocationExclusion(ctx, want); err != nil {
			return err
		}
		r.event(cluster, corev1.EventTypeNormal, "NodePoolDraining", fmt.Sprintf(
			"Moving the shards of the removed nodePools %v to the remaining nodes before deleting them", pools))
	}

	nodeList, err := osc.ListNodes(ctx)
	if err != nil {
		return err
	}
	excluded, err := osc.GetVotingConfigExclusions(ctx)
	if err != nil {
		return err
	}
	var toExclude []string
	elected := ""
	for _, n := range nodeList {
		if n.IsElectedClusterManager() {
			elected = n.Name
		}
		if slices.Contains(nodes, n.Name) && n.IsClusterManagerEligible() && !slices.Contains(excluded, n.Name) {
			toExclude = append(toExclude, n.Name)
		}
	}
	if len(toExclude) > 0 {
		if err := osc.AddVotingConfigExclusions(ctx, toExclude); err != nil {
			return err
		}
		log.Info("Excluded the cluster_manager nodes of the removed nodePools from voting", "nodes", toExclude)
		return nil
	}

	counts, err := osc.GetShardCountsByNode(ctx)
	if err != nil {
		return err
	}
	remaining := 0
	for _, n := range nodes {
		remaining += counts[n]
	}
	health, err := osc.GetClusterHealth(ctx)
	if err != nil {
		return err
	}
	if remaining > 0 || health.Status != constants.OpenSearchHealthGreen || health.RelocatingShards > 0 ||
		elected == "" || slices.Contains(nodes, elected) {
		log.Info("Draining the removed nodePools", "pools", pools, "shardsLeft", remaining,
			"relocating", health.RelocatingShards, "health", health.Status, "clusterManager", elected)
		if remaining > 0 && health.RelocatingShards == 0 && health.InitializingShards == 0 {
			r.event(cluster, corev1.EventTypeWarning, "NodePoolDrainStalled", fmt.Sprintf(
				"%d shard copies left on the removed nodePools %v and none is moving: check the disk space of the remaining nodes (disk watermarks), the indices' allocation filters, and GET _cluster/allocation/explain",
				remaining, pools))
		}
		return nil
	}

	for i := range orphans {
		sts := &orphans[i]
		base := sts.DeepCopy()
		sts.Spec.Replicas = ptr.To[int32](0)
		if err := r.Patch(ctx, sts, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("failed to scale %s down: %w", sts.Name, err)
		}
	}
	r.event(cluster, corev1.EventTypeNormal, "NodePoolDrained", fmt.Sprintf(
		"The removed nodePools %v hold no shard: stopping them", pools))
	return nil
}

// poolRemovalFailures returns why the declared nodePools cannot take over the data of the
// removed ones, empty when they can.
func (r *IndexerReconciler) poolRemovalFailures(ctx context.Context, cluster *wazuhv1.WazuhCluster) []string {
	osc := r.osClient
	var failures []string
	health, err := osc.GetClusterHealth(ctx)
	if err != nil {
		return []string{"cannot get the cluster health: " + err.Error()}
	}
	if health.Status != constants.OpenSearchHealthGreen || health.RelocatingShards > 0 ||
		health.InitializingShards > 0 || health.UnassignedShards > 0 {
		failures = append(failures, fmt.Sprintf(
			"the cluster must be green with no shard moving (status %s, relocating %d, initializing %d, unassigned %d)",
			health.Status, health.RelocatingShards, health.InitializingShards, health.UnassignedShards))
	}
	capacity := targetCapacity(cluster)
	if capacity.dataNodes == 0 {
		return append(failures, "the remaining nodePools have no data node")
	}
	placement, err := osc.GetIndexPlacement(ctx)
	if err != nil {
		return append(failures, "cannot get the index settings: "+err.Error())
	}
	if int32(placement.MaxReplicas)+1 > capacity.dataNodes {
		failures = append(failures, fmt.Sprintf("index %s has %d replicas, its copies need %d data nodes and the remaining nodePools have %d",
			placement.MaxReplicasIndex, placement.MaxReplicas, placement.MaxReplicas+1, capacity.dataNodes))
	}
	footprint, err := osc.GetDataFootprint(ctx)
	if err != nil {
		return append(failures, "cannot get the data size: "+err.Error())
	}
	if limit := int64(float64(capacity.totalBytes) * migrationCapacityRatio); footprint.TotalBytes > limit {
		failures = append(failures, fmt.Sprintf(
			"not enough disk: the data takes %s (replicas included), the remaining data nodes offer %s and may be filled to %d%% (%s)",
			humanBytes(footprint.TotalBytes), humanBytes(capacity.totalBytes), int(migrationCapacityRatio*100), humanBytes(limit)))
	}
	if limit := int64(float64(capacity.largestNodeBytes) * migrationCapacityRatio); footprint.LargestShardBytes > limit {
		failures = append(failures, fmt.Sprintf("the largest shard (%s) does not fit on any remaining data node (%d%% of %s)",
			humanBytes(footprint.LargestShardBytes), int(migrationCapacityRatio*100), humanBytes(capacity.largestNodeBytes)))
	}
	return failures
}

// deleteOrphanedNodePools deletes the StatefulSet, headless Service and ConfigMap of removed
// nodePools that run no pod, and lifts the exclusions set for them. Their volumes are kept.
func (r *IndexerReconciler) deleteOrphanedNodePools(ctx context.Context, cluster *wazuhv1.WazuhCluster, orphans []appsv1.StatefulSet) error {
	if err := r.ensureOpenSearchClient(ctx, cluster); err == nil {
		osc := r.osClient
		if current, err := osc.GetClusterSetting(ctx, constants.OpenSearchAllocationExcludeNameKey); err == nil &&
			current != "" && ownedByStatefulSets(strings.Split(current, ","), orphans) {
			if err := osc.ClearAllocationExclusion(ctx); err != nil {
				return err
			}
		}
		if excluded, err := osc.GetVotingConfigExclusions(ctx); err == nil &&
			len(excluded) > 0 && ownedByStatefulSets(excluded, orphans) {
			if err := osc.ClearVotingConfigExclusions(ctx); err != nil {
				return err
			}
		}
	}
	for i := range orphans {
		sts := &orphans[i]
		pool := sts.Labels[constants.LabelNodePool]
		for _, obj := range []client.Object{
			sts,
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: constants.IndexerNodePoolHeadlessName(cluster.Name, pool), Namespace: cluster.Namespace}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: constants.IndexerNodePoolConfigName(cluster.Name, pool), Namespace: cluster.Namespace}},
		} {
			if err := r.Delete(ctx, obj); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete %s: %w", obj.GetName(), err)
			}
		}
		if cluster.Status.Indexer != nil {
			delete(cluster.Status.Indexer.NodePoolStatuses, pool)
		}
		r.event(cluster, corev1.EventTypeNormal, "NodePoolDeleted", fmt.Sprintf(
			"Deleted the removed nodePool %s; the volumes (PVCs) of its nodes are kept", pool))
	}
	return nil
}

// ownedByStatefulSets reports whether every node name is a pod of one of the StatefulSets.
func ownedByStatefulSets(names []string, sets []appsv1.StatefulSet) bool {
	for _, name := range names {
		if !slices.ContainsFunc(sets, func(sts appsv1.StatefulSet) bool {
			ordinal, ok := strings.CutPrefix(name, sts.Name+"-")
			return ok && ordinal != "" && strings.Trim(ordinal, "0123456789") == ""
		}) {
			return false
		}
	}
	return true
}

func orphanPoolNames(orphans []appsv1.StatefulSet) []string {
	names := make([]string, 0, len(orphans))
	for _, sts := range orphans {
		names = append(names, sts.Labels[constants.LabelNodePool])
	}
	return names
}
