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

// Package topology lists the indexer pods of a WazuhCluster, in simple mode
// (<cluster>-indexer-N behind <cluster>-indexer-headless) and in advanced mode (one
// StatefulSet per nodePool: <cluster>-indexer-<pool>-N behind
// <cluster>-indexer-<pool>-headless).
package topology

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// IndexerPod is an indexer pod of a cluster.
type IndexerPod struct {
	Name string
	// Service is the headless Service that gives the pod its DNS name.
	Service string
	// Pool is the nodePool of the pod, "" in simple mode.
	Pool string
	// Ordinal is the pod's index in its StatefulSet.
	Ordinal int32
	// ClusterManager reports whether the pod is cluster-manager eligible.
	ClusterManager bool
}

// FQDN returns the pod's DNS name through its headless Service.
func (p IndexerPod) FQDN(namespace string) string {
	return dns.PodFQDN(p.Name, p.Service, namespace)
}

// IndexerPods returns the indexer pods of the cluster, in StatefulSet order: the pods the
// spec declares (the simple-mode pods, or each nodePool's pods in declaration order), then
// during a topology migration the pods of the topology being replaced
// (status.indexerMigration.sourceNodes). While the migration is blocked by its preflight
// checks, the declared pods are not created: only the source pods are returned.
func IndexerPods(cluster *wazuhv1.WazuhCluster) []IndexerPod {
	m := cluster.Status.IndexerMigration
	if !m.Active() {
		return DeclaredPods(cluster)
	}
	source := migrationSourcePods(cluster.Name, m)
	if m.Phase == wazuhv1.IndexerMigrationBlocked {
		return source
	}
	return append(DeclaredPods(cluster), source...)
}

// migrationSourcePods returns the pods of the topology a migration replaces.
func migrationSourcePods(clusterName string, m *wazuhv1.IndexerMigrationStatus) []IndexerPod {
	pods := make([]IndexerPod, 0, len(m.SourceNodes))
	for _, name := range m.SourceNodes {
		sts, ordinalStr, ok := strings.CutLast(name, "-")
		ordinal, err := strconv.ParseInt(ordinalStr, 10, 32)
		if !ok || err != nil {
			continue
		}
		pod := IndexerPod{Name: name, Ordinal: int32(ordinal)}
		if m.From == wazuhv1.IndexerTopologyNodePools {
			pod.Pool = strings.TrimPrefix(sts, constants.IndexerName(clusterName)+"-")
			pod.Service = constants.IndexerNodePoolHeadlessName(clusterName, pod.Pool)
		} else {
			pod.Service = constants.IndexerHeadlessName(clusterName)
			pod.ClusterManager = true
		}
		pods = append(pods, pod)
	}
	return pods
}

// DeclaredPods returns the indexer pods the cluster spec declares, without the pods of a
// topology being migrated away from.
func DeclaredPods(cluster *wazuhv1.WazuhCluster) []IndexerPod {
	spec := cluster.Spec.Indexer
	if spec == nil || !spec.IsAdvancedMode() {
		return simplePods(cluster.Name, spec.EffectiveReplicas())
	}
	var pods []IndexerPod
	for i := range spec.NodePools {
		pool := &spec.NodePools[i]
		sts := constants.IndexerNodePoolName(cluster.Name, pool.Name)
		for ordinal := range pool.Replicas {
			pods = append(pods, IndexerPod{
				Name:           fmt.Sprintf("%s-%d", sts, ordinal),
				Service:        constants.IndexerNodePoolHeadlessName(cluster.Name, pool.Name),
				Pool:           pool.Name,
				Ordinal:        ordinal,
				ClusterManager: pool.HasClusterManagerRole(),
			})
		}
	}
	return pods
}

func simplePods(clusterName string, replicas int32) []IndexerPod {
	pods := make([]IndexerPod, 0, replicas)
	for ordinal := range replicas {
		pods = append(pods, IndexerPod{
			Name:           fmt.Sprintf("%s-%d", constants.IndexerName(clusterName), ordinal),
			Service:        constants.IndexerHeadlessName(clusterName),
			Ordinal:        ordinal,
			ClusterManager: true,
		})
	}
	return pods
}

// FirstClusterManagerPod returns the first cluster-manager eligible pod (the one
// securityadmin and the operator's per-pod calls target first), and false when the spec
// declares none.
func FirstClusterManagerPod(cluster *wazuhv1.WazuhCluster) (IndexerPod, bool) {
	for _, p := range IndexerPods(cluster) {
		if p.ClusterManager {
			return p, true
		}
	}
	return IndexerPod{}, false
}

// HeadlessServices returns the headless Services the indexer pods are reached through.
func HeadlessServices(cluster *wazuhv1.WazuhCluster) []string {
	seen := map[string]bool{}
	var services []string
	for _, p := range IndexerPods(cluster) {
		if !seen[p.Service] {
			seen[p.Service] = true
			services = append(services, p.Service)
		}
	}
	if len(services) == 0 {
		services = append(services, constants.IndexerHeadlessName(cluster.Name))
	}
	return services
}

// ScaleDown is an indexer StatefulSet whose declared replicas are below its current ones:
// TargetPod, its highest-ordinal pod, is the next one removed.
type ScaleDown struct {
	StatefulSet *appsv1.StatefulSet
	Desired     int32
	Current     int32
	TargetPod   string
}

// FindScaleDown returns the indexer StatefulSet being scaled down: the simple-mode
// StatefulSet, or the first nodePool StatefulSet whose pool declares fewer replicas than it
// runs. Returns nil when none is. A StatefulSet that does not exist yet is skipped.
func FindScaleDown(ctx context.Context, c client.Reader, cluster *wazuhv1.WazuhCluster) (*ScaleDown, error) {
	type candidate struct {
		name    string
		desired int32
	}
	var candidates []candidate
	spec := cluster.Spec.Indexer
	if spec == nil || !spec.IsAdvancedMode() {
		candidates = append(candidates, candidate{constants.IndexerName(cluster.Name), spec.EffectiveReplicas()})
	} else {
		for _, pool := range spec.NodePools {
			candidates = append(candidates, candidate{constants.IndexerNodePoolName(cluster.Name, pool.Name), pool.Replicas})
		}
	}
	for _, cand := range candidates {
		sts := &appsv1.StatefulSet{}
		if err := c.Get(ctx, types.NamespacedName{Name: cand.name, Namespace: cluster.Namespace}, sts); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("failed to get indexer StatefulSet %s: %w", cand.name, err)
		}
		current := sts.Status.Replicas
		if sts.Spec.Replicas != nil {
			current = *sts.Spec.Replicas
		}
		if cand.desired < current {
			return &ScaleDown{StatefulSet: sts, Desired: cand.desired, Current: current,
				TargetPod: fmt.Sprintf("%s-%d", sts.Name, current-1)}, nil
		}
	}
	return nil, nil
}
