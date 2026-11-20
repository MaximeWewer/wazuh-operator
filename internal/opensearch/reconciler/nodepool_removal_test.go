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
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// TestRemovedNodePoolIsDrainedBeforeDeletion asserts a nodePool removed from the spec keeps
// running while the remaining pools could not take its data, then is drained, scaled down
// and only deleted once its pods are gone.
func TestRemovedNodePoolIsDrainedBeforeDeletion(t *testing.T) {
	ctx := context.Background()
	fos := &fakeOpenSearch{
		health: "green",
		nodes: []api.ClusterNode{
			{Name: "c-indexer-hot-0", Role: "dm", ClusterManager: "*"},
			{Name: "c-indexer-warm-0", Role: "dm"}, {Name: "c-indexer-warm-1", Role: "dm"}, {Name: "c-indexer-warm-2", Role: "dm"},
		},
		shards: map[string]int{"c-indexer-hot-0": 4, "c-indexer-warm-0": 2}, shardBytes: 1 << 30,
	}
	cluster := poolsCluster("1Gi") // 3 x 1Gi left for 6Gi of data
	cluster.Spec.Indexer.NodePools[0].Name = "warm"
	cluster.Spec.Indexer.NodePools[0].Replicas = 3
	r := migrationTestReconciler(t, fos, indexerStatefulSet("c-indexer-hot", 1, "hot"), indexerStatefulSet("c-indexer-warm", 3, "warm"))
	hot := func() *appsv1.StatefulSet {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: "c-indexer-hot", Namespace: "ns"}, sts); err != nil {
			return nil
		}
		return sts
	}
	cleanup := func() {
		t.Helper()
		if err := r.cleanupOrphanedNodePools(ctx, cluster); err != nil {
			t.Fatal(err)
		}
	}

	cleanup()
	if len(fos.writes) > 0 || hot() == nil || *hot().Spec.Replicas != 1 {
		t.Fatalf("the removal went on without room for the data: writes %v", fos.writes)
	}

	cluster.Spec.Indexer.NodePools[0].StorageSize = "50Gi"
	cleanup()
	if fos.exclude != "c-indexer-hot-0" {
		t.Fatalf("allocation exclusion = %q", fos.exclude)
	}
	cleanup() // excludes the hot node from voting, a warm node is elected
	if !slices.Equal(fos.voting, []string{"c-indexer-hot-0"}) {
		t.Fatalf("voting exclusions = %v", fos.voting)
	}
	cleanup() // shards still on the hot node
	if *hot().Spec.Replicas != 1 {
		t.Fatal("a nodePool holding shards was scaled down")
	}

	fos.shards = map[string]int{"c-indexer-warm-0": 3, "c-indexer-warm-1": 3}
	cleanup()
	if *hot().Spec.Replicas != 0 {
		t.Fatal("the drained nodePool was not scaled down")
	}
	cleanup() // pod still terminating
	if hot() == nil {
		t.Fatal("the nodePool was deleted before its pods were gone")
	}

	sts := hot()
	sts.Status.Replicas, sts.Status.ReadyReplicas = 0, 0
	if err := r.Status().Update(ctx, sts); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if hot() != nil {
		t.Error("the drained nodePool was not deleted")
	}
	if fos.exclude != "" || len(fos.voting) > 0 {
		t.Errorf("exclusions left: allocation %q, voting %v", fos.exclude, fos.voting)
	}
}

func TestOwnedByStatefulSets(t *testing.T) {
	sets := []appsv1.StatefulSet{*indexerStatefulSet("c-indexer-hot", 2, "hot")}
	for names, want := range map[string]bool{
		"c-indexer-hot-0,c-indexer-hot-1": true,
		"c-indexer-hot-0,c-indexer-0":     false,
		"c-indexer-hot-data-0":            false,
	} {
		if got := ownedByStatefulSets(strings.Split(names, ","), sets); got != want {
			t.Errorf("ownedByStatefulSets(%s) = %v, want %v", names, got, want)
		}
	}
}
