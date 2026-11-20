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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// fakeOpenSearch is the part of the OpenSearch API a topology migration uses.
type fakeOpenSearch struct {
	mu         sync.Mutex
	health     string
	relocating int
	nodes      []api.ClusterNode
	voting     []string
	exclude    string
	shards     map[string]int // node -> shard copies
	shardBytes int64          // size of each shard copy
	replicas   int
	writes     []string // mutating calls
}

func (f *fakeOpenSearch) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.URL.Path == "/_cluster/health":
		reply(map[string]any{"status": f.health, "relocating_shards": f.relocating})
	case r.URL.Path == "/_cat/nodes":
		reply(f.nodes)
	case r.URL.Path == "/_cluster/state/metadata":
		var excl []map[string]string
		for _, n := range f.voting {
			excl = append(excl, map[string]string{"node_name": n})
		}
		reply(map[string]any{"metadata": map[string]any{"cluster_coordination": map[string]any{"voting_config_exclusions": excl}}})
	case r.URL.Path == "/_cluster/voting_config_exclusions" && r.Method == http.MethodPost:
		f.writes = append(f.writes, "vote-exclude:"+r.URL.Query().Get("node_names"))
		f.voting = append(f.voting, strings.Split(r.URL.Query().Get("node_names"), ",")...)
		// The cluster elects a cluster manager among the nodes still voting.
		for i := range f.nodes {
			f.nodes[i].ClusterManager = ""
		}
		for i := range f.nodes {
			if f.nodes[i].IsClusterManagerEligible() && !slices.Contains(f.voting, f.nodes[i].Name) {
				f.nodes[i].ClusterManager = "*"
				break
			}
		}
		reply(map[string]any{})
	case r.URL.Path == "/_cluster/voting_config_exclusions" && r.Method == http.MethodDelete:
		f.writes = append(f.writes, "vote-clear")
		f.voting = nil
		reply(map[string]any{})
	case r.URL.Path == "/_cluster/settings" && r.Method == http.MethodGet:
		transient := map[string]any{}
		if f.exclude != "" {
			transient[constants.OpenSearchAllocationExcludeNameKey] = f.exclude
		}
		reply(map[string]any{"persistent": map[string]any{}, "transient": transient})
	case r.URL.Path == "/_cluster/settings" && r.Method == http.MethodPut:
		var body struct {
			Transient map[string]any `json:"transient"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		v := body.Transient[constants.OpenSearchAllocationExcludeNameKey]
		f.exclude = ""
		if v != nil {
			f.exclude = fmt.Sprint(v)
		}
		f.writes = append(f.writes, "exclude:"+f.exclude)
		reply(map[string]any{"acknowledged": true})
	case r.URL.Path == "/_all/_settings":
		reply(map[string]any{"wazuh-alerts": map[string]any{"settings": map[string]any{"index": map[string]any{
			"number_of_replicas": fmt.Sprint(f.replicas)}}}})
	case r.URL.Path == "/_cat/shards":
		var rows []map[string]string
		for node, n := range f.shards {
			for range n {
				rows = append(rows, map[string]string{"node": node, "store": fmt.Sprint(f.shardBytes)})
			}
		}
		reply(rows)
	default:
		http.NotFound(w, r)
	}
}

func migrationTestReconciler(t *testing.T, fos *fakeOpenSearch, objs ...client.Object) *IndexerReconciler {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fos.handler))
	t.Cleanup(srv.Close)
	osc, err := api.NewClient(api.ClientConfig{BaseURL: srv.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	r := NewIndexerReconciler(c, scheme)
	r.fixedOSClient = osc
	return r
}

func indexerStatefulSet(name string, replicas int32, pool string) *appsv1.StatefulSet {
	labels := map[string]string{constants.LabelInstance: "c", constants.LabelComponent: constants.ComponentIndexer}
	if pool != "" {
		labels[constants.LabelNodePool] = pool
	}
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Labels: labels},
		Spec:       appsv1.StatefulSetSpec{Replicas: new(replicas)},
		Status:     appsv1.StatefulSetStatus{Replicas: replicas, ReadyReplicas: replicas},
	}
}

func poolsCluster(storage string) *wazuhv1.WazuhCluster {
	return &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"},
		Spec: wazuhv1.WazuhClusterSpec{Indexer: &wazuhv1.WazuhIndexerClusterSpec{NodePools: []wazuhv1.IndexerNodePoolSpec{{
			Name: "hot", Replicas: 2, StorageSize: storage,
			Roles: []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleClusterManager, wazuhv1.IndexerNodeRoleData},
		}}}},
	}
}

// TestTopologyMigrationBlockedChangesNothing asserts a migration whose preflight fails (not
// enough disk on the declared data nodes) is reported and leaves the indexer untouched.
func TestTopologyMigrationBlockedChangesNothing(t *testing.T) {
	fos := &fakeOpenSearch{
		health: "green", nodes: []api.ClusterNode{{Name: "c-indexer-0", Role: "dimr", ClusterManager: "*"}},
		shards: map[string]int{"c-indexer-0": 4}, shardBytes: 1 << 30,
	}
	cluster := poolsCluster("2Gi") // 2 x 2Gi, 80% = 3.2Gi < 4Gi of data
	r := migrationTestReconciler(t, fos, indexerStatefulSet("c-indexer", 1, ""))

	res, err := r.ReconcileTopologyMigration(context.Background(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	m := cluster.Status.IndexerMigration
	if !res.SkipIndexer || m == nil || m.Phase != wazuhv1.IndexerMigrationBlocked {
		t.Fatalf("result %+v, migration %+v: want a blocked migration skipping the indexer", res, m)
	}
	if !strings.Contains(m.Message, "not enough disk") || m.From != wazuhv1.IndexerTopologySimple || m.To != wazuhv1.IndexerTopologyNodePools {
		t.Errorf("migration = %+v", m)
	}
	if len(fos.writes) > 0 {
		t.Errorf("a blocked migration changed the cluster: %v", fos.writes)
	}

	// Switching back to the simple mode drops the blocked migration.
	cluster.Spec.Indexer = &wazuhv1.WazuhIndexerClusterSpec{Replicas: 1}
	if _, err := r.ReconcileTopologyMigration(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	if cluster.Status.IndexerMigration != nil {
		t.Errorf("migration after switching back = %+v, want none", cluster.Status.IndexerMigration)
	}
}

// TestTopologyMigrationSimpleToNodePools walks a migration through its phases: the pools
// join, the simple node leaves the voting configuration and is drained, then scaled down
// and deleted, and the exclusions are lifted.
func TestTopologyMigrationSimpleToNodePools(t *testing.T) {
	ctx := context.Background()
	fos := &fakeOpenSearch{
		health: "green", nodes: []api.ClusterNode{{Name: "c-indexer-0", Role: "dimr", ClusterManager: "*"}},
		shards: map[string]int{"c-indexer-0": 4}, shardBytes: 1 << 20,
	}
	cluster := poolsCluster("10Gi")
	r := migrationTestReconciler(t, fos, indexerStatefulSet("c-indexer", 1, ""))
	step := func(want wazuhv1.IndexerMigrationPhase) {
		t.Helper()
		res, err := r.ReconcileTopologyMigration(ctx, cluster)
		if err != nil {
			t.Fatal(err)
		}
		if got := cluster.Status.IndexerMigration.Phase; got != want {
			t.Fatalf("phase = %s (%s), want %s", got, cluster.Status.IndexerMigration.Message, want)
		}
		if res.SkipIndexer {
			t.Fatalf("phase %s skips the indexer reconcile", want)
		}
	}

	step(wazuhv1.IndexerMigrationJoining)
	if !r.joinsExistingCluster(ctx, cluster, wazuhv1.IndexerTopologyNodePools, "c-indexer-hot-config") {
		t.Error("the nodePools created by the migration do not join the running cluster")
	}
	step(wazuhv1.IndexerMigrationJoining) // pools not joined yet

	fos.nodes = append(fos.nodes, api.ClusterNode{Name: "c-indexer-hot-0", Role: "dm"}, api.ClusterNode{Name: "c-indexer-hot-1", Role: "dm"})
	step(wazuhv1.IndexerMigrationTransferringClusterManager) // excludes the simple node from voting
	if !slices.Equal(fos.voting, []string{"c-indexer-0"}) {
		t.Fatalf("voting exclusions = %v", fos.voting)
	}
	step(wazuhv1.IndexerMigrationDraining) // a pool node is elected, drain starts
	if fos.exclude != "c-indexer-0" {
		t.Fatalf("allocation exclusion = %q", fos.exclude)
	}

	fos.shards = map[string]int{"c-indexer-hot-0": 2, "c-indexer-hot-1": 2}
	step(wazuhv1.IndexerMigrationRemoving)
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, types.NamespacedName{Name: "c-indexer", Namespace: "ns"}, sts); err != nil {
		t.Fatal(err)
	}
	if *sts.Spec.Replicas != 0 {
		t.Fatalf("simple-mode StatefulSet replicas = %d, want 0", *sts.Spec.Replicas)
	}

	// The pod is gone.
	sts.Status.Replicas, sts.Status.ReadyReplicas = 0, 0
	if err := r.Status().Update(ctx, sts); err != nil {
		t.Fatal(err)
	}
	step(wazuhv1.IndexerMigrationCompleted)
	if err := r.Get(ctx, types.NamespacedName{Name: "c-indexer", Namespace: "ns"}, sts); err == nil {
		t.Error("the simple-mode StatefulSet was not deleted")
	}
	if len(fos.voting) > 0 || fos.exclude != "" {
		t.Errorf("exclusions left: voting %v, allocation %q", fos.voting, fos.exclude)
	}
}

// TestTopologyMigrationReversed asserts switching back during the drain lifts the
// exclusions and migrates back to the topology declared again.
func TestTopologyMigrationReversed(t *testing.T) {
	ctx := context.Background()
	fos := &fakeOpenSearch{
		health: "green",
		nodes: []api.ClusterNode{{Name: "c-indexer-0", Role: "dimr"},
			{Name: "c-indexer-hot-0", Role: "dm", ClusterManager: "*"}, {Name: "c-indexer-hot-1", Role: "dm"}},
		voting: []string{"c-indexer-0"}, exclude: "c-indexer-0",
		shards: map[string]int{"c-indexer-0": 1, "c-indexer-hot-0": 2}, shardBytes: 1 << 20,
	}
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"},
		Spec:       wazuhv1.WazuhClusterSpec{Indexer: &wazuhv1.WazuhIndexerClusterSpec{Replicas: 1}},
		Status: wazuhv1.WazuhClusterStatus{IndexerMigration: &wazuhv1.IndexerMigrationStatus{
			From: wazuhv1.IndexerTopologySimple, To: wazuhv1.IndexerTopologyNodePools,
			Phase: wazuhv1.IndexerMigrationDraining, SourceNodes: []string{"c-indexer-0"},
		}},
	}
	r := migrationTestReconciler(t, fos, indexerStatefulSet("c-indexer", 1, ""), indexerStatefulSet("c-indexer-hot", 2, "hot"))

	if _, err := r.ReconcileTopologyMigration(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	m := cluster.Status.IndexerMigration
	if m.From != wazuhv1.IndexerTopologyNodePools || m.To != wazuhv1.IndexerTopologySimple {
		t.Fatalf("migration = %+v, want nodePools -> simple", m)
	}
	if !slices.Equal(m.SourceNodes, []string{"c-indexer-hot-0", "c-indexer-hot-1"}) {
		t.Errorf("source nodes = %v", m.SourceNodes)
	}
	if !slices.Contains(fos.writes, "vote-clear") || !slices.Contains(fos.writes, "exclude:") {
		t.Errorf("the exclusions towards the abandoned topology were not lifted: %v", fos.writes)
	}
	// The simple node already runs: it keeps its configuration (no restart).
	if r.joinsExistingCluster(ctx, cluster, wazuhv1.IndexerTopologySimple, "c-indexer-config") && m.Phase == wazuhv1.IndexerMigrationBlocked {
		t.Error("a blocked migration changes the configuration of the simple-mode nodes")
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{512: "512B", 1536: "1.5KiB", 10 << 30: "10.0GiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
