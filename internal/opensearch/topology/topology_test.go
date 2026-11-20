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

package topology

import (
	"os"
	"reflect"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestIndexerPods(t *testing.T) {
	cluster := func(indexer *wazuhv1.WazuhIndexerClusterSpec) *wazuhv1.WazuhCluster {
		return &wazuhv1.WazuhCluster{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"}, Spec: wazuhv1.WazuhClusterSpec{Indexer: indexer}}
	}
	names := func(pods []IndexerPod) []string {
		var n []string
		for _, p := range pods {
			n = append(n, p.Name+"@"+p.Service)
		}
		return n
	}

	if got := names(IndexerPods(cluster(&wazuhv1.WazuhIndexerClusterSpec{Replicas: 2}))); !reflect.DeepEqual(got,
		[]string{"c-indexer-0@c-indexer-headless", "c-indexer-1@c-indexer-headless"}) {
		t.Errorf("simple mode pods = %v", got)
	}
	if got := len(IndexerPods(cluster(&wazuhv1.WazuhIndexerClusterSpec{}))); got != 3 {
		t.Errorf("unset replicas: %d pods, want the default 3", got)
	}

	pools := cluster(&wazuhv1.WazuhIndexerClusterSpec{NodePools: []wazuhv1.IndexerNodePoolSpec{
		{Name: "hot", Replicas: 2, Roles: []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleClusterManager, wazuhv1.IndexerNodeRoleData}},
		{Name: "warm", Replicas: 1, Roles: []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleData}},
	}})
	want := []string{"c-indexer-hot-0@c-indexer-hot-headless", "c-indexer-hot-1@c-indexer-hot-headless", "c-indexer-warm-0@c-indexer-warm-headless"}
	if got := names(IndexerPods(pools)); !reflect.DeepEqual(got, want) {
		t.Errorf("node pool pods = %v, want %v", got, want)
	}
	if got := IndexerPods(pools)[2].FQDN("ns"); got != "c-indexer-warm-0.c-indexer-warm-headless.ns.svc.cluster.local" {
		t.Errorf("FQDN = %q", got)
	}
	if p, ok := FirstClusterManagerPod(pools); !ok || p.Name != "c-indexer-hot-0" {
		t.Errorf("FirstClusterManagerPod = %v, %v", p, ok)
	}
	if got := HeadlessServices(pools); !reflect.DeepEqual(got, []string{"c-indexer-hot-headless", "c-indexer-warm-headless"}) {
		t.Errorf("HeadlessServices = %v", got)
	}
}

func TestMain(m *testing.M) {
	if err := dns.InitializeWithDomain("cluster.local"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
