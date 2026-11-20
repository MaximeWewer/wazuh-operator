package sans

import (
	"os"
	"slices"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// TestGenerateIndexerSANsNodePools asserts the indexer certificate covers the pods of each
// nodePool and their headless Services, which the operator connects to pod by pod.
func TestGenerateIndexerSANsNodePools(t *testing.T) {
	got := GenerateIndexerSANs("c", "ns", []IndexerNode{
		{Pod: "c-indexer-hot-0", Service: "c-indexer-hot-headless"},
		{Pod: "c-indexer-warm-0", Service: "c-indexer-warm-headless"},
	})
	for _, want := range []string{
		"c-indexer.ns.svc.cluster.local",
		"*.c-indexer-headless.ns.svc.cluster.local",
		"*.c-indexer-hot-headless.ns.svc.cluster.local",
		"*.c-indexer-warm-headless.ns.svc.cluster.local",
		"c-indexer-hot-0", "c-indexer-hot-0.c-indexer-hot-headless.ns.svc.cluster.local",
		"c-indexer-warm-0.c-indexer-warm-headless.ns.svc.cluster.local",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("SANs miss %q: %v", want, got)
		}
	}
	// The simple-mode SANs are unchanged.
	simple := GenerateIndexerNodeSANs("c", "ns", 2)
	if !slices.Contains(simple, "c-indexer-1.c-indexer-headless.ns.svc.cluster.local") || len(simple) != 10 {
		t.Errorf("simple-mode SANs = %v", simple)
	}
}

func TestMain(m *testing.M) {
	if err := dns.InitializeWithDomain("cluster.local"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
