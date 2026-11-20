package config

import (
	"strings"
	"testing"
)

// TestBuildNodePoolConfigUsesCertificateDNs asserts nodePool nodes accept the same admin
// and node certificate subjects as the simple-mode nodes: with a custom certConfig the
// default DNs would reject the cluster's own certificates.
func TestBuildNodePoolConfigUsesCertificateDNs(t *testing.T) {
	yml := BuildNodePoolConfig(NodePoolConfigParams{
		ClusterName: "c", Namespace: "ns", PoolName: "hot", Roles: []string{"data"},
		AdminDN: "CN=admin,OU=SOC,O=Acme,C=FR", NodesDN: "CN=*,OU=SOC,O=Acme,C=FR",
	})
	for _, want := range []string{"CN=admin,OU=SOC,O=Acme,C=FR", "CN=*,OU=SOC,O=Acme,C=FR"} {
		if !strings.Contains(yml, want) {
			t.Errorf("nodePool opensearch.yml misses %q:\n%s", want, yml)
		}
	}
}
