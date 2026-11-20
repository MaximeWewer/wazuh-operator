package v1

import "testing"

// TestIndexerEffectiveReplicas asserts an unset replicas means DefaultIndexerReplicas in
// simple mode, whether or not the optional mutating webhook defaulted it, and nothing in
// advanced mode, where the node count comes from the nodePools.
func TestIndexerEffectiveReplicas(t *testing.T) {
	for name, tc := range map[string]struct {
		spec          *WazuhIndexerClusterSpec
		wantEffective int32
		wantTotal     int32
		wantSimple    bool
	}{
		"unset":            {spec: &WazuhIndexerClusterSpec{}, wantEffective: 3, wantTotal: 3, wantSimple: true},
		"set":              {spec: &WazuhIndexerClusterSpec{Replicas: 1}, wantEffective: 1, wantTotal: 1, wantSimple: true},
		"nil spec":         {spec: nil, wantEffective: 3},
		"node pools":       {spec: &WazuhIndexerClusterSpec{NodePools: []IndexerNodePoolSpec{{Name: "hot", Replicas: 2}, {Name: "warm", Replicas: 1}}}, wantEffective: 0, wantTotal: 3},
		"pools + replicas": {spec: &WazuhIndexerClusterSpec{Replicas: 3, NodePools: []IndexerNodePoolSpec{{Name: "hot", Replicas: 1}}}, wantEffective: 0, wantTotal: 1},
	} {
		if got := tc.spec.EffectiveReplicas(); got != tc.wantEffective {
			t.Errorf("%s: EffectiveReplicas() = %d, want %d", name, got, tc.wantEffective)
		}
		if tc.spec == nil {
			continue
		}
		if got := tc.spec.GetTotalReplicas(); got != tc.wantTotal {
			t.Errorf("%s: GetTotalReplicas() = %d, want %d", name, got, tc.wantTotal)
		}
		if got := tc.spec.IsSimpleMode(); got != tc.wantSimple {
			t.Errorf("%s: IsSimpleMode() = %v, want %v", name, got, tc.wantSimple)
		}
	}
}
