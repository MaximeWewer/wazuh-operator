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

package affinity

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func int32Ptr(i int32) *int32 {
	return new(i)
}

func TestBuildManagerAntiAffinity_Nil(t *testing.T) {
	// Test with nil spec
	result := BuildManagerAntiAffinity("test-cluster", nil)
	if result != nil {
		t.Error("expected nil result for nil spec")
	}
}

func TestBuildManagerAntiAffinity_Disabled(t *testing.T) {
	// Test with disabled anti-affinity
	spec := &v1.AntiAffinitySpec{
		Enabled: false,
	}
	result := BuildManagerAntiAffinity("test-cluster", spec)
	if result != nil {
		t.Error("expected nil result when anti-affinity is disabled")
	}
}

func TestBuildManagerAntiAffinity_Required_Default(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		// Type defaults to "required"
		// TopologyKey defaults to "kubernetes.io/hostname"
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be set")
	}

	// Required should have RequiredDuringSchedulingIgnoredDuringExecution
	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	// Should NOT have preferred rules
	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 0 {
		t.Errorf("expected 0 preferred rules, got %d", len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	// Verify topology key is default
	if rule.TopologyKey != DefaultTopologyKey {
		t.Errorf("expected topology key '%s', got '%s'", DefaultTopologyKey, rule.TopologyKey)
	}

	// Verify label selector
	if rule.LabelSelector == nil {
		t.Fatal("expected label selector to be set")
	}

	expectedLabels := constants.SelectorLabels("test-cluster", "wazuh-manager")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s=%s", k, v, k, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestBuildManagerAntiAffinity_Required_ExplicitType(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypeRequired,
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}
}

func TestBuildManagerAntiAffinity_Preferred_DefaultWeight(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		// Weight defaults to 100
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Should NOT have required rules
	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 0 {
		t.Errorf("expected 0 required rules, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	// Preferred should have PreferredDuringSchedulingIgnoredDuringExecution
	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 preferred rule, got %d", len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	// Verify default weight
	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected weight %d, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}

	// Verify topology key
	if rule.PodAffinityTerm.TopologyKey != DefaultTopologyKey {
		t.Errorf("expected topology key '%s', got '%s'", DefaultTopologyKey, rule.PodAffinityTerm.TopologyKey)
	}
}

func TestBuildManagerAntiAffinity_Preferred_CustomWeight(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  50,
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	if rule.Weight != 50 {
		t.Errorf("expected weight 50, got %d", rule.Weight)
	}
}

func TestBuildManagerAntiAffinity_CustomTopologyKey(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled:     true,
		TopologyKey: "topology.kubernetes.io/zone",
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	if rule.TopologyKey != "topology.kubernetes.io/zone" {
		t.Errorf("expected topology key 'topology.kubernetes.io/zone', got '%s'", rule.TopologyKey)
	}
}

func TestMergeAntiAffinity_BothNil(t *testing.T) {
	result := MergeAntiAffinity(nil, nil)
	if result != nil {
		t.Error("expected nil result when both inputs are nil")
	}
}

func TestMergeAntiAffinity_IndividualNil(t *testing.T) {
	clusterAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "kubernetes.io/hostname"},
			},
		},
	}

	result := MergeAntiAffinity(clusterAffinity, nil)

	if result != clusterAffinity {
		t.Error("expected cluster affinity to be returned when individual is nil")
	}
}

func TestMergeAntiAffinity_ClusterNil(t *testing.T) {
	individualAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "node-type", Operator: corev1.NodeSelectorOpIn, Values: []string{"manager"}},
						},
					},
				},
			},
		},
	}

	result := MergeAntiAffinity(nil, individualAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// NodeAffinity should be preserved
	if result.NodeAffinity == nil {
		t.Error("expected NodeAffinity to be preserved")
	}
}

func TestMergeAntiAffinity_BothSet_Required(t *testing.T) {
	clusterAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "kubernetes.io/hostname"},
			},
		},
	}

	individualAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "node-type", Operator: corev1.NodeSelectorOpIn, Values: []string{"manager"}},
						},
					},
				},
			},
		},
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "custom-key"},
			},
		},
	}

	result := MergeAntiAffinity(clusterAffinity, individualAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// NodeAffinity should be preserved from individual
	if result.NodeAffinity == nil {
		t.Error("expected NodeAffinity to be preserved from individual")
	}

	// Should have 2 required anti-affinity rules (1 from individual + 1 from cluster)
	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 2 {
		t.Errorf("expected 2 required rules, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	// Verify both topology keys are present
	topologyKeys := make(map[string]bool)
	for _, rule := range result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
		topologyKeys[rule.TopologyKey] = true
	}

	if !topologyKeys["custom-key"] {
		t.Error("expected 'custom-key' topology key from individual affinity")
	}
	if !topologyKeys["kubernetes.io/hostname"] {
		t.Error("expected 'kubernetes.io/hostname' topology key from cluster affinity")
	}
}

func TestMergeAntiAffinity_BothSet_Preferred(t *testing.T) {
	clusterAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{Weight: 100, PodAffinityTerm: corev1.PodAffinityTerm{TopologyKey: "kubernetes.io/hostname"}},
			},
		},
	}

	individualAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{Weight: 50, PodAffinityTerm: corev1.PodAffinityTerm{TopologyKey: "topology.kubernetes.io/zone"}},
			},
		},
	}

	result := MergeAntiAffinity(clusterAffinity, individualAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Should have 2 preferred anti-affinity rules
	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 2 {
		t.Errorf("expected 2 preferred rules, got %d", len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution))
	}
}

func TestMergeAntiAffinity_IndividualHasNoPodAntiAffinity(t *testing.T) {
	clusterAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "kubernetes.io/hostname"},
			},
		},
	}

	individualAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "node-type", Operator: corev1.NodeSelectorOpIn, Values: []string{"manager"}},
						},
					},
				},
			},
		},
		// No PodAntiAffinity
	}

	result := MergeAntiAffinity(clusterAffinity, individualAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// PodAntiAffinity should be created and have cluster rules
	if result.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be created")
	}

	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Errorf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	// NodeAffinity should be preserved
	if result.NodeAffinity == nil {
		t.Error("expected NodeAffinity to be preserved")
	}
}

func TestShouldApplyAntiAffinity(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *v1.WazuhCluster
		expectedResult bool
	}{
		{
			name: "anti-affinity enabled",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
						AntiAffinity: &v1.AntiAffinitySpec{
							Enabled: true,
						},
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "anti-affinity disabled",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
						AntiAffinity: &v1.AntiAffinitySpec{
							Enabled: false,
						},
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "anti-affinity not configured",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
						// AntiAffinity is nil
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "manager not configured",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					// Manager is nil
				},
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldApplyAntiAffinity(tt.cluster)
			if result != tt.expectedResult {
				t.Errorf("ShouldApplyAntiAffinity() = %v, expected %v", result, tt.expectedResult)
			}
		})
	}
}

func TestBuildManagerAntiAffinity_InvalidWeight(t *testing.T) {
	// Test that invalid weight (0) uses default
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  0, // Invalid, should use default
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected default weight %d for invalid input, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}
}

func TestBuildManagerAntiAffinity_InvalidWeightOver100(t *testing.T) {
	// Test that weight > 100 uses default
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  150, // Invalid, should use default
	}

	result := BuildManagerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected default weight %d for invalid input, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}
}

func TestMergeAntiAffinity_DoesNotMutateOriginal(t *testing.T) {
	individualAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "original"},
			},
		},
	}

	clusterAffinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "cluster"},
			},
		},
	}

	// Store original count
	originalCount := len(individualAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution)

	// Merge
	_ = MergeAntiAffinity(clusterAffinity, individualAffinity)

	// Verify original is not mutated
	if len(individualAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != originalCount {
		t.Error("original affinity was mutated by merge operation")
	}
}
