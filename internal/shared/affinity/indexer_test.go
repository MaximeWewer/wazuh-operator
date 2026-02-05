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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestBuildIndexerAntiAffinity_Nil(t *testing.T) {
	result := BuildIndexerAntiAffinity("test-cluster", nil)
	if result != nil {
		t.Error("expected nil result for nil spec")
	}
}

func TestBuildIndexerAntiAffinity_Disabled(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: false,
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)
	if result != nil {
		t.Error("expected nil result for disabled anti-affinity")
	}
}

func TestBuildIndexerAntiAffinity_Required_Default(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be set")
	}

	// Should use required by default
	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	// Should use default topology key
	if rule.TopologyKey != DefaultTopologyKey {
		t.Errorf("expected topology key '%s', got '%s'", DefaultTopologyKey, rule.TopologyKey)
	}

	// Verify label selector matches indexer pods
	expectedLabels := constants.SelectorLabels("test-cluster", "wazuh-indexer")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s", k, v, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestBuildIndexerAntiAffinity_Required_ExplicitType(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypeRequired,
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 0 {
		t.Error("expected no preferred rules for required type")
	}
}

func TestBuildIndexerAntiAffinity_Preferred_DefaultWeight(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 preferred rule, got %d", len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	// Should use default weight
	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected weight %d, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}
}

func TestBuildIndexerAntiAffinity_Preferred_CustomWeight(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  50,
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	if rule.Weight != 50 {
		t.Errorf("expected weight 50, got %d", rule.Weight)
	}
}

func TestBuildIndexerAntiAffinity_CustomTopologyKey(t *testing.T) {
	spec := &v1.AntiAffinitySpec{
		Enabled:     true,
		TopologyKey: "topology.kubernetes.io/zone",
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	if rule.TopologyKey != "topology.kubernetes.io/zone" {
		t.Errorf("expected topology key 'topology.kubernetes.io/zone', got '%s'", rule.TopologyKey)
	}
}

func TestShouldApplyIndexerAntiAffinity(t *testing.T) {
	tests := []struct {
		name        string
		cluster     *v1.WazuhCluster
		shouldApply bool
	}{
		{
			name: "anti-affinity enabled",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: v1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
						AntiAffinity: &v1.AntiAffinitySpec{
							Enabled: true,
						},
					},
				},
			},
			shouldApply: true,
		},
		{
			name: "anti-affinity disabled",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: v1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
						AntiAffinity: &v1.AntiAffinitySpec{
							Enabled: false,
						},
					},
				},
			},
			shouldApply: false,
		},
		{
			name: "anti-affinity not configured",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: v1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
					},
				},
			},
			shouldApply: false,
		},
		{
			name: "indexer not configured",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: v1.WazuhClusterSpec{
					Version: "4.9.0",
				},
			},
			shouldApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldApplyIndexerAntiAffinity(tt.cluster)
			if result != tt.shouldApply {
				t.Errorf("ShouldApplyIndexerAntiAffinity() = %v, expected %v", result, tt.shouldApply)
			}
		})
	}
}

func TestBuildIndexerAntiAffinity_InvalidWeight(t *testing.T) {
	// Test that invalid weight (0) uses default
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  0, // Invalid, should use default
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected default weight %d for invalid weight 0, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}
}

func TestBuildIndexerAntiAffinity_InvalidWeightOver100(t *testing.T) {
	// Test that invalid weight (>100) uses default
	spec := &v1.AntiAffinitySpec{
		Enabled: true,
		Type:    AntiAffinityTypePreferred,
		Weight:  150, // Invalid, should use default
	}
	result := BuildIndexerAntiAffinity("test-cluster", spec)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
	if rule.Weight != DefaultAntiAffinityWeight {
		t.Errorf("expected default weight %d for invalid weight 150, got %d", DefaultAntiAffinityWeight, rule.Weight)
	}
}
