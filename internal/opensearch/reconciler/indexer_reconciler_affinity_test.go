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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	affinityutil "github.com/MaximeWewer/wazuh-operator/internal/shared/affinity"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestIndexerAntiAffinityIntegration tests the anti-affinity integration with the indexer reconciler
// These tests verify that the anti-affinity logic correctly determines when to apply rules
// and how they merge with individual affinity settings

func TestIndexerAntiAffinityIntegration_ShouldApply(t *testing.T) {
	tests := []struct {
		name        string
		cluster     *wazuhv1.WazuhCluster
		shouldApply bool
	}{
		{
			name: "anti-affinity enabled - should apply",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 3,
						AntiAffinity: &wazuhv1.AntiAffinitySpec{
							Enabled: true,
						},
					},
				},
			},
			shouldApply: true,
		},
		{
			name: "anti-affinity disabled - should not apply",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 3,
						AntiAffinity: &wazuhv1.AntiAffinitySpec{
							Enabled: false,
						},
					},
				},
			},
			shouldApply: false,
		},
		{
			name: "anti-affinity not configured - should not apply",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 3,
					},
				},
			},
			shouldApply: false,
		},
		{
			name: "indexer not configured - should not apply",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
				},
			},
			shouldApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := affinityutil.ShouldApplyIndexerAntiAffinity(tt.cluster)
			if result != tt.shouldApply {
				t.Errorf("ShouldApplyIndexerAntiAffinity() = %v, expected %v", result, tt.shouldApply)
			}
		})
	}
}

func TestIndexerAntiAffinityIntegration_BuildRequiredRules(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled:     true,
					Type:        "required",
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be set")
	}

	// Verify required rules
	if len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 required rule, got %d", len(result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	// Verify topology key
	if rule.TopologyKey != "kubernetes.io/hostname" {
		t.Errorf("expected topology key 'kubernetes.io/hostname', got '%s'", rule.TopologyKey)
	}

	// Verify label selector matches indexer pods
	expectedLabels := constants.SelectorLabels("test-cluster", "wazuh-indexer")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s", k, v, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestIndexerAntiAffinityIntegration_BuildPreferredRules(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: true,
					Type:    "preferred",
					Weight:  75,
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify preferred rules
	if len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Fatalf("expected 1 preferred rule, got %d", len(result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution))
	}

	rule := result.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]

	// Verify weight
	if rule.Weight != 75 {
		t.Errorf("expected weight 75, got %d", rule.Weight)
	}
}

func TestIndexerAntiAffinityIntegration_MergeWithIndexerAffinity(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				// Indexer-specific node affinity
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{
											Key:      "node-type",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"indexer"},
										},
									},
								},
							},
						},
					},
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: true,
					Type:    "required",
				},
			},
		},
	}

	// Simulate what the reconciler does
	indexerAffinity := cluster.Spec.Indexer.Affinity

	// Build cluster-level anti-affinity
	clusterAntiAffinity := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)

	// Merge
	mergedAffinity := affinityutil.MergeAntiAffinity(clusterAntiAffinity, indexerAffinity)

	if mergedAffinity == nil {
		t.Fatal("expected non-nil merged affinity")
	}

	// Verify NodeAffinity from indexer is preserved
	if mergedAffinity.NodeAffinity == nil {
		t.Error("expected NodeAffinity from indexer to be preserved")
	} else {
		if mergedAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			t.Error("expected RequiredDuringSchedulingIgnoredDuringExecution NodeSelector to be preserved")
		}
	}

	// Verify PodAntiAffinity from cluster is added
	if mergedAffinity.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be set")
	}

	if len(mergedAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
		t.Errorf("expected 1 required anti-affinity rule, got %d", len(mergedAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}
}

func TestIndexerAntiAffinityIntegration_ZoneSpread(t *testing.T) {
	// Test zone-level spreading (common production use case)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ha-cluster",
			Namespace: "production",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled:     true,
					Type:        "required",
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	// Verify zone topology key
	if rule.TopologyKey != "topology.kubernetes.io/zone" {
		t.Errorf("expected topology key 'topology.kubernetes.io/zone', got '%s'", rule.TopologyKey)
	}

	// Verify label selector uses the correct cluster name
	expectedLabels := constants.SelectorLabels("ha-cluster", "wazuh-indexer")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s", k, v, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestIndexerAntiAffinityIntegration_DisabledByDefault(t *testing.T) {
	// Verify that anti-affinity is disabled by default (opt-in behavior)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				// No AntiAffinity field - should default to disabled
			},
		},
	}

	// Should not apply anti-affinity
	if affinityutil.ShouldApplyIndexerAntiAffinity(cluster) {
		t.Error("expected anti-affinity to be disabled by default")
	}

	// Building with nil spec should return nil
	result := affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)
	if result != nil {
		t.Error("expected nil result when anti-affinity is not configured")
	}
}

func TestIndexerAntiAffinityIntegration_SpecChangeTriggersUpdate(t *testing.T) {
	// Verify that changing anti-affinity spec would result in different affinity
	// This simulates what the reconciler would see when anti-affinity is enabled/changed

	clusterEnabled := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: true,
					Type:    "required",
				},
			},
		},
	}

	clusterDisabled := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: false,
				},
			},
		},
	}

	// Enabled cluster should have anti-affinity
	enabledAffinity := affinityutil.BuildIndexerAntiAffinity(clusterEnabled.Name, clusterEnabled.Spec.Indexer.AntiAffinity)
	if enabledAffinity == nil {
		t.Error("expected anti-affinity for enabled cluster")
	}

	// Disabled cluster should not have anti-affinity
	disabledAffinity := affinityutil.BuildIndexerAntiAffinity(clusterDisabled.Name, clusterDisabled.Spec.Indexer.AntiAffinity)
	if disabledAffinity != nil {
		t.Error("expected no anti-affinity for disabled cluster")
	}
}

func TestIndexerAntiAffinityIntegration_HashChangeOnAntiAffinityChange(t *testing.T) {
	// Test that changing anti-affinity configuration produces different merged affinity
	// which would result in different spec hash and trigger StatefulSet update

	baseCluster := func() *wazuhv1.WazuhCluster {
		return &wazuhv1.WazuhCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster",
				Namespace: "default",
			},
			Spec: wazuhv1.WazuhClusterSpec{
				Version: "4.9.0",
				Indexer: &wazuhv1.WazuhIndexerClusterSpec{
					Replicas: 3,
				},
			},
		}
	}

	tests := []struct {
		name         string
		antiAffinity *wazuhv1.AntiAffinitySpec
	}{
		{
			name:         "no anti-affinity",
			antiAffinity: nil,
		},
		{
			name: "required anti-affinity",
			antiAffinity: &wazuhv1.AntiAffinitySpec{
				Enabled: true,
				Type:    "required",
			},
		},
		{
			name: "preferred anti-affinity weight 50",
			antiAffinity: &wazuhv1.AntiAffinitySpec{
				Enabled: true,
				Type:    "preferred",
				Weight:  50,
			},
		},
		{
			name: "preferred anti-affinity weight 100",
			antiAffinity: &wazuhv1.AntiAffinitySpec{
				Enabled: true,
				Type:    "preferred",
				Weight:  100,
			},
		},
		{
			name: "zone topology key",
			antiAffinity: &wazuhv1.AntiAffinitySpec{
				Enabled:     true,
				Type:        "required",
				TopologyKey: "topology.kubernetes.io/zone",
			},
		},
	}

	// Build affinity for each configuration
	affinities := make([]*corev1.Affinity, len(tests))
	for i, tt := range tests {
		cluster := baseCluster()
		cluster.Spec.Indexer.AntiAffinity = tt.antiAffinity

		if affinityutil.ShouldApplyIndexerAntiAffinity(cluster) {
			affinities[i] = affinityutil.BuildIndexerAntiAffinity(cluster.Name, cluster.Spec.Indexer.AntiAffinity)
		}
	}

	// Verify that different anti-affinity configs produce different affinities
	for i := range tests {
		for j := i + 1; j < len(tests); j++ {
			// If both are nil, they're equal (both disabled)
			if affinities[i] == nil && affinities[j] == nil {
				continue
			}

			// If one is nil and other is not, they're different
			if (affinities[i] == nil) != (affinities[j] == nil) {
				continue // Different, as expected
			}

			// Both non-nil - compare the actual rules
			affI := affinities[i].PodAntiAffinity
			affJ := affinities[j].PodAntiAffinity

			// Check required rules
			reqI := len(affI.RequiredDuringSchedulingIgnoredDuringExecution)
			reqJ := len(affJ.RequiredDuringSchedulingIgnoredDuringExecution)

			// Check preferred rules
			prefI := len(affI.PreferredDuringSchedulingIgnoredDuringExecution)
			prefJ := len(affJ.PreferredDuringSchedulingIgnoredDuringExecution)

			// Different rule types = different configs
			if reqI != reqJ || prefI != prefJ {
				continue // Different, as expected
			}

			// Same rule type - check topology key or weight differences
			if reqI > 0 {
				topoI := affI.RequiredDuringSchedulingIgnoredDuringExecution[0].TopologyKey
				topoJ := affJ.RequiredDuringSchedulingIgnoredDuringExecution[0].TopologyKey
				if topoI != topoJ {
					continue // Different, as expected
				}
			}

			if prefI > 0 {
				weightI := affI.PreferredDuringSchedulingIgnoredDuringExecution[0].Weight
				weightJ := affJ.PreferredDuringSchedulingIgnoredDuringExecution[0].Weight
				if weightI != weightJ {
					continue // Different, as expected
				}

				topoI := affI.PreferredDuringSchedulingIgnoredDuringExecution[0].PodAffinityTerm.TopologyKey
				topoJ := affJ.PreferredDuringSchedulingIgnoredDuringExecution[0].PodAffinityTerm.TopologyKey
				if topoI != topoJ {
					continue // Different, as expected
				}
			}

			// If we get here, the two configs produced identical affinities (unexpected)
			t.Errorf("configs %q and %q produced identical affinities, but should be different", tests[i].name, tests[j].name)
		}
	}
}
