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
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	affinityutil "github.com/MaximeWewer/wazuh-operator/pkg/resources/affinity"
)

// TestAntiAffinityIntegration tests the anti-affinity integration with the reconciler
// These tests verify that the anti-affinity logic correctly determines when to apply rules
// and how they merge with individual affinity settings

func TestAntiAffinityIntegration_ShouldApply(t *testing.T) {
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
					},
				},
			},
			shouldApply: false,
		},
		{
			name: "manager not configured - should not apply",
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
			result := affinityutil.ShouldApplyAntiAffinity(tt.cluster)
			if result != tt.shouldApply {
				t.Errorf("ShouldApplyAntiAffinity() = %v, expected %v", result, tt.shouldApply)
			}
		})
	}
}

func TestAntiAffinityIntegration_BuildRequiredRules(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled:     true,
					Type:        "required",
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)

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

	// Verify label selector matches manager pods
	expectedLabels := constants.SelectorLabels("test-cluster", "wazuh-manager")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s", k, v, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestAntiAffinityIntegration_BuildPreferredRules(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: true,
					Type:    "preferred",
					Weight:  75,
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)

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

func TestAntiAffinityIntegration_MergeWithMasterAffinity(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
					// Master-specific affinity (node affinity)
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "node-type",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{"manager"},
											},
										},
									},
								},
							},
						},
					},
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: true,
					Type:    "required",
				},
			},
		},
	}

	// Simulate what the reconciler does
	masterAffinity := cluster.Spec.Manager.Master.Affinity

	// Build cluster-level anti-affinity
	clusterAntiAffinity := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)

	// Merge
	mergedAffinity := affinityutil.MergeAntiAffinity(clusterAntiAffinity, masterAffinity)

	if mergedAffinity == nil {
		t.Fatal("expected non-nil merged affinity")
	}

	// Verify NodeAffinity from master is preserved
	if mergedAffinity.NodeAffinity == nil {
		t.Error("expected NodeAffinity from master to be preserved")
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

func TestAntiAffinityIntegration_MergeWithWorkerAffinity(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
					// Worker-specific affinity (existing pod anti-affinity)
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									TopologyKey: "custom-topology-key",
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"custom-label": "custom-value",
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
	workerAffinity := cluster.Spec.Manager.Workers.Affinity

	// Build cluster-level anti-affinity
	clusterAntiAffinity := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)

	// Merge
	mergedAffinity := affinityutil.MergeAntiAffinity(clusterAntiAffinity, workerAffinity)

	if mergedAffinity == nil {
		t.Fatal("expected non-nil merged affinity")
	}

	// Verify PodAntiAffinity has BOTH rules (worker's custom + cluster's anti-affinity)
	if mergedAffinity.PodAntiAffinity == nil {
		t.Fatal("expected PodAntiAffinity to be set")
	}

	// Should have 2 required rules: 1 from worker + 1 from cluster
	if len(mergedAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) != 2 {
		t.Errorf("expected 2 required anti-affinity rules, got %d", len(mergedAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution))
	}

	// Verify both topology keys are present
	topologyKeys := make(map[string]bool)
	for _, rule := range mergedAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
		topologyKeys[rule.TopologyKey] = true
	}

	if !topologyKeys["custom-topology-key"] {
		t.Error("expected 'custom-topology-key' from worker affinity")
	}
	if !topologyKeys["kubernetes.io/hostname"] {
		t.Error("expected 'kubernetes.io/hostname' from cluster anti-affinity")
	}
}

func TestAntiAffinityIntegration_ZoneSpread(t *testing.T) {
	// Test zone-level spreading (common production use case)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ha-cluster",
			Namespace: "production",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled:     true,
					Type:        "required",
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}

	// Build anti-affinity
	result := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	rule := result.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]

	// Verify zone topology key
	if rule.TopologyKey != "topology.kubernetes.io/zone" {
		t.Errorf("expected topology key 'topology.kubernetes.io/zone', got '%s'", rule.TopologyKey)
	}

	// Verify label selector uses the correct cluster name
	expectedLabels := constants.SelectorLabels("ha-cluster", "wazuh-manager")
	for k, v := range expectedLabels {
		if rule.LabelSelector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s", k, v, rule.LabelSelector.MatchLabels[k])
		}
	}
}

func TestAntiAffinityIntegration_DisabledByDefault(t *testing.T) {
	// Verify that anti-affinity is disabled by default (opt-in behavior)
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				// No AntiAffinity field - should default to disabled
			},
		},
	}

	// Should not apply anti-affinity
	if affinityutil.ShouldApplyAntiAffinity(cluster) {
		t.Error("expected anti-affinity to be disabled by default")
	}

	// Building with nil spec should return nil
	result := affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)
	if result != nil {
		t.Error("expected nil result when anti-affinity is not configured")
	}
}

func TestAntiAffinityIntegration_SpecChangeTriggersUpdate(t *testing.T) {
	// Verify that changing anti-affinity spec would result in different affinity
	// This simulates what the reconciler would see when anti-affinity is enabled/changed

	clusterEnabled := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
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
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
				AntiAffinity: &wazuhv1.AntiAffinitySpec{
					Enabled: false,
				},
			},
		},
	}

	// Enabled cluster should have anti-affinity
	enabledAffinity := affinityutil.BuildManagerAntiAffinity(clusterEnabled.Name, clusterEnabled.Spec.Manager.AntiAffinity)
	if enabledAffinity == nil {
		t.Error("expected anti-affinity for enabled cluster")
	}

	// Disabled cluster should not have anti-affinity
	disabledAffinity := affinityutil.BuildManagerAntiAffinity(clusterDisabled.Name, clusterDisabled.Spec.Manager.AntiAffinity)
	if disabledAffinity != nil {
		t.Error("expected no anti-affinity for disabled cluster")
	}
}

func TestAntiAffinityIntegration_HashChangeOnAntiAffinityChange(t *testing.T) {
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
				Manager: &wazuhv1.WazuhManagerClusterSpec{
					Master: wazuhv1.WazuhMasterSpec{
						StorageSize: "10Gi",
					},
					Workers: wazuhv1.WazuhWorkerSpec{
						Replicas: int32Ptr(2),
					},
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
		cluster.Spec.Manager.AntiAffinity = tt.antiAffinity

		if affinityutil.ShouldApplyAntiAffinity(cluster) {
			affinities[i] = affinityutil.BuildManagerAntiAffinity(cluster.Name, cluster.Spec.Manager.AntiAffinity)
		}
	}

	// Verify that different anti-affinity configs produce different affinities
	// (which would result in different spec hashes)
	for i := 0; i < len(tests); i++ {
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
			// For required type, compare RequiredDuringSchedulingIgnoredDuringExecution
			// For preferred type, compare PreferredDuringSchedulingIgnoredDuringExecution

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
