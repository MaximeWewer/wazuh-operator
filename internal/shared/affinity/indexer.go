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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// BuildIndexerAntiAffinity creates a corev1.Affinity with podAntiAffinity rules for indexer pods
// Returns nil if spec is nil or anti-affinity is disabled
func BuildIndexerAntiAffinity(clusterName string, spec *v1.AntiAffinitySpec) *corev1.Affinity {
	if spec == nil || !spec.Enabled {
		return nil
	}

	// Determine topology key (default to hostname-level spreading)
	topologyKey := DefaultTopologyKey
	if spec.TopologyKey != "" {
		topologyKey = spec.TopologyKey
	}

	// Determine anti-affinity type (default to required/hard)
	antiAffinityType := AntiAffinityTypeRequired
	if spec.Type != "" {
		antiAffinityType = spec.Type
	}

	// Build label selector to match indexer pods
	// Indexer StatefulSets use "wazuh-indexer" as component label
	labelSelector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(clusterName, "wazuh-indexer"),
	}

	affinity := &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{},
	}

	if antiAffinityType == AntiAffinityTypeRequired {
		// Hard constraint: pods MUST be scheduled on different topology domains
		affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = []corev1.PodAffinityTerm{
			{
				LabelSelector: labelSelector,
				TopologyKey:   topologyKey,
			},
		}
	} else {
		// Soft constraint: scheduler PREFERS different topology domains
		weight := DefaultAntiAffinityWeight
		if spec.Weight > 0 && spec.Weight <= 100 {
			weight = spec.Weight
		}

		affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution = []corev1.WeightedPodAffinityTerm{
			{
				Weight: weight,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: labelSelector,
					TopologyKey:   topologyKey,
				},
			},
		}
	}

	return affinity
}

// ShouldApplyIndexerAntiAffinity determines if anti-affinity should be applied for the indexer
func ShouldApplyIndexerAntiAffinity(cluster *v1.WazuhCluster) bool {
	// Don't apply if indexer is not configured
	if cluster.Spec.Indexer == nil {
		return false
	}

	// Don't apply if anti-affinity is not configured
	if cluster.Spec.Indexer.AntiAffinity == nil {
		return false
	}

	// Don't apply if explicitly disabled
	if !cluster.Spec.Indexer.AntiAffinity.Enabled {
		return false
	}

	return true
}
