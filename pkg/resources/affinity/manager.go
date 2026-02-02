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

const (
	// DefaultTopologyKey is the default key for node labels used to define topology domains
	DefaultTopologyKey = "kubernetes.io/hostname"

	// AntiAffinityTypeRequired indicates pods MUST be scheduled on different topology domains
	AntiAffinityTypeRequired = "required"

	// AntiAffinityTypePreferred indicates scheduler PREFERS different topology domains
	AntiAffinityTypePreferred = "preferred"

	// DefaultAntiAffinityWeight is the default weight for preferred anti-affinity rules
	DefaultAntiAffinityWeight int32 = 100
)

// BuildManagerAntiAffinity creates a corev1.Affinity with podAntiAffinity rules for manager pods
// Returns nil if spec is nil or anti-affinity is disabled
func BuildManagerAntiAffinity(clusterName string, spec *v1.AntiAffinitySpec) *corev1.Affinity {
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

	// Build label selector to match manager pods
	// Manager StatefulSets use "wazuh-manager" as component label (matches pdb/manager.go pattern)
	labelSelector := &metav1.LabelSelector{
		MatchLabels: constants.SelectorLabels(clusterName, "wazuh-manager"),
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

// MergeAntiAffinity merges cluster-level anti-affinity with individual (Master/Worker) affinity
// If individualAffinity is nil, returns clusterAntiAffinity unchanged
// If clusterAntiAffinity is nil, returns individualAffinity unchanged
// When both are set:
//   - NodeAffinity: individualAffinity takes precedence
//   - PodAffinity: individualAffinity takes precedence
//   - PodAntiAffinity: rules from both are combined (cluster-level appended to individual)
func MergeAntiAffinity(clusterAntiAffinity, individualAffinity *corev1.Affinity) *corev1.Affinity {
	if individualAffinity == nil {
		return clusterAntiAffinity
	}
	if clusterAntiAffinity == nil {
		return individualAffinity
	}

	// Start with a deep copy of the individual affinity to preserve all settings
	merged := individualAffinity.DeepCopy()

	// Initialize PodAntiAffinity if needed
	if merged.PodAntiAffinity == nil {
		merged.PodAntiAffinity = &corev1.PodAntiAffinity{}
	}

	// Append cluster-level anti-affinity rules to individual rules
	if clusterAntiAffinity.PodAntiAffinity != nil {
		// Append required anti-affinity rules
		if len(clusterAntiAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			merged.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = append(
				merged.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				clusterAntiAffinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution...,
			)
		}

		// Append preferred anti-affinity rules
		if len(clusterAntiAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0 {
			merged.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				merged.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				clusterAntiAffinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution...,
			)
		}
	}

	return merged
}

// ShouldApplyAntiAffinity determines if anti-affinity should be applied for the manager
func ShouldApplyAntiAffinity(cluster *v1.WazuhCluster) bool {
	// Don't apply if manager is not configured
	if cluster.Spec.Manager == nil {
		return false
	}

	// Don't apply if anti-affinity is not configured
	if cluster.Spec.Manager.AntiAffinity == nil {
		return false
	}

	// Don't apply if explicitly disabled
	if !cluster.Spec.Manager.AntiAffinity.Enabled {
		return false
	}

	return true
}
