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

package patch

import (
	appsv1 "k8s.io/api/apps/v1"
)

// MergeStatefulSetUpdate merges mutable fields from desired into current.
// This avoids a full PUT replacement that can fail silently when server-defaulted
// immutable fields (e.g. VolumeClaimTemplates) differ from the freshly-built object.
// After calling this, update current (not desired) via the API.
func MergeStatefulSetUpdate(current, desired *appsv1.StatefulSet) {
	// Merge metadata
	current.Labels = mergeStringMaps(current.Labels, desired.Labels)
	current.Annotations = mergeStringMaps(current.Annotations, desired.Annotations)
	current.OwnerReferences = desired.OwnerReferences

	// Merge mutable spec fields
	current.Spec.Replicas = desired.Spec.Replicas
	current.Spec.Template = desired.Spec.Template
	current.Spec.UpdateStrategy = desired.Spec.UpdateStrategy
	current.Spec.MinReadySeconds = desired.Spec.MinReadySeconds
	current.Spec.PersistentVolumeClaimRetentionPolicy = desired.Spec.PersistentVolumeClaimRetentionPolicy
	current.Spec.Ordinals = desired.Spec.Ordinals

	// Immutable fields are intentionally NOT touched:
	// - Spec.Selector
	// - Spec.ServiceName
	// - Spec.VolumeClaimTemplates
	// - Spec.PodManagementPolicy
}

// MergeDeploymentUpdate merges mutable fields from desired into current.
// Same principle as MergeStatefulSetUpdate for Deployments.
func MergeDeploymentUpdate(current, desired *appsv1.Deployment) {
	// Merge metadata
	current.Labels = mergeStringMaps(current.Labels, desired.Labels)
	current.Annotations = mergeStringMaps(current.Annotations, desired.Annotations)
	current.OwnerReferences = desired.OwnerReferences

	// Merge mutable spec fields
	current.Spec.Replicas = desired.Spec.Replicas
	current.Spec.Template = desired.Spec.Template
	current.Spec.Strategy = desired.Spec.Strategy
	current.Spec.MinReadySeconds = desired.Spec.MinReadySeconds
	current.Spec.RevisionHistoryLimit = desired.Spec.RevisionHistoryLimit
	current.Spec.Paused = desired.Spec.Paused
	current.Spec.ProgressDeadlineSeconds = desired.Spec.ProgressDeadlineSeconds

	// Immutable fields are intentionally NOT touched:
	// - Spec.Selector
}

// mergeStringMaps merges desired entries into current, preserving server-added entries.
// If desired is nil, current is returned unchanged.
func mergeStringMaps(current, desired map[string]string) map[string]string {
	if desired == nil {
		return current
	}
	merged := make(map[string]string, len(current)+len(desired))
	for k, v := range current {
		merged[k] = v
	}
	for k, v := range desired {
		merged[k] = v
	}
	return merged
}
