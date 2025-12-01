/*
Copyright 2025.

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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
)

// CheckStatefulSetImmutableFields verifies that immutable fields haven't changed
// Returns an error if any immutable field change is detected
func CheckStatefulSetImmutableFields(current, desired *appsv1.StatefulSet) error {
	// Check selector (immutable after creation)
	if current.Spec.Selector != nil && desired.Spec.Selector != nil {
		if !equality.Semantic.DeepEqual(current.Spec.Selector, desired.Spec.Selector) {
			return NewImmutableFieldError(
				"spec.selector",
				"StatefulSet",
				current.Name,
				fmt.Sprintf("%v", current.Spec.Selector.MatchLabels),
				fmt.Sprintf("%v", desired.Spec.Selector.MatchLabels),
			)
		}
	}

	// Check serviceName (immutable after creation)
	if current.Spec.ServiceName != desired.Spec.ServiceName {
		return NewImmutableFieldError(
			"spec.serviceName",
			"StatefulSet",
			current.Name,
			current.Spec.ServiceName,
			desired.Spec.ServiceName,
		)
	}

	// Check VolumeClaimTemplates - can only add new ones, not modify existing
	if err := checkVolumeClaimTemplates(current, desired); err != nil {
		return err
	}

	return nil
}

// checkVolumeClaimTemplates verifies VolumeClaimTemplate changes are valid
func checkVolumeClaimTemplates(current, desired *appsv1.StatefulSet) error {
	currentVCTs := current.Spec.VolumeClaimTemplates
	desiredVCTs := desired.Spec.VolumeClaimTemplates

	// Build map of current VCTs by name
	currentMap := make(map[string]int)
	for i, vct := range currentVCTs {
		currentMap[vct.Name] = i
	}

	// Check each desired VCT
	for _, desiredVCT := range desiredVCTs {
		if idx, exists := currentMap[desiredVCT.Name]; exists {
			currentVCT := currentVCTs[idx]

			// Storage size can only be increased (if StorageClass allows)
			// But for simplicity, we'll warn if it changes at all since
			// most storage classes don't support resize
			currentStorage := currentVCT.Spec.Resources.Requests.Storage()
			desiredStorage := desiredVCT.Spec.Resources.Requests.Storage()

			if currentStorage != nil && desiredStorage != nil {
				if currentStorage.Cmp(*desiredStorage) != 0 {
					return NewImmutableFieldError(
						fmt.Sprintf("spec.volumeClaimTemplates[%s].resources.requests.storage", desiredVCT.Name),
						"StatefulSet",
						current.Name,
						currentStorage.String(),
						desiredStorage.String(),
					)
				}
			}

			// StorageClassName is immutable
			if currentVCT.Spec.StorageClassName != nil && desiredVCT.Spec.StorageClassName != nil {
				if *currentVCT.Spec.StorageClassName != *desiredVCT.Spec.StorageClassName {
					return NewImmutableFieldError(
						fmt.Sprintf("spec.volumeClaimTemplates[%s].storageClassName", desiredVCT.Name),
						"StatefulSet",
						current.Name,
						*currentVCT.Spec.StorageClassName,
						*desiredVCT.Spec.StorageClassName,
					)
				}
			}

			// AccessModes are immutable
			if !equality.Semantic.DeepEqual(currentVCT.Spec.AccessModes, desiredVCT.Spec.AccessModes) {
				return NewImmutableFieldError(
					fmt.Sprintf("spec.volumeClaimTemplates[%s].accessModes", desiredVCT.Name),
					"StatefulSet",
					current.Name,
					fmt.Sprintf("%v", currentVCT.Spec.AccessModes),
					fmt.Sprintf("%v", desiredVCT.Spec.AccessModes),
				)
			}
		}
		// New VCTs are allowed (will create new PVCs for existing pods on next restart)
	}

	// Removing VCTs is not allowed (would orphan PVCs)
	for _, currentVCT := range currentVCTs {
		found := false
		for _, desiredVCT := range desiredVCTs {
			if desiredVCT.Name == currentVCT.Name {
				found = true
				break
			}
		}
		if !found {
			return NewImmutableFieldError(
				fmt.Sprintf("spec.volumeClaimTemplates[%s]", currentVCT.Name),
				"StatefulSet",
				current.Name,
				currentVCT.Name,
				"<removed>",
			)
		}
	}

	return nil
}

// CheckDeploymentImmutableFields verifies that immutable fields haven't changed
// Deployments have fewer immutable fields than StatefulSets
func CheckDeploymentImmutableFields(current, desired *appsv1.Deployment) error {
	// Check selector (immutable after creation, but Deployments are more flexible)
	// Kubernetes allows selector changes if the new selector matches existing pods
	// For safety, we still check for changes
	if current.Spec.Selector != nil && desired.Spec.Selector != nil {
		if !equality.Semantic.DeepEqual(current.Spec.Selector, desired.Spec.Selector) {
			return NewImmutableFieldError(
				"spec.selector",
				"Deployment",
				current.Name,
				fmt.Sprintf("%v", current.Spec.Selector.MatchLabels),
				fmt.Sprintf("%v", desired.Spec.Selector.MatchLabels),
			)
		}
	}

	return nil
}

// CanUpdateStatefulSet checks if a StatefulSet can be updated without recreation
// Returns true if safe to update, false if recreation is required
func CanUpdateStatefulSet(current, desired *appsv1.StatefulSet) (bool, string) {
	if err := CheckStatefulSetImmutableFields(current, desired); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// CanUpdateDeployment checks if a Deployment can be updated without recreation
// Returns true if safe to update, false if recreation is required
func CanUpdateDeployment(current, desired *appsv1.Deployment) (bool, string) {
	if err := CheckDeploymentImmutableFields(current, desired); err != nil {
		return false, err.Error()
	}
	return true, ""
}
