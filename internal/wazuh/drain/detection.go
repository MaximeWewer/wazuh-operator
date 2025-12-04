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

package drain

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
)

// ScaleDownInfo contains information about a detected scale-down operation
type ScaleDownInfo struct {
	// Detected indicates if a scale-down was detected
	Detected bool

	// CurrentReplicas is the current number of replicas
	CurrentReplicas int32

	// TargetReplicas is the target number of replicas
	TargetReplicas int32

	// ScaleAmount is the number of replicas being scaled down
	ScaleAmount int32

	// TargetPodName is the name of the pod that will be removed
	// For StatefulSets, this is the highest-numbered pod
	TargetPodName string

	// TargetPodIndex is the index of the pod being removed
	TargetPodIndex int32
}

// DetectStatefulSetScaleDown checks if a StatefulSet is being scaled down
// It compares the desired replicas in the spec against the current ready replicas
func DetectStatefulSetScaleDown(sts *appsv1.StatefulSet, desiredReplicas int32) ScaleDownInfo {
	info := ScaleDownInfo{
		TargetReplicas: desiredReplicas,
	}

	if sts == nil {
		return info
	}

	// Get current replicas from status
	currentReplicas := sts.Status.Replicas

	// If spec replicas is set, use it as the current state
	if sts.Spec.Replicas != nil {
		currentReplicas = *sts.Spec.Replicas
	}

	info.CurrentReplicas = currentReplicas

	// Detect scale-down
	if desiredReplicas < currentReplicas {
		info.Detected = true
		info.ScaleAmount = currentReplicas - desiredReplicas

		// For StatefulSets, pods are removed in reverse ordinal order
		// The highest-numbered pod is removed first
		targetIndex := currentReplicas - 1
		info.TargetPodIndex = targetIndex
		info.TargetPodName = fmt.Sprintf("%s-%d", sts.Name, targetIndex)
	}

	return info
}

// GetNextTargetPod returns the next pod to be drained during a multi-pod scale-down
// For example, if scaling from 5 to 2, pods 4, 3, and 2 need to be drained in order
func GetNextTargetPod(stsName string, currentReplicas, targetReplicas int32, alreadyDrained int32) (string, int32, bool) {
	if currentReplicas <= targetReplicas {
		return "", 0, false
	}

	// Calculate which pod is next
	// If we're scaling from 5 to 2 and have drained 0 pods, next is pod 4 (index 4)
	// If we've drained 1 pod, next is pod 3 (index 3)
	nextIndex := currentReplicas - 1 - alreadyDrained

	if nextIndex < targetReplicas {
		return "", 0, false // All pods that need draining have been drained
	}

	podName := fmt.Sprintf("%s-%d", stsName, nextIndex)
	return podName, nextIndex, true
}

// GetAllTargetPods returns all pods that need to be drained for a scale-down
func GetAllTargetPods(stsName string, currentReplicas, targetReplicas int32) []string {
	if currentReplicas <= targetReplicas {
		return nil
	}

	var pods []string
	for i := currentReplicas - 1; i >= targetReplicas; i-- {
		pods = append(pods, fmt.Sprintf("%s-%d", stsName, i))
	}
	return pods
}

// GetPodOrdinalFromName extracts the ordinal from a StatefulSet pod name
// e.g., "indexer-2" returns 2
func GetPodOrdinalFromName(podName, stsName string) (int32, error) {
	expectedPrefix := stsName + "-"
	if len(podName) <= len(expectedPrefix) {
		return 0, fmt.Errorf("pod name %s does not match StatefulSet %s pattern", podName, stsName)
	}

	var ordinal int32
	_, err := fmt.Sscanf(podName, stsName+"-%d", &ordinal)
	if err != nil {
		return 0, fmt.Errorf("failed to parse ordinal from pod name %s: %w", podName, err)
	}

	return ordinal, nil
}

// NeedsScaleDown checks if the desired replicas are less than current replicas
func NeedsScaleDown(currentReplicas, desiredReplicas int32) bool {
	return desiredReplicas < currentReplicas && desiredReplicas >= 0
}

// NeedsScaleUp checks if the desired replicas are greater than current replicas
func NeedsScaleUp(currentReplicas, desiredReplicas int32) bool {
	return desiredReplicas > currentReplicas
}

// CalculateScaleDownAmount returns how many replicas will be removed
func CalculateScaleDownAmount(currentReplicas, desiredReplicas int32) int32 {
	if desiredReplicas >= currentReplicas {
		return 0
	}
	return currentReplicas - desiredReplicas
}
