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

package storage

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// PVCExpansionPhase represents the expansion phase of a PVC
type PVCExpansionPhase string

const (
	// PVCExpansionPhaseNone indicates no expansion is in progress
	PVCExpansionPhaseNone PVCExpansionPhase = ""

	// PVCExpansionPhaseResizing indicates the volume is being resized
	PVCExpansionPhaseResizing PVCExpansionPhase = "Resizing"

	// PVCExpansionPhaseFileSystemResizePending indicates filesystem resize is pending
	PVCExpansionPhaseFileSystemResizePending PVCExpansionPhase = "FileSystemResizePending"

	// PVCExpansionPhaseCompleted indicates expansion is complete
	PVCExpansionPhaseCompleted PVCExpansionPhase = "Completed"
)

// PVCExpansionCondition represents the current expansion state of a PVC
type PVCExpansionCondition struct {
	// Phase is the current expansion phase
	Phase PVCExpansionPhase

	// Message provides additional details
	Message string

	// IsComplete indicates if expansion is fully complete
	IsComplete bool
}

// ExpandPVC patches a PVC with a new storage size.
// It also adds an annotation to track the expansion request.
// Returns an error if the patch fails.
func ExpandPVC(ctx context.Context, c client.Client, pvc *corev1.PersistentVolumeClaim, newSize string) error {
	// Parse the new size to validate it
	newQuantity, err := resource.ParseQuantity(newSize)
	if err != nil {
		return fmt.Errorf("invalid storage size %q: %w", newSize, err)
	}

	// Create a copy of the PVC for patching
	pvcPatch := pvc.DeepCopy()

	// Update the storage request
	if pvcPatch.Spec.Resources.Requests == nil {
		pvcPatch.Spec.Resources.Requests = make(corev1.ResourceList)
	}
	pvcPatch.Spec.Resources.Requests[corev1.ResourceStorage] = newQuantity

	// Add annotations for tracking
	if pvcPatch.Annotations == nil {
		pvcPatch.Annotations = make(map[string]string)
	}
	pvcPatch.Annotations[constants.AnnotationRequestedStorageSize] = newSize
	pvcPatch.Annotations[constants.AnnotationLastExpansionTime] = time.Now().UTC().Format(time.RFC3339)

	// Patch the PVC
	if err := c.Patch(ctx, pvcPatch, client.MergeFrom(pvc)); err != nil {
		return fmt.Errorf("failed to patch PVC %s/%s: %w", pvc.Namespace, pvc.Name, err)
	}

	return nil
}

// GetPVCExpansionCondition returns the current expansion condition of a PVC.
// It checks the PVC status conditions for FileSystemResizePending and Resizing.
func GetPVCExpansionCondition(pvc *corev1.PersistentVolumeClaim) PVCExpansionCondition {
	result := PVCExpansionCondition{
		Phase:      PVCExpansionPhaseNone,
		IsComplete: true, // Default to complete (no expansion in progress)
	}

	// Check each condition if there are any
	if pvc.Status.Conditions != nil {
		for _, condition := range pvc.Status.Conditions {
			switch condition.Type {
			case corev1.PersistentVolumeClaimResizing:
				if condition.Status == corev1.ConditionTrue {
					result.Phase = PVCExpansionPhaseResizing
					result.Message = condition.Message
					result.IsComplete = false
					return result
				}
			case corev1.PersistentVolumeClaimFileSystemResizePending:
				if condition.Status == corev1.ConditionTrue {
					result.Phase = PVCExpansionPhaseFileSystemResizePending
					result.Message = condition.Message
					result.IsComplete = false
					return result
				}
			}
		}
	}

	// If we have a requested size annotation and the current size matches,
	// the expansion is complete
	if pvc.Annotations != nil {
		if requestedSize, ok := pvc.Annotations[constants.AnnotationRequestedStorageSize]; ok {
			currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
			requestedQty, err := resource.ParseQuantity(requestedSize)
			if err == nil && currentSize.Cmp(requestedQty) >= 0 {
				result.Phase = PVCExpansionPhaseCompleted
				result.Message = "Expansion completed successfully"
				result.IsComplete = true
			}
		}
	}

	return result
}

// IsPVCExpansionComplete checks if the PVC expansion has completed.
// This is determined by:
// 1. No Resizing or FileSystemResizePending conditions are true
// 2. The actual storage size matches or exceeds the requested size
func IsPVCExpansionComplete(pvc *corev1.PersistentVolumeClaim, requestedSize string) (bool, error) {
	// Check if there are any pending expansion conditions
	condition := GetPVCExpansionCondition(pvc)
	if !condition.IsComplete {
		return false, nil
	}

	// Parse requested size
	requestedQty, err := resource.ParseQuantity(requestedSize)
	if err != nil {
		return false, fmt.Errorf("invalid requested size %q: %w", requestedSize, err)
	}

	// Check if current size matches or exceeds requested size
	currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	return currentSize.Cmp(requestedQty) >= 0, nil
}

// GetPVCStorageSize returns the current storage size of a PVC as a string.
func GetPVCStorageSize(pvc *corev1.PersistentVolumeClaim) string {
	if pvc.Spec.Resources.Requests == nil {
		return ""
	}
	size := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	return size.String()
}
