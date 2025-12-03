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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ExpansionValidationResult represents the result of expansion validation
type ExpansionValidationResult struct {
	// Valid indicates if expansion is valid
	Valid bool

	// NeedsExpansion indicates if the PVC needs to be expanded
	NeedsExpansion bool

	// CurrentSize is the current PVC storage size
	CurrentSize resource.Quantity

	// RequestedSize is the requested storage size
	RequestedSize resource.Quantity

	// ErrorMessage contains the error message if validation failed
	ErrorMessage string

	// StorageClassSupportsExpansion indicates if the storage class supports expansion
	StorageClassSupportsExpansion bool
}

// ValidateExpansion validates whether a PVC can be expanded to the requested size.
// It checks:
// 1. If the requested size is greater than the current size (shrinking is not supported)
// 2. If the StorageClass supports volume expansion
//
// Returns an ExpansionValidationResult with details about the validation.
func ValidateExpansion(ctx context.Context, c client.Client, pvc *corev1.PersistentVolumeClaim, requestedSizeStr string) (*ExpansionValidationResult, error) {
	result := &ExpansionValidationResult{}

	// Parse the requested size
	requestedSize, err := resource.ParseQuantity(requestedSizeStr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("invalid requested size %q: %v", requestedSizeStr, err)
		return result, nil
	}
	result.RequestedSize = requestedSize

	// Get current PVC size
	currentSize := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	result.CurrentSize = currentSize

	// Compare sizes
	comparison := CompareStorageSizes(currentSize, requestedSize)

	switch comparison {
	case -1:
		// Current < Requested: expansion is needed
		result.NeedsExpansion = true
	case 0:
		// Current == Requested: no change needed
		result.Valid = true
		result.NeedsExpansion = false
		return result, nil
	case 1:
		// Current > Requested: shrinking is not supported
		result.ErrorMessage = fmt.Sprintf("cannot decrease storage size from %s to %s: Kubernetes does not support shrinking PVCs", currentSize.String(), requestedSize.String())
		return result, nil
	}

	// Get storage class name
	storageClassName, err := GetStorageClassForPVC(ctx, c, pvc.Spec.StorageClassName)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to determine storage class: %v", err)
		return result, nil
	}

	// Check if StorageClass supports expansion
	canExpand, err := CanStorageClassExpand(ctx, c, storageClassName)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to check StorageClass expansion support: %v", err)
		return result, nil
	}

	result.StorageClassSupportsExpansion = canExpand

	if !canExpand {
		result.ErrorMessage = fmt.Sprintf("StorageClass %q does not support volume expansion (allowVolumeExpansion is not true)", storageClassName)
		return result, nil
	}

	// All checks passed
	result.Valid = true
	return result, nil
}

// CompareStorageSizes compares two storage quantities.
// Returns:
//
//	-1 if a < b
//	 0 if a == b
//	 1 if a > b
func CompareStorageSizes(a, b resource.Quantity) int {
	return a.Cmp(b)
}

// CompareStorageSizeStrings compares two storage size strings.
// Returns:
//
//	-1 if a < b
//	 0 if a == b
//	 1 if a > b
//
// Returns an error if either string cannot be parsed.
func CompareStorageSizeStrings(aStr, bStr string) (int, error) {
	a, err := resource.ParseQuantity(aStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size %q: %w", aStr, err)
	}

	b, err := resource.ParseQuantity(bStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size %q: %w", bStr, err)
	}

	return CompareStorageSizes(a, b), nil
}

// IsShrinkRequest checks if the requested size is smaller than the current size.
// Returns true if this would be a shrink operation (which is not supported).
func IsShrinkRequest(currentSizeStr, requestedSizeStr string) (bool, error) {
	comparison, err := CompareStorageSizeStrings(currentSizeStr, requestedSizeStr)
	if err != nil {
		return false, err
	}
	return comparison > 0, nil
}

// IsExpansionRequest checks if the requested size is larger than the current size.
// Returns true if this would be an expansion operation.
func IsExpansionRequest(currentSizeStr, requestedSizeStr string) (bool, error) {
	comparison, err := CompareStorageSizeStrings(currentSizeStr, requestedSizeStr)
	if err != nil {
		return false, err
	}
	return comparison < 0, nil
}
