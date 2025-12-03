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

	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DefaultStorageClassAnnotation is the annotation key for marking a StorageClass as default
	DefaultStorageClassAnnotation = "storageclass.kubernetes.io/is-default-class"
)

// CanStorageClassExpand checks if a StorageClass supports volume expansion.
// Returns true if the StorageClass has AllowVolumeExpansion set to true.
// Returns an error if the StorageClass cannot be found.
func CanStorageClassExpand(ctx context.Context, c client.Client, storageClassName string) (bool, error) {
	if storageClassName == "" {
		return false, fmt.Errorf("storage class name cannot be empty")
	}

	sc := &storagev1.StorageClass{}
	if err := c.Get(ctx, types.NamespacedName{Name: storageClassName}, sc); err != nil {
		return false, fmt.Errorf("failed to get StorageClass %s: %w", storageClassName, err)
	}

	// AllowVolumeExpansion is a *bool, nil means false
	if sc.AllowVolumeExpansion == nil {
		return false, nil
	}

	return *sc.AllowVolumeExpansion, nil
}

// GetStorageClassName returns the storage class name for a PVC.
// If the PVC has a storage class specified, it returns that name.
// If not, it tries to find the default StorageClass.
// Returns an error if no storage class can be determined.
func GetStorageClassName(ctx context.Context, c client.Client, storageClassName *string) (string, error) {
	// If storage class is explicitly set, use it
	if storageClassName != nil && *storageClassName != "" {
		return *storageClassName, nil
	}

	// Otherwise, try to find the default StorageClass
	return GetDefaultStorageClass(ctx, c)
}

// GetDefaultStorageClass finds the default StorageClass in the cluster.
// A StorageClass is considered default if it has the annotation
// storageclass.kubernetes.io/is-default-class=true
func GetDefaultStorageClass(ctx context.Context, c client.Client) (string, error) {
	scList := &storagev1.StorageClassList{}
	if err := c.List(ctx, scList); err != nil {
		return "", fmt.Errorf("failed to list StorageClasses: %w", err)
	}

	for _, sc := range scList.Items {
		if sc.Annotations == nil {
			continue
		}
		if sc.Annotations[DefaultStorageClassAnnotation] == "true" {
			return sc.Name, nil
		}
	}

	return "", fmt.Errorf("no default StorageClass found in the cluster")
}

// GetStorageClassForPVC returns the storage class name for a PVC's StorageClassName field.
// If the PVC's StorageClassName is nil or empty, it returns the default storage class.
func GetStorageClassForPVC(ctx context.Context, c client.Client, pvcStorageClassName *string) (string, error) {
	if pvcStorageClassName != nil && *pvcStorageClassName != "" {
		return *pvcStorageClassName, nil
	}
	return GetDefaultStorageClass(ctx, c)
}
