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

package utils

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// SetOwnerReference sets the owner reference on a resource
func SetOwnerReference(owner, controlled metav1.Object, scheme *runtime.Scheme) error {
	return controllerutil.SetControllerReference(owner, controlled, scheme)
}

// ObjectKey creates a types.NamespacedName from namespace and name
func ObjectKey(namespace, name string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
}

// ObjectKeyFromObject creates a types.NamespacedName from a client.Object
func ObjectKeyFromObject(obj client.Object) types.NamespacedName {
	return types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}

// ObjectKeyString returns a string representation of namespace/name
func ObjectKeyString(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return fmt.Sprintf("%s/%s", namespace, name)
}

// ResourceName generates a resource name with the cluster prefix
func ResourceName(clusterName, suffix string) string {
	return fmt.Sprintf("%s-%s", clusterName, suffix)
}

// EnsureLabels ensures that required labels are present on an object
func EnsureLabels(obj metav1.Object, labels map[string]string) {
	existing := obj.GetLabels()
	if existing == nil {
		existing = make(map[string]string)
	}
	for k, v := range labels {
		existing[k] = v
	}
	obj.SetLabels(existing)
}

// EnsureAnnotations ensures that required annotations are present on an object
func EnsureAnnotations(obj metav1.Object, annotations map[string]string) {
	existing := obj.GetAnnotations()
	if existing == nil {
		existing = make(map[string]string)
	}
	for k, v := range annotations {
		existing[k] = v
	}
	obj.SetAnnotations(existing)
}

// GetAnnotation safely gets an annotation value
func GetAnnotation(obj metav1.Object, key string) string {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return ""
	}
	return annotations[key]
}

// SetAnnotation safely sets an annotation value
func SetAnnotation(obj metav1.Object, key, value string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[key] = value
	obj.SetAnnotations(annotations)
}

// RemoveAnnotation safely removes an annotation
func RemoveAnnotation(obj metav1.Object, key string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return
	}
	delete(annotations, key)
	obj.SetAnnotations(annotations)
}

// GetLabel safely gets a label value
func GetLabel(obj metav1.Object, key string) string {
	labels := obj.GetLabels()
	if labels == nil {
		return ""
	}
	return labels[key]
}

// SetLabel safely sets a label value
func SetLabel(obj metav1.Object, key, value string) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[key] = value
	obj.SetLabels(labels)
}

// HasFinalizer checks if an object has a specific finalizer
func HasFinalizer(obj client.Object, finalizer string) bool {
	return controllerutil.ContainsFinalizer(obj, finalizer)
}

// AddFinalizer adds a finalizer to an object
func AddFinalizer(obj client.Object, finalizer string) {
	controllerutil.AddFinalizer(obj, finalizer)
}

// RemoveFinalizer removes a finalizer from an object
func RemoveFinalizer(obj client.Object, finalizer string) {
	controllerutil.RemoveFinalizer(obj, finalizer)
}

// IsBeingDeleted checks if an object is being deleted
func IsBeingDeleted(obj metav1.Object) bool {
	return !obj.GetDeletionTimestamp().IsZero()
}

// Int32Ptr returns a pointer to an int32
func Int32Ptr(i int32) *int32 {
	return &i
}

// Int64Ptr returns a pointer to an int64
func Int64Ptr(i int64) *int64 {
	return &i
}

// BoolPtr returns a pointer to a bool
func BoolPtr(b bool) *bool {
	return &b
}

// StringPtr returns a pointer to a string
func StringPtr(s string) *string {
	return &s
}
