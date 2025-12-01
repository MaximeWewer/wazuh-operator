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

// Package pvc provides Kubernetes PersistentVolumeClaim builders for Wazuh components
package pvc

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerPVCBuilder builds PersistentVolumeClaims for Wazuh Manager
type ManagerPVCBuilder struct {
	name             string
	namespace        string
	clusterName      string
	version          string
	nodeType         string // "master" or "worker"
	storageSize      string
	storageClassName *string
	accessModes      []corev1.PersistentVolumeAccessMode
	volumeMode       *corev1.PersistentVolumeMode
	labels           map[string]string
	annotations      map[string]string
}

// NewManagerPVCBuilder creates a new ManagerPVCBuilder
func NewManagerPVCBuilder(clusterName, namespace, nodeType string) *ManagerPVCBuilder {
	name := fmt.Sprintf("%s-manager-%s-data", clusterName, nodeType)
	return &ManagerPVCBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		nodeType:    nodeType,
		storageSize: constants.DefaultManagerStorageSize,
		accessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ManagerPVCBuilder) WithVersion(version string) *ManagerPVCBuilder {
	b.version = version
	return b
}

// WithStorageSize sets the storage size
func (b *ManagerPVCBuilder) WithStorageSize(size string) *ManagerPVCBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *ManagerPVCBuilder) WithStorageClassName(className string) *ManagerPVCBuilder {
	b.storageClassName = &className
	return b
}

// WithAccessModes sets the access modes
func (b *ManagerPVCBuilder) WithAccessModes(modes []corev1.PersistentVolumeAccessMode) *ManagerPVCBuilder {
	b.accessModes = modes
	return b
}

// WithVolumeMode sets the volume mode
func (b *ManagerPVCBuilder) WithVolumeMode(mode corev1.PersistentVolumeMode) *ManagerPVCBuilder {
	b.volumeMode = &mode
	return b
}

// WithLabels adds custom labels
func (b *ManagerPVCBuilder) WithLabels(labels map[string]string) *ManagerPVCBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *ManagerPVCBuilder) WithAnnotations(annotations map[string]string) *ManagerPVCBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the PersistentVolumeClaim
func (b *ManagerPVCBuilder) Build() *corev1.PersistentVolumeClaim {
	labels := b.buildLabels()

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      b.accessModes,
			StorageClassName: b.storageClassName,
			VolumeMode:       b.volumeMode,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(b.storageSize),
				},
			},
		},
	}

	return pvc
}

// BuildVolumeClaimTemplate creates a PVC template for StatefulSet
func (b *ManagerPVCBuilder) BuildVolumeClaimTemplate() corev1.PersistentVolumeClaim {
	labels := b.buildSelectorLabels()

	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "wazuh-manager-data",
			Labels: labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      b.accessModes,
			StorageClassName: b.storageClassName,
			VolumeMode:       b.volumeMode,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(b.storageSize),
				},
			},
		},
	}
}

// buildLabels builds the complete label set
func (b *ManagerPVCBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = b.nodeType
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *ManagerPVCBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	labels[constants.LabelManagerNodeType] = b.nodeType
	return labels
}
