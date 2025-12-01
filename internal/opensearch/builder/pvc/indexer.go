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

// Package pvc provides Kubernetes PersistentVolumeClaim builders for OpenSearch components
package pvc

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerPVCBuilder builds PersistentVolumeClaims for OpenSearch Indexer
type IndexerPVCBuilder struct {
	name             string
	namespace        string
	clusterName      string
	version          string
	storageSize      string
	storageClassName *string
	accessModes      []corev1.PersistentVolumeAccessMode
	volumeMode       *corev1.PersistentVolumeMode
	labels           map[string]string
	annotations      map[string]string
}

// NewIndexerPVCBuilder creates a new IndexerPVCBuilder
func NewIndexerPVCBuilder(clusterName, namespace string) *IndexerPVCBuilder {
	name := fmt.Sprintf("%s-indexer-data", clusterName)
	return &IndexerPVCBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		storageSize: constants.DefaultIndexerStorageSize,
		accessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerPVCBuilder) WithVersion(version string) *IndexerPVCBuilder {
	b.version = version
	return b
}

// WithStorageSize sets the storage size
func (b *IndexerPVCBuilder) WithStorageSize(size string) *IndexerPVCBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *IndexerPVCBuilder) WithStorageClassName(className string) *IndexerPVCBuilder {
	b.storageClassName = &className
	return b
}

// WithAccessModes sets the access modes
func (b *IndexerPVCBuilder) WithAccessModes(modes []corev1.PersistentVolumeAccessMode) *IndexerPVCBuilder {
	b.accessModes = modes
	return b
}

// WithVolumeMode sets the volume mode
func (b *IndexerPVCBuilder) WithVolumeMode(mode corev1.PersistentVolumeMode) *IndexerPVCBuilder {
	b.volumeMode = &mode
	return b
}

// WithLabels adds custom labels
func (b *IndexerPVCBuilder) WithLabels(labels map[string]string) *IndexerPVCBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerPVCBuilder) WithAnnotations(annotations map[string]string) *IndexerPVCBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the PersistentVolumeClaim
func (b *IndexerPVCBuilder) Build() *corev1.PersistentVolumeClaim {
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
func (b *IndexerPVCBuilder) BuildVolumeClaimTemplate() corev1.PersistentVolumeClaim {
	labels := b.buildSelectorLabels()

	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "opensearch-data",
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
func (b *IndexerPVCBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *IndexerPVCBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, constants.ComponentIndexer)
}
