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

package pvc

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WorkerPVCBuilder builds PersistentVolumeClaims for Wazuh Worker
type WorkerPVCBuilder struct {
	clusterName      string
	namespace        string
	storageSize      string
	storageClassName string
}

// NewWorkerPVCBuilder creates a new WorkerPVCBuilder
func NewWorkerPVCBuilder(clusterName, namespace string) *WorkerPVCBuilder {
	return &WorkerPVCBuilder{
		clusterName: clusterName,
		namespace:   namespace,
		storageSize: constants.DefaultManagerStorageSize,
	}
}

// WithStorageSize sets the storage size
func (b *WorkerPVCBuilder) WithStorageSize(size string) *WorkerPVCBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *WorkerPVCBuilder) WithStorageClassName(className string) *WorkerPVCBuilder {
	b.storageClassName = className
	return b
}

// Build creates the PVC for Wazuh Worker data
func (b *WorkerPVCBuilder) Build() *corev1.PersistentVolumeClaim {
	name := b.clusterName + "-manager-worker-data"

	labels := map[string]string{
		constants.LabelName:      "wazuh-manager",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "manager-worker",
		constants.LabelPartOf:    "wazuh",
		constants.LabelManagedBy: "wazuh-operator",
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(b.storageSize),
				},
			},
		},
	}

	if b.storageClassName != "" {
		pvc.Spec.StorageClassName = &b.storageClassName
	}

	return pvc
}

// BuildVolumeClaimTemplate creates a VolumeClaimTemplate for StatefulSet
func (b *WorkerPVCBuilder) BuildVolumeClaimTemplate() corev1.PersistentVolumeClaim {
	name := "wazuh-worker-data"

	labels := map[string]string{
		constants.LabelName:      "wazuh-manager",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "manager-worker",
		constants.LabelPartOf:    "wazuh",
		constants.LabelManagedBy: "wazuh-operator",
	}

	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(b.storageSize),
				},
			},
		},
	}

	if b.storageClassName != "" {
		pvc.Spec.StorageClassName = &b.storageClassName
	}

	return pvc
}
