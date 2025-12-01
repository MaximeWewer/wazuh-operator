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

package services

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WorkerServiceBuilder builds Services for Wazuh Manager Worker nodes
type WorkerServiceBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	serviceType corev1.ServiceType
	headless    bool
	labels      map[string]string
	annotations map[string]string
}

// NewWorkerServiceBuilder creates a new WorkerServiceBuilder
func NewWorkerServiceBuilder(clusterName, namespace string) *WorkerServiceBuilder {
	name := fmt.Sprintf("%s-manager-worker", clusterName)
	return &WorkerServiceBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		serviceType: corev1.ServiceTypeClusterIP,
		headless:    false,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *WorkerServiceBuilder) WithVersion(version string) *WorkerServiceBuilder {
	b.version = version
	return b
}

// WithServiceType sets the service type
func (b *WorkerServiceBuilder) WithServiceType(serviceType corev1.ServiceType) *WorkerServiceBuilder {
	b.serviceType = serviceType
	return b
}

// WithHeadless makes this a headless service
func (b *WorkerServiceBuilder) WithHeadless(headless bool) *WorkerServiceBuilder {
	b.headless = headless
	return b
}

// WithLabels adds custom labels
func (b *WorkerServiceBuilder) WithLabels(labels map[string]string) *WorkerServiceBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *WorkerServiceBuilder) WithAnnotations(annotations map[string]string) *WorkerServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the Service
func (b *WorkerServiceBuilder) Build() *corev1.Service {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     b.serviceType,
			Selector: selectorLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       constants.PortNameManagerAPI,
					Port:       constants.PortManagerAPI,
					TargetPort: intstr.FromInt(int(constants.PortManagerAPI)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameManagerAgentEvents,
					Port:       constants.PortManagerAgentEvents,
					TargetPort: intstr.FromInt(int(constants.PortManagerAgentEvents)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameManagerCluster,
					Port:       constants.PortManagerCluster,
					TargetPort: intstr.FromInt(int(constants.PortManagerCluster)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Handle headless service
	if b.headless {
		svc.Spec.ClusterIP = corev1.ClusterIPNone
	}

	return svc
}

// BuildHeadless creates a headless Service for StatefulSet pod discovery
func (b *WorkerServiceBuilder) BuildHeadless() *corev1.Service {
	b.headless = true
	return b.Build()
}

// buildLabels builds the complete label set
func (b *WorkerServiceBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = "worker"
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *WorkerServiceBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	labels[constants.LabelManagerNodeType] = "worker"
	return labels
}
