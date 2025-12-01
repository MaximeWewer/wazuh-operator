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

// Package services provides Kubernetes Service builders for OpenSearch components
package services

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerServiceBuilder builds Services for OpenSearch Indexer
type IndexerServiceBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	serviceType    corev1.ServiceType
	headless       bool
	labels         map[string]string
	annotations    map[string]string
	loadBalancerIP string
}

// NewIndexerServiceBuilder creates a new IndexerServiceBuilder
func NewIndexerServiceBuilder(clusterName, namespace string) *IndexerServiceBuilder {
	name := fmt.Sprintf("%s-indexer", clusterName)
	return &IndexerServiceBuilder{
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

// WithVersion sets the OpenSearch version
func (b *IndexerServiceBuilder) WithVersion(version string) *IndexerServiceBuilder {
	b.version = version
	return b
}

// WithServiceType sets the service type
func (b *IndexerServiceBuilder) WithServiceType(serviceType corev1.ServiceType) *IndexerServiceBuilder {
	b.serviceType = serviceType
	return b
}

// WithHeadless makes this a headless service
func (b *IndexerServiceBuilder) WithHeadless(headless bool) *IndexerServiceBuilder {
	b.headless = headless
	return b
}

// WithLabels adds custom labels
func (b *IndexerServiceBuilder) WithLabels(labels map[string]string) *IndexerServiceBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerServiceBuilder) WithAnnotations(annotations map[string]string) *IndexerServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithLoadBalancerIP sets the load balancer IP
func (b *IndexerServiceBuilder) WithLoadBalancerIP(ip string) *IndexerServiceBuilder {
	b.loadBalancerIP = ip
	return b
}

// Build creates the Service
func (b *IndexerServiceBuilder) Build() *corev1.Service {
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
					Name:       constants.PortNameIndexerREST,
					Port:       constants.PortIndexerREST,
					TargetPort: intstr.FromInt(int(constants.PortIndexerREST)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       constants.PortNameIndexerTransport,
					Port:       constants.PortIndexerTransport,
					TargetPort: intstr.FromInt(int(constants.PortIndexerTransport)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Handle headless service
	if b.headless {
		svc.Spec.ClusterIP = corev1.ClusterIPNone
		// Add metrics port for headless service (used for discovery)
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:       constants.PortNameIndexerMetrics,
			Port:       constants.PortIndexerMetrics,
			TargetPort: intstr.FromInt(int(constants.PortIndexerMetrics)),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	// Handle LoadBalancer IP
	if b.serviceType == corev1.ServiceTypeLoadBalancer && b.loadBalancerIP != "" {
		svc.Spec.LoadBalancerIP = b.loadBalancerIP
	}

	return svc
}

// BuildHeadless creates a headless Service for StatefulSet pod discovery
// Returns a service with name "{clusterName}-indexer-headless" and ClusterIP: None
func (b *IndexerServiceBuilder) BuildHeadless() *corev1.Service {
	// Save original name
	originalName := b.name

	// Set headless mode and append -headless suffix
	b.headless = true
	b.name = originalName + "-headless"

	svc := b.Build()

	// Restore original state for subsequent calls
	b.headless = false
	b.name = originalName

	return svc
}

// buildLabels builds the complete label set
func (b *IndexerServiceBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *IndexerServiceBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, constants.ComponentIndexer)
}
