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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// NodePoolServiceBuilder builds headless Services for OpenSearch nodePools
// Each nodePool requires a headless service for StatefulSet pod DNS discovery
type NodePoolServiceBuilder struct {
	clusterName string
	namespace   string
	poolName    string
	version     string
	labels      map[string]string
	annotations map[string]string
}

// NewNodePoolServiceBuilder creates a new NodePoolServiceBuilder
func NewNodePoolServiceBuilder(clusterName, namespace, poolName string) *NodePoolServiceBuilder {
	return &NodePoolServiceBuilder{
		clusterName: clusterName,
		namespace:   namespace,
		poolName:    poolName,
		version:     constants.DefaultWazuhVersion,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *NodePoolServiceBuilder) WithVersion(version string) *NodePoolServiceBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *NodePoolServiceBuilder) WithLabels(labels map[string]string) *NodePoolServiceBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *NodePoolServiceBuilder) WithAnnotations(annotations map[string]string) *NodePoolServiceBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the headless Service for pod discovery
func (b *NodePoolServiceBuilder) Build() *corev1.Service {
	name := constants.IndexerNodePoolHeadlessName(b.clusterName, b.poolName)
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: corev1.ServiceSpec{
			// Headless service for StatefulSet pod DNS
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selectorLabels,
			// PublishNotReadyAddresses allows pods to be discoverable before becoming ready
			// This is important for OpenSearch cluster formation
			PublishNotReadyAddresses: true,
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
				{
					Name:       constants.PortNameIndexerMetrics,
					Port:       constants.PortIndexerMetrics,
					TargetPort: intstr.FromInt(int(constants.PortIndexerMetrics)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// buildLabels builds the complete label set
func (b *NodePoolServiceBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	// Add nodePool-specific labels
	labels[constants.LabelNodePool] = b.poolName
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels to target this nodePool's pods
func (b *NodePoolServiceBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, constants.ComponentIndexer)
	// Add nodePool label to selector for pool-specific targeting
	labels[constants.LabelNodePool] = b.poolName
	return labels
}
