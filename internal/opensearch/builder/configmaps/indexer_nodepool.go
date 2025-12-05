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

package configmaps

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// NodePoolConfigMapBuilder builds ConfigMaps for OpenSearch nodePools
// Each nodePool requires its own ConfigMap with role-specific opensearch.yml
type NodePoolConfigMapBuilder struct {
	clusterName   string
	namespace     string
	poolName      string
	version       string
	opensearchYML string
	data          map[string]string
	labels        map[string]string
	annotations   map[string]string
}

// NewNodePoolConfigMapBuilder creates a new NodePoolConfigMapBuilder
func NewNodePoolConfigMapBuilder(clusterName, namespace, poolName string) *NodePoolConfigMapBuilder {
	return &NodePoolConfigMapBuilder{
		clusterName: clusterName,
		namespace:   namespace,
		poolName:    poolName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string]string),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *NodePoolConfigMapBuilder) WithVersion(version string) *NodePoolConfigMapBuilder {
	b.version = version
	return b
}

// WithOpenSearchYML sets the opensearch.yml content
// This should include role-specific configuration (node.roles, node.attr.*)
func (b *NodePoolConfigMapBuilder) WithOpenSearchYML(config string) *NodePoolConfigMapBuilder {
	b.opensearchYML = config
	return b
}

// WithLabels adds custom labels
func (b *NodePoolConfigMapBuilder) WithLabels(labels map[string]string) *NodePoolConfigMapBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *NodePoolConfigMapBuilder) WithAnnotations(annotations map[string]string) *NodePoolConfigMapBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithData adds additional data entries
func (b *NodePoolConfigMapBuilder) WithData(data map[string]string) *NodePoolConfigMapBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// Build creates the ConfigMap for this nodePool
func (b *NodePoolConfigMapBuilder) Build() *corev1.ConfigMap {
	name := constants.IndexerNodePoolConfigName(b.clusterName, b.poolName)
	labels := b.buildLabels()

	// Build data map
	data := make(map[string]string)

	// Add opensearch.yml if provided
	if b.opensearchYML != "" {
		data[constants.ConfigMapKeyOpenSearchYml] = b.opensearchYML
	}

	// Add any additional data
	for k, v := range b.data {
		data[k] = v
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Data: data,
	}
}

// buildLabels builds the complete label set
func (b *NodePoolConfigMapBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	// Add nodePool-specific labels
	labels[constants.LabelNodePool] = b.poolName
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}
