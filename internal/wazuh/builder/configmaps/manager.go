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

// Package configmaps provides Kubernetes ConfigMap builders for Wazuh components
package configmaps

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerConfigMapBuilder builds ConfigMaps for Wazuh Manager
type ManagerConfigMapBuilder struct {
	name         string
	namespace    string
	clusterName  string
	version      string
	nodeType     string // "master" or "worker"
	data         map[string]string
	binaryData   map[string][]byte
	labels       map[string]string
	annotations  map[string]string
	ossecConf    string
	filebeatYml  string
	extraConfigs map[string]string
}

// NewManagerConfigMapBuilder creates a new ManagerConfigMapBuilder
func NewManagerConfigMapBuilder(clusterName, namespace, nodeType string) *ManagerConfigMapBuilder {
	name := fmt.Sprintf("%s-manager-%s-config", clusterName, nodeType)
	return &ManagerConfigMapBuilder{
		name:         name,
		namespace:    namespace,
		clusterName:  clusterName,
		version:      constants.DefaultWazuhVersion,
		nodeType:     nodeType,
		data:         make(map[string]string),
		binaryData:   make(map[string][]byte),
		labels:       make(map[string]string),
		annotations:  make(map[string]string),
		extraConfigs: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ManagerConfigMapBuilder) WithVersion(version string) *ManagerConfigMapBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *ManagerConfigMapBuilder) WithLabels(labels map[string]string) *ManagerConfigMapBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *ManagerConfigMapBuilder) WithAnnotations(annotations map[string]string) *ManagerConfigMapBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithOSSECConfig sets the ossec.conf content
func (b *ManagerConfigMapBuilder) WithOSSECConfig(config string) *ManagerConfigMapBuilder {
	b.ossecConf = config
	return b
}

// WithFilebeatConfig sets the filebeat.yml content
func (b *ManagerConfigMapBuilder) WithFilebeatConfig(config string) *ManagerConfigMapBuilder {
	b.filebeatYml = config
	return b
}

// WithExtraConfig adds additional configuration files
func (b *ManagerConfigMapBuilder) WithExtraConfig(filename, content string) *ManagerConfigMapBuilder {
	b.extraConfigs[filename] = content
	return b
}

// WithIndexedOSSECConfig adds an ossec.conf for a specific worker index
// The config is stored with key format "ossec-worker-{index}.conf"
// This enables per-pod specialization when combined with an init container
func (b *ManagerConfigMapBuilder) WithIndexedOSSECConfig(index int32, config string) *ManagerConfigMapBuilder {
	key := fmt.Sprintf("ossec-worker-%d.conf", index)
	b.extraConfigs[key] = config
	return b
}

// WithData adds raw data entries
func (b *ManagerConfigMapBuilder) WithData(data map[string]string) *ManagerConfigMapBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// WithBinaryData adds binary data entries
func (b *ManagerConfigMapBuilder) WithBinaryData(data map[string][]byte) *ManagerConfigMapBuilder {
	for k, v := range data {
		b.binaryData[k] = v
	}
	return b
}

// Build creates the ConfigMap
func (b *ManagerConfigMapBuilder) Build() *corev1.ConfigMap {
	labels := b.buildLabels()

	// Build data map
	data := make(map[string]string)

	// Add ossec.conf if provided
	// The key must be "etc/ossec.conf" so that the Docker entrypoint copies it to /var/ossec/etc/ossec.conf
	// The entrypoint does: cp -r /wazuh-config-mount/* /var/ossec/
	if b.ossecConf != "" {
		data["etc/ossec.conf"] = b.ossecConf
	}

	// Add filebeat.yml if provided
	// The key must be "etc/filebeat/filebeat.yml" for the Docker entrypoint
	if b.filebeatYml != "" {
		data["etc/filebeat/filebeat.yml"] = b.filebeatYml
	}

	// Add extra configs
	for k, v := range b.extraConfigs {
		data[k] = v
	}

	// Add any additional data
	for k, v := range b.data {
		data[k] = v
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Data:       data,
		BinaryData: b.binaryData,
	}
}

// buildLabels builds the complete label set
func (b *ManagerConfigMapBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = b.nodeType
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// SharedConfigMapBuilder builds shared ConfigMaps for Wazuh Manager cluster
type SharedConfigMapBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	data        map[string]string
	labels      map[string]string
	annotations map[string]string
}

// NewSharedConfigMapBuilder creates a new SharedConfigMapBuilder
func NewSharedConfigMapBuilder(clusterName, namespace string) *SharedConfigMapBuilder {
	name := fmt.Sprintf("%s-manager-shared-config", clusterName)
	return &SharedConfigMapBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string]string),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *SharedConfigMapBuilder) WithVersion(version string) *SharedConfigMapBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *SharedConfigMapBuilder) WithLabels(labels map[string]string) *SharedConfigMapBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *SharedConfigMapBuilder) WithAnnotations(annotations map[string]string) *SharedConfigMapBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithData adds data entries
func (b *SharedConfigMapBuilder) WithData(data map[string]string) *SharedConfigMapBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// Build creates the ConfigMap
func (b *SharedConfigMapBuilder) Build() *corev1.ConfigMap {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	for k, v := range b.labels {
		labels[k] = v
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Data: b.data,
	}
}
