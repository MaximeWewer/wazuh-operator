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

// FilebeatConfigMapBuilder builds ConfigMaps for Filebeat configuration
type FilebeatConfigMapBuilder struct {
	clusterName     string
	namespace       string
	config          string
	indexTemplate   string
	ingestPipeline  string
	ownerReferences []metav1.OwnerReference
}

// NewFilebeatConfigMapBuilder creates a new FilebeatConfigMapBuilder
func NewFilebeatConfigMapBuilder(clusterName, namespace string) *FilebeatConfigMapBuilder {
	return &FilebeatConfigMapBuilder{
		clusterName: clusterName,
		namespace:   namespace,
	}
}

// WithConfig sets the Filebeat configuration content (filebeat.yml)
func (b *FilebeatConfigMapBuilder) WithConfig(config string) *FilebeatConfigMapBuilder {
	b.config = config
	return b
}

// WithIndexTemplate sets the Wazuh index template content (wazuh-template.json)
func (b *FilebeatConfigMapBuilder) WithIndexTemplate(template string) *FilebeatConfigMapBuilder {
	b.indexTemplate = template
	return b
}

// WithIngestPipeline sets the ingest pipeline content (pipeline.json)
func (b *FilebeatConfigMapBuilder) WithIngestPipeline(pipeline string) *FilebeatConfigMapBuilder {
	b.ingestPipeline = pipeline
	return b
}

// WithOwnerReference sets the owner reference for garbage collection
func (b *FilebeatConfigMapBuilder) WithOwnerReference(ownerRef metav1.OwnerReference) *FilebeatConfigMapBuilder {
	b.ownerReferences = append(b.ownerReferences, ownerRef)
	return b
}

// WithOwnerReferences sets multiple owner references for garbage collection
func (b *FilebeatConfigMapBuilder) WithOwnerReferences(ownerRefs []metav1.OwnerReference) *FilebeatConfigMapBuilder {
	b.ownerReferences = ownerRefs
	return b
}

// Build creates the ConfigMap for Filebeat
func (b *FilebeatConfigMapBuilder) Build() *corev1.ConfigMap {
	name := b.clusterName + "-filebeat-config"

	labels := map[string]string{
		constants.LabelName:      "filebeat",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "filebeat",
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	data := make(map[string]string)

	// Always include filebeat.yml
	if b.config != "" {
		data[constants.ConfigMapKeyFilebeatYml] = b.config
	}

	// Include index template if provided
	if b.indexTemplate != "" {
		data[constants.ConfigMapKeyWazuhTemplate] = b.indexTemplate
	}

	// Include ingest pipeline if provided
	if b.ingestPipeline != "" {
		data[constants.ConfigMapKeyPipeline] = b.ingestPipeline
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Data: data,
	}

	// Set owner references if provided
	if len(b.ownerReferences) > 0 {
		cm.OwnerReferences = b.ownerReferences
	}

	return cm
}

// GetConfigMapName returns the ConfigMap name for a given cluster
func GetConfigMapName(clusterName string) string {
	return clusterName + "-filebeat-config"
}
