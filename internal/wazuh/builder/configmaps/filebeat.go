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
	clusterName string
	namespace   string
	config      string
}

// NewFilebeatConfigMapBuilder creates a new FilebeatConfigMapBuilder
func NewFilebeatConfigMapBuilder(clusterName, namespace string) *FilebeatConfigMapBuilder {
	return &FilebeatConfigMapBuilder{
		clusterName: clusterName,
		namespace:   namespace,
	}
}

// WithConfig sets the Filebeat configuration content
func (b *FilebeatConfigMapBuilder) WithConfig(config string) *FilebeatConfigMapBuilder {
	b.config = config
	return b
}

// Build creates the ConfigMap for Filebeat
func (b *FilebeatConfigMapBuilder) Build() *corev1.ConfigMap {
	name := b.clusterName + "-filebeat-config"

	labels := map[string]string{
		constants.LabelName:      "filebeat",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "filebeat",
		constants.LabelPartOf:    "wazuh",
		constants.LabelManagedBy: "wazuh-operator",
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"filebeat.yml": b.config,
		},
	}
}
