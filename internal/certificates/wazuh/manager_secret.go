/*
Copyright 2026.

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

package wazuhcerts

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerCertsSecretBuilder builds certificate Secrets for Wazuh Manager
type ManagerCertsSecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
}

// NewManagerCertsSecretBuilder creates a new ManagerCertsSecretBuilder
func NewManagerCertsSecretBuilder(clusterName, namespace string) *ManagerCertsSecretBuilder {
	name := fmt.Sprintf("%s-manager-certs", clusterName)
	return &ManagerCertsSecretBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string][]byte),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ManagerCertsSecretBuilder) WithVersion(version string) *ManagerCertsSecretBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *ManagerCertsSecretBuilder) WithLabels(labels map[string]string) *ManagerCertsSecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *ManagerCertsSecretBuilder) WithAnnotations(annotations map[string]string) *ManagerCertsSecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithCACert adds the CA certificate
func (b *ManagerCertsSecretBuilder) WithCACert(cert []byte) *ManagerCertsSecretBuilder {
	b.data["root-ca.pem"] = cert
	return b
}

// WithNodeCert adds the node certificate
func (b *ManagerCertsSecretBuilder) WithNodeCert(cert []byte) *ManagerCertsSecretBuilder {
	b.data["node.pem"] = cert
	return b
}

// WithNodeKey adds the node private key
func (b *ManagerCertsSecretBuilder) WithNodeKey(key []byte) *ManagerCertsSecretBuilder {
	b.data["node-key.pem"] = key
	return b
}

// WithFilebeatCert adds the filebeat certificate
func (b *ManagerCertsSecretBuilder) WithFilebeatCert(cert []byte) *ManagerCertsSecretBuilder {
	b.data["filebeat.pem"] = cert
	return b
}

// WithFilebeatKey adds the filebeat private key
func (b *ManagerCertsSecretBuilder) WithFilebeatKey(key []byte) *ManagerCertsSecretBuilder {
	b.data["filebeat-key.pem"] = key
	return b
}

// WithData adds raw data entries
func (b *ManagerCertsSecretBuilder) WithData(data map[string][]byte) *ManagerCertsSecretBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// Build creates the Secret
func (b *ManagerCertsSecretBuilder) Build() *corev1.Secret {
	labels := b.buildLabels()

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: b.data,
	}
}

// buildLabels builds the complete label set
func (b *ManagerCertsSecretBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}
