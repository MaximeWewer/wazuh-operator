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

package opensearchcerts

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerCertsSecretBuilder builds certificate Secrets for OpenSearch Indexer
type IndexerCertsSecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
}

// NewIndexerCertsSecretBuilder creates a new IndexerCertsSecretBuilder
func NewIndexerCertsSecretBuilder(clusterName, namespace string) *IndexerCertsSecretBuilder {
	return &IndexerCertsSecretBuilder{
		name:        constants.IndexerCertsName(clusterName),
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string][]byte),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerCertsSecretBuilder) WithVersion(version string) *IndexerCertsSecretBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *IndexerCertsSecretBuilder) WithLabels(labels map[string]string) *IndexerCertsSecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerCertsSecretBuilder) WithAnnotations(annotations map[string]string) *IndexerCertsSecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithCACert adds the CA certificate
func (b *IndexerCertsSecretBuilder) WithCACert(cert []byte) *IndexerCertsSecretBuilder {
	b.data[constants.SecretKeyCACert] = cert
	return b
}

// WithNodeCert adds the node certificate
func (b *IndexerCertsSecretBuilder) WithNodeCert(cert []byte) *IndexerCertsSecretBuilder {
	b.data[constants.SecretKeyTLSCert] = cert
	return b
}

// WithNodeKey adds the node private key
func (b *IndexerCertsSecretBuilder) WithNodeKey(key []byte) *IndexerCertsSecretBuilder {
	b.data[constants.SecretKeyTLSKey] = key
	return b
}

// WithAdminCert adds the admin certificate
func (b *IndexerCertsSecretBuilder) WithAdminCert(cert []byte) *IndexerCertsSecretBuilder {
	b.data[constants.SecretKeyAdminCert] = cert
	return b
}

// WithAdminKey adds the admin private key
func (b *IndexerCertsSecretBuilder) WithAdminKey(key []byte) *IndexerCertsSecretBuilder {
	b.data[constants.SecretKeyAdminKey] = key
	return b
}

// WithData adds raw data entries
func (b *IndexerCertsSecretBuilder) WithData(data map[string][]byte) *IndexerCertsSecretBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// Build creates the Secret
func (b *IndexerCertsSecretBuilder) Build() *corev1.Secret {
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
func (b *IndexerCertsSecretBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}
