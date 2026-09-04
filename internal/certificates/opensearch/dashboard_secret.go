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
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardCertsSecretBuilder builds certificate Secrets for OpenSearch Dashboard
type DashboardCertsSecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
}

// NewDashboardCertsSecretBuilder creates a new DashboardCertsSecretBuilder
func NewDashboardCertsSecretBuilder(clusterName, namespace string) *DashboardCertsSecretBuilder {
	return &DashboardCertsSecretBuilder{
		name:        constants.DashboardCertsName(clusterName),
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string][]byte),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *DashboardCertsSecretBuilder) WithVersion(version string) *DashboardCertsSecretBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *DashboardCertsSecretBuilder) WithLabels(labels map[string]string) *DashboardCertsSecretBuilder {
	maps.Copy(b.labels, labels)
	return b
}

// WithAnnotations adds custom annotations
func (b *DashboardCertsSecretBuilder) WithAnnotations(annotations map[string]string) *DashboardCertsSecretBuilder {
	maps.Copy(b.annotations, annotations)
	return b
}

// WithCACert adds the CA certificate
func (b *DashboardCertsSecretBuilder) WithCACert(cert []byte) *DashboardCertsSecretBuilder {
	b.data[constants.SecretKeyRootCA] = cert
	return b
}

// WithDashboardCert adds the dashboard certificate
func (b *DashboardCertsSecretBuilder) WithDashboardCert(cert []byte) *DashboardCertsSecretBuilder {
	b.data[constants.SecretKeyDashboardCert] = cert
	return b
}

// WithDashboardKey adds the dashboard private key
func (b *DashboardCertsSecretBuilder) WithDashboardKey(key []byte) *DashboardCertsSecretBuilder {
	b.data[constants.SecretKeyDashboardKey] = key
	return b
}

// WithData adds raw data entries
func (b *DashboardCertsSecretBuilder) WithData(data map[string][]byte) *DashboardCertsSecretBuilder {
	maps.Copy(b.data, data)
	return b
}

// Build creates the Secret
func (b *DashboardCertsSecretBuilder) Build() *corev1.Secret {
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
func (b *DashboardCertsSecretBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentDashboard, b.version)
	maps.Copy(labels, b.labels)
	return labels
}
