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

// Package secrets provides Kubernetes Secret builders for Wazuh components
package secrets

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

// ClusterKeySecretBuilder builds cluster key Secrets for Wazuh Manager cluster
type ClusterKeySecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	clusterKey  string
	labels      map[string]string
	annotations map[string]string
}

// NewClusterKeySecretBuilder creates a new ClusterKeySecretBuilder
func NewClusterKeySecretBuilder(clusterName, namespace string) *ClusterKeySecretBuilder {
	name := fmt.Sprintf("%s-cluster-key", clusterName)
	return &ClusterKeySecretBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ClusterKeySecretBuilder) WithVersion(version string) *ClusterKeySecretBuilder {
	b.version = version
	return b
}

// WithClusterKey sets the cluster key
func (b *ClusterKeySecretBuilder) WithClusterKey(key string) *ClusterKeySecretBuilder {
	b.clusterKey = key
	return b
}

// WithLabels adds custom labels
func (b *ClusterKeySecretBuilder) WithLabels(labels map[string]string) *ClusterKeySecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *ClusterKeySecretBuilder) WithAnnotations(annotations map[string]string) *ClusterKeySecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the Secret
func (b *ClusterKeySecretBuilder) Build() *corev1.Secret {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	for k, v := range b.labels {
		labels[k] = v
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyClusterKey: []byte(b.clusterKey),
		},
	}
}

// APICredentialsSecretBuilder builds API credentials Secrets for Wazuh Manager
type APICredentialsSecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	username    string
	password    string
	labels      map[string]string
	annotations map[string]string
}

// NewAPICredentialsSecretBuilder creates a new APICredentialsSecretBuilder
// Default credentials are the Wazuh default admin user
func NewAPICredentialsSecretBuilder(clusterName, namespace string) *APICredentialsSecretBuilder {
	name := fmt.Sprintf("%s-api-credentials", clusterName)
	return &APICredentialsSecretBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		username:    constants.DefaultWazuhAPIUsername,
		password:    constants.DefaultWazuhAPIPassword,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *APICredentialsSecretBuilder) WithVersion(version string) *APICredentialsSecretBuilder {
	b.version = version
	return b
}

// WithCredentials sets the API credentials
func (b *APICredentialsSecretBuilder) WithCredentials(username, password string) *APICredentialsSecretBuilder {
	b.username = username
	b.password = password
	return b
}

// WithLabels adds custom labels
func (b *APICredentialsSecretBuilder) WithLabels(labels map[string]string) *APICredentialsSecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *APICredentialsSecretBuilder) WithAnnotations(annotations map[string]string) *APICredentialsSecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the Secret
func (b *APICredentialsSecretBuilder) Build() *corev1.Secret {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	for k, v := range b.labels {
		labels[k] = v
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte(b.username),
			"password": []byte(b.password),
		},
	}
}
