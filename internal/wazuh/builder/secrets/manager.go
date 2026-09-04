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

// Package secrets provides Kubernetes Secret builders for Wazuh components
package secrets

import (
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

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
	maps.Copy(b.labels, labels)
	return b
}

// WithAnnotations adds custom annotations
func (b *ClusterKeySecretBuilder) WithAnnotations(annotations map[string]string) *ClusterKeySecretBuilder {
	maps.Copy(b.annotations, annotations)
	return b
}

// Build creates the Secret
func (b *ClusterKeySecretBuilder) Build() *corev1.Secret {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	maps.Copy(labels, b.labels)

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
// Default username is the Wazuh default admin user
// Password must be set explicitly via WithCredentials() - no default password for security
func NewAPICredentialsSecretBuilder(clusterName, namespace string) *APICredentialsSecretBuilder {
	name := fmt.Sprintf("%s-api-credentials", clusterName)
	return &APICredentialsSecretBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		username:    constants.DefaultWazuhAPIUsername,
		password:    "", // Must be set explicitly - no default for security
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
	maps.Copy(b.labels, labels)
	return b
}

// WithAnnotations adds custom annotations
func (b *APICredentialsSecretBuilder) WithAnnotations(annotations map[string]string) *APICredentialsSecretBuilder {
	maps.Copy(b.annotations, annotations)
	return b
}

// Build creates the Secret
func (b *APICredentialsSecretBuilder) Build() *corev1.Secret {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	maps.Copy(labels, b.labels)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyAPIUsername: []byte(b.username),
			constants.SecretKeyAPIPassword: []byte(b.password),
		},
	}
}
