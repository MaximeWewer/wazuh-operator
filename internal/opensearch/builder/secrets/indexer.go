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

// Package secrets provides Kubernetes Secret builders for OpenSearch components
package secrets

import (
	"fmt"

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
	name := fmt.Sprintf("%s-indexer-certs", clusterName)
	return &IndexerCertsSecretBuilder{
		name:        name,
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
	b.data["admin.crt"] = cert
	return b
}

// WithAdminKey adds the admin private key
func (b *IndexerCertsSecretBuilder) WithAdminKey(key []byte) *IndexerCertsSecretBuilder {
	b.data["admin.key"] = key
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

// IndexerSecuritySecretBuilder builds security configuration Secrets for OpenSearch Indexer
type IndexerSecuritySecretBuilder struct {
	name        string
	namespace   string
	clusterName string
	version     string
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
}

// NewIndexerSecuritySecretBuilder creates a new IndexerSecuritySecretBuilder
func NewIndexerSecuritySecretBuilder(clusterName, namespace string) *IndexerSecuritySecretBuilder {
	name := fmt.Sprintf("%s-indexer-security", clusterName)
	return &IndexerSecuritySecretBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string][]byte),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerSecuritySecretBuilder) WithVersion(version string) *IndexerSecuritySecretBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *IndexerSecuritySecretBuilder) WithLabels(labels map[string]string) *IndexerSecuritySecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerSecuritySecretBuilder) WithAnnotations(annotations map[string]string) *IndexerSecuritySecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithInternalUsers adds the internal_users.yml content
func (b *IndexerSecuritySecretBuilder) WithInternalUsers(content []byte) *IndexerSecuritySecretBuilder {
	b.data["internal_users.yml"] = content
	return b
}

// WithRoles adds the roles.yml content
func (b *IndexerSecuritySecretBuilder) WithRoles(content []byte) *IndexerSecuritySecretBuilder {
	b.data["roles.yml"] = content
	return b
}

// WithRolesMapping adds the roles_mapping.yml content
func (b *IndexerSecuritySecretBuilder) WithRolesMapping(content []byte) *IndexerSecuritySecretBuilder {
	b.data["roles_mapping.yml"] = content
	return b
}

// WithActionGroups adds the action_groups.yml content
func (b *IndexerSecuritySecretBuilder) WithActionGroups(content []byte) *IndexerSecuritySecretBuilder {
	b.data["action_groups.yml"] = content
	return b
}

// WithTenants adds the tenants.yml content
func (b *IndexerSecuritySecretBuilder) WithTenants(content []byte) *IndexerSecuritySecretBuilder {
	b.data["tenants.yml"] = content
	return b
}

// WithConfig adds the config.yml content
func (b *IndexerSecuritySecretBuilder) WithConfig(content []byte) *IndexerSecuritySecretBuilder {
	b.data["config.yml"] = content
	return b
}

// WithData adds raw data entries
func (b *IndexerSecuritySecretBuilder) WithData(data map[string][]byte) *IndexerSecuritySecretBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// Build creates the Secret
func (b *IndexerSecuritySecretBuilder) Build() *corev1.Secret {
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
func (b *IndexerSecuritySecretBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// IndexerCredentialsSecretBuilder builds credentials Secrets for OpenSearch Indexer
type IndexerCredentialsSecretBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	adminUsername  string
	adminPassword  string
	kibanaPassword string
	labels         map[string]string
	annotations    map[string]string
}

// NewIndexerCredentialsSecretBuilder creates a new IndexerCredentialsSecretBuilder
func NewIndexerCredentialsSecretBuilder(clusterName, namespace string) *IndexerCredentialsSecretBuilder {
	name := fmt.Sprintf("%s-indexer-credentials", clusterName)
	return &IndexerCredentialsSecretBuilder{
		name:          name,
		namespace:     namespace,
		clusterName:   clusterName,
		version:       constants.DefaultWazuhVersion,
		adminUsername: "admin",
		labels:        make(map[string]string),
		annotations:   make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerCredentialsSecretBuilder) WithVersion(version string) *IndexerCredentialsSecretBuilder {
	b.version = version
	return b
}

// WithAdminCredentials sets the admin credentials
func (b *IndexerCredentialsSecretBuilder) WithAdminCredentials(username, password string) *IndexerCredentialsSecretBuilder {
	b.adminUsername = username
	b.adminPassword = password
	return b
}

// WithKibanaPassword sets the kibanaserver password
func (b *IndexerCredentialsSecretBuilder) WithKibanaPassword(password string) *IndexerCredentialsSecretBuilder {
	b.kibanaPassword = password
	return b
}

// WithLabels adds custom labels
func (b *IndexerCredentialsSecretBuilder) WithLabels(labels map[string]string) *IndexerCredentialsSecretBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerCredentialsSecretBuilder) WithAnnotations(annotations map[string]string) *IndexerCredentialsSecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// Build creates the Secret
func (b *IndexerCredentialsSecretBuilder) Build() *corev1.Secret {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}

	data := map[string][]byte{
		constants.SecretKeyAdminUsername: []byte(b.adminUsername),
		constants.SecretKeyAdminPassword: []byte(b.adminPassword),
	}

	if b.kibanaPassword != "" {
		data["kibana-password"] = []byte(b.kibanaPassword)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

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
	name := fmt.Sprintf("%s-dashboard-certs", clusterName)
	return &DashboardCertsSecretBuilder{
		name:        name,
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
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *DashboardCertsSecretBuilder) WithAnnotations(annotations map[string]string) *DashboardCertsSecretBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithCACert adds the CA certificate
func (b *DashboardCertsSecretBuilder) WithCACert(cert []byte) *DashboardCertsSecretBuilder {
	b.data["root-ca.pem"] = cert
	return b
}

// WithDashboardCert adds the dashboard certificate
func (b *DashboardCertsSecretBuilder) WithDashboardCert(cert []byte) *DashboardCertsSecretBuilder {
	b.data["dashboard.pem"] = cert
	return b
}

// WithDashboardKey adds the dashboard private key
func (b *DashboardCertsSecretBuilder) WithDashboardKey(key []byte) *DashboardCertsSecretBuilder {
	b.data["dashboard-key.pem"] = key
	return b
}

// WithData adds raw data entries
func (b *DashboardCertsSecretBuilder) WithData(data map[string][]byte) *DashboardCertsSecretBuilder {
	for k, v := range data {
		b.data[k] = v
	}
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
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}
