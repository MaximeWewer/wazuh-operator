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

// Package configmaps provides Kubernetes ConfigMap builders for OpenSearch components
package configmaps

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerConfigMapBuilder builds ConfigMaps for OpenSearch Indexer
type IndexerConfigMapBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	data           map[string]string
	binaryData     map[string][]byte
	labels         map[string]string
	annotations    map[string]string
	opensearchYML  string
	securityConfig string
	internalUsers  string
	roles          string
	rolesMapping   string
	actionGroups   string
	tenants        string
	// Auth config from CRD
	authConfig      *v1alpha1.OpenSearchAuthConfigSpec
	resolvedSecrets map[string]string
}

// NewIndexerConfigMapBuilder creates a new IndexerConfigMapBuilder
func NewIndexerConfigMapBuilder(clusterName, namespace string) *IndexerConfigMapBuilder {
	name := fmt.Sprintf("%s-indexer-config", clusterName)
	return &IndexerConfigMapBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		data:        make(map[string]string),
		binaryData:  make(map[string][]byte),
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerConfigMapBuilder) WithVersion(version string) *IndexerConfigMapBuilder {
	b.version = version
	return b
}

// WithLabels adds custom labels
func (b *IndexerConfigMapBuilder) WithLabels(labels map[string]string) *IndexerConfigMapBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *IndexerConfigMapBuilder) WithAnnotations(annotations map[string]string) *IndexerConfigMapBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithOpenSearchYML sets the opensearch.yml content
func (b *IndexerConfigMapBuilder) WithOpenSearchYML(config string) *IndexerConfigMapBuilder {
	b.opensearchYML = config
	return b
}

// WithSecurityConfig sets the security config content
func (b *IndexerConfigMapBuilder) WithSecurityConfig(config string) *IndexerConfigMapBuilder {
	b.securityConfig = config
	return b
}

// WithInternalUsers sets the internal_users.yml content
func (b *IndexerConfigMapBuilder) WithInternalUsers(config string) *IndexerConfigMapBuilder {
	b.internalUsers = config
	return b
}

// WithRoles sets the roles.yml content
func (b *IndexerConfigMapBuilder) WithRoles(config string) *IndexerConfigMapBuilder {
	b.roles = config
	return b
}

// WithRolesMapping sets the roles_mapping.yml content
func (b *IndexerConfigMapBuilder) WithRolesMapping(config string) *IndexerConfigMapBuilder {
	b.rolesMapping = config
	return b
}

// WithActionGroups sets the action_groups.yml content
func (b *IndexerConfigMapBuilder) WithActionGroups(config string) *IndexerConfigMapBuilder {
	b.actionGroups = config
	return b
}

// WithTenants sets the tenants.yml content
func (b *IndexerConfigMapBuilder) WithTenants(config string) *IndexerConfigMapBuilder {
	b.tenants = config
	return b
}

// WithAuthConfig sets the authentication configuration from CRD
// This will be used to generate the security config.yml
func (b *IndexerConfigMapBuilder) WithAuthConfig(authConfig *v1alpha1.OpenSearchAuthConfigSpec) *IndexerConfigMapBuilder {
	b.authConfig = authConfig
	return b
}

// WithResolvedSecrets sets the resolved secrets for auth config
// Keys: "oidc_client_secret", "saml_exchange_key", "ldap_bind_password"
func (b *IndexerConfigMapBuilder) WithResolvedSecrets(secrets map[string]string) *IndexerConfigMapBuilder {
	b.resolvedSecrets = secrets
	return b
}

// BuildSecurityConfigFromAuth generates security config.yml from auth configuration
func (b *IndexerConfigMapBuilder) BuildSecurityConfigFromAuth() string {
	if b.authConfig == nil {
		// Return default security config if no auth config provided
		return config.BuildSecurityConfig()
	}

	builder := config.NewAuthConfigBuilder(b.authConfig)
	for key, value := range b.resolvedSecrets {
		builder.WithSecret(key, value)
	}
	return builder.BuildSecurityConfig()
}

// WithData adds raw data entries
func (b *IndexerConfigMapBuilder) WithData(data map[string]string) *IndexerConfigMapBuilder {
	for k, v := range data {
		b.data[k] = v
	}
	return b
}

// WithBinaryData adds binary data entries
func (b *IndexerConfigMapBuilder) WithBinaryData(data map[string][]byte) *IndexerConfigMapBuilder {
	for k, v := range data {
		b.binaryData[k] = v
	}
	return b
}

// Build creates the ConfigMap
func (b *IndexerConfigMapBuilder) Build() *corev1.ConfigMap {
	labels := b.buildLabels()

	// Build data map
	data := make(map[string]string)

	// Add opensearch.yml if provided
	if b.opensearchYML != "" {
		data["opensearch.yml"] = b.opensearchYML
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
func (b *IndexerConfigMapBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}
