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

package config

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// FilebeatTemplateBuilder builds the wazuh-template.json content
type FilebeatTemplateBuilder struct {
	shards             int32
	replicas           int32
	refreshInterval    string
	fieldLimit         int32
	additionalMappings json.RawMessage
}

// NewFilebeatTemplateBuilder creates a new FilebeatTemplateBuilder with defaults
func NewFilebeatTemplateBuilder() *FilebeatTemplateBuilder {
	return &FilebeatTemplateBuilder{
		shards:          constants.DefaultFilebeatTemplateShards,
		replicas:        constants.DefaultFilebeatTemplateReplicas,
		refreshInterval: constants.DefaultFilebeatTemplateRefreshInterval,
		fieldLimit:      constants.DefaultFilebeatTemplateFieldLimit,
	}
}

// WithShards sets the number of primary shards
func (b *FilebeatTemplateBuilder) WithShards(shards int32) *FilebeatTemplateBuilder {
	if shards > 0 {
		b.shards = shards
	}
	return b
}

// WithReplicas sets the number of replica shards
func (b *FilebeatTemplateBuilder) WithReplicas(replicas int32) *FilebeatTemplateBuilder {
	if replicas >= 0 {
		b.replicas = replicas
	}
	return b
}

// WithRefreshInterval sets the index refresh interval
func (b *FilebeatTemplateBuilder) WithRefreshInterval(interval string) *FilebeatTemplateBuilder {
	if interval != "" {
		b.refreshInterval = interval
	}
	return b
}

// WithFieldLimit sets the maximum number of fields per document
func (b *FilebeatTemplateBuilder) WithFieldLimit(limit int32) *FilebeatTemplateBuilder {
	if limit > 0 {
		b.fieldLimit = limit
	}
	return b
}

// WithAdditionalMappings adds custom field mappings to merge with defaults
func (b *FilebeatTemplateBuilder) WithAdditionalMappings(mappings json.RawMessage) *FilebeatTemplateBuilder {
	if len(mappings) > 0 {
		b.additionalMappings = mappings
	}
	return b
}

// Build generates the wazuh-template.json content as a string
func (b *FilebeatTemplateBuilder) Build() (string, error) {
	// Parse the default template
	var template map[string]interface{}
	if err := json.Unmarshal([]byte(DefaultWazuhTemplateJSON), &template); err != nil {
		return "", fmt.Errorf("failed to parse default template: %w", err)
	}

	// Update settings with builder values
	settings, ok := template["settings"].(map[string]interface{})
	if !ok {
		settings = make(map[string]interface{})
		template["settings"] = settings
	}

	settings["index.number_of_shards"] = fmt.Sprintf("%d", b.shards)
	settings["index.number_of_replicas"] = fmt.Sprintf("%d", b.replicas)
	settings["index.refresh_interval"] = b.refreshInterval
	settings["index.mapping.total_fields.limit"] = b.fieldLimit

	// Merge additional mappings if provided
	if len(b.additionalMappings) > 0 {
		if err := b.mergeAdditionalMappings(template); err != nil {
			return "", fmt.Errorf("failed to merge additional mappings: %w", err)
		}
	}

	// Marshal back to JSON
	result, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal template: %w", err)
	}

	return string(result), nil
}

// mergeAdditionalMappings merges custom mappings into the template
func (b *FilebeatTemplateBuilder) mergeAdditionalMappings(template map[string]interface{}) error {
	var additionalProps map[string]interface{}
	if err := json.Unmarshal(b.additionalMappings, &additionalProps); err != nil {
		return fmt.Errorf("failed to parse additional mappings: %w", err)
	}

	mappings, ok := template["mappings"].(map[string]interface{})
	if !ok {
		mappings = make(map[string]interface{})
		template["mappings"] = mappings
	}

	properties, ok := mappings["properties"].(map[string]interface{})
	if !ok {
		properties = make(map[string]interface{})
		mappings["properties"] = properties
	}

	// Merge additional properties
	for key, value := range additionalProps {
		properties[key] = value
	}

	return nil
}

// LoadCustomTemplate loads a custom template from a ConfigMap
// Returns the template content string or an error
func LoadCustomTemplate(ctx context.Context, c client.Client, namespace, configMapName, key string) (string, error) {
	configMap := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      configMapName,
	}, configMap); err != nil {
		return "", fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, configMapName, err)
	}

	content, ok := configMap.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in ConfigMap %s/%s", key, namespace, configMapName)
	}

	// Validate JSON
	var template map[string]interface{}
	if err := json.Unmarshal([]byte(content), &template); err != nil {
		return "", fmt.Errorf("invalid JSON in ConfigMap %s/%s key %q: %w", namespace, configMapName, key, err)
	}

	return content, nil
}

// GetDefaultTemplate returns the default Wazuh template JSON
func GetDefaultTemplate() string {
	return DefaultWazuhTemplateJSON
}

// GetDefaultTemplateVersion returns the version of the default template
func GetDefaultTemplateVersion() string {
	return DefaultWazuhTemplateVersion
}
