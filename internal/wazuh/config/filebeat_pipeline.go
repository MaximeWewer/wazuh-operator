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

// FilebeatPipelineBuilder builds the pipeline.json content
type FilebeatPipelineBuilder struct {
	geoipEnabled           bool
	indexPrefix            string
	additionalRemoveFields []string
	timestampFormat        string
}

// NewFilebeatPipelineBuilder creates a new FilebeatPipelineBuilder with defaults
func NewFilebeatPipelineBuilder() *FilebeatPipelineBuilder {
	return &FilebeatPipelineBuilder{
		geoipEnabled:           true,
		indexPrefix:            constants.DefaultFilebeatIndexPrefix,
		additionalRemoveFields: []string{},
		timestampFormat:        constants.DefaultFilebeatTimestampFormat,
	}
}

// WithGeoIPEnabled enables or disables GeoIP enrichment processors
func (b *FilebeatPipelineBuilder) WithGeoIPEnabled(enabled bool) *FilebeatPipelineBuilder {
	b.geoipEnabled = enabled
	return b
}

// WithIndexPrefix sets the index name prefix for date_index_name processor
func (b *FilebeatPipelineBuilder) WithIndexPrefix(prefix string) *FilebeatPipelineBuilder {
	if prefix != "" {
		b.indexPrefix = prefix
	}
	return b
}

// WithAdditionalRemoveFields adds extra fields to remove in the pipeline
func (b *FilebeatPipelineBuilder) WithAdditionalRemoveFields(fields []string) *FilebeatPipelineBuilder {
	if len(fields) > 0 {
		b.additionalRemoveFields = fields
	}
	return b
}

// WithTimestampFormat sets the timestamp format for date parsing
func (b *FilebeatPipelineBuilder) WithTimestampFormat(format string) *FilebeatPipelineBuilder {
	if format != "" {
		b.timestampFormat = format
	}
	return b
}

// Build generates the pipeline.json content as a string
func (b *FilebeatPipelineBuilder) Build() (string, error) {
	// Parse the default pipeline
	var pipeline map[string]interface{}
	if err := json.Unmarshal([]byte(DefaultWazuhPipelineJSON), &pipeline); err != nil {
		return "", fmt.Errorf("failed to parse default pipeline: %w", err)
	}

	processors, ok := pipeline["processors"].([]interface{})
	if !ok {
		return "", fmt.Errorf("invalid pipeline structure: processors not found")
	}

	// Filter out GeoIP processors if disabled
	if !b.geoipEnabled {
		processors = b.filterGeoIPProcessors(processors)
	}

	// Update date_index_name processor with custom index prefix
	processors = b.updateIndexPrefix(processors)

	// Update timestamp format in date processor
	processors = b.updateTimestampFormat(processors)

	// Add additional remove fields
	processors = b.updateRemoveFields(processors)

	pipeline["processors"] = processors

	// Marshal back to JSON
	result, err := json.MarshalIndent(pipeline, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal pipeline: %w", err)
	}

	return string(result), nil
}

// filterGeoIPProcessors removes all GeoIP processors from the pipeline
func (b *FilebeatPipelineBuilder) filterGeoIPProcessors(processors []interface{}) []interface{} {
	filtered := make([]interface{}, 0, len(processors))
	for _, p := range processors {
		proc, ok := p.(map[string]interface{})
		if !ok {
			filtered = append(filtered, p)
			continue
		}
		// Skip GeoIP processors
		if _, hasGeoIP := proc["geoip"]; hasGeoIP {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// updateIndexPrefix updates the date_index_name processor with the custom index prefix
func (b *FilebeatPipelineBuilder) updateIndexPrefix(processors []interface{}) []interface{} {
	for _, p := range processors {
		proc, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if dateIndexName, ok := proc["date_index_name"].(map[string]interface{}); ok {
			dateIndexName["index_name_prefix"] = b.indexPrefix + "-"
		}
	}
	return processors
}

// updateTimestampFormat updates the date processor with the custom timestamp format
func (b *FilebeatPipelineBuilder) updateTimestampFormat(processors []interface{}) []interface{} {
	for _, p := range processors {
		proc, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if date, ok := proc["date"].(map[string]interface{}); ok {
			date["formats"] = []string{b.timestampFormat}
		}
		if dateIndexName, ok := proc["date_index_name"].(map[string]interface{}); ok {
			dateIndexName["date_formats"] = []string{b.timestampFormat}
		}
	}
	return processors
}

// updateRemoveFields adds additional fields to the remove processor
func (b *FilebeatPipelineBuilder) updateRemoveFields(processors []interface{}) []interface{} {
	if len(b.additionalRemoveFields) == 0 {
		return processors
	}

	for _, p := range processors {
		proc, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if remove, ok := proc["remove"].(map[string]interface{}); ok {
			existingFields, _ := remove["field"].([]interface{})
			// Convert to string slice and add new fields
			fields := make([]string, 0, len(existingFields)+len(b.additionalRemoveFields))
			for _, f := range existingFields {
				if s, ok := f.(string); ok {
					fields = append(fields, s)
				}
			}
			fields = append(fields, b.additionalRemoveFields...)
			remove["field"] = fields
		}
	}
	return processors
}

// LoadCustomPipeline loads a custom pipeline from a ConfigMap
// Returns the pipeline content string or an error
func LoadCustomPipeline(ctx context.Context, c client.Client, namespace, configMapName, key string) (string, error) {
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
	var pipeline map[string]interface{}
	if err := json.Unmarshal([]byte(content), &pipeline); err != nil {
		return "", fmt.Errorf("invalid JSON in ConfigMap %s/%s key %q: %w", namespace, configMapName, key, err)
	}

	return content, nil
}

// GetDefaultPipeline returns the default Wazuh pipeline JSON
func GetDefaultPipeline() string {
	return DefaultWazuhPipelineJSON
}

// GetDefaultPipelineVersion returns the version of the default pipeline
func GetDefaultPipelineVersion() string {
	return DefaultWazuhPipelineVersion
}
