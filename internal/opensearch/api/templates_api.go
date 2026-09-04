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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
)

// TemplatesAPI provides index and component template operations
type TemplatesAPI struct {
	client *Client
}

// NewTemplatesAPI creates a new Templates API client
func NewTemplatesAPI(client *Client) *TemplatesAPI {
	return &TemplatesAPI{client: client}
}

// IndexTemplate represents an index template
type IndexTemplate struct {
	IndexPatterns   []string        `json:"index_patterns"`
	Template        *TemplateSpec   `json:"template,omitempty"`
	ComposedOf      []string        `json:"composed_of,omitempty"`
	Priority        int             `json:"priority,omitempty"`
	Version         int             `json:"version,omitempty"`
	Meta            map[string]any  `json:"_meta,omitempty"`
	DataStream      *DataStreamSpec `json:"data_stream,omitempty"`
	AllowAutoCreate *bool           `json:"allow_auto_create,omitempty"`
}

// TemplateSpec represents the template specification
type TemplateSpec struct {
	Settings map[string]any       `json:"settings,omitempty"`
	Mappings map[string]any       `json:"mappings,omitempty"`
	Aliases  map[string]AliasSpec `json:"aliases,omitempty"`
}

// AliasSpec represents an alias specification
type AliasSpec struct {
	Filter        map[string]any `json:"filter,omitempty"`
	IndexRouting  string         `json:"index_routing,omitempty"`
	SearchRouting string         `json:"search_routing,omitempty"`
	IsHidden      *bool          `json:"is_hidden,omitempty"`
	IsWriteIndex  *bool          `json:"is_write_index,omitempty"`
}

// DataStreamSpec represents data stream specification
type DataStreamSpec struct {
	Hidden             *bool `json:"hidden,omitempty"`
	AllowCustomRouting *bool `json:"allow_custom_routing,omitempty"`
}

// ComponentTemplate represents a component template
type ComponentTemplate struct {
	Template *ComponentTemplateSpec `json:"template"`
	Version  int                    `json:"version,omitempty"`
	Meta     map[string]any         `json:"_meta,omitempty"`
}

// ComponentTemplateSpec represents the component template specification
type ComponentTemplateSpec struct {
	Settings    map[string]any       `json:"settings,omitempty"`
	Mappings    map[string]any       `json:"mappings,omitempty"`
	Aliases     map[string]AliasSpec `json:"aliases,omitempty"`
	SettingsRaw json.RawMessage      `json:"-"`
	MappingsRaw json.RawMessage      `json:"-"`
}

// MarshalJSON implements custom JSON marshaling for ComponentTemplateSpec
func (s ComponentTemplateSpec) MarshalJSON() ([]byte, error) {
	result := make(map[string]any)

	// Use raw settings if provided
	if len(s.SettingsRaw) > 0 {
		var settings map[string]any
		if err := json.Unmarshal(s.SettingsRaw, &settings); err == nil {
			result["settings"] = NormalizeIndexSettings(settings)
		}
	} else if s.Settings != nil {
		result["settings"] = NormalizeIndexSettings(s.Settings)
	}

	// Use raw mappings if provided
	if len(s.MappingsRaw) > 0 {
		var mappings any
		if err := json.Unmarshal(s.MappingsRaw, &mappings); err == nil {
			result["mappings"] = mappings
		}
	} else if s.Mappings != nil {
		result["mappings"] = s.Mappings
	}

	if s.Aliases != nil {
		result["aliases"] = s.Aliases
	}

	return json.Marshal(result)
}

// camelToSnakeSettings maps known camelCase index setting keys to their OpenSearch snake_case equivalents.
var camelToSnakeSettings = map[string]string{
	"numberOfShards":        "number_of_shards",
	"numberOfReplicas":      "number_of_replicas",
	"numberOfRoutingShards": "number_of_routing_shards",
	"refreshInterval":       "refresh_interval",
	"maxResultWindow":       "max_result_window",
	"autoExpandReplicas":    "auto_expand_replicas",
}

// NormalizeIndexSettings converts known camelCase shorthand settings keys to their
// OpenSearch snake_case equivalents, wrapping them under an "index" object.
// Keys already in snake_case or under "index" are passed through unchanged.
func NormalizeIndexSettings(settings map[string]any) map[string]any {
	if len(settings) == 0 {
		return settings
	}

	result := make(map[string]any, len(settings))
	indexSettings := map[string]any{}

	// Check if there's already an "index" key
	if existing, ok := settings["index"]; ok {
		if m, ok := existing.(map[string]any); ok {
			maps.Copy(indexSettings, m)
		}
	}

	for key, value := range settings {
		if key == "index" {
			continue // already handled above
		}
		if snakeKey, ok := camelToSnakeSettings[key]; ok {
			indexSettings[snakeKey] = value
		} else {
			result[key] = value
		}
	}

	if len(indexSettings) > 0 {
		result["index"] = indexSettings
	}

	return result
}

// CreateIndexTemplate creates a new index template
func (a *TemplatesAPI) CreateIndexTemplate(ctx context.Context, name string, template IndexTemplate) error {
	resp, err := a.client.Put(ctx, fmt.Sprintf("/_index_template/%s", name), template)
	if err != nil {
		return fmt.Errorf("failed to create index template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create index template: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetIndexTemplate retrieves an index template
func (a *TemplatesAPI) GetIndexTemplate(ctx context.Context, name string) (*IndexTemplate, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_index_template/%s", name))
	if err != nil {
		return nil, fmt.Errorf("failed to get index template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get index template: status %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		IndexTemplates []struct {
			Name          string        `json:"name"`
			IndexTemplate IndexTemplate `json:"index_template"`
		} `json:"index_templates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode index template: %w", err)
	}

	if len(result.IndexTemplates) == 0 {
		return nil, nil
	}

	return &result.IndexTemplates[0].IndexTemplate, nil
}

// DeleteIndexTemplate deletes an index template
func (a *TemplatesAPI) DeleteIndexTemplate(ctx context.Context, name string) error {
	resp, err := a.client.Delete(ctx, fmt.Sprintf("/_index_template/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete index template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete index template: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// IndexTemplateExists checks if an index template exists
func (a *TemplatesAPI) IndexTemplateExists(ctx context.Context, name string) (bool, error) {
	template, err := a.GetIndexTemplate(ctx, name)
	if err != nil {
		return false, err
	}
	return template != nil, nil
}

// CreateComponentTemplate creates a new component template
func (a *TemplatesAPI) CreateComponentTemplate(ctx context.Context, name string, template ComponentTemplate) error {
	resp, err := a.client.Put(ctx, fmt.Sprintf("/_component_template/%s", name), template)
	if err != nil {
		return fmt.Errorf("failed to create component template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create component template: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetComponentTemplate retrieves a component template
func (a *TemplatesAPI) GetComponentTemplate(ctx context.Context, name string) (*ComponentTemplate, error) {
	resp, err := a.client.Get(ctx, fmt.Sprintf("/_component_template/%s", name))
	if err != nil {
		return nil, fmt.Errorf("failed to get component template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get component template: status %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ComponentTemplates []struct {
			Name              string            `json:"name"`
			ComponentTemplate ComponentTemplate `json:"component_template"`
		} `json:"component_templates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode component template: %w", err)
	}

	if len(result.ComponentTemplates) == 0 {
		return nil, nil
	}

	return &result.ComponentTemplates[0].ComponentTemplate, nil
}

// DeleteComponentTemplate deletes a component template
func (a *TemplatesAPI) DeleteComponentTemplate(ctx context.Context, name string) error {
	resp, err := a.client.Delete(ctx, fmt.Sprintf("/_component_template/%s", name))
	if err != nil {
		return fmt.Errorf("failed to delete component template: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete component template: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ComponentTemplateExists checks if a component template exists
func (a *TemplatesAPI) ComponentTemplateExists(ctx context.Context, name string) (bool, error) {
	template, err := a.GetComponentTemplate(ctx, name)
	if err != nil {
		return false, err
	}
	return template != nil, nil
}
