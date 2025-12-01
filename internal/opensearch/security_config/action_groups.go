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

package security_config

// ActionGroupBuilder builds OpenSearch action groups
type ActionGroupBuilder struct {
	name           string
	description    string
	allowedActions []string
	groupType      string
}

// NewActionGroupBuilder creates a new ActionGroupBuilder
func NewActionGroupBuilder(name string) *ActionGroupBuilder {
	return &ActionGroupBuilder{
		name:           name,
		allowedActions: []string{},
		groupType:      "index",
	}
}

// WithDescription sets the description
func (b *ActionGroupBuilder) WithDescription(description string) *ActionGroupBuilder {
	b.description = description
	return b
}

// WithAllowedActions sets allowed actions
func (b *ActionGroupBuilder) WithAllowedActions(actions ...string) *ActionGroupBuilder {
	b.allowedActions = append(b.allowedActions, actions...)
	return b
}

// WithType sets the action group type (index or cluster)
func (b *ActionGroupBuilder) WithType(groupType string) *ActionGroupBuilder {
	b.groupType = groupType
	return b
}

// Build builds the action group configuration
func (b *ActionGroupBuilder) Build() map[string]interface{} {
	return map[string]interface{}{
		"description":     b.description,
		"allowed_actions": b.allowedActions,
		"type":            b.groupType,
	}
}

// DefaultWazuhActionGroups returns default Wazuh action groups
func DefaultWazuhActionGroups() map[string]map[string]interface{} {
	groups := make(map[string]map[string]interface{})

	// Wazuh alerts read action group
	alertsRead := NewActionGroupBuilder("wazuh_alerts_read").
		WithDescription("Read Wazuh alerts").
		WithType("index").
		WithAllowedActions(
			"indices:data/read/search",
			"indices:data/read/get",
			"indices:data/read/mget",
		).
		Build()
	groups["wazuh_alerts_read"] = alertsRead

	// Wazuh cluster read action group
	clusterRead := NewActionGroupBuilder("wazuh_cluster_read").
		WithDescription("Read Wazuh cluster info").
		WithType("cluster").
		WithAllowedActions(
			"cluster:monitor/health",
			"cluster:monitor/state",
		).
		Build()
	groups["wazuh_cluster_read"] = clusterRead

	return groups
}
