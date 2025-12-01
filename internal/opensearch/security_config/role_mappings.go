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

// RoleMappingBuilder builds OpenSearch role mappings
type RoleMappingBuilder struct {
	roleName     string
	description  string
	backendRoles []string
	hosts        []string
	users        []string
}

// NewRoleMappingBuilder creates a new RoleMappingBuilder
func NewRoleMappingBuilder(roleName string) *RoleMappingBuilder {
	return &RoleMappingBuilder{
		roleName:     roleName,
		backendRoles: []string{},
		hosts:        []string{},
		users:        []string{},
	}
}

// WithDescription sets the description
func (b *RoleMappingBuilder) WithDescription(description string) *RoleMappingBuilder {
	b.description = description
	return b
}

// WithBackendRoles sets backend roles
func (b *RoleMappingBuilder) WithBackendRoles(roles ...string) *RoleMappingBuilder {
	b.backendRoles = append(b.backendRoles, roles...)
	return b
}

// WithHosts sets hosts
func (b *RoleMappingBuilder) WithHosts(hosts ...string) *RoleMappingBuilder {
	b.hosts = append(b.hosts, hosts...)
	return b
}

// WithUsers sets users
func (b *RoleMappingBuilder) WithUsers(users ...string) *RoleMappingBuilder {
	b.users = append(b.users, users...)
	return b
}

// Build builds the role mapping configuration
func (b *RoleMappingBuilder) Build() map[string]interface{} {
	mapping := map[string]interface{}{
		"description": b.description,
	}

	if len(b.backendRoles) > 0 {
		mapping["backend_roles"] = b.backendRoles
	}
	if len(b.hosts) > 0 {
		mapping["hosts"] = b.hosts
	}
	if len(b.users) > 0 {
		mapping["users"] = b.users
	}

	return mapping
}

// DefaultWazuhRoleMappings returns default Wazuh role mappings
func DefaultWazuhRoleMappings() map[string]map[string]interface{} {
	mappings := make(map[string]map[string]interface{})

	// Map admin user to all_access
	allAccess := NewRoleMappingBuilder("all_access").
		WithDescription("Maps admin user to all_access role").
		WithUsers("admin").
		Build()
	mappings["all_access"] = allAccess

	// Map kibanaserver user
	kibanaServer := NewRoleMappingBuilder("kibana_server").
		WithDescription("Maps kibanaserver user").
		WithUsers("kibanaserver").
		Build()
	mappings["kibana_server"] = kibanaServer

	return mappings
}
