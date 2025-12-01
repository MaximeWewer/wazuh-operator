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

// Package security_config provides security configuration builders for OpenSearch
package security_config

// RoleBuilder builds OpenSearch security roles
type RoleBuilder struct {
	name               string
	description        string
	clusterPermissions []string
	indexPermissions   []IndexPermission
	tenantPermissions  []TenantPermission
}

// IndexPermission represents permissions for an index pattern
type IndexPermission struct {
	IndexPatterns  []string
	AllowedActions []string
	DLS            string
	FLS            []string
	MaskedFields   []string
}

// TenantPermission represents permissions for a tenant
type TenantPermission struct {
	TenantPatterns []string
	AllowedActions []string
}

// NewRoleBuilder creates a new RoleBuilder
func NewRoleBuilder(name string) *RoleBuilder {
	return &RoleBuilder{
		name:               name,
		clusterPermissions: []string{},
		indexPermissions:   []IndexPermission{},
		tenantPermissions:  []TenantPermission{},
	}
}

// WithDescription sets the description
func (b *RoleBuilder) WithDescription(description string) *RoleBuilder {
	b.description = description
	return b
}

// WithClusterPermissions sets cluster permissions
func (b *RoleBuilder) WithClusterPermissions(permissions ...string) *RoleBuilder {
	b.clusterPermissions = append(b.clusterPermissions, permissions...)
	return b
}

// WithIndexPermission adds an index permission
func (b *RoleBuilder) WithIndexPermission(perm IndexPermission) *RoleBuilder {
	b.indexPermissions = append(b.indexPermissions, perm)
	return b
}

// WithTenantPermission adds a tenant permission
func (b *RoleBuilder) WithTenantPermission(perm TenantPermission) *RoleBuilder {
	b.tenantPermissions = append(b.tenantPermissions, perm)
	return b
}

// Build builds the role configuration
func (b *RoleBuilder) Build() map[string]interface{} {
	role := map[string]interface{}{
		"description":         b.description,
		"cluster_permissions": b.clusterPermissions,
	}

	if len(b.indexPermissions) > 0 {
		indexPerms := make([]map[string]interface{}, len(b.indexPermissions))
		for i, perm := range b.indexPermissions {
			indexPerms[i] = map[string]interface{}{
				"index_patterns":  perm.IndexPatterns,
				"allowed_actions": perm.AllowedActions,
			}
			if perm.DLS != "" {
				indexPerms[i]["dls"] = perm.DLS
			}
			if len(perm.FLS) > 0 {
				indexPerms[i]["fls"] = perm.FLS
			}
			if len(perm.MaskedFields) > 0 {
				indexPerms[i]["masked_fields"] = perm.MaskedFields
			}
		}
		role["index_permissions"] = indexPerms
	}

	if len(b.tenantPermissions) > 0 {
		tenantPerms := make([]map[string]interface{}, len(b.tenantPermissions))
		for i, perm := range b.tenantPermissions {
			tenantPerms[i] = map[string]interface{}{
				"tenant_patterns": perm.TenantPatterns,
				"allowed_actions": perm.AllowedActions,
			}
		}
		role["tenant_permissions"] = tenantPerms
	}

	return role
}

// DefaultWazuhRoles returns the default Wazuh roles
func DefaultWazuhRoles() map[string]map[string]interface{} {
	roles := make(map[string]map[string]interface{})

	// Wazuh admin role
	wazuhAdmin := NewRoleBuilder("wazuh_admin").
		WithDescription("Wazuh administrator role").
		WithClusterPermissions("cluster_all").
		WithIndexPermission(IndexPermission{
			IndexPatterns:  []string{"wazuh-*"},
			AllowedActions: []string{"indices_all"},
		}).
		Build()
	roles["wazuh_admin"] = wazuhAdmin

	// Wazuh read-only role
	wazuhReadonly := NewRoleBuilder("wazuh_readonly").
		WithDescription("Wazuh read-only role").
		WithClusterPermissions("cluster_composite_ops_ro").
		WithIndexPermission(IndexPermission{
			IndexPatterns:  []string{"wazuh-*"},
			AllowedActions: []string{"read"},
		}).
		Build()
	roles["wazuh_readonly"] = wazuhReadonly

	return roles
}
