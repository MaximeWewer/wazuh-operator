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
	"fmt"
	"strings"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexPermission represents permissions for index patterns
type IndexPermission struct {
	// IndexPatterns are the index patterns this permission applies to
	IndexPatterns []string
	// AllowedActions are the actions allowed on these indices
	AllowedActions []string
	// DocumentLevelSecurity is the DLS query (optional)
	DocumentLevelSecurity string
	// FieldLevelSecurity defines field-level permissions (optional)
	FieldLevelSecurity *FieldLevelSecurity
}

// FieldLevelSecurity defines field-level security settings
type FieldLevelSecurity struct {
	// Include lists fields to include
	Include []string
	// Exclude lists fields to exclude
	Exclude []string
}

// TenantPermission represents tenant access permissions
type TenantPermission struct {
	// TenantPatterns are the tenant patterns
	TenantPatterns []string
	// AllowedActions are the actions allowed (e.g., "kibana_all_read", "kibana_all_write")
	AllowedActions []string
}

// Role represents an OpenSearch security role
type Role struct {
	// Name is the role identifier
	Name string
	// Reserved marks the role as reserved
	Reserved bool
	// Hidden hides the role from API responses
	Hidden bool
	// Description is a human-readable description
	Description string
	// ClusterPermissions are cluster-level permissions
	ClusterPermissions []string
	// IndexPermissions are index-level permissions
	IndexPermissions []IndexPermission
	// TenantPermissions are tenant-level permissions
	TenantPermissions []TenantPermission
}

// RolesConfig holds the configuration for roles.yml
type RolesConfig struct {
	Roles []Role
}

// DefaultRolesConfig returns a default roles configuration for Wazuh
func DefaultRolesConfig() *RolesConfig {
	return &RolesConfig{
		Roles: []Role{
			// Wazuh specific roles
			{
				Name:        "wazuh_admin",
				Reserved:    false,
				Description: "Wazuh administrator role with full access",
				ClusterPermissions: []string{
					"cluster_all",
				},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns:  []string{"wazuh-*"},
						AllowedActions: []string{"indices_all"},
					},
				},
			},
			{
				Name:        "wazuh_user",
				Reserved:    false,
				Description: "Wazuh user role with read access to alerts",
				ClusterPermissions: []string{
					"cluster_monitor",
				},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns:  []string{"wazuh-alerts-*"},
						AllowedActions: []string{"read", "search"},
					},
					{
						IndexPatterns:  []string{"wazuh-monitoring-*"},
						AllowedActions: []string{"read", "search"},
					},
				},
			},
			// Standard OpenSearch roles
			{
				Name:               "all_access",
				Reserved:           true,
				Hidden:             false,
				Description:        "Allow full access to all indices and all cluster permissions",
				ClusterPermissions: []string{"*"},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns:  []string{"*"},
						AllowedActions: []string{"*"},
					},
				},
				TenantPermissions: []TenantPermission{
					{
						TenantPatterns: []string{"*"},
						AllowedActions: []string{"kibana_all_write"},
					},
				},
			},
			{
				Name:        "readall",
				Reserved:    true,
				Hidden:      false,
				Description: "Provide read-only access to all indices",
				ClusterPermissions: []string{
					"cluster_composite_ops_ro",
				},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns:  []string{"*"},
						AllowedActions: []string{"read"},
					},
				},
			},
			{
				Name:        "kibana_user",
				Reserved:    true,
				Hidden:      false,
				Description: "Provide the minimum permissions for a kibana user",
				ClusterPermissions: []string{
					"cluster_composite_ops",
				},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns: []string{
							".kibana",
							".kibana-*",
							constants.IndexOpenSearchDashboards,
							constants.IndexOpenSearchDashboardsWildcard,
						},
						AllowedActions: []string{
							"read",
							"delete",
							"manage",
							"index",
						},
					},
					{
						IndexPatterns:  []string{".tasks", ".management-beats"},
						AllowedActions: []string{"indices_all"},
					},
				},
			},
			{
				Name:        "kibana_server",
				Reserved:    true,
				Hidden:      false,
				Description: "Provide the minimum permissions for the Kibana server",
				ClusterPermissions: []string{
					"cluster_monitor",
					"cluster_composite_ops",
					"manage_index_templates",
					"manage_point_in_time",
				},
				IndexPermissions: []IndexPermission{
					{
						IndexPatterns: []string{
							".kibana",
							".kibana-*",
							constants.IndexOpenSearchDashboards,
							constants.IndexOpenSearchDashboardsWildcard,
						},
						AllowedActions: []string{"indices_all"},
					},
					{
						IndexPatterns:  []string{".tasks", ".management-beats", "*:.tasks", "*:.management-beats"},
						AllowedActions: []string{"indices_all"},
					},
				},
			},
		},
	}
}

// NewRolesConfig creates a new empty RolesConfig
func NewRolesConfig() *RolesConfig {
	return &RolesConfig{
		Roles: make([]Role, 0),
	}
}

// AddRole adds a role to the configuration
func (c *RolesConfig) AddRole(role Role) *RolesConfig {
	c.Roles = append(c.Roles, role)
	return c
}

// Build generates the roles.yml content
func (c *RolesConfig) Build() string {
	var sb strings.Builder

	sb.WriteString("# OpenSearch Roles Configuration\n")
	sb.WriteString("# Generated by Wazuh Operator\n")
	sb.WriteString("---\n")
	sb.WriteString("_meta:\n")
	sb.WriteString("  type: \"roles\"\n")
	sb.WriteString("  config_version: 2\n\n")

	for _, role := range c.Roles {
		sb.WriteString(fmt.Sprintf("%s:\n", role.Name))

		if role.Reserved {
			sb.WriteString("  reserved: true\n")
		}

		if role.Hidden {
			sb.WriteString("  hidden: true\n")
		}

		if role.Description != "" {
			sb.WriteString(fmt.Sprintf("  description: \"%s\"\n", role.Description))
		}

		if len(role.ClusterPermissions) > 0 {
			sb.WriteString("  cluster_permissions:\n")
			for _, perm := range role.ClusterPermissions {
				sb.WriteString(fmt.Sprintf("    - \"%s\"\n", perm))
			}
		}

		if len(role.IndexPermissions) > 0 {
			sb.WriteString("  index_permissions:\n")
			for _, ip := range role.IndexPermissions {
				sb.WriteString("    - index_patterns:\n")
				for _, pattern := range ip.IndexPatterns {
					sb.WriteString(fmt.Sprintf("        - \"%s\"\n", pattern))
				}
				if len(ip.AllowedActions) > 0 {
					sb.WriteString("      allowed_actions:\n")
					for _, action := range ip.AllowedActions {
						sb.WriteString(fmt.Sprintf("        - \"%s\"\n", action))
					}
				}
				if ip.DocumentLevelSecurity != "" {
					sb.WriteString(fmt.Sprintf("      dls: \"%s\"\n", ip.DocumentLevelSecurity))
				}
				if ip.FieldLevelSecurity != nil {
					sb.WriteString("      fls:\n")
					if len(ip.FieldLevelSecurity.Include) > 0 {
						for _, field := range ip.FieldLevelSecurity.Include {
							sb.WriteString(fmt.Sprintf("        - \"%s\"\n", field))
						}
					}
					if len(ip.FieldLevelSecurity.Exclude) > 0 {
						for _, field := range ip.FieldLevelSecurity.Exclude {
							sb.WriteString(fmt.Sprintf("        - \"~%s\"\n", field))
						}
					}
				}
			}
		}

		if len(role.TenantPermissions) > 0 {
			sb.WriteString("  tenant_permissions:\n")
			for _, tp := range role.TenantPermissions {
				sb.WriteString("    - tenant_patterns:\n")
				for _, pattern := range tp.TenantPatterns {
					sb.WriteString(fmt.Sprintf("        - \"%s\"\n", pattern))
				}
				if len(tp.AllowedActions) > 0 {
					sb.WriteString("      allowed_actions:\n")
					for _, action := range tp.AllowedActions {
						sb.WriteString(fmt.Sprintf("        - \"%s\"\n", action))
					}
				}
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// BuildRoles is a convenience function to build default roles.yml
func BuildRoles() string {
	return DefaultRolesConfig().Build()
}
