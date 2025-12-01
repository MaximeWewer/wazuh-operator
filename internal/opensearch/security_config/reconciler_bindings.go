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

// Package security_config provides security configuration management for OpenSearch
package security_config

import (
	"context"
	"fmt"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// ReconcilerBinding provides security reconciliation for OpenSearch
type ReconcilerBinding struct {
	client *api.Client
}

// NewReconcilerBinding creates a new ReconcilerBinding
func NewReconcilerBinding(client *api.Client) *ReconcilerBinding {
	return &ReconcilerBinding{
		client: client,
	}
}

// ReconcileDefaultSecurityConfig reconciles the default security configuration
func (r *ReconcilerBinding) ReconcileDefaultSecurityConfig(ctx context.Context) error {
	// Reconcile default roles
	roles := DefaultWazuhRoles()
	rolesAPI := api.NewRolesAPI(r.client)
	for name, role := range roles {
		osRole := api.Role{
			Description:        role["description"].(string),
			ClusterPermissions: toStringSlice(role["cluster_permissions"]),
		}
		if err := rolesAPI.Create(ctx, name, osRole); err != nil {
			return fmt.Errorf("failed to create role %s: %w", name, err)
		}
	}

	// Reconcile default role mappings
	mappings := DefaultWazuhRoleMappings()
	securityAPI := api.NewSecurityAPI(r.client)
	for name, mapping := range mappings {
		osMapping := api.RoleMapping{
			Description: mapping["description"].(string),
			Users:       toStringSlice(mapping["users"]),
		}
		if err := securityAPI.CreateRoleMapping(ctx, name, osMapping); err != nil {
			return fmt.Errorf("failed to create role mapping %s: %w", name, err)
		}
	}

	// Reconcile default action groups
	actionGroups := DefaultWazuhActionGroups()
	for name, ag := range actionGroups {
		osAG := api.ActionGroup{
			Description:    ag["description"].(string),
			AllowedActions: toStringSlice(ag["allowed_actions"]),
			Type:           ag["type"].(string),
		}
		if err := securityAPI.CreateActionGroup(ctx, name, osAG); err != nil {
			return fmt.Errorf("failed to create action group %s: %w", name, err)
		}
	}

	// Reconcile default tenants
	tenants := DefaultWazuhTenants()
	for name, tenant := range tenants {
		osTenant := api.Tenant{
			Description: tenant["description"].(string),
		}
		if err := securityAPI.CreateTenant(ctx, name, osTenant); err != nil {
			return fmt.Errorf("failed to create tenant %s: %w", name, err)
		}
	}

	return nil
}

// toStringSlice converts an interface to []string
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if slice, ok := v.([]string); ok {
		return slice
	}
	if slice, ok := v.([]interface{}); ok {
		result := make([]string, len(slice))
		for i, item := range slice {
			result[i] = item.(string)
		}
		return result
	}
	return nil
}
