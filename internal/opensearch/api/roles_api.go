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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Role represents an OpenSearch security role
type Role struct {
	Reserved           bool               `json:"reserved,omitempty"`
	Hidden             bool               `json:"hidden,omitempty"`
	Description        string             `json:"description,omitempty"`
	ClusterPermissions []string           `json:"cluster_permissions,omitempty"`
	IndexPermissions   []IndexPermission  `json:"index_permissions,omitempty"`
	TenantPermissions  []TenantPermission `json:"tenant_permissions,omitempty"`
}

// IndexPermission represents index-level permissions
type IndexPermission struct {
	IndexPatterns         []string `json:"index_patterns"`
	DocumentLevelSecurity string   `json:"dls,omitempty"`
	FieldLevelSecurity    []string `json:"fls,omitempty"`
	MaskedFields          []string `json:"masked_fields,omitempty"`
	AllowedActions        []string `json:"allowed_actions"`
}

// TenantPermission represents tenant-level permissions
type TenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// RolesAPI provides role management operations
type RolesAPI struct {
	client *Client
}

// NewRolesAPI creates a new RolesAPI
func NewRolesAPI(client *Client) *RolesAPI {
	return &RolesAPI{client: client}
}

// Create creates a new role
func (a *RolesAPI) Create(ctx context.Context, roleName string, role Role) error {
	resp, err := a.client.Put(ctx, "/_plugins/_security/api/roles/"+roleName, role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role: %s", string(body))
	}

	return nil
}

// Get retrieves a role
func (a *RolesAPI) Get(ctx context.Context, roleName string) (*Role, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/roles/"+roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get role: %s", string(body))
	}

	var roles map[string]Role
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode role: %w", err)
	}

	if role, ok := roles[roleName]; ok {
		return &role, nil
	}

	return nil, nil
}

// Delete deletes a role
func (a *RolesAPI) Delete(ctx context.Context, roleName string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_security/api/roles/"+roleName)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete role: %s", string(body))
	}

	return nil
}

// List lists all roles
func (a *RolesAPI) List(ctx context.Context) (map[string]Role, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/roles")
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list roles: %s", string(body))
	}

	var roles map[string]Role
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles: %w", err)
	}

	return roles, nil
}
