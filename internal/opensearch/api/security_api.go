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

// RoleMapping represents a role mapping
type RoleMapping struct {
	Reserved        bool     `json:"reserved,omitempty"`
	Hidden          bool     `json:"hidden,omitempty"`
	Description     string   `json:"description,omitempty"`
	BackendRoles    []string `json:"backend_roles,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	Users           []string `json:"users,omitempty"`
	AndBackendRoles []string `json:"and_backend_roles,omitempty"`
}

// Tenant represents a tenant
type Tenant struct {
	Reserved    bool   `json:"reserved,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
	Description string `json:"description,omitempty"`
}

// ActionGroup represents an action group
type ActionGroup struct {
	Reserved       bool     `json:"reserved,omitempty"`
	Hidden         bool     `json:"hidden,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
	Type           string   `json:"type,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// SecurityAPI provides security-related operations
type SecurityAPI struct {
	client *Client
}

// NewSecurityAPI creates a new SecurityAPI
func NewSecurityAPI(client *Client) *SecurityAPI {
	return &SecurityAPI{client: client}
}

// CreateRoleMapping creates a role mapping
func (a *SecurityAPI) CreateRoleMapping(ctx context.Context, roleName string, mapping RoleMapping) error {
	resp, err := a.client.Put(ctx, "/_plugins/_security/api/rolesmapping/"+roleName, mapping)
	if err != nil {
		return fmt.Errorf("failed to create role mapping: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create role mapping: %s", string(body))
	}

	return nil
}

// GetRoleMapping retrieves a role mapping
func (a *SecurityAPI) GetRoleMapping(ctx context.Context, roleName string) (*RoleMapping, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/rolesmapping/"+roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role mapping: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get role mapping: %s", string(body))
	}

	var mappings map[string]RoleMapping
	if err := json.NewDecoder(resp.Body).Decode(&mappings); err != nil {
		return nil, fmt.Errorf("failed to decode role mapping: %w", err)
	}

	if mapping, ok := mappings[roleName]; ok {
		return &mapping, nil
	}

	return nil, nil
}

// DeleteRoleMapping deletes a role mapping
func (a *SecurityAPI) DeleteRoleMapping(ctx context.Context, roleName string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_security/api/rolesmapping/"+roleName)
	if err != nil {
		return fmt.Errorf("failed to delete role mapping: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete role mapping: %s", string(body))
	}

	return nil
}

// CreateTenant creates a tenant
func (a *SecurityAPI) CreateTenant(ctx context.Context, tenantName string, tenant Tenant) error {
	resp, err := a.client.Put(ctx, "/_plugins/_security/api/tenants/"+tenantName, tenant)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create tenant: %s", string(body))
	}

	return nil
}

// GetTenant retrieves a tenant
func (a *SecurityAPI) GetTenant(ctx context.Context, tenantName string) (*Tenant, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/tenants/"+tenantName)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get tenant: %s", string(body))
	}

	var tenants map[string]Tenant
	if err := json.NewDecoder(resp.Body).Decode(&tenants); err != nil {
		return nil, fmt.Errorf("failed to decode tenant: %w", err)
	}

	if tenant, ok := tenants[tenantName]; ok {
		return &tenant, nil
	}

	return nil, nil
}

// DeleteTenant deletes a tenant
func (a *SecurityAPI) DeleteTenant(ctx context.Context, tenantName string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_security/api/tenants/"+tenantName)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete tenant: %s", string(body))
	}

	return nil
}

// CreateActionGroup creates an action group
func (a *SecurityAPI) CreateActionGroup(ctx context.Context, name string, actionGroup ActionGroup) error {
	resp, err := a.client.Put(ctx, "/_plugins/_security/api/actiongroups/"+name, actionGroup)
	if err != nil {
		return fmt.Errorf("failed to create action group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create action group: %s", string(body))
	}

	return nil
}

// GetActionGroup retrieves an action group
func (a *SecurityAPI) GetActionGroup(ctx context.Context, name string) (*ActionGroup, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/actiongroups/"+name)
	if err != nil {
		return nil, fmt.Errorf("failed to get action group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get action group: %s", string(body))
	}

	var groups map[string]ActionGroup
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, fmt.Errorf("failed to decode action group: %w", err)
	}

	if group, ok := groups[name]; ok {
		return &group, nil
	}

	return nil, nil
}

// DeleteActionGroup deletes an action group
func (a *SecurityAPI) DeleteActionGroup(ctx context.Context, name string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_security/api/actiongroups/"+name)
	if err != nil {
		return fmt.Errorf("failed to delete action group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete action group: %s", string(body))
	}

	return nil
}
