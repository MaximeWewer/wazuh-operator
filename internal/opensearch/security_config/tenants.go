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

// TenantBuilder builds OpenSearch tenants
type TenantBuilder struct {
	name        string
	description string
}

// NewTenantBuilder creates a new TenantBuilder
func NewTenantBuilder(name string) *TenantBuilder {
	return &TenantBuilder{
		name: name,
	}
}

// WithDescription sets the description
func (b *TenantBuilder) WithDescription(description string) *TenantBuilder {
	b.description = description
	return b
}

// Build builds the tenant configuration
func (b *TenantBuilder) Build() map[string]interface{} {
	return map[string]interface{}{
		"description": b.description,
	}
}

// DefaultWazuhTenants returns default Wazuh tenants
func DefaultWazuhTenants() map[string]map[string]interface{} {
	tenants := make(map[string]map[string]interface{})

	// Global tenant (built-in)
	global := NewTenantBuilder("global_tenant").
		WithDescription("Global tenant").
		Build()
	tenants["global_tenant"] = global

	// Admin tenant
	admin := NewTenantBuilder("admin_tenant").
		WithDescription("Admin tenant for private dashboards").
		Build()
	tenants["admin_tenant"] = admin

	return tenants
}
