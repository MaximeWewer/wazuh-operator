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

// UserBuilder builds OpenSearch internal users
type UserBuilder struct {
	username      string
	password      string
	hash          string
	backendRoles  []string
	attributes    map[string]string
	description   string
	securityRoles []string
}

// NewUserBuilder creates a new UserBuilder
func NewUserBuilder(username string) *UserBuilder {
	return &UserBuilder{
		username:      username,
		backendRoles:  []string{},
		attributes:    make(map[string]string),
		securityRoles: []string{},
	}
}

// WithPassword sets the password
func (b *UserBuilder) WithPassword(password string) *UserBuilder {
	b.password = password
	return b
}

// WithHash sets the password hash
func (b *UserBuilder) WithHash(hash string) *UserBuilder {
	b.hash = hash
	return b
}

// WithBackendRoles sets backend roles
func (b *UserBuilder) WithBackendRoles(roles ...string) *UserBuilder {
	b.backendRoles = append(b.backendRoles, roles...)
	return b
}

// WithAttribute sets an attribute
func (b *UserBuilder) WithAttribute(key, value string) *UserBuilder {
	b.attributes[key] = value
	return b
}

// WithDescription sets the description
func (b *UserBuilder) WithDescription(description string) *UserBuilder {
	b.description = description
	return b
}

// WithSecurityRoles sets security roles
func (b *UserBuilder) WithSecurityRoles(roles ...string) *UserBuilder {
	b.securityRoles = append(b.securityRoles, roles...)
	return b
}

// Build builds the user configuration
func (b *UserBuilder) Build() map[string]interface{} {
	user := map[string]interface{}{
		"description": b.description,
	}

	if b.password != "" {
		user["password"] = b.password
	}
	if b.hash != "" {
		user["hash"] = b.hash
	}
	if len(b.backendRoles) > 0 {
		user["backend_roles"] = b.backendRoles
	}
	if len(b.attributes) > 0 {
		user["attributes"] = b.attributes
	}
	if len(b.securityRoles) > 0 {
		user["opendistro_security_roles"] = b.securityRoles
	}

	return user
}

// DefaultWazuhUsers returns default Wazuh users (without passwords - must be set at deploy time)
func DefaultWazuhUsers() map[string]map[string]interface{} {
	users := make(map[string]map[string]interface{})

	// Kibana server user
	kibanaserver := NewUserBuilder("kibanaserver").
		WithDescription("OpenSearch Dashboards service user").
		WithBackendRoles("kibanaserver").
		Build()
	users["kibanaserver"] = kibanaserver

	// Kibanaro user (read-only)
	kibanaro := NewUserBuilder("kibanaro").
		WithDescription("Read-only Kibana user").
		WithBackendRoles("kibanauser", "readall").
		Build()
	users["kibanaro"] = kibanaro

	return users
}
