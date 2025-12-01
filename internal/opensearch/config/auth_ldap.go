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

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ============================================================================
// LDAP Auth Domain Builder (T012)
// ============================================================================

// buildLDAPAuthDomain creates the LDAP authentication domain configuration
func (b *AuthConfigBuilder) buildLDAPAuthDomain(spec *v1alpha1.LDAPAuthSpec) AuthDomainConfig {
	config := make(map[string]interface{})

	// Enable LDAP
	config["enable_ssl"] = false
	config["enable_start_tls"] = false

	// TLS configuration
	if spec.TLS != nil {
		config["enable_ssl"] = spec.TLS.EnableSSL
		config["enable_start_tls"] = spec.TLS.EnableStartTLS
		config["verify_hostnames"] = spec.TLS.VerifyHostnames

		if spec.TLS.TrustAllCertificates {
			config["enable_ssl_client_auth"] = false
		}

		if spec.TLS.PemTrustedCAsFilepath != "" {
			config["pemtrustedcas_filepath"] = spec.TLS.PemTrustedCAsFilepath
		}
	}

	// Hosts
	if len(spec.Hosts) > 0 {
		config["hosts"] = spec.Hosts
	}

	// Bind credentials
	if spec.Authentication.BindDN != "" {
		config["bind_dn"] = spec.Authentication.BindDN
	}

	// Bind password from resolved secrets
	if secret, ok := b.resolvedSecrets["ldap_bind_password"]; ok && secret != "" {
		config["password"] = secret
	}

	// User search configuration
	config["userbase"] = spec.Authentication.UserBase
	config["usersearch"] = spec.Authentication.UserSearch
	config["username_attribute"] = spec.Authentication.UsernameAttribute

	return AuthDomainConfig{
		Name:              "ldap_auth_domain",
		Order:             spec.Order,
		HTTPEnabled:       spec.HTTPEnabled,
		TransportEnabled:  spec.TransportEnabled,
		Challenge:         spec.Challenge,
		AuthenticatorType: "basic",
		BackendType:       "ldap",
		BackendConfig:     config,
		Description:       "Authenticate via LDAP/Active Directory",
	}
}

// buildLDAPAuthzDomain creates the LDAP authorization domain configuration
func (b *AuthConfigBuilder) buildLDAPAuthzDomain(spec *v1alpha1.LDAPAuthSpec) AuthDomainConfig {
	config := make(map[string]interface{})

	// TLS configuration (same as auth)
	if spec.TLS != nil {
		config["enable_ssl"] = spec.TLS.EnableSSL
		config["enable_start_tls"] = spec.TLS.EnableStartTLS
		config["verify_hostnames"] = spec.TLS.VerifyHostnames

		if spec.TLS.PemTrustedCAsFilepath != "" {
			config["pemtrustedcas_filepath"] = spec.TLS.PemTrustedCAsFilepath
		}
	}

	// Hosts
	if len(spec.Hosts) > 0 {
		config["hosts"] = spec.Hosts
	}

	// Bind credentials
	if spec.Authentication.BindDN != "" {
		config["bind_dn"] = spec.Authentication.BindDN
	}

	// Bind password from resolved secrets
	if secret, ok := b.resolvedSecrets["ldap_bind_password"]; ok && secret != "" {
		config["password"] = secret
	}

	// User base for authorization lookups
	config["userbase"] = spec.Authentication.UserBase
	config["usersearch"] = spec.Authentication.UserSearch

	// Role configuration
	if spec.Authorization != nil {
		config["rolebase"] = spec.Authorization.RoleBase
		config["rolesearch"] = spec.Authorization.RoleSearch
		config["rolename"] = spec.Authorization.RoleName

		if spec.Authorization.UserRoleName != "" {
			config["userrolename"] = spec.Authorization.UserRoleName
		}

		config["resolve_nested_roles"] = spec.Authorization.ResolveNestedRoles
		config["skip_users"] = spec.Authorization.SkipUsers
	}

	return AuthDomainConfig{
		Name:          "ldap_authz_domain",
		HTTPEnabled:   spec.HTTPEnabled,
		BackendType:   "ldap",
		BackendConfig: config,
		Description:   "Authorize via LDAP/Active Directory groups",
	}
}

// LDAPConfigBuilder builds LDAP-specific configuration
type LDAPConfigBuilder struct {
	spec            *v1alpha1.LDAPAuthSpec
	resolvedSecrets map[string]string
}

// NewLDAPConfigBuilder creates a new LDAPConfigBuilder
func NewLDAPConfigBuilder(spec *v1alpha1.LDAPAuthSpec) *LDAPConfigBuilder {
	return &LDAPConfigBuilder{
		spec:            spec,
		resolvedSecrets: make(map[string]string),
	}
}

// WithBindPassword sets the resolved bind password
func (b *LDAPConfigBuilder) WithBindPassword(password string) *LDAPConfigBuilder {
	b.resolvedSecrets["bind_password"] = password
	return b
}

// BuildAuthBackendConfig returns the LDAP authentication backend configuration
func (b *LDAPConfigBuilder) BuildAuthBackendConfig() map[string]interface{} {
	config := make(map[string]interface{})

	// TLS settings
	if b.spec.TLS != nil {
		config["enable_ssl"] = b.spec.TLS.EnableSSL
		config["enable_start_tls"] = b.spec.TLS.EnableStartTLS
		config["verify_hostnames"] = b.spec.TLS.VerifyHostnames

		if b.spec.TLS.PemTrustedCAsFilepath != "" {
			config["pemtrustedcas_filepath"] = b.spec.TLS.PemTrustedCAsFilepath
		}
	}

	// Hosts
	config["hosts"] = b.spec.Hosts

	// Bind credentials
	if b.spec.Authentication.BindDN != "" {
		config["bind_dn"] = b.spec.Authentication.BindDN
	}
	if pwd, ok := b.resolvedSecrets["bind_password"]; ok && pwd != "" {
		config["password"] = pwd
	}

	// User search
	config["userbase"] = b.spec.Authentication.UserBase
	config["usersearch"] = b.spec.Authentication.UserSearch
	config["username_attribute"] = b.spec.Authentication.UsernameAttribute

	return config
}

// BuildAuthzBackendConfig returns the LDAP authorization backend configuration
func (b *LDAPConfigBuilder) BuildAuthzBackendConfig() map[string]interface{} {
	if b.spec.Authorization == nil {
		return nil
	}

	config := make(map[string]interface{})

	// TLS settings (same as auth)
	if b.spec.TLS != nil {
		config["enable_ssl"] = b.spec.TLS.EnableSSL
		config["enable_start_tls"] = b.spec.TLS.EnableStartTLS
		config["verify_hostnames"] = b.spec.TLS.VerifyHostnames

		if b.spec.TLS.PemTrustedCAsFilepath != "" {
			config["pemtrustedcas_filepath"] = b.spec.TLS.PemTrustedCAsFilepath
		}
	}

	// Hosts
	config["hosts"] = b.spec.Hosts

	// Bind credentials
	if b.spec.Authentication.BindDN != "" {
		config["bind_dn"] = b.spec.Authentication.BindDN
	}
	if pwd, ok := b.resolvedSecrets["bind_password"]; ok && pwd != "" {
		config["password"] = pwd
	}

	// User base
	config["userbase"] = b.spec.Authentication.UserBase
	config["usersearch"] = b.spec.Authentication.UserSearch

	// Role settings
	config["rolebase"] = b.spec.Authorization.RoleBase
	config["rolesearch"] = b.spec.Authorization.RoleSearch
	config["rolename"] = b.spec.Authorization.RoleName

	if b.spec.Authorization.UserRoleName != "" {
		config["userrolename"] = b.spec.Authorization.UserRoleName
	}

	config["resolve_nested_roles"] = b.spec.Authorization.ResolveNestedRoles
	config["skip_users"] = b.spec.Authorization.SkipUsers

	return config
}

// IsEnabled returns true if LDAP is configured and enabled
func (b *LDAPConfigBuilder) IsEnabled() bool {
	return b.spec != nil && b.spec.Enabled &&
		len(b.spec.Hosts) > 0 &&
		b.spec.Authentication.UserBase != ""
}

// ValidateConfig validates the LDAP configuration
func (b *LDAPConfigBuilder) ValidateConfig() error {
	if b.spec == nil || !b.spec.Enabled {
		return nil
	}

	if len(b.spec.Hosts) == 0 {
		return &ValidationError{Field: "ldap.hosts", Message: "at least one LDAP host is required when LDAP is enabled"}
	}

	if b.spec.Authentication.UserBase == "" {
		return &ValidationError{
			Field:   "ldap.authentication.userBase",
			Message: "userBase is required when LDAP is enabled",
		}
	}

	// Validate authorization if enabled
	if b.spec.Authorization != nil && b.spec.Authorization.Enabled {
		if b.spec.Authorization.RoleBase == "" {
			return &ValidationError{
				Field:   "ldap.authorization.roleBase",
				Message: "roleBase is required when LDAP authorization is enabled",
			}
		}
	}

	return nil
}

// GetConnectionString returns a descriptive LDAP connection string
func (b *LDAPConfigBuilder) GetConnectionString() string {
	if b.spec == nil || len(b.spec.Hosts) == 0 {
		return ""
	}

	protocol := "ldap"
	if b.spec.TLS != nil && b.spec.TLS.EnableSSL {
		protocol = "ldaps"
	}

	hosts := make([]string, len(b.spec.Hosts))
	for i, host := range b.spec.Hosts {
		hosts[i] = fmt.Sprintf("%s://%s", protocol, host)
	}

	return strings.Join(hosts, ", ")
}
