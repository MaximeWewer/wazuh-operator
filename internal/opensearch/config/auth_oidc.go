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
	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ============================================================================
// OIDC Auth Domain Builder (T010)
// ============================================================================

// buildOIDCAuthDomain creates the OIDC auth domain configuration
func (b *AuthConfigBuilder) buildOIDCAuthDomain(spec *v1alpha1.OIDCAuthSpec) AuthDomainConfig {
	config := make(map[string]interface{})

	// Required OIDC settings
	config["openid_connect_url"] = spec.ConnectURL
	config["client_id"] = spec.ClientID

	// Client secret from resolved secrets
	if secret, ok := b.resolvedSecrets["oidc_client_secret"]; ok && secret != "" {
		config["client_secret"] = secret
	}

	// Subject and roles mapping
	if spec.SubjectKey != "" {
		config["subject_key"] = spec.SubjectKey
	}
	if spec.RolesKey != "" {
		config["roles_key"] = spec.RolesKey
	}

	// Scope
	if spec.Scope != "" {
		config["scope"] = spec.Scope
	}

	// Logout URL
	if spec.LogoutURL != "" {
		config["logout_url"] = spec.LogoutURL
	}

	return AuthDomainConfig{
		Name:                "openid_auth_domain",
		Order:               spec.Order,
		HTTPEnabled:         spec.HTTPEnabled,
		TransportEnabled:    false, // OIDC is HTTP only
		Challenge:           spec.Challenge,
		AuthenticatorType:   "openid",
		AuthenticatorConfig: config,
		BackendType:         "noop",
		Description:         "Authenticate via OpenID Connect",
	}
}

// OIDCConfigBuilder builds OIDC-specific configuration
type OIDCConfigBuilder struct {
	spec            *v1alpha1.OIDCAuthSpec
	resolvedSecrets map[string]string
}

// NewOIDCConfigBuilder creates a new OIDCConfigBuilder
func NewOIDCConfigBuilder(spec *v1alpha1.OIDCAuthSpec) *OIDCConfigBuilder {
	return &OIDCConfigBuilder{
		spec:            spec,
		resolvedSecrets: make(map[string]string),
	}
}

// WithClientSecret sets the resolved client secret
func (b *OIDCConfigBuilder) WithClientSecret(secret string) *OIDCConfigBuilder {
	b.resolvedSecrets["client_secret"] = secret
	return b
}

// BuildAuthenticatorConfig returns the OIDC authenticator configuration map
func (b *OIDCConfigBuilder) BuildAuthenticatorConfig() map[string]interface{} {
	config := make(map[string]interface{})

	config["openid_connect_url"] = b.spec.ConnectURL
	config["client_id"] = b.spec.ClientID

	if secret, ok := b.resolvedSecrets["client_secret"]; ok && secret != "" {
		config["client_secret"] = secret
	}

	if b.spec.SubjectKey != "" {
		config["subject_key"] = b.spec.SubjectKey
	}
	if b.spec.RolesKey != "" {
		config["roles_key"] = b.spec.RolesKey
	}
	if b.spec.Scope != "" {
		config["scope"] = b.spec.Scope
	}
	if b.spec.LogoutURL != "" {
		config["logout_url"] = b.spec.LogoutURL
	}

	return config
}

// IsEnabled returns true if OIDC is configured and enabled
func (b *OIDCConfigBuilder) IsEnabled() bool {
	return b.spec != nil && b.spec.Enabled && b.spec.ConnectURL != "" && b.spec.ClientID != ""
}

// ValidateConfig validates the OIDC configuration
func (b *OIDCConfigBuilder) ValidateConfig() error {
	if b.spec == nil || !b.spec.Enabled {
		return nil
	}

	if b.spec.ConnectURL == "" {
		return &ValidationError{Field: "oidc.connectURL", Message: "connectURL is required when OIDC is enabled"}
	}

	if b.spec.ClientID == "" {
		return &ValidationError{Field: "oidc.clientId", Message: "clientId is required when OIDC is enabled"}
	}

	return nil
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}
