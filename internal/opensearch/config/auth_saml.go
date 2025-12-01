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

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// ============================================================================
// SAML Auth Domain Builder (T011)
// ============================================================================

// buildSAMLAuthDomain creates the SAML auth domain configuration
func (b *AuthConfigBuilder) buildSAMLAuthDomain(spec *v1alpha1.SAMLAuthSpec) AuthDomainConfig {
	config := make(map[string]interface{})

	// IdP metadata configuration
	if spec.IdpMetadataURL != "" {
		config["idp.metadata_url"] = spec.IdpMetadataURL
	} else if spec.IdpMetadataFile != "" {
		config["idp.metadata_file"] = spec.IdpMetadataFile
	}

	// Entity IDs
	config["idp.entity_id"] = spec.IdpEntityID
	config["sp.entity_id"] = spec.SpEntityID

	// Kibana/Dashboard URL for ACS
	config["kibana_url"] = spec.KibanaURL

	// Subject and roles mapping
	if spec.SubjectKey != "" {
		config["subject_key"] = spec.SubjectKey
	}
	if spec.RolesKey != "" {
		config["roles_key"] = spec.RolesKey
	}

	// Exchange key from resolved secrets
	if secret, ok := b.resolvedSecrets["saml_exchange_key"]; ok && secret != "" {
		config["exchange_key"] = secret
	}

	return AuthDomainConfig{
		Name:                "saml_auth_domain",
		Order:               spec.Order,
		HTTPEnabled:         spec.HTTPEnabled,
		TransportEnabled:    false, // SAML is HTTP only
		Challenge:           spec.Challenge,
		AuthenticatorType:   "saml",
		AuthenticatorConfig: config,
		BackendType:         "noop",
		Description:         "Authenticate via SAML 2.0",
	}
}

// SAMLConfigBuilder builds SAML-specific configuration
type SAMLConfigBuilder struct {
	spec            *v1alpha1.SAMLAuthSpec
	resolvedSecrets map[string]string
}

// NewSAMLConfigBuilder creates a new SAMLConfigBuilder
func NewSAMLConfigBuilder(spec *v1alpha1.SAMLAuthSpec) *SAMLConfigBuilder {
	return &SAMLConfigBuilder{
		spec:            spec,
		resolvedSecrets: make(map[string]string),
	}
}

// WithExchangeKey sets the resolved exchange key
func (b *SAMLConfigBuilder) WithExchangeKey(key string) *SAMLConfigBuilder {
	b.resolvedSecrets["exchange_key"] = key
	return b
}

// BuildAuthenticatorConfig returns the SAML authenticator configuration map
func (b *SAMLConfigBuilder) BuildAuthenticatorConfig() map[string]interface{} {
	config := make(map[string]interface{})

	// IdP metadata
	if b.spec.IdpMetadataURL != "" {
		config["idp.metadata_url"] = b.spec.IdpMetadataURL
	} else if b.spec.IdpMetadataFile != "" {
		config["idp.metadata_file"] = b.spec.IdpMetadataFile
	}

	// Entity IDs
	config["idp.entity_id"] = b.spec.IdpEntityID
	config["sp.entity_id"] = b.spec.SpEntityID

	// Dashboard/Kibana URL
	config["kibana_url"] = b.spec.KibanaURL

	// Subject and roles
	if b.spec.SubjectKey != "" {
		config["subject_key"] = b.spec.SubjectKey
	}
	if b.spec.RolesKey != "" {
		config["roles_key"] = b.spec.RolesKey
	}

	// Exchange key for signing
	if key, ok := b.resolvedSecrets["exchange_key"]; ok && key != "" {
		config["exchange_key"] = key
	}

	return config
}

// IsEnabled returns true if SAML is configured and enabled
func (b *SAMLConfigBuilder) IsEnabled() bool {
	return b.spec != nil && b.spec.Enabled &&
		(b.spec.IdpMetadataURL != "" || b.spec.IdpMetadataFile != "") &&
		b.spec.IdpEntityID != "" && b.spec.SpEntityID != ""
}

// ValidateConfig validates the SAML configuration
func (b *SAMLConfigBuilder) ValidateConfig() error {
	if b.spec == nil || !b.spec.Enabled {
		return nil
	}

	if b.spec.IdpMetadataURL == "" && b.spec.IdpMetadataFile == "" {
		return &ValidationError{
			Field:   "saml",
			Message: "either idpMetadataUrl or idpMetadataFile is required when SAML is enabled",
		}
	}

	if b.spec.IdpEntityID == "" {
		return &ValidationError{Field: "saml.idpEntityId", Message: "idpEntityId is required when SAML is enabled"}
	}

	if b.spec.SpEntityID == "" {
		return &ValidationError{Field: "saml.spEntityId", Message: "spEntityId is required when SAML is enabled"}
	}

	if b.spec.KibanaURL == "" {
		return &ValidationError{Field: "saml.kibanaUrl", Message: "kibanaUrl is required when SAML is enabled"}
	}

	return nil
}

// GetACSEndpoint returns the SAML Assertion Consumer Service endpoint
func (b *SAMLConfigBuilder) GetACSEndpoint() string {
	if b.spec == nil || b.spec.KibanaURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/_opendistro/_security/saml/acs", b.spec.KibanaURL)
}

// GetSLOEndpoint returns the SAML Single Logout endpoint
func (b *SAMLConfigBuilder) GetSLOEndpoint() string {
	if b.spec == nil || b.spec.KibanaURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/_opendistro/_security/saml/logout", b.spec.KibanaURL)
}
