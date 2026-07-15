/*
Copyright 2026.

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
	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// ============================================================================
// Proxy Auth Domain Builder
// ============================================================================

// buildProxyAuthDomain creates the proxy auth domain configuration for config.yml.
// Reference: https://docs.opensearch.org/latest/security/authentication-backends/proxy/
//
// Proxy authentication is an INDEXER/API-layer backend only: the security plugin trusts
// identity headers (user/roles) injected by a trusted front proxy. It has no verified
// opensearch_dashboards.yml auth.type, so the dashboard keeps basicauth (like LDAP) and
// is intentionally left untouched. The companion xff (proxy detection) block is emitted
// separately in BuildSecurityConfig; without it the plugin ignores the identity headers.
func (b *AuthConfigBuilder) buildProxyAuthDomain(spec *v1.ProxyAuthSpec) AuthDomainConfig {
	config := make(map[string]any)

	if spec.UserHeader != "" {
		config["user_header"] = spec.UserHeader
	}
	if spec.RolesHeader != "" {
		config["roles_header"] = spec.RolesHeader
	}
	if spec.RolesSeparator != "" {
		config["roles_separator"] = spec.RolesSeparator
	}

	// The extended-proxy authenticator additionally forwards user attributes (headers
	// prefixed by attr_header_prefix) for document-level security.
	authType := "proxy"
	if spec.Extended {
		authType = "extended-proxy"
		if spec.AttrHeaderPrefix != "" {
			config["attr_header_prefix"] = spec.AttrHeaderPrefix
		}
	}

	return AuthDomainConfig{
		Name:             "proxy_auth_domain",
		Order:            spec.Order,
		HTTPEnabled:      spec.HTTPEnabled,
		TransportEnabled: spec.TransportEnabled,
		// A proxy cannot issue an interactive challenge.
		Challenge:           false,
		AuthenticatorType:   authType,
		AuthenticatorConfig: config,
		BackendType:         "noop",
		Description:         "Authenticate via a trusted front proxy",
	}
}
