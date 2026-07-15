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
// Kerberos Auth Domain Builder
// ============================================================================

// buildKerberosAuthDomain creates the kerberos auth domain configuration for config.yml.
// Reference: https://docs.opensearch.org/latest/security/authentication-backends/kerberos/
//
// Kerberos authentication is an INDEXER/API-layer backend only: the security plugin validates
// the SPNEGO token in the "Authorization: Negotiate" header against the service keytab. The
// three static settings (krb5_filepath, acceptor_keytab_filepath, acceptor_principal) and the
// mounted krb5.conf/keytab are wired by the reconciler; here we only emit the config.yml domain.
// The dashboard keeps basicauth (like LDAP/proxy) and is intentionally left untouched.
func (b *AuthConfigBuilder) buildKerberosAuthDomain(spec *v1.KerberosAuthSpec) AuthDomainConfig {
	// strip_realm_from_principal defaults to true (per OpenSearch docs); only override when set.
	stripRealm := true
	if spec.StripRealmFromPrincipal != nil {
		stripRealm = *spec.StripRealmFromPrincipal
	}

	config := map[string]any{
		"krb_debug":                  spec.KrbDebug,
		"strip_realm_from_principal": stripRealm,
	}

	return AuthDomainConfig{
		Name:                "kerberos_auth_domain",
		Order:               spec.Order,
		HTTPEnabled:         true,
		TransportEnabled:    false,
		Challenge:           spec.Challenge,
		AuthenticatorType:   "kerberos",
		AuthenticatorConfig: config,
		BackendType:         "noop",
		Description:         "Authenticate via Kerberos/SPNEGO",
	}
}
