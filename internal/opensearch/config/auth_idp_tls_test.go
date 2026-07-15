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
	"strings"
	"testing"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// A representative multi-line PEM CA bundle. It MUST survive rendering as a YAML
// literal block scalar (never folded onto one line), or the security plugin fails
// to parse the certificate.
const testIdpCAPEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJANV3mF1p2Zk9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QtY2EtMTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QtY2EtMTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDabcdefghijklmn
opqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr
stuvAgMBAAEwDQYJKoZIhvcNAQELBQADQQBexampleexampleexampleexampleex
ampleexampleexampleexampleexampleexampleexampleexampleexampleex
-----END CERTIFICATE-----`

func boolPtr(b bool) *bool { return &b }

// assertBlockScalar checks the PEM was rendered under the given key as a "|-" literal
// block scalar and its lines were NOT folded onto a single line.
func assertBlockScalar(t *testing.T, out, key string) {
	t.Helper()
	if !strings.Contains(out, key+": |-") {
		t.Fatalf("expected %q rendered as a |- block scalar, got:\n%s", key, out)
	}
	// A folded single-line rendering would keep the PEM header on the same line as the key.
	if strings.Contains(out, key+": -----BEGIN") || strings.Contains(out, key+": \"-----BEGIN") {
		t.Fatalf("%q PEM was folded onto one line (must be a block scalar):\n%s", key, out)
	}
	// The BEGIN/END markers must appear on their own indented lines.
	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") || !strings.Contains(out, "-----END CERTIFICATE-----") {
		t.Fatalf("PEM body missing from rendered config for %q:\n%s", key, out)
	}
}

func TestBuildSecurityConfig_OIDCIdpTLS(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		OIDC: &v1.OIDCAuthSpec{
			Enabled:    true,
			Order:      0,
			ConnectURL: "https://idp.internal/.well-known/openid-configuration",
			ClientID:   "wazuh",
			IdpTLS: &v1.IdpTLSSpec{
				EnableSSL:       true,
				VerifyHostnames: boolPtr(false),
			},
		},
	}
	out := NewAuthConfigBuilder(spec).
		WithSecret(AuthSecretKeyOIDCIdpCA, testIdpCAPEM).
		BuildSecurityConfig()

	if !strings.Contains(out, "openid_connect_idp.enable_ssl: true") {
		t.Fatalf("missing openid_connect_idp.enable_ssl:\n%s", out)
	}
	if !strings.Contains(out, "openid_connect_idp.verify_hostnames: false") {
		t.Fatalf("missing openid_connect_idp.verify_hostnames:\n%s", out)
	}
	assertBlockScalar(t, out, "openid_connect_idp.pemtrustedcas_content")
}

func TestBuildSecurityConfig_SAMLIdpTLS(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		SAML: &v1.SAMLAuthSpec{
			Enabled:        true,
			Order:          0,
			IdpMetadataURL: "https://idp.internal/saml/metadata",
			IdpEntityID:    "https://idp.internal/entity",
			SpEntityID:     "wazuh-dashboard",
			KibanaURL:      "https://wazuh.example.com",
			IdpTLS: &v1.IdpTLSSpec{
				EnableSSL:       true,
				VerifyHostnames: boolPtr(false),
			},
		},
	}
	out := NewAuthConfigBuilder(spec).
		WithSecret(AuthSecretKeySAMLIdpCA, testIdpCAPEM).
		BuildSecurityConfig()

	if !strings.Contains(out, "idp.enable_ssl: true") {
		t.Fatalf("missing idp.enable_ssl:\n%s", out)
	}
	if !strings.Contains(out, "idp.verify_hostnames: false") {
		t.Fatalf("missing idp.verify_hostnames:\n%s", out)
	}
	assertBlockScalar(t, out, "idp.pemtrustedcas_content")
}

func TestBuildSecurityConfig_LDAPIdpTLS(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		LDAP: &v1.LDAPAuthSpec{
			Enabled: true,
			Order:   0,
			Hosts:   []string{"ldaps://ldap.internal:636"},
			Authentication: v1.LDAPAuthenticationSpec{
				UserBase:          "ou=users,dc=example,dc=com",
				UserSearch:        "(uid={0})",
				UsernameAttribute: "uid",
			},
			TLS: &v1.LDAPTLSSpec{EnableSSL: true},
		},
	}
	out := NewAuthConfigBuilder(spec).
		WithSecret(AuthSecretKeyLDAPCA, testIdpCAPEM).
		BuildSecurityConfig()

	assertBlockScalar(t, out, "pemtrustedcas_content")
}

// When no IdpTLS is configured, none of the custom-CA TLS keys must be emitted (no
// regression, no empty emission).
func TestBuildSecurityConfig_NoIdpTLS_NoKeys(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		OIDC: &v1.OIDCAuthSpec{
			Enabled:    true,
			Order:      0,
			ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
			ClientID:   "wazuh",
		},
		SAML: &v1.SAMLAuthSpec{
			Enabled:        true,
			Order:          1,
			IdpMetadataURL: "https://idp.example.com/saml/metadata",
			IdpEntityID:    "https://idp.example.com/entity",
			SpEntityID:     "wazuh-dashboard",
			KibanaURL:      "https://wazuh.example.com",
		},
	}
	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	for _, key := range []string{
		"openid_connect_idp.enable_ssl",
		"openid_connect_idp.verify_hostnames",
		"openid_connect_idp.pemtrustedcas_content",
		"idp.enable_ssl",
		"idp.verify_hostnames",
		"idp.pemtrustedcas_content",
		"pemtrustedcas_content",
	} {
		if strings.Contains(out, key) {
			t.Fatalf("unexpected key %q emitted when IdpTLS is nil:\n%s", key, out)
		}
	}
}
