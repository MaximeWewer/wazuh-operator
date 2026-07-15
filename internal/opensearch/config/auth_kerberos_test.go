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

// Kerberos enabled emits a kerberos_auth_domain with the kerberos authenticator, the
// documented default strip_realm_from_principal=true, krb_debug=false and a noop backend.
func TestBuildSecurityConfig_KerberosEnabled(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		Kerberos: &v1.KerberosAuthSpec{
			Enabled:           true,
			Order:             6,
			AcceptorPrincipal: "HTTP/opensearch.example.com",
			CredentialsSecret: "kerberos-creds",
		},
	}

	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	for _, want := range []string{
		"kerberos_auth_domain:",
		"type: \"kerberos\"",
		"challenge: false",
		"krb_debug: false",
		"strip_realm_from_principal: true",
		"type: \"noop\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected config.yml to contain %q:\n%s", want, out)
		}
	}
}

// StripRealmFromPrincipal=false overrides the default; krbDebug=true is emitted as-is.
func TestBuildSecurityConfig_KerberosStripRealmFalse(t *testing.T) {
	strip := false
	spec := &v1.OpenSearchAuthConfigSpec{
		Kerberos: &v1.KerberosAuthSpec{
			Enabled:                 true,
			KrbDebug:                true,
			StripRealmFromPrincipal: &strip,
			AcceptorPrincipal:       "HTTP/opensearch.example.com",
			CredentialsSecret:       "kerberos-creds",
		},
	}

	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	if !strings.Contains(out, "strip_realm_from_principal: false") {
		t.Fatalf("expected strip_realm_from_principal: false:\n%s", out)
	}
	if !strings.Contains(out, "krb_debug: true") {
		t.Fatalf("expected krb_debug: true:\n%s", out)
	}
}

// Kerberos disabled / nil emits no kerberos_auth_domain.
func TestBuildSecurityConfig_KerberosDisabledOrNil(t *testing.T) {
	cases := map[string]*v1.OpenSearchAuthConfigSpec{
		"nil kerberos": {
			BasicAuth: &v1.BasicAuthSpec{Enabled: true, Challenge: true},
		},
		"disabled kerberos": {
			BasicAuth: &v1.BasicAuthSpec{Enabled: true, Challenge: true},
			Kerberos:  &v1.KerberosAuthSpec{Enabled: false, AcceptorPrincipal: "HTTP/x", CredentialsSecret: "s"},
		},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			out := NewAuthConfigBuilder(spec).BuildSecurityConfig()
			if strings.Contains(out, "kerberos_auth_domain") {
				t.Fatalf("did not expect a kerberos_auth_domain:\n%s", out)
			}
		})
	}
}

// The three static Kerberos settings render into opensearch.yml with paths RELATIVE to the
// OpenSearch config dir (prefixed "kerberos/", not the absolute config path).
func TestOpenSearchConfig_KerberosSettings(t *testing.T) {
	cfg := DefaultOpenSearchConfig("test-cluster", "test-namespace")
	cfg.WithReplicas(1)
	cfg.WithCustomSetting("plugins.security.kerberos.krb5_filepath", "kerberos/krb5.conf")
	cfg.WithCustomSetting("plugins.security.kerberos.acceptor_keytab_filepath", "kerberos/opensearch.keytab")
	cfg.WithCustomSetting("plugins.security.kerberos.acceptor_principal", "HTTP/opensearch.example.com")

	out := cfg.Build()

	for _, want := range []string{
		"plugins.security.kerberos.krb5_filepath: kerberos/krb5.conf",
		"plugins.security.kerberos.acceptor_keytab_filepath: kerberos/opensearch.keytab",
		"plugins.security.kerberos.acceptor_principal: HTTP/opensearch.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected opensearch.yml to contain %q:\n%s", want, out)
		}
	}
}
