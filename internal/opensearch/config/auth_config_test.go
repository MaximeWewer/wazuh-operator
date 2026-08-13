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

// The dashboard (kibanaserver), the operator API client (admin) and securityadmin
// all authenticate via HTTP Basic, so basic_internal_auth_domain must ALWAYS be in
// the rendered config.yml - even for an SSO-only spec like the one in the GitHub
// issue that triggered "Unable to retrieve version information from OpenSearch nodes".
func TestBuildSecurityConfig_AlwaysIncludesBasicInternalDomain(t *testing.T) {
	cases := map[string]*v1.OpenSearchAuthConfigSpec{
		"oidc only (no basicAuth)": {
			OIDC: &v1.OIDCAuthSpec{Enabled: true, Order: 0, ConnectURL: "https://idp/.well-known/openid-configuration", ClientID: "x"},
		},
		"basicAuth disabled is ignored": {
			BasicAuth: &v1.BasicAuthSpec{Enabled: false, Order: 5, Challenge: true},
		},
		"empty spec": {},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			out := NewAuthConfigBuilder(spec).BuildSecurityConfig()
			if !strings.Contains(out, "basic_internal_auth_domain:") {
				t.Fatalf("basic_internal_auth_domain missing from config.yml:\n%s", out)
			}
			if !strings.Contains(out, "type: \"internal\"") {
				t.Fatalf("internal backend missing from config.yml:\n%s", out)
			}
		})
	}
}

// HTTP/transport are forced on so service accounts always work, even if the user
// tried to disable them.
func TestBuildBasicAuthDomain_ForcesHTTPAndTransport(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		BasicAuth: &v1.BasicAuthSpec{Enabled: true, HTTPEnabled: false, TransportEnabled: false, Challenge: true},
	}
	d := NewAuthConfigBuilder(spec).buildBasicAuthDomain(spec.BasicAuth)
	if !d.HTTPEnabled || !d.TransportEnabled {
		t.Fatalf("basic domain must force http/transport enabled, got http=%v transport=%v", d.HTTPEnabled, d.TransportEnabled)
	}
}

// When no basicAuth is given alongside SSO, basic is placed AFTER the SSO domain so
// SSO owns the front door while basic stays the interactive fallback (challenge=true).
func TestBuildBasicAuthDomain_DefaultsAfterSSO(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		OIDC: &v1.OIDCAuthSpec{Enabled: true, Order: 0},
	}
	d := NewAuthConfigBuilder(spec).buildBasicAuthDomain(nil)
	if d.Order != 1 {
		t.Fatalf("expected basic order 1 (after OIDC order 0), got %d", d.Order)
	}
	if !d.Challenge {
		t.Fatalf("basic must keep challenge=true so local accounts stay reachable")
	}
}
