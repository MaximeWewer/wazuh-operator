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

// Proxy enabled emits the xff block under http: plus a proxy_auth_domain with the
// proxy authenticator, challenge=false and a noop backend.
func TestBuildSecurityConfig_ProxyEnabled(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		Proxy: &v1.ProxyAuthSpec{
			Enabled:        true,
			Order:          5,
			HTTPEnabled:    true,
			UserHeader:     "x-proxy-user",
			RolesHeader:    "x-proxy-roles",
			RolesSeparator: ",",
			XFF: v1.ProxyXFFSpec{
				InternalProxies: ".*",
				RemoteIPHeader:  "x-forwarded-for",
			},
		},
	}

	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	for _, want := range []string{
		"      xff:",
		"        enabled: true",
		"        internalProxies: '.*'",
		"        remoteIpHeader: 'x-forwarded-for'",
		"proxy_auth_domain:",
		"type: \"proxy\"",
		"challenge: false",
		"user_header: x-proxy-user",
		"roles_header: x-proxy-roles",
		"roles_separator: ','",
		"type: \"noop\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected config.yml to contain %q:\n%s", want, out)
		}
	}
}

// Extended=true switches to the extended-proxy authenticator and emits attr_header_prefix.
func TestBuildSecurityConfig_ProxyExtended(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		Proxy: &v1.ProxyAuthSpec{
			Enabled:          true,
			Order:            5,
			HTTPEnabled:      true,
			UserHeader:       "x-proxy-user",
			RolesHeader:      "x-proxy-roles",
			RolesSeparator:   ",",
			Extended:         true,
			AttrHeaderPrefix: "x-proxy-ext-",
			XFF:              v1.ProxyXFFSpec{InternalProxies: ".*"},
		},
	}

	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	if !strings.Contains(out, "type: \"extended-proxy\"") {
		t.Fatalf("expected extended-proxy authenticator:\n%s", out)
	}
	if !strings.Contains(out, "attr_header_prefix: x-proxy-ext-") {
		t.Fatalf("expected attr_header_prefix:\n%s", out)
	}
}

// Proxy disabled / nil emits neither the xff block nor the proxy_auth_domain.
func TestBuildSecurityConfig_ProxyDisabledOrNil(t *testing.T) {
	cases := map[string]*v1.OpenSearchAuthConfigSpec{
		"nil proxy": {
			BasicAuth: &v1.BasicAuthSpec{Enabled: true, Challenge: true},
		},
		"disabled proxy": {
			BasicAuth: &v1.BasicAuthSpec{Enabled: true, Challenge: true},
			Proxy:     &v1.ProxyAuthSpec{Enabled: false, XFF: v1.ProxyXFFSpec{InternalProxies: ".*"}},
		},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			out := NewAuthConfigBuilder(spec).BuildSecurityConfig()
			if strings.Contains(out, "xff:") {
				t.Fatalf("did not expect an xff block:\n%s", out)
			}
			if strings.Contains(out, "proxy_auth_domain") {
				t.Fatalf("did not expect a proxy_auth_domain:\n%s", out)
			}
		})
	}
}

// A regex internalProxies value round-trips verbatim inside the single-quoted scalar.
func TestBuildSecurityConfig_ProxyInternalProxiesRegex(t *testing.T) {
	spec := &v1.OpenSearchAuthConfigSpec{
		Proxy: &v1.ProxyAuthSpec{
			Enabled:     true,
			HTTPEnabled: true,
			XFF:         v1.ProxyXFFSpec{InternalProxies: `192\.168\.0\.\d+|10\.0\.0\.1`},
		},
	}

	out := NewAuthConfigBuilder(spec).BuildSecurityConfig()

	if !strings.Contains(out, `internalProxies: '192\.168\.0\.\d+|10\.0\.0\.1'`) {
		t.Fatalf("expected regex to round-trip inside single-quoted scalar:\n%s", out)
	}
}
