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

package configmaps

import (
	"strings"
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// The pod probes hit /api/status, and the security plugin defaults
// opensearch_security.auth.unauthenticated_routes to an empty list - meaning every route,
// /api/status included, answers 401 to the unauthenticated kubelet. The generated config must
// therefore declare the route explicitly, whatever the auth type: without it the dashboard never
// reports healthy (verified on a live cluster: /api/status answers 401 without the setting and 200
// with it, under both basicauth and openid).
func TestDashboardConfigExposesStatusRoute(t *testing.T) {
	tests := []struct {
		name       string
		authConfig *wazuhv1.OpenSearchAuthConfigSpec
	}{
		{
			name:       "basicauth (no auth config)",
			authConfig: nil,
		},
		{
			name: "external IdP (OIDC)",
			authConfig: &wazuhv1.OpenSearchAuthConfigSpec{
				OIDC: &wazuhv1.OIDCAuthSpec{
					Enabled:    true,
					ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
					ClientID:   "wazuh-dashboard",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewDashboardConfigMapBuilder("cluster", "ns").
				WithIndexerHost("indexer").
				WithIndexerPort(9200)
			if tt.authConfig != nil {
				builder = builder.WithAuthConfig(tt.authConfig)
			}

			cm, err := builder.Build()
			if err != nil {
				t.Fatalf("Build() error: %v", err)
			}

			var yml string
			for _, v := range cm.Data {
				if strings.Contains(v, "opensearch.hosts") || strings.Contains(v, "opensearch_security") {
					yml = v
					break
				}
			}
			if yml == "" {
				t.Fatalf("dashboard yml not found in ConfigMap data (keys: %v)", keysOf(cm.Data))
			}

			if !strings.Contains(yml, "opensearch_security.auth.unauthenticated_routes") {
				t.Errorf("config does not declare unauthenticated_routes, so /api/status answers 401 "+
					"and the probes can never pass:\n%s", yml)
			}
			if !strings.Contains(yml, "/api/status") {
				t.Errorf("config does not expose /api/status, the path the pod probes hit:\n%s", yml)
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
