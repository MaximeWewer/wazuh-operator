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

package security

import (
	"strings"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestBuildInternalUsersCommand(t *testing.T) {
	tests := []struct {
		name          string
		wazuhVersion  string
		wantPreferred string
		wantFallback  string
	}{
		{
			name:          "modern version (>= 4.14.0) prefers config dir with legacy fallback",
			wazuhVersion:  "4.14.0",
			wantPreferred: constants.PathIndexerSecurityConfig + "/internal_users.yml",
			wantFallback:  constants.PathIndexerLegacySecurityConfig + "/internal_users.yml",
		},
		{
			name:          "legacy version (< 4.14.0) prefers legacy dir with config fallback",
			wazuhVersion:  "4.13.0",
			wantPreferred: constants.PathIndexerLegacySecurityConfig + "/internal_users.yml",
			wantFallback:  constants.PathIndexerSecurityConfig + "/internal_users.yml",
		},
		{
			name:          "newer version prefers config dir with legacy fallback",
			wazuhVersion:  "4.15.1",
			wantPreferred: constants.PathIndexerSecurityConfig + "/internal_users.yml",
			wantFallback:  constants.PathIndexerLegacySecurityConfig + "/internal_users.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := buildInternalUsersCommand(tt.wazuhVersion)

			// Command should be: ["bash", "-c", "<script>"]
			if len(cmd) != 3 {
				t.Fatalf("expected 3 args (bash -c <script>), got %d: %v", len(cmd), cmd)
			}
			if cmd[0] != "bash" || cmd[1] != "-c" {
				t.Errorf("expected bash -c prefix, got %s %s", cmd[0], cmd[1])
			}

			script := cmd[2]

			// Verify OPENSEARCH_JAVA_HOME is set
			if !strings.Contains(script, "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk") {
				t.Error("expected OPENSEARCH_JAVA_HOME in script")
			}

			// Verify securityadmin.sh path
			if !strings.Contains(script, "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh") {
				t.Error("expected securityadmin.sh path in script")
			}

			// Verify preferred and fallback internal_users.yml paths are present
			if !strings.Contains(script, "INTERNAL_USERS_FILE="+tt.wantPreferred) {
				t.Errorf("expected preferred path %s in script, got: %s", tt.wantPreferred, script)
			}
			if !strings.Contains(script, "[ -f "+tt.wantFallback+" ]") {
				t.Errorf("expected fallback file check for %s in script, got: %s", tt.wantFallback, script)
			}
			if !strings.Contains(script, "internal_users.yml not found at "+tt.wantPreferred+" or "+tt.wantFallback) {
				t.Errorf("expected not-found message with both paths in script, got: %s", script)
			}

			// Verify securityadmin receives resolved path variable
			if !strings.Contains(script, "-f \"$INTERNAL_USERS_FILE\"") {
				t.Errorf("expected -f \"$INTERNAL_USERS_FILE\" in script, got: %s", script)
			}

			// Verify -t internalusers is present
			if !strings.Contains(script, "-t internalusers") {
				t.Error("expected -t internalusers in script")
			}

			// Verify TLS cert flags are present
			if !strings.Contains(script, "-cacert "+constants.PathIndexerCerts+"/ca.crt") {
				t.Error("expected -cacert flag with correct path")
			}
			if !strings.Contains(script, "-cert "+constants.PathIndexerAdminCerts+"/tls.crt") {
				t.Error("expected -cert flag with correct path")
			}
			if !strings.Contains(script, "-key "+constants.PathIndexerAdminCerts+"/tls.key") {
				t.Error("expected -key flag with correct path")
			}

			// Verify -icl and -nhnv flags
			if !strings.Contains(script, "-icl") {
				t.Error("expected -icl flag in script")
			}
			if !strings.Contains(script, "-nhnv") {
				t.Error("expected -nhnv flag in script")
			}
		})
	}
}
