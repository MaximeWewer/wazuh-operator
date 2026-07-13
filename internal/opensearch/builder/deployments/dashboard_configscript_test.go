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

package deployments

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runDashboardConfigProcessScript executes the real config-processor script against a temporary
// template, with the paths rewritten to the temp dir, and returns the processed config.
func runDashboardConfigProcessScript(t *testing.T, template, username, password string) string {
	t.Helper()

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available")
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "in.yml")
	out := filepath.Join(dir, "out.yml")
	if err := os.WriteFile(in, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	script := strings.ReplaceAll(dashboardConfigProcessScript, "/config-template/opensearch_dashboards.yml", in)
	script = strings.ReplaceAll(script, "/config-processed/opensearch_dashboards.yml", out)

	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "INDEXER_USERNAME="+username, "INDEXER_PASSWORD="+password)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, output)
	}

	processed, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read processed config: %v", err)
	}
	return string(processed)
}

// TestDashboardConfigProcessScript_SedMetacharacters guards the substitution against credentials
// containing sed metacharacters. The previous `sed s/${INDEXER_PASSWORD}/$INDEXER_PASSWORD/g`
// broke on "/" (delimiter) and silently corrupted the password on "&" (matched-text reference).
// Passwords supplied via spec.indexer.credentials are arbitrary, so these must round-trip.
func TestDashboardConfigProcessScript_SedMetacharacters(t *testing.T) {
	const template = `opensearch.username: "${INDEXER_USERNAME}"
opensearch.password: "${INDEXER_PASSWORD}"
opensearch.hosts: ["https://indexer:9200"]
`

	tests := []struct {
		name             string
		username         string
		password         string
		wantUsernameLine string
		wantPasswordLine string
	}{
		{
			name:             "alphanumeric (operator-generated)",
			username:         "admin",
			password:         "aB3xY9zQ",
			wantUsernameLine: `opensearch.username: "admin"`,
			wantPasswordLine: `opensearch.password: "aB3xY9zQ"`,
		},
		{
			name:             "slash breaks sed s/// delimiter",
			username:         "admin",
			password:         "pa/ss/word",
			wantUsernameLine: `opensearch.username: "admin"`,
			wantPasswordLine: `opensearch.password: "pa/ss/word"`,
		},
		{
			name:             "ampersand is the matched text in a sed replacement",
			username:         "admin",
			password:         "pa&ss&word",
			wantUsernameLine: `opensearch.username: "admin"`,
			wantPasswordLine: `opensearch.password: "pa&ss&word"`,
		},
		{
			name:             "backslash and quote are escaped for the YAML scalar",
			username:         "ad\\min",
			password:         `pa\ss"word`,
			wantUsernameLine: `opensearch.username: "ad\\min"`,
			wantPasswordLine: `opensearch.password: "pa\\ss\"word"`,
		},
		{
			name:             "all sed metacharacters at once",
			username:         "admin",
			password:         `a/b&c\d"e`,
			wantUsernameLine: `opensearch.username: "admin"`,
			wantPasswordLine: `opensearch.password: "a/b&c\\d\"e"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runDashboardConfigProcessScript(t, template, tt.username, tt.password)

			if !strings.Contains(got, tt.wantUsernameLine) {
				t.Errorf("username line not substituted correctly\nwant line: %s\ngot config:\n%s", tt.wantUsernameLine, got)
			}
			if !strings.Contains(got, tt.wantPasswordLine) {
				t.Errorf("password line not substituted correctly\nwant line: %s\ngot config:\n%s", tt.wantPasswordLine, got)
			}
			if strings.Contains(got, "${INDEXER_USERNAME}") || strings.Contains(got, "${INDEXER_PASSWORD}") {
				t.Errorf("placeholder left unsubstituted in config:\n%s", got)
			}
			// Untouched lines must survive verbatim.
			if !strings.Contains(got, `opensearch.hosts: ["https://indexer:9200"]`) {
				t.Errorf("unrelated line was altered:\n%s", got)
			}
		})
	}
}
