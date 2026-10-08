package configmaps

import (
	"strings"
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// The *bool plugin settings must render as YAML booleans, never as pointer
// addresses: an address is both an invalid value for the dashboard and a
// different string on every reconcile, which rewrites the wazuh.yml Secret in
// a loop and breaks the dashboard's subPath mount on container restart.
func TestBuildWazuhConfigRendersBoolPointers(t *testing.T) {
	_ = dns.InitializeWithDomain("cluster.local")
	plugin := &wazuhv1.WazuhPluginConfig{
		IPSelector: new(false),
		Monitoring: &wazuhv1.WazuhMonitoringConfig{},
		Checks: &wazuhv1.WazuhChecksConfig{
			Pattern:    new(false),
			MaxBuckets: new(true),
		},
		CronStatistics: &wazuhv1.WazuhCronStatisticsConfig{Status: new(false)},
	}

	build := func() string {
		return NewDashboardConfigMapBuilder("wazuh", "wazuh").WithWazuhPlugin(plugin).buildWazuhConfig()
	}
	got := build()

	if strings.Contains(got, "0x") {
		t.Fatalf("wazuh.yml contains a pointer address:\n%s", got)
	}
	if again := build(); again != got {
		t.Fatalf("wazuh.yml is not deterministic:\n%s\n---\n%s", got, again)
	}

	for _, want := range []string{
		"ip.selector: false\n",             // explicit false kept
		"wazuh.monitoring.enabled: true\n", // nil -> CRD default
		"checks.pattern: false\n",          // explicit false kept
		"checks.template: true\n",          // nil -> CRD default
		"checks.maxBuckets: true\n",        // explicit true
		"cron.statistics.status: false\n",  // explicit false kept
	} {
		if !strings.Contains(got, want) {
			t.Errorf("wazuh.yml missing %q:\n%s", want, got)
		}
	}
}

// TestRequestHeadersAllowlistForwardsCustomJWTHeader guards SSO through a custom JWT header
// (Teleport): the dashboard must forward that header to the indexer, or every JWT user gets
// "Authentication Exception".
func TestRequestHeadersAllowlistForwardsCustomJWTHeader(t *testing.T) {
	b := &DashboardConfigMapBuilder{}
	if got := b.requestHeadersAllowlist(); got != "  - securitytenant\n  - Authorization\n" {
		t.Fatalf("default allowlist = %q", got)
	}
	b.authConfig = &wazuhv1.OpenSearchAuthConfigSpec{JWT: &wazuhv1.JWTAuthSpec{Enabled: true, JwtHeader: "Teleport-Jwt-Assertion"}}
	if got := b.requestHeadersAllowlist(); !strings.Contains(got, "  - Teleport-Jwt-Assertion\n") {
		t.Fatalf("custom JWT header not forwarded: %q", got)
	}
	b.authConfig.JWT.JwtHeader = "Authorization"
	if got := b.requestHeadersAllowlist(); strings.Count(got, "Authorization") != 1 {
		t.Fatalf("Authorization listed twice: %q", got)
	}
}
