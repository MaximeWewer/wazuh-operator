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

package monitoring

import (
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func exporterEnv(t *testing.T, exporter wazuhv1.WazuhExporterConfig, sm *wazuhv1.ServiceMonitorConfig) map[string]string {
	t.Helper()
	exporter.Enabled = true
	cluster := &wazuhv1.WazuhCluster{Spec: wazuhv1.WazuhClusterSpec{Monitoring: &wazuhv1.MonitoringConfig{
		Enabled: true, WazuhExporter: &exporter, ServiceMonitor: sm,
	}}}
	env := map[string]string{}
	for _, e := range NewWazuhExporterConfig(cluster).buildEnvVars() {
		env[e.Name] = e.Value
	}
	return env
}

// TestExporterCacheOptions asserts the cache and timeout options reach the exporter, and
// that the cache TTL defaults to twice the scrape interval so every scrape is served from
// the cache instead of querying the Wazuh API again.
func TestExporterCacheOptions(t *testing.T) {
	env := exporterEnv(t, wazuhv1.WazuhExporterConfig{
		CacheTTL: "90s", CacheMaxStale: "5m", BackgroundFetchTimeout: "45s", ScrapeTimeout: "20s",
	}, &wazuhv1.ServiceMonitorConfig{Enabled: true, Interval: "60s"})
	for name, want := range map[string]string{
		"WAZUH_CACHE_TTL": "90s", "WAZUH_CACHE_MAX_STALE": "5m",
		"WAZUH_BACKGROUND_FETCH_TIMEOUT": "45s", "WAZUH_SCRAPE_TIMEOUT": "20s",
	} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}

	for name, tc := range map[string]struct {
		sm   *wazuhv1.ServiceMonitorConfig
		want string
	}{
		"twice the interval":            {sm: &wazuhv1.ServiceMonitorConfig{Enabled: true, Interval: "60s"}, want: "2m0s"},
		"default interval":              {sm: &wazuhv1.ServiceMonitorConfig{Enabled: true}, want: "1m0s"},
		"clamped to the exporter's max": {sm: &wazuhv1.ServiceMonitorConfig{Enabled: true, Interval: "10m"}, want: "5m0s"},
		"clamped to the exporter's min": {sm: &wazuhv1.ServiceMonitorConfig{Enabled: true, Interval: "1s"}, want: "5s"},
		"no ServiceMonitor":             {sm: nil, want: ""},
		"unparsable interval":           {sm: &wazuhv1.ServiceMonitorConfig{Enabled: true, Interval: "soon"}, want: ""},
	} {
		env := exporterEnv(t, wazuhv1.WazuhExporterConfig{}, tc.sm)
		if env["WAZUH_CACHE_TTL"] != tc.want {
			t.Errorf("%s: WAZUH_CACHE_TTL = %q, want %q", name, env["WAZUH_CACHE_TTL"], tc.want)
		}
		for _, unset := range []string{"WAZUH_CACHE_MAX_STALE", "WAZUH_BACKGROUND_FETCH_TIMEOUT", "WAZUH_SCRAPE_TIMEOUT"} {
			if _, ok := env[unset]; ok {
				t.Errorf("%s: %s set without its field, the exporter default should apply", name, unset)
			}
		}
	}
}
