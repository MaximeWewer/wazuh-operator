/*
Copyright 2025.

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
)

func TestOpenSearchConfig_VersionAwareHotReload(t *testing.T) {
	tests := []struct {
		name           string
		wazuhVersion   string
		expectedConfig string
		notExpected    string
	}{
		{
			name:           "Wazuh 4.14.1 should use automatic hot reload",
			wazuhVersion:   "4.14.1",
			expectedConfig: "plugins.security.ssl.certificates_hot_reload.enabled: true",
			notExpected:    "plugins.security.ssl_cert_reload_enabled: true",
		},
		{
			name:           "Wazuh 4.12.0 should use automatic hot reload",
			wazuhVersion:   "4.12.0",
			expectedConfig: "plugins.security.ssl.certificates_hot_reload.enabled: true",
			notExpected:    "plugins.security.ssl_cert_reload_enabled: true",
		},
		{
			name:           "Wazuh 4.10.0 should use API-based reload",
			wazuhVersion:   "4.10.0",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
		{
			name:           "Wazuh 4.9.0 should use API-based reload",
			wazuhVersion:   "4.9.0",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
		{
			name:           "Empty version should use legacy fallback",
			wazuhVersion:   "",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultOpenSearchConfig("test-cluster", "test-ns")
			if tt.wazuhVersion != "" {
				config.WithWazuhVersion(tt.wazuhVersion)
			}

			result := config.Build()

			if !strings.Contains(result, tt.expectedConfig) {
				t.Errorf("Expected config to contain %q for Wazuh version %q, but it did not.\nConfig:\n%s",
					tt.expectedConfig, tt.wazuhVersion, result)
			}

			if tt.notExpected != "" && strings.Contains(result, tt.notExpected) {
				t.Errorf("Expected config NOT to contain %q for Wazuh version %q, but it did.\nConfig:\n%s",
					tt.notExpected, tt.wazuhVersion, result)
			}
		})
	}
}

func TestOpenSearchConfig_WithWazuhVersion(t *testing.T) {
	config := DefaultOpenSearchConfig("test-cluster", "test-ns")

	// Test chaining
	result := config.WithWazuhVersion("4.14.1")

	if result != config {
		t.Error("WithWazuhVersion should return the same config for chaining")
	}

	if config.WazuhVersion != "4.14.1" {
		t.Errorf("Expected WazuhVersion to be 4.14.1, got %s", config.WazuhVersion)
	}
}

func TestBuildIndexerConfig(t *testing.T) {
	config := BuildIndexerConfig("test-cluster", "test-ns", 3, "4.14.1")

	// Should contain basic cluster configuration
	if !strings.Contains(config, "cluster.name: test-cluster") {
		t.Error("Expected config to contain cluster name")
	}

	// Should contain discovery hosts for 3 replicas
	if !strings.Contains(config, "test-cluster-indexer-0") {
		t.Error("Expected config to contain first discovery host")
	}
	if !strings.Contains(config, "test-cluster-indexer-2") {
		t.Error("Expected config to contain third discovery host")
	}

	// Should have security enabled by default
	if !strings.Contains(config, "plugins.security.disabled: false") {
		t.Error("Expected security to be enabled by default")
	}

	// With Wazuh 4.14.1, should use automatic hot reload
	if !strings.Contains(config, "plugins.security.ssl.certificates_hot_reload.enabled: true") {
		t.Error("Expected automatic hot reload for Wazuh 4.14.1")
	}
}

func TestBuildIndexerConfig_NoVersion(t *testing.T) {
	// When no version is provided, should use fallback (legacy setting)
	config := BuildIndexerConfig("test-cluster", "test-ns", 1, "")

	if !strings.Contains(config, "plugins.security.ssl_cert_reload_enabled: true") {
		t.Error("Expected fallback hot reload setting when no version provided")
	}

	if strings.Contains(config, "plugins.security.ssl.certificates_hot_reload.enabled: true") {
		t.Error("Should NOT use automatic hot reload when no version provided")
	}
}
