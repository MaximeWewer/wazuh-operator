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

package constants

import (
	"strings"
	"testing"
)

func TestGetDefaultOpenSearchVersion(t *testing.T) {
	version := GetDefaultOpenSearchVersion()

	// Should return a valid OpenSearch version (format X.X.X)
	if version == "" {
		t.Error("GetDefaultOpenSearchVersion() returned empty string")
	}

	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		t.Errorf("GetDefaultOpenSearchVersion() = %v, expected format X.X.X", version)
	}

	// For Wazuh 4.9.0, OpenSearch version should be 2.13.0
	if DefaultWazuhVersion == "4.9.0" && version != "2.13.0" {
		t.Errorf("GetDefaultOpenSearchVersion() = %v for Wazuh 4.9.0, expected 2.13.0", version)
	}
}

func TestGetDefaultPrometheusExporterPluginVersion(t *testing.T) {
	version := GetDefaultPrometheusExporterPluginVersion()

	// Should return a valid plugin version (format X.X.X.X)
	if version == "" {
		t.Error("GetDefaultPrometheusExporterPluginVersion() returned empty string")
	}

	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		t.Errorf("GetDefaultPrometheusExporterPluginVersion() = %v, expected format X.X.X.X", version)
	}

	// For Wazuh 4.9.0, plugin version should be 2.13.0.0
	if DefaultWazuhVersion == "4.9.0" && version != "2.13.0.0" {
		t.Errorf("GetDefaultPrometheusExporterPluginVersion() = %v for Wazuh 4.9.0, expected 2.13.0.0", version)
	}
}

func TestGetOpenSearchVersionForWazuh(t *testing.T) {
	tests := []struct {
		wazuhVersion string
		expected     string
	}{
		{"4.9.0", "2.13.0"},
		{"4.14.1", "2.19.1"},
		{"invalid", GetDefaultOpenSearchVersion()}, // Should fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.wazuhVersion, func(t *testing.T) {
			got := GetOpenSearchVersionForWazuh(tt.wazuhVersion)
			if got != tt.expected {
				t.Errorf("GetOpenSearchVersionForWazuh(%v) = %v, expected %v",
					tt.wazuhVersion, got, tt.expected)
			}
		})
	}
}

func TestGetPrometheusExporterPluginVersionForWazuh(t *testing.T) {
	tests := []struct {
		wazuhVersion string
		expected     string
	}{
		{"4.9.0", "2.13.0.0"},
		{"4.14.1", "2.19.1.0"},
		{"invalid", GetDefaultPrometheusExporterPluginVersion()}, // Should fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.wazuhVersion, func(t *testing.T) {
			got := GetPrometheusExporterPluginVersionForWazuh(tt.wazuhVersion)
			if got != tt.expected {
				t.Errorf("GetPrometheusExporterPluginVersionForWazuh(%v) = %v, expected %v",
					tt.wazuhVersion, got, tt.expected)
			}
		})
	}
}

func TestGetVersionInfo(t *testing.T) {
	// Valid version
	info := GetVersionInfo("4.14.1")
	if info == nil {
		t.Fatal("GetVersionInfo(4.14.1) returned nil")
	}
	if info.WazuhVersion != "4.14.1" {
		t.Errorf("GetVersionInfo(4.14.1).WazuhVersion = %v, expected 4.14.1", info.WazuhVersion)
	}
	if info.OpenSearchVersion != "2.19.1" {
		t.Errorf("GetVersionInfo(4.14.1).OpenSearchVersion = %v, expected 2.19.1", info.OpenSearchVersion)
	}

	// Invalid version should return nil
	info = GetVersionInfo("invalid")
	if info != nil {
		t.Errorf("GetVersionInfo(invalid) = %v, expected nil", info)
	}
}

func TestVersionConsistency(t *testing.T) {
	// Ensure all version functions are consistent for the default version
	opensearchVersion := GetDefaultOpenSearchVersion()
	pluginVersion := GetDefaultPrometheusExporterPluginVersion()

	// Plugin version should start with OpenSearch version
	if !strings.HasPrefix(pluginVersion, opensearchVersion) {
		t.Errorf("Plugin version %v should start with OpenSearch version %v",
			pluginVersion, opensearchVersion)
	}
}
