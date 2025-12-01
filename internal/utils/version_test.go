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

package utils

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantMajor int
		wantMinor int
		wantPatch int
		wantErr   bool
	}{
		{
			name:      "standard version",
			version:   "4.9.0",
			wantMajor: 4,
			wantMinor: 9,
			wantPatch: 0,
		},
		{
			name:      "version with v prefix",
			version:   "v4.14.1",
			wantMajor: 4,
			wantMinor: 14,
			wantPatch: 1,
		},
		{
			name:      "version with rc suffix",
			version:   "4.9.0-rc1",
			wantMajor: 4,
			wantMinor: 9,
			wantPatch: 0,
		},
		{
			name:      "two part version",
			version:   "4.9",
			wantMajor: 4,
			wantMinor: 9,
			wantPatch: 0,
		},
		{
			name:    "invalid version",
			version: "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if v.Major != tt.wantMajor || v.Minor != tt.wantMinor || v.Patch != tt.wantPatch {
					t.Errorf("ParseVersion() = %d.%d.%d, want %d.%d.%d",
						v.Major, v.Minor, v.Patch,
						tt.wantMajor, tt.wantMinor, tt.wantPatch)
				}
			}
		})
	}
}

func TestGetWazuhVersionInfo(t *testing.T) {
	tests := []struct {
		name                  string
		wazuhVersion          string
		wantOpenSearchVersion string
		wantPluginVersion     string
		wantErr               bool
	}{
		{
			name:                  "Wazuh 4.9.0",
			wazuhVersion:          "4.9.0",
			wantOpenSearchVersion: "2.13.0",
			wantPluginVersion:     "2.13.0.0",
		},
		{
			name:                  "Wazuh 4.9.2",
			wazuhVersion:          "4.9.2",
			wantOpenSearchVersion: "2.13.0",
			wantPluginVersion:     "2.13.0.0",
		},
		{
			name:                  "Wazuh 4.10.0",
			wazuhVersion:          "4.10.0",
			wantOpenSearchVersion: "2.16.0",
			wantPluginVersion:     "2.16.0.0",
		},
		{
			name:                  "Wazuh 4.11.2",
			wazuhVersion:          "4.11.2",
			wantOpenSearchVersion: "2.16.0",
			wantPluginVersion:     "2.16.0.0",
		},
		{
			name:                  "Wazuh 4.14.1",
			wazuhVersion:          "4.14.1",
			wantOpenSearchVersion: "2.19.1",
			wantPluginVersion:     "2.19.1.0",
		},
		{
			name:                  "Wazuh with v prefix",
			wazuhVersion:          "v4.14.1",
			wantOpenSearchVersion: "2.19.1",
			wantPluginVersion:     "2.19.1.0",
		},
		{
			name:         "Unsupported version",
			wazuhVersion: "4.8.0",
			wantErr:      true,
		},
		{
			name:         "Invalid version",
			wazuhVersion: "invalid",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetWazuhVersionInfo(tt.wazuhVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWazuhVersionInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if info.OpenSearchVersion != tt.wantOpenSearchVersion {
					t.Errorf("GetWazuhVersionInfo() OpenSearchVersion = %v, want %v",
						info.OpenSearchVersion, tt.wantOpenSearchVersion)
				}
				if info.PrometheusExporterPluginVersion != tt.wantPluginVersion {
					t.Errorf("GetWazuhVersionInfo() PrometheusExporterPluginVersion = %v, want %v",
						info.PrometheusExporterPluginVersion, tt.wantPluginVersion)
				}
			}
		})
	}
}

func TestGetOpenSearchVersionFromWazuh(t *testing.T) {
	tests := []struct {
		name         string
		wazuhVersion string
		want         string
		wantErr      bool
	}{
		{
			name:         "Wazuh 4.9.0",
			wazuhVersion: "4.9.0",
			want:         "2.13.0",
		},
		{
			name:         "Wazuh 4.14.1",
			wazuhVersion: "4.14.1",
			want:         "2.19.1",
		},
		{
			name:         "Unsupported version",
			wazuhVersion: "4.8.0",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetOpenSearchVersionFromWazuh(tt.wazuhVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetOpenSearchVersionFromWazuh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("GetOpenSearchVersionFromWazuh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrometheusExporterPluginVersion(t *testing.T) {
	tests := []struct {
		name         string
		wazuhVersion string
		want         string
		wantErr      bool
	}{
		{
			name:         "Wazuh 4.9.0",
			wazuhVersion: "4.9.0",
			want:         "2.13.0.0",
		},
		{
			name:         "Wazuh 4.14.1",
			wazuhVersion: "4.14.1",
			want:         "2.19.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPrometheusExporterPluginVersion(tt.wazuhVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrometheusExporterPluginVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("GetPrometheusExporterPluginVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrometheusExporterDownloadURL(t *testing.T) {
	url, err := GetPrometheusExporterDownloadURL("4.14.1")
	if err != nil {
		t.Fatalf("GetPrometheusExporterDownloadURL() error = %v", err)
	}

	expected := "https://github.com/opensearch-project/opensearch-prometheus-exporter/releases/download/2.19.1.0/prometheus-exporter-2.19.1.0.zip"
	if url != expected {
		t.Errorf("GetPrometheusExporterDownloadURL() = %v, want %v", url, expected)
	}
}

func TestExtractOpenSearchVersionFromPluginVersion(t *testing.T) {
	tests := []struct {
		pluginVersion string
		want          string
	}{
		{"2.19.1.0", "2.19.1"},
		{"2.13.0.0", "2.13.0"},
		{"2.16.0.0", "2.16.0"},
		{"2.13.0", "2.13.0"},
	}

	for _, tt := range tests {
		t.Run(tt.pluginVersion, func(t *testing.T) {
			got := ExtractOpenSearchVersionFromPluginVersion(tt.pluginVersion)
			if got != tt.want {
				t.Errorf("ExtractOpenSearchVersionFromPluginVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWazuhToOpenSearchVersion(t *testing.T) {
	tests := []struct {
		name         string
		wazuhVersion string
		wantVersion  string
		wantErr      bool
	}{
		{
			name:         "Wazuh 4.9.0 exact match",
			wazuhVersion: "4.9.0",
			wantVersion:  "2.13.0",
		},
		{
			name:         "Wazuh 4.14.1 exact match",
			wazuhVersion: "4.14.1",
			wantVersion:  "2.19.1",
		},
		{
			name:         "Wazuh 4.8.0 fallback",
			wazuhVersion: "4.8.0",
			wantVersion:  "2.10.0",
		},
		{
			name:         "Wazuh 5.0.0 fallback",
			wazuhVersion: "5.0.0",
			wantVersion:  "2.19.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := WazuhToOpenSearchVersion(tt.wazuhVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("WazuhToOpenSearchVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				got := v.String()
				if got != tt.wantVersion {
					t.Errorf("WazuhToOpenSearchVersion() = %v, want %v", got, tt.wantVersion)
				}
			}
		})
	}
}

func TestGetHotReloadSupportForWazuh(t *testing.T) {
	tests := []struct {
		name         string
		wazuhVersion string
		wantSupport  HotReloadSupport
	}{
		{
			name:         "Wazuh 4.9.0 requires API call",
			wazuhVersion: "4.9.0",
			wantSupport:  HotReloadWithAPICall,
		},
		{
			name:         "Wazuh 4.11.0 requires API call",
			wazuhVersion: "4.11.0",
			wantSupport:  HotReloadWithAPICall,
		},
		{
			name:         "Wazuh 4.12.0 automatic",
			wazuhVersion: "4.12.0",
			wantSupport:  HotReloadAutomatic,
		},
		{
			name:         "Wazuh 4.14.1 automatic",
			wazuhVersion: "4.14.1",
			wantSupport:  HotReloadAutomatic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			support, err := GetHotReloadSupportForWazuh(tt.wazuhVersion)
			if err != nil {
				t.Fatalf("GetHotReloadSupportForWazuh() error = %v", err)
			}
			if support != tt.wantSupport {
				t.Errorf("GetHotReloadSupportForWazuh() = %v, want %v", support, tt.wantSupport)
			}
		})
	}
}
