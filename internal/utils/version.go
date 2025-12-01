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
	"fmt"
	"strconv"
	"strings"
)

// Version represents a semantic version
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses a version string like "4.9.0" into a Version struct
func ParseVersion(version string) (*Version, error) {
	// Remove any leading 'v' if present
	version = strings.TrimPrefix(version, "v")

	// Split by dots
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch := 0
	if len(parts) >= 3 {
		// Handle patch version which might have additional suffixes like "0-rc1"
		patchStr := strings.Split(parts[2], "-")[0]
		patch, err = strconv.Atoi(patchStr)
		if err != nil {
			// If patch can't be parsed, default to 0
			patch = 0
		}
	}

	return &Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

// Compare compares two versions
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// GreaterThanOrEqual returns true if v >= other
func (v *Version) GreaterThanOrEqual(other *Version) bool {
	return v.Compare(other) >= 0
}

// LessThan returns true if v < other
func (v *Version) LessThan(other *Version) bool {
	return v.Compare(other) < 0
}

// String returns the version as a string
func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// WazuhToOpenSearchVersion maps Wazuh versions to corresponding OpenSearch versions
// Based on Wazuh documentation:
// - Wazuh 4.9.x uses OpenSearch 2.13.x
// - Wazuh 4.10.x-4.11.x uses OpenSearch 2.16.x
// - Wazuh 4.12.x+ uses OpenSearch 2.19.x
// - Wazuh 5.0.x (future) will use OpenSearch 2.19.x+
func WazuhToOpenSearchVersion(wazuhVersion string) (*Version, error) {
	// First try to get exact version from the mapping table
	info, err := GetWazuhVersionInfo(wazuhVersion)
	if err == nil {
		return ParseVersion(info.OpenSearchVersion)
	}

	// Fallback to approximate mapping for older/unknown versions
	wv, parseErr := ParseVersion(wazuhVersion)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse Wazuh version: %w", parseErr)
	}

	// Mapping table based on Wazuh releases
	// https://documentation.wazuh.com/current/release-notes/index.html
	switch {
	case wv.Major == 4 && wv.Minor >= 12:
		// Wazuh 4.12.x+ → OpenSearch 2.19.x
		return &Version{Major: 2, Minor: 19, Patch: 1}, nil
	case wv.Major == 4 && wv.Minor >= 10:
		// Wazuh 4.10.x-4.11.x → OpenSearch 2.16.x
		return &Version{Major: 2, Minor: 16, Patch: 0}, nil
	case wv.Major == 4 && wv.Minor >= 9:
		// Wazuh 4.9.x → OpenSearch 2.13.x
		return &Version{Major: 2, Minor: 13, Patch: 0}, nil
	case wv.Major == 4 && wv.Minor >= 7:
		// Wazuh 4.7.x-4.8.x → OpenSearch 2.10.x
		return &Version{Major: 2, Minor: 10, Patch: 0}, nil
	case wv.Major == 4 && wv.Minor >= 4:
		// Wazuh 4.4.x-4.6.x → OpenSearch 2.6.x
		return &Version{Major: 2, Minor: 6, Patch: 0}, nil
	case wv.Major >= 5:
		// Wazuh 5.x (future) → OpenSearch 2.19.x+
		return &Version{Major: 2, Minor: 19, Patch: 0}, nil
	default:
		// Older versions → OpenSearch 1.x or earlier
		return &Version{Major: 1, Minor: 0, Patch: 0}, nil
	}
}

// HotReloadSupport represents the level of hot reload support for a version
type HotReloadSupport int

const (
	// HotReloadNotSupported indicates the version doesn't support hot reload
	HotReloadNotSupported HotReloadSupport = iota
	// HotReloadWithAPICall indicates hot reload is supported but requires API call
	// This applies to OpenSearch 2.13 - 2.18.x
	HotReloadWithAPICall
	// HotReloadAutomatic indicates fully automatic hot reload via config only
	// This applies to OpenSearch 2.19+
	HotReloadAutomatic
)

// String returns a human-readable description of the hot reload support level
func (h HotReloadSupport) String() string {
	switch h {
	case HotReloadNotSupported:
		return "not supported"
	case HotReloadWithAPICall:
		return "supported (requires API call)"
	case HotReloadAutomatic:
		return "fully automatic"
	default:
		return "unknown"
	}
}

// MinOpenSearchVersionForHotReload is the minimum OpenSearch version that supports hot reload
var MinOpenSearchVersionForHotReload = &Version{Major: 2, Minor: 13, Patch: 0}

// MinOpenSearchVersionForAutoHotReload is the minimum version for automatic hot reload
var MinOpenSearchVersionForAutoHotReload = &Version{Major: 2, Minor: 19, Patch: 0}

// MinWazuhVersionForHotReload is the minimum Wazuh version that supports hot reload
var MinWazuhVersionForHotReload = &Version{Major: 4, Minor: 9, Patch: 0}

// GetHotReloadSupport returns the hot reload support level for a given OpenSearch version
func GetHotReloadSupport(openSearchVersion *Version) HotReloadSupport {
	if openSearchVersion == nil {
		return HotReloadNotSupported
	}

	if openSearchVersion.LessThan(MinOpenSearchVersionForHotReload) {
		return HotReloadNotSupported
	}

	if openSearchVersion.GreaterThanOrEqual(MinOpenSearchVersionForAutoHotReload) {
		return HotReloadAutomatic
	}

	return HotReloadWithAPICall
}

// GetHotReloadSupportForWazuh returns the hot reload support level for a given Wazuh version
func GetHotReloadSupportForWazuh(wazuhVersion string) (HotReloadSupport, error) {
	osVersion, err := WazuhToOpenSearchVersion(wazuhVersion)
	if err != nil {
		return HotReloadNotSupported, err
	}
	return GetHotReloadSupport(osVersion), nil
}

// SupportsHotReload returns true if the given Wazuh version supports hot reload
func SupportsHotReload(wazuhVersion string) bool {
	support, err := GetHotReloadSupportForWazuh(wazuhVersion)
	if err != nil {
		return false
	}
	return support != HotReloadNotSupported
}

// RequiresAPIReload returns true if the given Wazuh version requires API call for hot reload
func RequiresAPIReload(wazuhVersion string) bool {
	support, err := GetHotReloadSupportForWazuh(wazuhVersion)
	if err != nil {
		return false
	}
	return support == HotReloadWithAPICall
}

// SupportsAutomaticHotReload returns true if the Wazuh version supports fully automatic hot reload
func SupportsAutomaticHotReload(wazuhVersion string) bool {
	support, err := GetHotReloadSupportForWazuh(wazuhVersion)
	if err != nil {
		return false
	}
	return support == HotReloadAutomatic
}

// WazuhVersionInfo contains version information for a Wazuh release
// including the corresponding OpenSearch version and Prometheus exporter plugin version
type WazuhVersionInfo struct {
	// WazuhVersion is the Wazuh version (e.g., "4.9.0")
	WazuhVersion string
	// OpenSearchVersion is the corresponding OpenSearch version (e.g., "2.13.0")
	OpenSearchVersion string
	// PrometheusExporterPluginVersion is the OpenSearch Prometheus exporter plugin version (e.g., "2.13.0.0")
	// Format: OpenSearchVersion.PatchVersion (X.X.X.X)
	PrometheusExporterPluginVersion string
}

// wazuhVersionMapping maps Wazuh versions to OpenSearch and Prometheus exporter plugin versions
// Based on Wazuh compatibility matrix
// The plugin version format is: OpenSearchVersion.PatchVersion (e.g., 2.19.1.0)
var wazuhVersionMapping = map[string]WazuhVersionInfo{
	// Wazuh 4.14.x - OpenSearch 2.19.1
	"4.14.1": {WazuhVersion: "4.14.1", OpenSearchVersion: "2.19.1", PrometheusExporterPluginVersion: "2.19.1.0"},
	"4.14.0": {WazuhVersion: "4.14.0", OpenSearchVersion: "2.19.1", PrometheusExporterPluginVersion: "2.19.1.0"},
	// Wazuh 4.13.x - OpenSearch 2.19.1
	"4.13.1": {WazuhVersion: "4.13.1", OpenSearchVersion: "2.19.1", PrometheusExporterPluginVersion: "2.19.1.0"},
	"4.13.0": {WazuhVersion: "4.13.0", OpenSearchVersion: "2.19.1", PrometheusExporterPluginVersion: "2.19.1.0"},
	// Wazuh 4.12.x - OpenSearch 2.19.1
	"4.12.0": {WazuhVersion: "4.12.0", OpenSearchVersion: "2.19.1", PrometheusExporterPluginVersion: "2.19.1.0"},
	// Wazuh 4.11.x - OpenSearch 2.16.0
	"4.11.2": {WazuhVersion: "4.11.2", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	"4.11.1": {WazuhVersion: "4.11.1", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	"4.11.0": {WazuhVersion: "4.11.0", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	// Wazuh 4.10.x - OpenSearch 2.16.0
	"4.10.2": {WazuhVersion: "4.10.2", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	"4.10.1": {WazuhVersion: "4.10.1", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	"4.10.0": {WazuhVersion: "4.10.0", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	// Wazuh 4.9.x - OpenSearch 2.13.0
	"4.9.2": {WazuhVersion: "4.9.2", OpenSearchVersion: "2.13.0", PrometheusExporterPluginVersion: "2.13.0.0"},
	"4.9.1": {WazuhVersion: "4.9.1", OpenSearchVersion: "2.13.0", PrometheusExporterPluginVersion: "2.13.0.0"},
	"4.9.0": {WazuhVersion: "4.9.0", OpenSearchVersion: "2.13.0", PrometheusExporterPluginVersion: "2.13.0.0"},
}

// GetWazuhVersionInfo returns complete version information for a given Wazuh version
// including the corresponding OpenSearch version and Prometheus exporter plugin version.
// Returns an error if the Wazuh version is not supported.
func GetWazuhVersionInfo(wazuhVersion string) (*WazuhVersionInfo, error) {
	// Normalize version (remove leading 'v' if present)
	wazuhVersion = strings.TrimPrefix(wazuhVersion, "v")

	// Direct lookup in mapping table
	if info, exists := wazuhVersionMapping[wazuhVersion]; exists {
		return &info, nil
	}

	// Try to find the closest matching version based on major.minor
	wv, err := ParseVersion(wazuhVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid Wazuh version format: %s", wazuhVersion)
	}

	// Find the best match based on major.minor version
	var bestMatch *WazuhVersionInfo
	var bestMatchVersion *Version

	for verStr, info := range wazuhVersionMapping {
		mappedVer, _ := ParseVersion(verStr)
		if mappedVer == nil {
			continue
		}

		// Must match major version
		if mappedVer.Major != wv.Major {
			continue
		}

		// Must match minor version
		if mappedVer.Minor != wv.Minor {
			continue
		}

		// Select the highest patch version that doesn't exceed the requested version
		if bestMatchVersion == nil || mappedVer.Patch > bestMatchVersion.Patch {
			if mappedVer.Patch <= wv.Patch {
				infoCopy := info
				bestMatch = &infoCopy
				bestMatchVersion = mappedVer
			}
		}
	}

	if bestMatch != nil {
		// Update with the actual requested version
		bestMatch.WazuhVersion = wazuhVersion
		return bestMatch, nil
	}

	return nil, fmt.Errorf("unsupported Wazuh version %s: only versions 4.9.0 and above are supported", wazuhVersion)
}

// GetOpenSearchVersionFromWazuh maps Wazuh versions to their corresponding OpenSearch versions
// Returns: openSearchVersion (X.X.X format), error
// This is a convenience wrapper around GetWazuhVersionInfo
func GetOpenSearchVersionFromWazuh(wazuhVersion string) (string, error) {
	info, err := GetWazuhVersionInfo(wazuhVersion)
	if err != nil {
		return "", err
	}
	return info.OpenSearchVersion, nil
}

// GetPrometheusExporterPluginVersion maps Wazuh versions to their corresponding
// OpenSearch Prometheus exporter plugin versions
// Returns: pluginVersion (X.X.X.X format), error
// This is used for installing the prometheus-exporter plugin in the indexer
func GetPrometheusExporterPluginVersion(wazuhVersion string) (string, error) {
	info, err := GetWazuhVersionInfo(wazuhVersion)
	if err != nil {
		return "", err
	}
	return info.PrometheusExporterPluginVersion, nil
}

// GetPrometheusExporterDownloadURL returns the download URL for the OpenSearch Prometheus exporter plugin
// based on the Wazuh version
func GetPrometheusExporterDownloadURL(wazuhVersion string) (string, error) {
	pluginVersion, err := GetPrometheusExporterPluginVersion(wazuhVersion)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"https://github.com/opensearch-project/opensearch-prometheus-exporter/releases/download/%s/prometheus-exporter-%s.zip",
		pluginVersion,
		pluginVersion,
	), nil
}

// ExtractOpenSearchVersionFromPluginVersion extracts the OpenSearch version (X.X.X) from
// the plugin version (X.X.X.X)
func ExtractOpenSearchVersionFromPluginVersion(pluginVersion string) string {
	// Split by dots and take first 3 parts
	parts := strings.Split(pluginVersion, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}
	return pluginVersion
}
