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

package constants

import "github.com/MaximeWewer/wazuh-operator/pkg/versions"

// MinWazuhVersionForIndexerConfigDir is the first version that reads opensearch.yml from config dir
var MinWazuhVersionForIndexerConfigDir = &versions.Version{Major: 4, Minor: 14, Patch: 0}

// UsesIndexerConfigDir returns true when Wazuh uses /usr/share/wazuh-indexer/config
func UsesIndexerConfigDir(wazuhVersion string) bool {
	parsed, err := versions.ParseVersion(wazuhVersion)
	if err != nil {
		return true
	}
	return parsed.GreaterThanOrEqual(MinWazuhVersionForIndexerConfigDir)
}

// IndexerConfigFilePath returns the correct opensearch.yml path for the given Wazuh version
func IndexerConfigFilePath(wazuhVersion string) string {
	if UsesIndexerConfigDir(wazuhVersion) {
		return PathIndexerConfig + "/opensearch.yml"
	}
	return PathIndexerBase + "/opensearch.yml"
}

// IndexerSecurityConfigDir returns the correct security config dir for the given Wazuh version
func IndexerSecurityConfigDir(wazuhVersion string) string {
	if UsesIndexerConfigDir(wazuhVersion) {
		return PathIndexerSecurityConfig
	}
	return PathIndexerLegacySecurityConfig
}

// IndexerCertsDir returns the correct certs directory for the given Wazuh version
func IndexerCertsDir(wazuhVersion string) string {
	if UsesIndexerConfigDir(wazuhVersion) {
		return PathIndexerCerts
	}
	return PathIndexerLegacyCerts
}
