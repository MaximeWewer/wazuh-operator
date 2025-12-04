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

// Volume names for Wazuh Manager pods
const (
	// VolumeNameWazuhData is the volume name for Wazuh data persistence
	VolumeNameWazuhData = "wazuh-data"

	// VolumeNameWazuhConfigSource is the volume name for config source (from ConfigMap)
	VolumeNameWazuhConfigSource = "wazuh-config-source"

	// VolumeNameWazuhConfigMount is the volume name for config mount (emptyDir for copy)
	VolumeNameWazuhConfigMount = "wazuh-config-mount"

	// VolumeNameWazuhCerts is the volume name for Wazuh certificates
	VolumeNameWazuhCerts = "wazuh-certs"

	// VolumeNameFilebeatConfig is the volume name for Filebeat configuration
	VolumeNameFilebeatConfig = "filebeat-config"

	// VolumeNameFilebeatCerts is the volume name for Filebeat certificates
	VolumeNameFilebeatCerts = "filebeat-certs"
)

// Volume names for OpenSearch Indexer pods
const (
	// VolumeNameIndexerData is the volume name for Indexer data persistence
	VolumeNameIndexerData = "indexer-data"

	// VolumeNameIndexerConfig is the volume name for Indexer configuration
	VolumeNameIndexerConfig = "indexer-config"

	// VolumeNameIndexerCerts is the volume name for Indexer certificates
	VolumeNameIndexerCerts = "indexer-certs"

	// VolumeNameIndexerSecurity is the volume name for Indexer security configuration
	VolumeNameIndexerSecurity = "indexer-security"

	// VolumeNameAdminCerts is the volume name for admin certificates (securityadmin)
	VolumeNameAdminCerts = "admin-certs"

	// VolumeNamePlugins is the volume name for plugins
	VolumeNamePlugins = "plugins"

	// VolumeNameConfigProcessed is the volume name for processed config (emptyDir)
	VolumeNameConfigProcessed = "config-processed"
)

// Volume names for OpenSearch Dashboard pods
const (
	// VolumeNameDashboardConfig is the volume name for Dashboard configuration
	VolumeNameDashboardConfig = "dashboard-config"

	// VolumeNameDashboardCerts is the volume name for Dashboard certificates
	VolumeNameDashboardCerts = "dashboard-certs"

	// VolumeNameDashboardData is the volume name for Dashboard data
	VolumeNameDashboardData = "dashboard-data"

	// VolumeNameDashboardConfigProcessed is the volume name for processed dashboard config
	VolumeNameDashboardConfigProcessed = "dashboard-config-processed"

	// VolumeNameWazuhAppConfigScript is the volume name for Wazuh app config script
	VolumeNameWazuhAppConfigScript = "wazuh-app-config-script"

	// VolumeNameWazuhConfig is the volume name for Wazuh config (wazuh.yml)
	VolumeNameWazuhConfig = "wazuh-config"
)

// Shared volume names
const (
	// VolumeNameTmpDir is the volume name for temporary directory
	VolumeNameTmpDir = "tmp-dir"

	// VolumeNameInitScripts is the volume name for init scripts
	VolumeNameInitScripts = "init-scripts"
)
