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

// Wazuh Manager paths
const (
	// PathWazuhBase is the base path for Wazuh installation
	PathWazuhBase = "/var/ossec"

	// PathWazuhData is the data directory
	PathWazuhData = "/var/ossec/data"

	// PathWazuhLogs is the logs directory
	PathWazuhLogs = "/var/ossec/logs"

	// PathWazuhConfig is the configuration directory
	PathWazuhConfig = "/var/ossec/etc"

	// PathWazuhOssecConf is the main configuration file
	PathWazuhOssecConf = "/var/ossec/etc/ossec.conf"

	// PathWazuhRulesLocal is the local rules directory
	PathWazuhRulesLocal = "/var/ossec/etc/rules"

	// PathWazuhDecodersLocal is the local decoders directory
	PathWazuhDecodersLocal = "/var/ossec/etc/decoders"

	// PathWazuhQueue is the queue directory
	PathWazuhQueue = "/var/ossec/queue"

	// PathWazuhSharedGroups is the shared groups directory
	PathWazuhSharedGroups = "/var/ossec/etc/shared"
)

// OpenSearch Indexer paths (using Wazuh Indexer paths)
const (
	// PathIndexerBase is the base path for Wazuh Indexer
	PathIndexerBase = "/usr/share/wazuh-indexer"

	// PathIndexerData is the data directory
	PathIndexerData = "/var/lib/wazuh-indexer"

	// PathIndexerConfig is the configuration directory
	PathIndexerConfig = "/usr/share/wazuh-indexer"

	// PathIndexerLogs is the logs directory
	PathIndexerLogs = "/var/log/wazuh-indexer"

	// PathIndexerSecurityConfig is the security plugin config directory
	PathIndexerSecurityConfig = "/usr/share/wazuh-indexer/opensearch-security"

	// PathIndexerCerts is the certificates directory
	PathIndexerCerts = "/usr/share/wazuh-indexer/certs"

	// PathIndexerPlugins is the plugins directory
	PathIndexerPlugins = "/usr/share/wazuh-indexer/plugins"
)

// OpenSearch Dashboard paths (using Wazuh Dashboard paths)
const (
	// PathDashboardBase is the base path for Wazuh Dashboard
	PathDashboardBase = "/usr/share/wazuh-dashboard"

	// PathDashboardConfig is the configuration directory
	PathDashboardConfig = "/usr/share/wazuh-dashboard/config"

	// PathDashboardData is the data directory
	PathDashboardData = "/usr/share/wazuh-dashboard/data"

	// PathDashboardCerts is the certificates directory
	PathDashboardCerts = "/usr/share/wazuh-dashboard/certs"

	// PathDashboardPlugins is the plugins directory
	PathDashboardPlugins = "/usr/share/wazuh-dashboard/plugins"
)

// Filebeat paths
const (
	// PathFilebeatBase is the base path for Filebeat
	PathFilebeatBase = "/usr/share/filebeat"

	// PathFilebeatConfig is the configuration directory
	PathFilebeatConfig = "/etc/filebeat"

	// PathFilebeatData is the data directory
	PathFilebeatData = "/var/lib/filebeat"

	// PathFilebeatCerts is the certificates directory
	PathFilebeatCerts = "/etc/filebeat/certs"
)

// TLS Secret key names (Kubernetes convention)
const (
	// SecretKeyTLSCert is the standard Kubernetes TLS certificate key
	SecretKeyTLSCert = "tls.crt"

	// SecretKeyTLSKey is the standard Kubernetes TLS private key
	SecretKeyTLSKey = "tls.key"

	// SecretKeyCACert is the CA certificate key in secrets
	SecretKeyCACert = "ca.crt"

	// SecretKeyCAKey is the CA private key in secrets
	SecretKeyCAKey = "ca.key"
)

// Certificate file names
const (
	// FilenameCACert is the CA certificate filename
	FilenameCACert = "ca.crt"

	// FilenameCAKey is the CA private key filename
	FilenameCAKey = "ca.key"

	// FilenameNodeCert is the node certificate filename
	FilenameNodeCert = "node.crt"

	// FilenameNodeKey is the node private key filename
	FilenameNodeKey = "node.key"

	// FilenameAdminCert is the admin certificate filename
	FilenameAdminCert = "admin.crt"

	// FilenameAdminKey is the admin private key filename
	FilenameAdminKey = "admin.key"

	// FilenameDashboardCert is the dashboard certificate filename
	FilenameDashboardCert = "dashboard.crt"

	// FilenameDashboardKey is the dashboard private key filename
	FilenameDashboardKey = "dashboard.key"

	// FilenameFilebeatCert is the filebeat certificate filename
	FilenameFilebeatCert = "filebeat.crt"

	// FilenameFilebeatKey is the filebeat private key filename
	FilenameFilebeatKey = "filebeat.key"
)

// ConfigMap key names
const (
	// ConfigMapKeyOssecConf is the key for ossec.conf in ConfigMap
	ConfigMapKeyOssecConf = "ossec.conf"

	// ConfigMapKeyOpenSearchYml is the key for opensearch.yml in ConfigMap
	ConfigMapKeyOpenSearchYml = "opensearch.yml"

	// ConfigMapKeyDashboardYml is the key for opensearch_dashboards.yml in ConfigMap
	ConfigMapKeyDashboardYml = "opensearch_dashboards.yml"

	// ConfigMapKeyFilebeatYml is the key for filebeat.yml in ConfigMap
	ConfigMapKeyFilebeatYml = "filebeat.yml"
)

// Secret key names
const (
	// SecretKeyAdminUsername is the key for admin username in indexer credentials secret
	SecretKeyAdminUsername = "admin-username"

	// SecretKeyAdminPassword is the key for admin password in indexer credentials secret
	SecretKeyAdminPassword = "admin-password"

	// SecretKeyClusterKey is the key for Wazuh cluster key
	SecretKeyClusterKey = "cluster-key"

	// SecretKeyAPIUsername is the key for Wazuh API username
	SecretKeyAPIUsername = "api-username"

	// SecretKeyAPIPassword is the key for Wazuh API password
	SecretKeyAPIPassword = "api-password"
)
