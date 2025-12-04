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
	"bytes"
	"fmt"
	"text/template"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// FilebeatConfig holds configuration for filebeat.yml generation
type FilebeatConfig struct {
	// IndexerHost is the OpenSearch indexer host
	IndexerHost string
	// IndexerPort is the OpenSearch indexer port
	IndexerPort int
	// IndexerProtocol is the protocol (http/https)
	IndexerProtocol string
	// IndexerUsername is the username for authentication
	IndexerUsername string
	// IndexerPassword is the password for authentication
	IndexerPassword string
	// SSLEnabled enables SSL/TLS
	SSLEnabled bool
	// SSLVerificationMode is the SSL verification mode (full, certificate, none)
	SSLVerificationMode string
	// CACertPath is the path to the CA certificate
	CACertPath string
	// CertPath is the path to the client certificate
	CertPath string
	// KeyPath is the path to the client key
	KeyPath string
	// WazuhAlertsIndex is the index name for alerts
	WazuhAlertsIndex string
	// WazuhArchivesIndex is the index name for archives
	WazuhArchivesIndex string
	// ClusterName is the Wazuh cluster name
	ClusterName string
	// NodeName is the node name
	NodeName string
	// LogPath is the path to Wazuh alerts JSON file
	LogPath string
}

// DefaultFilebeatConfig returns a default FilebeatConfig
// Note: IndexerUsername defaults to empty - reconciler should set it from CredentialsSecretRef
func DefaultFilebeatConfig(clusterName, indexerHost string) *FilebeatConfig {
	return &FilebeatConfig{
		IndexerHost:         indexerHost,
		IndexerPort:         int(constants.PortIndexerREST),
		IndexerProtocol:     "https",
		IndexerUsername:     "", // Set by reconciler from indexer CredentialsSecretRef
		IndexerPassword:     "", //
		SSLEnabled:          true,
		SSLVerificationMode: "full",
		CACertPath:          constants.PathFilebeatCAFile,
		CertPath:            constants.PathFilebeatCertFile,
		KeyPath:             constants.PathFilebeatKeyFile,
		WazuhAlertsIndex:    constants.IndexWazuhAlerts,
		WazuhArchivesIndex:  constants.IndexWazuhArchives,
		ClusterName:         clusterName,
		NodeName:            "master-node",
		LogPath:             constants.PathWazuhLogs + "/alerts/alerts.json",
	}
}

// FilebeatConfigBuilder builds filebeat.yml content
type FilebeatConfigBuilder struct {
	config *FilebeatConfig
}

// NewFilebeatConfigBuilder creates a new FilebeatConfigBuilder
func NewFilebeatConfigBuilder(config *FilebeatConfig) *FilebeatConfigBuilder {
	if config == nil {
		config = DefaultFilebeatConfig("wazuh", "wazuh-indexer")
	}
	return &FilebeatConfigBuilder{config: config}
}

// Build generates the filebeat.yml content
func (b *FilebeatConfigBuilder) Build() (string, error) {
	tmpl, err := template.New("filebeat.yml").Parse(filebeatConfigTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse filebeat.yml template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, b.config); err != nil {
		return "", fmt.Errorf("failed to execute filebeat.yml template: %w", err)
	}

	return buf.String(), nil
}

// SetIndexerHost sets the indexer host
func (b *FilebeatConfigBuilder) SetIndexerHost(host string) *FilebeatConfigBuilder {
	b.config.IndexerHost = host
	return b
}

// SetIndexerPort sets the indexer port
func (b *FilebeatConfigBuilder) SetIndexerPort(port int) *FilebeatConfigBuilder {
	b.config.IndexerPort = port
	return b
}

// SetIndexerCredentials sets the indexer username and password
func (b *FilebeatConfigBuilder) SetIndexerCredentials(username, password string) *FilebeatConfigBuilder {
	b.config.IndexerUsername = username
	b.config.IndexerPassword = password
	return b
}

// SetSSLConfig sets the SSL configuration
func (b *FilebeatConfigBuilder) SetSSLConfig(enabled bool, verificationMode, caPath, certPath, keyPath string) *FilebeatConfigBuilder {
	b.config.SSLEnabled = enabled
	b.config.SSLVerificationMode = verificationMode
	b.config.CACertPath = caPath
	b.config.CertPath = certPath
	b.config.KeyPath = keyPath
	return b
}

// SetClusterName sets the cluster name
func (b *FilebeatConfigBuilder) SetClusterName(clusterName string) *FilebeatConfigBuilder {
	b.config.ClusterName = clusterName
	return b
}

// SetNodeName sets the node name
func (b *FilebeatConfigBuilder) SetNodeName(nodeName string) *FilebeatConfigBuilder {
	b.config.NodeName = nodeName
	return b
}

// BuildFilebeatConfig builds filebeat.yml for a Wazuh manager
// The username parameter should be resolved from the cluster's indexer credentials (CredentialsSecretRef)
// If username is empty, it defaults to "admin" for backwards compatibility
func BuildFilebeatConfig(clusterName, namespace, indexerService string, sslVerificationMode string) (string, error) {
	return BuildFilebeatConfigWithCredentials(clusterName, namespace, indexerService, sslVerificationMode, "", "")
}

// BuildFilebeatConfigWithCredentials builds filebeat.yml with explicit credentials
// This is the preferred method - the reconciler should resolve credentials from the
// indexer's CredentialsSecretRef and pass them here
// The password is passed via INDEXER_PASSWORD env var in the container, so only username is embedded
func BuildFilebeatConfigWithCredentials(clusterName, namespace, indexerService, sslVerificationMode, username, password string) (string, error) {
	indexerHost := fmt.Sprintf("%s.%s.svc.cluster.local", indexerService, namespace)

	// Default to OpenSearch admin username if no username provided (backwards compatibility)
	if username == "" {
		username = constants.DefaultOpenSearchAdminUsername
	}

	config := &FilebeatConfig{
		IndexerHost:         indexerHost,
		IndexerPort:         int(constants.PortIndexerREST),
		IndexerProtocol:     "https",
		IndexerUsername:     username,
		IndexerPassword:     password,
		SSLEnabled:          true,
		SSLVerificationMode: sslVerificationMode,
		CACertPath:          "/etc/ssl/certs/indexer/root-ca.pem",
		CertPath:            "/etc/ssl/certs/wazuh/filebeat.pem",
		KeyPath:             "/etc/ssl/certs/wazuh/filebeat-key.pem",
		WazuhAlertsIndex:    "wazuh-alerts-4.x-",
		WazuhArchivesIndex:  "wazuh-archives-4.x-",
		ClusterName:         clusterName,
		NodeName:            "manager",
		LogPath:             constants.PathWazuhLogs + "/alerts/alerts.json",
	}
	return NewFilebeatConfigBuilder(config).Build()
}

// GenerateIndexerServiceName generates the indexer service name
func GenerateIndexerServiceName(clusterName, namespace string) string {
	return fmt.Sprintf("%s-indexer.%s.svc.cluster.local", clusterName, namespace)
}

// filebeatConfigTemplate is the template for generating filebeat.yml
// All values are embedded directly - no environment variable substitution needed
const filebeatConfigTemplate = `# Wazuh Filebeat Configuration
# Generated by Wazuh Operator

# Wazuh - Filebeat configuration file
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false

# TODO : Add the ability to manage the Filebeat configuration from a CRD
# filebeat.overwrite_pipelines: true

setup.template.enabled: true
setup.template.overwrite: true
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'

# ILM (Index Lifecycle Management) is an Elasticsearch feature not supported by OpenSearch
# Must be disabled for Wazuh Indexer (OpenSearch)
setup.ilm.enabled: false

output.elasticsearch:
{{- if .SSLEnabled }}
  protocol: {{ .IndexerProtocol }}
{{- end }}
  hosts:
    - "{{ .IndexerHost }}:{{ .IndexerPort }}"
{{- if .IndexerUsername }}
  username: "{{ .IndexerUsername }}"
{{- end }}
{{- if .IndexerPassword }}
  password: "{{ .IndexerPassword }}"
{{- end }}
{{- if .SSLEnabled }}
  ssl:
    certificate_authorities:
      - {{ .CACertPath }}
    certificate: {{ .CertPath }}
    key: {{ .KeyPath }}
{{- if .SSLVerificationMode }}
    verification_mode: {{ .SSLVerificationMode }}
{{- end }}
{{- end }}

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

logging.metrics.enabled: false

# Seccomp configuration to avoid pthread_create failures in containerized environments
# The rseq syscall is needed for thread creation on modern kernels
seccomp:
  default_action: allow
  syscalls:
  - action: allow
    names:
    - rseq
`
