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
	"strings"
	"text/template"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// NodeTypeMaster indicates a master node
	NodeTypeMaster = "master"
	// NodeTypeWorker indicates a worker node
	NodeTypeWorker = "worker"
)

// GlobalConfig holds configuration for the <global> section
type GlobalConfig struct {
	// JSONOutOutput enables JSON output for alerts
	// +kubebuilder:default=true
	JSONOutOutput bool
	// AlertsLog enables alerts.log file
	// +kubebuilder:default=true
	AlertsLog bool
	// LogAll enables logging all events
	// +kubebuilder:default=false
	LogAll bool
	// LogAllJSON enables logging all events in JSON
	// +kubebuilder:default=false
	LogAllJSON bool
	// EmailNotification enables email notifications
	// +kubebuilder:default=false
	EmailNotification bool
	// SMTPServer is the SMTP server address
	SMTPServer string
	// EmailFrom is the sender email address
	EmailFrom string
	// EmailTo is the recipient email address
	EmailTo string
	// EmailMaxPerHour limits emails per hour
	// +kubebuilder:default=12
	EmailMaxPerHour int
	// EmailLogSource is the log source for emails
	// +kubebuilder:default="alerts.log"
	EmailLogSource string
	// AgentsDisconnectionTime is the time before agents are marked disconnected
	// +kubebuilder:default="10m"
	AgentsDisconnectionTime string
	// AgentsDisconnectionAlertTime is the time before disconnection alert (0 = disabled)
	// +kubebuilder:default="0"
	AgentsDisconnectionAlertTime string
}

// DefaultGlobalConfig returns a GlobalConfig with sensible defaults
func DefaultGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		JSONOutOutput:                true,
		AlertsLog:                    true,
		LogAll:                       false,
		LogAllJSON:                   false,
		EmailNotification:            false,
		SMTPServer:                   "smtp.example.wazuh.com",
		EmailFrom:                    "wazuh@example.wazuh.com",
		EmailTo:                      "recipient@example.wazuh.com",
		EmailMaxPerHour:              12,
		EmailLogSource:               "alerts.log",
		AgentsDisconnectionTime:      "10m",
		AgentsDisconnectionAlertTime: "0",
	}
}

// AlertsConfig holds configuration for the <alerts> section
type AlertsConfig struct {
	// LogAlertLevel is the minimum level for logging alerts (0-16)
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	LogAlertLevel int
	// EmailAlertLevel is the minimum level for email alerts (0-16)
	// +kubebuilder:default=12
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	EmailAlertLevel int
}

// DefaultAlertsConfig returns an AlertsConfig with sensible defaults
func DefaultAlertsConfig() *AlertsConfig {
	return &AlertsConfig{
		LogAlertLevel:   3,
		EmailAlertLevel: 12,
	}
}

// LoggingConfig holds configuration for the <logging> section
type LoggingConfig struct {
	// LogFormat is the log format (plain, json, plain,json)
	// +kubebuilder:default="plain"
	// +kubebuilder:validation:Enum=plain;json;"plain,json"
	LogFormat string
}

// DefaultLoggingConfig returns a LoggingConfig with sensible defaults
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		LogFormat: "plain",
	}
}

// RemoteConfig holds configuration for the <remote> section
type RemoteConfig struct {
	// Connection type (secure, syslog)
	// +kubebuilder:default="secure"
	// +kubebuilder:validation:Enum=secure;syslog
	Connection string
	// Port for agent connections
	// +kubebuilder:default=1514
	Port int
	// Protocol for agent connections (tcp, udp)
	// +kubebuilder:default="tcp"
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol string
	// QueueSize for the queue
	// +kubebuilder:default=131072
	QueueSize int
}

// DefaultRemoteConfig returns a RemoteConfig with sensible defaults
func DefaultRemoteConfig() *RemoteConfig {
	return &RemoteConfig{
		Connection: "secure",
		Port:       int(constants.PortManagerAgentEvents),
		Protocol:   "tcp",
		QueueSize:  131072,
	}
}

// AuthConfig holds configuration for the <auth> section (wazuh-authd)
type AuthConfig struct {
	// Disabled disables wazuh-authd
	// +kubebuilder:default=false
	Disabled bool
	// Port for authd
	// +kubebuilder:default=1515
	Port int
	// UseSourceIP uses agent's source IP for identification
	// +kubebuilder:default=false
	UseSourceIP bool
	// Purge removes old agent keys when re-enrolling
	// +kubebuilder:default=true
	Purge bool
	// UsePassword enables password authentication for agent enrollment
	// +kubebuilder:default=false
	UsePassword bool
	// PasswordSecretRef references a secret containing the authd password
	// If UsePassword is true and this is set, the password will be read from the secret
	PasswordSecretRef *SecretKeyReference
	// Ciphers for SSL connections
	// +kubebuilder:default="HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
	Ciphers string
	// SSLVerifyHost verifies the host SSL certificate
	// +kubebuilder:default=false
	SSLVerifyHost bool
	// SSLManagerCert is the path to the manager certificate
	// +kubebuilder:default="etc/sslmanager.cert"
	SSLManagerCert string
	// SSLManagerKey is the path to the manager key
	// +kubebuilder:default="etc/sslmanager.key"
	SSLManagerKey string
	// SSLAutoNegotiate enables SSL auto-negotiation
	// +kubebuilder:default=false
	SSLAutoNegotiate bool
	// EnabledOnMasterOnly when true, enables authd only on master node
	// When false, authd is enabled on all nodes (master and workers)
	// +kubebuilder:default=true
	EnabledOnMasterOnly bool
}

// SecretKeyReference references a secret key
type SecretKeyReference struct {
	// Name is the secret name
	Name string
	// Key is the key in the secret
	// +kubebuilder:default="password"
	Key string
}

// DefaultAuthConfig returns an AuthConfig with sensible defaults
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Disabled:            false,
		Port:                int(constants.PortManagerAgentAuth),
		UseSourceIP:         false,
		Purge:               true,
		UsePassword:         false,
		PasswordSecretRef:   nil,
		Ciphers:             "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH",
		SSLVerifyHost:       false,
		SSLManagerCert:      "etc/sslmanager.cert",
		SSLManagerKey:       "etc/sslmanager.key",
		SSLAutoNegotiate:    false,
		EnabledOnMasterOnly: true,
	}
}

// OSSECConfig holds configuration for ossec.conf generation
type OSSECConfig struct {
	// Node type (master or worker)
	NodeType string
	// Node name
	NodeName string
	// Cluster name
	ClusterName string
	// Cluster key (base64)
	ClusterKey string
	// Master node address (for workers)
	MasterAddress string
	// Master node port (for workers)
	MasterPort int
	// API protocol (http/https)
	APIProtocol string
	// API host
	APIHost string
	// API port
	APIPort int
	// Enable cluster
	ClusterEnabled bool
	// Cluster nodes
	ClusterNodes []string
	// Hidden (whether this node is hidden from cluster)
	Hidden bool
	// Extra configuration to append
	ExtraConfig string
	// IndexerHost is the OpenSearch indexer service host
	IndexerHost string
	// Namespace for service discovery
	Namespace string
	// GlobalConfig holds the <global> section configuration
	Global *GlobalConfig
	// AlertsConfig holds the <alerts> section configuration
	Alerts *AlertsConfig
	// LoggingConfig holds the <logging> section configuration
	Logging *LoggingConfig
	// RemoteConfig holds the <remote> section configuration
	Remote *RemoteConfig
	// AuthConfig holds the <auth> section configuration
	Auth *AuthConfig
	// AuthdPassword is the resolved password for authd (if UsePassword is true)
	AuthdPassword string
}

// DefaultOSSECConfig returns a default OSSECConfig for master node
func DefaultOSSECConfig(clusterName, nodeName string) *OSSECConfig {
	return &OSSECConfig{
		NodeType:       NodeTypeMaster,
		NodeName:       nodeName,
		ClusterName:    clusterName,
		ClusterKey:     "",
		MasterAddress:  "",
		MasterPort:     int(constants.PortManagerCluster),
		APIProtocol:    "https",
		APIHost:        "0.0.0.0",
		APIPort:        int(constants.PortManagerAPI),
		ClusterEnabled: true,
		ClusterNodes:   []string{},
		Hidden:         false,
		ExtraConfig:    "",
		IndexerHost:    fmt.Sprintf("%s-indexer", clusterName),
		Namespace:      "default",
		Global:         DefaultGlobalConfig(),
		Alerts:         DefaultAlertsConfig(),
		Logging:        DefaultLoggingConfig(),
		Remote:         DefaultRemoteConfig(),
		Auth:           DefaultAuthConfig(),
		AuthdPassword:  "",
	}
}

// OSSECConfigBuilder builds ossec.conf content
type OSSECConfigBuilder struct {
	config *OSSECConfig
}

// NewOSSECConfigBuilder creates a new OSSECConfigBuilder
func NewOSSECConfigBuilder(config *OSSECConfig) *OSSECConfigBuilder {
	if config == nil {
		config = DefaultOSSECConfig("wazuh", "master-node")
	}
	return &OSSECConfigBuilder{config: config}
}

// Build generates the ossec.conf content
func (b *OSSECConfigBuilder) Build() (string, error) {
	tmpl, err := template.New("ossec.conf").Parse(ossecConfTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse ossec.conf template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, b.config); err != nil {
		return "", fmt.Errorf("failed to execute ossec.conf template: %w", err)
	}

	return buf.String(), nil
}

// SetNodeType sets the node type
func (b *OSSECConfigBuilder) SetNodeType(nodeType string) *OSSECConfigBuilder {
	b.config.NodeType = nodeType
	return b
}

// SetNodeName sets the node name
func (b *OSSECConfigBuilder) SetNodeName(nodeName string) *OSSECConfigBuilder {
	b.config.NodeName = nodeName
	return b
}

// SetClusterName sets the cluster name
func (b *OSSECConfigBuilder) SetClusterName(clusterName string) *OSSECConfigBuilder {
	b.config.ClusterName = clusterName
	return b
}

// SetClusterKey sets the cluster key
func (b *OSSECConfigBuilder) SetClusterKey(clusterKey string) *OSSECConfigBuilder {
	b.config.ClusterKey = clusterKey
	return b
}

// SetMasterAddress sets the master address for workers
func (b *OSSECConfigBuilder) SetMasterAddress(address string) *OSSECConfigBuilder {
	b.config.MasterAddress = address
	return b
}

// SetMasterPort sets the master port for workers
func (b *OSSECConfigBuilder) SetMasterPort(port int) *OSSECConfigBuilder {
	b.config.MasterPort = port
	return b
}

// SetExtraConfig sets extra configuration to append
func (b *OSSECConfigBuilder) SetExtraConfig(extraConfig string) *OSSECConfigBuilder {
	b.config.ExtraConfig = extraConfig
	return b
}

// SetIndexerHost sets the indexer host for OpenSearch connection
func (b *OSSECConfigBuilder) SetIndexerHost(host string) *OSSECConfigBuilder {
	b.config.IndexerHost = host
	return b
}

// SetNamespace sets the namespace for service discovery
func (b *OSSECConfigBuilder) SetNamespace(namespace string) *OSSECConfigBuilder {
	b.config.Namespace = namespace
	return b
}

// SetClusterNodes sets the list of cluster nodes
func (b *OSSECConfigBuilder) SetClusterNodes(nodes []string) *OSSECConfigBuilder {
	b.config.ClusterNodes = nodes
	return b
}

// SetClusterEnabled sets whether the cluster is enabled
func (b *OSSECConfigBuilder) SetClusterEnabled(enabled bool) *OSSECConfigBuilder {
	b.config.ClusterEnabled = enabled
	return b
}

// SetGlobalConfig sets the global configuration
func (b *OSSECConfigBuilder) SetGlobalConfig(global *GlobalConfig) *OSSECConfigBuilder {
	if global != nil {
		b.config.Global = global
	}
	return b
}

// SetAlertsConfig sets the alerts configuration
func (b *OSSECConfigBuilder) SetAlertsConfig(alerts *AlertsConfig) *OSSECConfigBuilder {
	if alerts != nil {
		b.config.Alerts = alerts
	}
	return b
}

// SetLoggingConfig sets the logging configuration
func (b *OSSECConfigBuilder) SetLoggingConfig(logging *LoggingConfig) *OSSECConfigBuilder {
	if logging != nil {
		b.config.Logging = logging
	}
	return b
}

// SetRemoteConfig sets the remote configuration
func (b *OSSECConfigBuilder) SetRemoteConfig(remote *RemoteConfig) *OSSECConfigBuilder {
	if remote != nil {
		b.config.Remote = remote
	}
	return b
}

// SetAuthConfig sets the auth configuration
func (b *OSSECConfigBuilder) SetAuthConfig(auth *AuthConfig) *OSSECConfigBuilder {
	if auth != nil {
		b.config.Auth = auth
	}
	return b
}

// SetAuthdPassword sets the resolved authd password
func (b *OSSECConfigBuilder) SetAuthdPassword(password string) *OSSECConfigBuilder {
	b.config.AuthdPassword = password
	return b
}

// BuildMasterConfig builds ossec.conf for a master node
func BuildMasterConfig(clusterName, namespace, nodeName, clusterKey string, extraConfig string) (string, error) {
	config := &OSSECConfig{
		NodeType:       NodeTypeMaster,
		NodeName:       nodeName,
		ClusterName:    clusterName,
		ClusterKey:     clusterKey,
		APIProtocol:    "https",
		APIHost:        "0.0.0.0",
		APIPort:        int(constants.PortManagerAPI),
		ClusterEnabled: true,
		Hidden:         false,
		ExtraConfig:    extraConfig,
		IndexerHost:    fmt.Sprintf("%s-indexer", clusterName),
		Namespace:      namespace,
		Global:         DefaultGlobalConfig(),
		Alerts:         DefaultAlertsConfig(),
		Logging:        DefaultLoggingConfig(),
		Remote:         DefaultRemoteConfig(),
		Auth:           DefaultAuthConfig(),
	}
	return NewOSSECConfigBuilder(config).Build()
}

// BuildWorkerConfig builds ossec.conf for a worker node
func BuildWorkerConfig(clusterName, namespace, nodeName, clusterKey, masterAddress string, masterPort int, extraConfig string) (string, error) {
	config := &OSSECConfig{
		NodeType:       NodeTypeWorker,
		NodeName:       nodeName,
		ClusterName:    clusterName,
		ClusterKey:     clusterKey,
		MasterAddress:  masterAddress,
		MasterPort:     masterPort,
		APIProtocol:    "https",
		APIHost:        "0.0.0.0",
		APIPort:        int(constants.PortManagerAPI),
		ClusterEnabled: true,
		Hidden:         false,
		ExtraConfig:    extraConfig,
		IndexerHost:    fmt.Sprintf("%s-indexer", clusterName),
		Namespace:      namespace,
		Global:         DefaultGlobalConfig(),
		Alerts:         DefaultAlertsConfig(),
		Logging:        DefaultLoggingConfig(),
		Remote:         DefaultRemoteConfig(),
		Auth:           DefaultAuthConfig(),
	}
	return NewOSSECConfigBuilder(config).Build()
}

// GenerateMasterServiceName generates the master service name
func GenerateMasterServiceName(clusterName, namespace string) string {
	return fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", clusterName, namespace)
}

// GenerateWorkerServiceName generates the worker service name
func GenerateWorkerServiceName(clusterName, namespace string) string {
	return fmt.Sprintf("%s-manager-workers.%s.svc.cluster.local", clusterName, namespace)
}

// MergeConfigs merges extra configuration with the base template
func MergeConfigs(baseConfig, extraConfig string) string {
	if extraConfig == "" {
		return baseConfig
	}

	// Find the closing </ossec_config> tag and insert extra config before it
	closingTag := "</ossec_config>"
	if idx := strings.LastIndex(baseConfig, closingTag); idx != -1 {
		return baseConfig[:idx] + "\n" + strings.TrimSpace(extraConfig) + "\n" + closingTag
	}
	return baseConfig + "\n" + extraConfig
}

// boolToYesNo converts a boolean to "yes" or "no" string
func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ossecConfTemplate is the template for generating ossec.conf
const ossecConfTemplate = `<!--
  Wazuh - Manager - Configuration
  Generated by Wazuh Operator
-->

<ossec_config>
  <global>
    <jsonout_output>{{ if .Global.JSONOutOutput }}yes{{ else }}no{{ end }}</jsonout_output>
    <alerts_log>{{ if .Global.AlertsLog }}yes{{ else }}no{{ end }}</alerts_log>
    <logall>{{ if .Global.LogAll }}yes{{ else }}no{{ end }}</logall>
    <logall_json>{{ if .Global.LogAllJSON }}yes{{ else }}no{{ end }}</logall_json>
    <email_notification>{{ if .Global.EmailNotification }}yes{{ else }}no{{ end }}</email_notification>
    <smtp_server>{{ .Global.SMTPServer }}</smtp_server>
    <email_from>{{ .Global.EmailFrom }}</email_from>
    <email_to>{{ .Global.EmailTo }}</email_to>
    <email_maxperhour>{{ .Global.EmailMaxPerHour }}</email_maxperhour>
    <email_log_source>{{ .Global.EmailLogSource }}</email_log_source>
    <agents_disconnection_time>{{ .Global.AgentsDisconnectionTime }}</agents_disconnection_time>
    <agents_disconnection_alert_time>{{ .Global.AgentsDisconnectionAlertTime }}</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>{{ .Alerts.LogAlertLevel }}</log_alert_level>
    <email_alert_level>{{ .Alerts.EmailAlertLevel }}</email_alert_level>
  </alerts>

{{- if .ClusterEnabled }}
  <cluster>
    <name>{{ .ClusterName }}</name>
    <node_name>{{ .NodeName }}</node_name>
    <node_type>{{ .NodeType }}</node_type>
    <key>{{ .ClusterKey }}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
{{- if eq .NodeType "worker" }}
    <nodes>
      <node>{{ .MasterAddress }}</node>
    </nodes>
{{- else }}
    <nodes>
      <node>NODE_IP</node>
    </nodes>
{{- end }}
    <hidden>{{ if .Hidden }}yes{{ else }}no{{ end }}</hidden>
    <disabled>no</disabled>
  </cluster>
{{- end }}

  <logging>
    <log_format>{{ .Logging.LogFormat }}</log_format>
  </logging>

  <remote>
    <connection>{{ .Remote.Connection }}</connection>
    <port>{{ .Remote.Port }}</port>
    <protocol>{{ .Remote.Protocol }}</protocol>
    <queue_size>{{ .Remote.QueueSize }}</queue_size>
  </remote>

{{- /* Auth section: enabled based on EnabledOnMasterOnly flag and node type */ -}}
{{- $authDisabled := .Auth.Disabled -}}
{{- if and .Auth.EnabledOnMasterOnly (eq .NodeType "worker") -}}
{{- $authDisabled = true -}}
{{- end }}
  <!-- wazuh-authd configuration -->
  <auth>
    <disabled>{{ if $authDisabled }}yes{{ else }}no{{ end }}</disabled>
    <port>{{ .Auth.Port }}</port>
    <use_source_ip>{{ if .Auth.UseSourceIP }}yes{{ else }}no{{ end }}</use_source_ip>
    <purge>{{ if .Auth.Purge }}yes{{ else }}no{{ end }}</purge>
    <use_password>{{ if .Auth.UsePassword }}yes{{ else }}no{{ end }}</use_password>
{{- if and .Auth.UsePassword .AuthdPassword }}
    <authd_pass>{{ .AuthdPassword }}</authd_pass>
{{- end }}
    <ciphers>{{ .Auth.Ciphers }}</ciphers>
    <ssl_verify_host>{{ if .Auth.SSLVerifyHost }}yes{{ else }}no{{ end }}</ssl_verify_host>
    <ssl_manager_cert>{{ .Auth.SSLManagerCert }}</ssl_manager_cert>
    <ssl_manager_key>{{ .Auth.SSLManagerKey }}</ssl_manager_key>
    <ssl_auto_negotiate>{{ if .Auth.SSLAutoNegotiate }}yes{{ else }}no{{ end }}</ssl_auto_negotiate>
  </auth>

{{- if .ExtraConfig }}
  <!-- Extra configuration -->
{{ .ExtraConfig }}
{{- end }}
</ossec_config>
`

// =============================================================================
// CRD Spec to Config Conversion Helpers
// =============================================================================

// GlobalConfigFromSpec converts OSSECGlobalSpec to GlobalConfig
// Returns default config if spec is nil
func GlobalConfigFromSpec(spec *v1alpha1.OSSECGlobalSpec) *GlobalConfig {
	defaults := DefaultGlobalConfig()
	if spec == nil {
		return defaults
	}

	config := &GlobalConfig{
		JSONOutOutput:                defaults.JSONOutOutput,
		AlertsLog:                    defaults.AlertsLog,
		LogAll:                       defaults.LogAll,
		LogAllJSON:                   defaults.LogAllJSON,
		EmailNotification:            defaults.EmailNotification,
		SMTPServer:                   defaults.SMTPServer,
		EmailFrom:                    defaults.EmailFrom,
		EmailTo:                      defaults.EmailTo,
		EmailMaxPerHour:              defaults.EmailMaxPerHour,
		EmailLogSource:               defaults.EmailLogSource,
		AgentsDisconnectionTime:      defaults.AgentsDisconnectionTime,
		AgentsDisconnectionAlertTime: defaults.AgentsDisconnectionAlertTime,
	}

	// Override with spec values if set
	if spec.JSONOutOutput != nil {
		config.JSONOutOutput = *spec.JSONOutOutput
	}
	if spec.AlertsLog != nil {
		config.AlertsLog = *spec.AlertsLog
	}
	if spec.LogAll != nil {
		config.LogAll = *spec.LogAll
	}
	if spec.LogAllJSON != nil {
		config.LogAllJSON = *spec.LogAllJSON
	}
	if spec.EmailNotification != nil {
		config.EmailNotification = *spec.EmailNotification
	}
	if spec.SMTPServer != "" {
		config.SMTPServer = spec.SMTPServer
	}
	if spec.EmailFrom != "" {
		config.EmailFrom = spec.EmailFrom
	}
	if spec.EmailTo != "" {
		config.EmailTo = spec.EmailTo
	}
	if spec.EmailMaxPerHour != nil {
		config.EmailMaxPerHour = *spec.EmailMaxPerHour
	}
	if spec.EmailLogSource != "" {
		config.EmailLogSource = spec.EmailLogSource
	}
	if spec.AgentsDisconnectionTime != "" {
		config.AgentsDisconnectionTime = spec.AgentsDisconnectionTime
	}
	if spec.AgentsDisconnectionAlertTime != "" {
		config.AgentsDisconnectionAlertTime = spec.AgentsDisconnectionAlertTime
	}

	return config
}

// AlertsConfigFromSpec converts OSSECAlertsSpec to AlertsConfig
// Returns default config if spec is nil
func AlertsConfigFromSpec(spec *v1alpha1.OSSECAlertsSpec) *AlertsConfig {
	defaults := DefaultAlertsConfig()
	if spec == nil {
		return defaults
	}

	config := &AlertsConfig{
		LogAlertLevel:   defaults.LogAlertLevel,
		EmailAlertLevel: defaults.EmailAlertLevel,
	}

	if spec.LogAlertLevel != nil {
		config.LogAlertLevel = *spec.LogAlertLevel
	}
	if spec.EmailAlertLevel != nil {
		config.EmailAlertLevel = *spec.EmailAlertLevel
	}

	return config
}

// LoggingConfigFromSpec converts OSSECLoggingSpec to LoggingConfig
// Returns default config if spec is nil
func LoggingConfigFromSpec(spec *v1alpha1.OSSECLoggingSpec) *LoggingConfig {
	defaults := DefaultLoggingConfig()
	if spec == nil {
		return defaults
	}

	config := &LoggingConfig{
		LogFormat: defaults.LogFormat,
	}

	if spec.LogFormat != "" {
		config.LogFormat = spec.LogFormat
	}

	return config
}

// RemoteConfigFromSpec converts OSSECRemoteSpec to RemoteConfig
// Returns default config if spec is nil
func RemoteConfigFromSpec(spec *v1alpha1.OSSECRemoteSpec) *RemoteConfig {
	defaults := DefaultRemoteConfig()
	if spec == nil {
		return defaults
	}

	config := &RemoteConfig{
		Connection: defaults.Connection,
		Port:       defaults.Port,
		Protocol:   defaults.Protocol,
		QueueSize:  defaults.QueueSize,
	}

	if spec.Connection != "" {
		config.Connection = spec.Connection
	}
	if spec.Port != nil {
		config.Port = *spec.Port
	}
	if spec.Protocol != "" {
		config.Protocol = spec.Protocol
	}
	if spec.QueueSize != nil {
		config.QueueSize = *spec.QueueSize
	}

	return config
}

// AuthConfigFromSpec converts OSSECAuthSpec to AuthConfig
// Returns default config if spec is nil
// Note: PasswordSecretRef is converted but the actual password must be resolved by the reconciler
func AuthConfigFromSpec(spec *v1alpha1.OSSECAuthSpec) *AuthConfig {
	defaults := DefaultAuthConfig()
	if spec == nil {
		return defaults
	}

	config := &AuthConfig{
		Disabled:            defaults.Disabled,
		Port:                defaults.Port,
		UseSourceIP:         defaults.UseSourceIP,
		Purge:               defaults.Purge,
		UsePassword:         defaults.UsePassword,
		PasswordSecretRef:   nil,
		Ciphers:             defaults.Ciphers,
		SSLVerifyHost:       defaults.SSLVerifyHost,
		SSLManagerCert:      defaults.SSLManagerCert,
		SSLManagerKey:       defaults.SSLManagerKey,
		SSLAutoNegotiate:    defaults.SSLAutoNegotiate,
		EnabledOnMasterOnly: defaults.EnabledOnMasterOnly,
	}

	if spec.Disabled != nil {
		config.Disabled = *spec.Disabled
	}
	if spec.Port != nil {
		config.Port = *spec.Port
	}
	if spec.UseSourceIP != nil {
		config.UseSourceIP = *spec.UseSourceIP
	}
	if spec.Purge != nil {
		config.Purge = *spec.Purge
	}
	if spec.UsePassword != nil {
		config.UsePassword = *spec.UsePassword
	}
	if spec.PasswordSecretRef != nil {
		config.PasswordSecretRef = &SecretKeyReference{
			Name: spec.PasswordSecretRef.Name,
			Key:  spec.PasswordSecretRef.Key,
		}
	}
	if spec.Ciphers != "" {
		config.Ciphers = spec.Ciphers
	}
	if spec.SSLVerifyHost != nil {
		config.SSLVerifyHost = *spec.SSLVerifyHost
	}
	if spec.SSLManagerCert != "" {
		config.SSLManagerCert = spec.SSLManagerCert
	}
	if spec.SSLManagerKey != "" {
		config.SSLManagerKey = spec.SSLManagerKey
	}
	if spec.SSLAutoNegotiate != nil {
		config.SSLAutoNegotiate = *spec.SSLAutoNegotiate
	}
	if spec.EnabledOnMasterOnly != nil {
		config.EnabledOnMasterOnly = *spec.EnabledOnMasterOnly
	}

	return config
}

// WazuhConfigFromSpec converts WazuhConfigSpec to all config structs
// This is a convenience function that converts all config sections at once
func WazuhConfigFromSpec(spec *v1alpha1.WazuhConfigSpec) (global *GlobalConfig, alerts *AlertsConfig, logging *LoggingConfig, remote *RemoteConfig, auth *AuthConfig) {
	if spec == nil {
		return DefaultGlobalConfig(), DefaultAlertsConfig(), DefaultLoggingConfig(), DefaultRemoteConfig(), DefaultAuthConfig()
	}
	return GlobalConfigFromSpec(spec.Global),
		AlertsConfigFromSpec(spec.Alerts),
		LoggingConfigFromSpec(spec.Logging),
		RemoteConfigFromSpec(spec.Remote),
		AuthConfigFromSpec(spec.Auth)
}
