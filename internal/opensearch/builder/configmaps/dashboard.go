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

package configmaps

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// DashboardConfigMapBuilder builds ConfigMaps for OpenSearch Dashboard configuration
type DashboardConfigMapBuilder struct {
	clusterName  string
	namespace    string
	indexerHost  string
	indexerPort  int32
	serverHost   string
	serverPort   int32
	enableSSL    bool
	customConfig string
	// Wazuh plugin configuration
	wazuhPlugin *wazuhv1.WazuhPluginConfig
	// Manager API URL for default endpoint
	managerAPIURL string
	// Resolved credentials per endpoint ID (from secretRefs)
	// Key format: "endpointID:username" and "endpointID:password"
	resolvedCredentials map[string]string
	// Auth config from CRD for SSO settings
	authConfig  *wazuhv1.OpenSearchAuthConfigSpec
	authSecrets map[string]string
}

// NewDashboardConfigMapBuilder creates a new DashboardConfigMapBuilder
func NewDashboardConfigMapBuilder(clusterName, namespace string) *DashboardConfigMapBuilder {
	return &DashboardConfigMapBuilder{
		clusterName: clusterName,
		namespace:   namespace,
		indexerPort: constants.PortIndexerHTTP,
		serverHost:  "0.0.0.0",
		serverPort:  constants.PortDashboardHTTP,
		enableSSL:   true,
	}
}

// WithIndexerHost sets the OpenSearch Indexer host
func (b *DashboardConfigMapBuilder) WithIndexerHost(host string) *DashboardConfigMapBuilder {
	b.indexerHost = host
	return b
}

// WithIndexerPort sets the OpenSearch Indexer port
func (b *DashboardConfigMapBuilder) WithIndexerPort(port int32) *DashboardConfigMapBuilder {
	b.indexerPort = port
	return b
}

// WithServerHost sets the Dashboard server host
func (b *DashboardConfigMapBuilder) WithServerHost(host string) *DashboardConfigMapBuilder {
	b.serverHost = host
	return b
}

// WithServerPort sets the Dashboard server port
func (b *DashboardConfigMapBuilder) WithServerPort(port int32) *DashboardConfigMapBuilder {
	b.serverPort = port
	return b
}

// WithEnableSSL sets whether the dashboard server should use SSL
func (b *DashboardConfigMapBuilder) WithEnableSSL(enabled bool) *DashboardConfigMapBuilder {
	b.enableSSL = enabled
	return b
}

// WithCustomConfig sets custom configuration content
func (b *DashboardConfigMapBuilder) WithCustomConfig(content string) *DashboardConfigMapBuilder {
	b.customConfig = content
	return b
}

// WithWazuhPlugin sets the Wazuh plugin configuration
func (b *DashboardConfigMapBuilder) WithWazuhPlugin(pluginConfig *wazuhv1.WazuhPluginConfig) *DashboardConfigMapBuilder {
	b.wazuhPlugin = pluginConfig
	return b
}

// WithManagerAPIURL sets the default manager API URL
func (b *DashboardConfigMapBuilder) WithManagerAPIURL(url string) *DashboardConfigMapBuilder {
	b.managerAPIURL = url
	return b
}

// WithResolvedCredentials sets the resolved credentials for API endpoints
// The map keys are "endpointID:username" and "endpointID:password"
func (b *DashboardConfigMapBuilder) WithResolvedCredentials(credentials map[string]string) *DashboardConfigMapBuilder {
	b.resolvedCredentials = credentials
	return b
}

// NeedsDefaultCredentials returns true if the default API endpoint password
// has not been resolved yet (no wazuhPlugin config or no explicit credentials)
func (b *DashboardConfigMapBuilder) NeedsDefaultCredentials() bool {
	if b.resolvedCredentials != nil {
		if _, ok := b.resolvedCredentials["default:password"]; ok {
			return false
		}
	}
	return true
}

// WithAuthConfig sets the authentication configuration from CRD
// This will be used to generate SSO settings in opensearch_dashboards.yml
func (b *DashboardConfigMapBuilder) WithAuthConfig(authConfig *wazuhv1.OpenSearchAuthConfigSpec) *DashboardConfigMapBuilder {
	b.authConfig = authConfig
	return b
}

// WithAuthSecrets sets the resolved secrets for auth config
// Keys: "oidc_client_secret", "oidc_cookie_password", "saml_exchange_key"
func (b *DashboardConfigMapBuilder) WithAuthSecrets(secrets map[string]string) *DashboardConfigMapBuilder {
	b.authSecrets = secrets
	return b
}

// Build creates the ConfigMap for OpenSearch Dashboard
func (b *DashboardConfigMapBuilder) Build() (*corev1.ConfigMap, error) {
	name := constants.DashboardConfigName(b.clusterName)

	labels := map[string]string{
		constants.LabelName:      constants.AppName + "-" + constants.ComponentDashboard,
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: constants.ComponentDashboard,
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	// Build default indexer host if not provided
	indexerHost := b.indexerHost
	if indexerHost == "" {
		indexerHost = constants.IndexerServiceFQDN(b.clusterName, b.namespace)
	}

	// Build opensearch_dashboards.yml configuration
	dashboardConfig, err := b.buildDashboardConfig(indexerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to build dashboard config: %w", err)
	}

	// Build custom wazuh_app_config.sh script
	wazuhAppConfigScript := b.buildWazuhAppConfigScript()

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"opensearch_dashboards.yml": dashboardConfig,
			"wazuh_app_config.sh":       wazuhAppConfigScript,
		},
	}, nil
}

// BuildWazuhConfigSecret creates a Secret containing wazuh.yml.
// This is kept in a Secret (not a ConfigMap) because wazuh.yml contains
// Wazuh API credentials and Secrets are encrypted at rest when etcd
// encryption is enabled.
func (b *DashboardConfigMapBuilder) BuildWazuhConfigSecret() *corev1.Secret {
	name := constants.DashboardWazuhConfigSecretName(b.clusterName)

	labels := map[string]string{
		constants.LabelName:      constants.AppName + "-" + constants.ComponentDashboard,
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: constants.ComponentDashboard,
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	wazuhConfig := b.buildWazuhConfig()

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		StringData: map[string]string{
			"wazuh.yml": wazuhConfig,
		},
	}
}

// buildDashboardConfig generates the opensearch_dashboards.yml content
func (b *DashboardConfigMapBuilder) buildDashboardConfig(indexerHost string) (string, error) {
	if b.customConfig != "" {
		return b.customConfig, nil
	}

	baseConfig := fmt.Sprintf(`# OpenSearch Dashboards configuration
# Generated by Wazuh Operator

server.host: "%s"
server.port: %d
server.name: "%s-dashboard"

# Default route to Wazuh home
uiSettings.overrides.defaultRoute: /app/wz-home

# OpenSearch connection
opensearch.hosts:
  - https://%s:%d

# SSL configuration for OpenSearch connection
opensearch.ssl.verificationMode: full
opensearch.ssl.certificateAuthorities:
  - /usr/share/wazuh-dashboard/config/certs/root-ca.pem

opensearch.requestHeadersAllowlist:
  - securitytenant
  - Authorization

# Authentication
opensearch.username: "${INDEXER_USERNAME}"
opensearch.password: "${INDEXER_PASSWORD}"

`, b.serverHost, b.serverPort, b.clusterName, indexerHost, b.indexerPort)

	if b.enableSSL {
		baseConfig += `# Dashboard server SSL
server.ssl.enabled: true
server.ssl.certificate: /usr/share/wazuh-dashboard/config/certs/dashboard.pem
server.ssl.key: /usr/share/wazuh-dashboard/config/certs/dashboard-key.pem

`
	} else {
		baseConfig += `# Dashboard server SSL
server.ssl.enabled: false

`
	}

	authSection, err := b.buildAuthSection()
	if err != nil {
		return "", err
	}
	return baseConfig + authSection, nil
}

// buildAuthSection generates the SSO authentication settings for opensearch_dashboards.yml
func (b *DashboardConfigMapBuilder) buildAuthSection() (string, error) {
	if b.authConfig == nil {
		// Default to basic auth only
		return `# Security Authentication
opensearch_security.auth.type: "basicauth"
`, nil
	}

	builder := config.NewDashboardAuthConfigBuilder(b.authConfig)
	for key, value := range b.authSecrets {
		builder.WithSecret(key, value)
	}
	return builder.BuildAuthSection()
}

// buildWazuhConfig generates the wazuh.yml configuration for the Wazuh plugin
func (b *DashboardConfigMapBuilder) buildWazuhConfig() string {
	var sb strings.Builder

	sb.WriteString("# Wazuh Dashboard Plugin Configuration\n")
	sb.WriteString("# Generated by Wazuh Operator\n\n")

	// Build hosts section
	sb.WriteString("hosts:\n")

	if b.wazuhPlugin != nil && len(b.wazuhPlugin.APIEndpoints) > 0 {
		// Use configured API endpoints
		for _, endpoint := range b.wazuhPlugin.APIEndpoints {
			port := endpoint.Port
			if port == 0 {
				port = constants.PortManagerAPI
			}

			// Priority for credentials resolution:
			// 1. Resolved credentials from secretRef (if available in resolvedCredentials map)
			// 2. Inline credentials from CRD
			// 3. Default username only - password MUST be provided
			username := constants.DefaultWazuhAPIUsername
			password := ""

			// Try resolved credentials first
			if b.resolvedCredentials != nil {
				if resolvedUser, ok := b.resolvedCredentials[endpoint.ID+":username"]; ok && resolvedUser != "" {
					username = resolvedUser
				}
				if resolvedPwd, ok := b.resolvedCredentials[endpoint.ID+":password"]; ok && resolvedPwd != "" {
					password = resolvedPwd
				}
			}

			// Fall back to inline values if not resolved
			if endpoint.Username != "" {
				username = endpoint.Username
			}
			if password == "" && endpoint.Password != "" {
				password = endpoint.Password
			}

			fmt.Fprintf(&sb, "  - %s:\n", endpoint.ID)
			fmt.Fprintf(&sb, "      url: %s\n", endpoint.URL)
			fmt.Fprintf(&sb, "      port: %d\n", port)
			fmt.Fprintf(&sb, "      username: %s\n", username)
			fmt.Fprintf(&sb, "      password: %s\n", password)
			fmt.Fprintf(&sb, "      run_as: %v\n", endpoint.RunAs)
		}
	} else {
		// Default host configuration
		// Use defaultApiEndpoint if configured, otherwise use hardcoded defaults
		sb.WriteString("  - default:\n")
		if b.managerAPIURL != "" {
			fmt.Fprintf(&sb, "      url: %s\n", b.managerAPIURL)
		} else {
			fmt.Fprintf(&sb, "      url: https://%s\n", dns.ServiceFQDN(b.clusterName+"-manager-master", b.namespace))
		}

		// Port configuration
		port := constants.PortManagerAPI
		runAs := false
		if b.wazuhPlugin != nil && b.wazuhPlugin.DefaultAPIEndpoint != nil {
			if b.wazuhPlugin.DefaultAPIEndpoint.Port > 0 {
				port = b.wazuhPlugin.DefaultAPIEndpoint.Port
			}
			runAs = b.wazuhPlugin.DefaultAPIEndpoint.RunAs
		}
		fmt.Fprintf(&sb, "      port: %d\n", port)

		// Credentials: try resolved from secret - password MUST be provided
		username := constants.DefaultWazuhAPIUsername
		password := ""
		if b.resolvedCredentials != nil {
			if resolvedUser, ok := b.resolvedCredentials["default:username"]; ok && resolvedUser != "" {
				username = resolvedUser
			}
			if resolvedPwd, ok := b.resolvedCredentials["default:password"]; ok && resolvedPwd != "" {
				password = resolvedPwd
			}
		}
		fmt.Fprintf(&sb, "      username: %s\n", username)
		fmt.Fprintf(&sb, "      password: %s\n", password)
		fmt.Fprintf(&sb, "      run_as: %v\n", runAs)
	}

	// Add additional settings if wazuhPlugin is configured
	if b.wazuhPlugin != nil {
		sb.WriteString("\n")

		// Pattern
		if b.wazuhPlugin.Pattern != "" {
			fmt.Fprintf(&sb, "pattern: %s\n", b.wazuhPlugin.Pattern)
		}

		// Timeout
		if b.wazuhPlugin.Timeout > 0 {
			fmt.Fprintf(&sb, "timeout: %d\n", b.wazuhPlugin.Timeout)
		}

		// IP Selector
		fmt.Fprintf(&sb, "ip.selector: %v\n", b.wazuhPlugin.IPSelector)

		// IP Ignore
		if len(b.wazuhPlugin.IPIgnore) > 0 {
			sb.WriteString("ip.ignore:\n")
			for _, ignore := range b.wazuhPlugin.IPIgnore {
				fmt.Fprintf(&sb, "  - %s\n", ignore)
			}
		}

		// Hide Manager Alerts
		fmt.Fprintf(&sb, "hideManagerAlerts: %v\n", b.wazuhPlugin.HideManagerAlerts)

		// Alerts Sample Prefix
		if b.wazuhPlugin.AlertsSamplePrefix != "" {
			fmt.Fprintf(&sb, "alerts.sample.prefix: %s\n", b.wazuhPlugin.AlertsSamplePrefix)
		}

		// Enrollment DNS
		if b.wazuhPlugin.EnrollmentDNS != "" {
			fmt.Fprintf(&sb, "enrollment.dns: %s\n", b.wazuhPlugin.EnrollmentDNS)
		}

		// Enrollment Password
		if b.wazuhPlugin.EnrollmentPassword != "" {
			fmt.Fprintf(&sb, "enrollment.password: %s\n", b.wazuhPlugin.EnrollmentPassword)
		}

		// Cron Prefix
		if b.wazuhPlugin.CronPrefix != "" {
			fmt.Fprintf(&sb, "cron.prefix: %s\n", b.wazuhPlugin.CronPrefix)
		}

		// Updates Disabled
		fmt.Fprintf(&sb, "wazuh.updates.disabled: %v\n", b.wazuhPlugin.UpdatesDisabled)

		// Monitoring configuration
		if b.wazuhPlugin.Monitoring != nil {
			fmt.Fprintf(&sb, "wazuh.monitoring.enabled: %v\n", b.wazuhPlugin.Monitoring.Enabled)
			if b.wazuhPlugin.Monitoring.Frequency > 0 {
				fmt.Fprintf(&sb, "wazuh.monitoring.frequency: %d\n", b.wazuhPlugin.Monitoring.Frequency)
			}
			if b.wazuhPlugin.Monitoring.Pattern != "" {
				fmt.Fprintf(&sb, "wazuh.monitoring.pattern: %s\n", b.wazuhPlugin.Monitoring.Pattern)
			}
			if b.wazuhPlugin.Monitoring.Creation != "" {
				fmt.Fprintf(&sb, "wazuh.monitoring.creation: %s\n", b.wazuhPlugin.Monitoring.Creation)
			}
			if b.wazuhPlugin.Monitoring.Shards > 0 {
				fmt.Fprintf(&sb, "wazuh.monitoring.shards: %d\n", b.wazuhPlugin.Monitoring.Shards)
			}
			fmt.Fprintf(&sb, "wazuh.monitoring.replicas: %d\n", b.wazuhPlugin.Monitoring.Replicas)
		}

		// Checks configuration
		if b.wazuhPlugin.Checks != nil {
			fmt.Fprintf(&sb, "checks.pattern: %v\n", b.wazuhPlugin.Checks.Pattern)
			fmt.Fprintf(&sb, "checks.template: %v\n", b.wazuhPlugin.Checks.Template)
			fmt.Fprintf(&sb, "checks.api: %v\n", b.wazuhPlugin.Checks.API)
			fmt.Fprintf(&sb, "checks.setup: %v\n", b.wazuhPlugin.Checks.Setup)
			fmt.Fprintf(&sb, "checks.fields: %v\n", b.wazuhPlugin.Checks.Fields)
			fmt.Fprintf(&sb, "checks.metaFields: %v\n", b.wazuhPlugin.Checks.MetaFields)
			fmt.Fprintf(&sb, "checks.timeFilter: %v\n", b.wazuhPlugin.Checks.TimeFilter)
			fmt.Fprintf(&sb, "checks.maxBuckets: %v\n", b.wazuhPlugin.Checks.MaxBuckets)
		}

		// Cron Statistics configuration
		if b.wazuhPlugin.CronStatistics != nil {
			fmt.Fprintf(&sb, "cron.statistics.status: %v\n", b.wazuhPlugin.CronStatistics.Status)
			if len(b.wazuhPlugin.CronStatistics.APIs) > 0 {
				sb.WriteString("cron.statistics.apis:\n")
				for _, api := range b.wazuhPlugin.CronStatistics.APIs {
					fmt.Fprintf(&sb, "  - %s\n", api)
				}
			}
			if b.wazuhPlugin.CronStatistics.Interval != "" {
				fmt.Fprintf(&sb, "cron.statistics.interval: %s\n", b.wazuhPlugin.CronStatistics.Interval)
			}
			if b.wazuhPlugin.CronStatistics.IndexName != "" {
				fmt.Fprintf(&sb, "cron.statistics.index.name: %s\n", b.wazuhPlugin.CronStatistics.IndexName)
			}
			if b.wazuhPlugin.CronStatistics.IndexCreation != "" {
				fmt.Fprintf(&sb, "cron.statistics.index.creation: %s\n", b.wazuhPlugin.CronStatistics.IndexCreation)
			}
			if b.wazuhPlugin.CronStatistics.Shards > 0 {
				fmt.Fprintf(&sb, "cron.statistics.shards: %d\n", b.wazuhPlugin.CronStatistics.Shards)
			}
			fmt.Fprintf(&sb, "cron.statistics.index.replicas: %d\n", b.wazuhPlugin.CronStatistics.Replicas)
		}
	}

	return sb.String()
}

// buildWazuhAppConfigScript generates a custom wazuh_app_config.sh script
// This script replaces the default one to allow flexible host configuration
func (b *DashboardConfigMapBuilder) buildWazuhAppConfigScript() string {
	// If custom API endpoints are defined, we skip the default script behavior
	// The wazuh.yml will already have the hosts configured
	hasCustomEndpoints := b.wazuhPlugin != nil && len(b.wazuhPlugin.APIEndpoints) > 0

	if hasCustomEndpoints {
		// Script that copies operator-managed wazuh.yml to the data directory
		return `#!/bin/bash
# Wazuh App Config Script (Operator-managed)
# Custom API endpoints are pre-configured in wazuh.yml

source_config="/usr/share/wazuh-dashboard/config/wazuh.yml"
dashboard_config_file="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

# Always copy operator-managed wazuh.yml to data directory
mkdir -p "$(dirname "$dashboard_config_file")"
cp "$source_config" "$dashboard_config_file"

echo "Wazuh APP configured by operator with custom API endpoints"
`
	}

	// Default script that uses environment variables for host configuration
	// This is the user's requested simplified version
	// Default credentials use Wazuh API admin user (wazuh:wazuh)
	return `#!/bin/bash
# Wazuh App Config Script (Operator-managed)
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)

wazuh_url="${WAZUH_API_URL:-https://wazuh}"
wazuh_port="${API_PORT:-55000}"
api_username="${API_USERNAME:-wazuh}"
api_password="${API_PASSWORD:-wazuh}"
api_run_as="${RUN_AS:-false}"

dashboard_config_file="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$dashboard_config_file")"

# Check if hosts are already configured (to support operator-managed config)
if [ -f "$dashboard_config_file" ] && grep -q "^hosts:" "$dashboard_config_file"; then
    echo "Wazuh APP already configured with hosts"
    exit 0
fi

# Write the hosts configuration
cat << EOF >> $dashboard_config_file
hosts:
  - default:
      url: $wazuh_url
      port: $wazuh_port
      username: $api_username
      password: $api_password
      run_as: $api_run_as
EOF

echo "Wazuh APP configured with default host"
`
}
