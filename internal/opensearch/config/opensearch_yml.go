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

// Package config provides configuration builders for OpenSearch components
package config

import (
	"fmt"
	"strings"

	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// GenerateRandomPassword generates a secure random password
// Deprecated: Use utils.GenerateRandomPassword instead
func GenerateRandomPassword(length int) string {
	return utils.GenerateRandomPassword(length)
}

// OpenSearchConfig holds configuration options for opensearch.yml
type OpenSearchConfig struct {
	ClusterName        string
	NodeName           string
	Namespace          string
	Replicas           int32
	HTTPPort           int32
	TransportPort      int32
	DiscoverySeedHosts []string
	InitialMasterNodes []string
	NetworkHost        string
	PathData           string
	PathLogs           string
	JavaOpts           string
	// Security settings
	SecurityEnabled bool
	CertPath        string
	AdminDN         string
	NodesDN         string
	// WazuhVersion for feature detection (determines OpenSearch version automatically)
	WazuhVersion string
	// Custom settings
	CustomSettings map[string]string

	// Advanced topology settings (for nodePool support)
	// NodeRoles specifies the OpenSearch roles for this node
	// Empty means all roles (default for simple mode)
	// Valid values: cluster_manager, data, ingest, ml, remote_cluster_client
	// coordinating_only is represented by an empty slice
	NodeRoles []string
	// NodeAttributes are custom attributes for shard allocation awareness
	// Rendered as node.attr.<key>: <value> in opensearch.yml
	// Common uses: {temp: hot}, {zone: az-1}
	NodeAttributes map[string]string
}

// DefaultOpenSearchConfig returns a default OpenSearch configuration
func DefaultOpenSearchConfig(clusterName, namespace string) *OpenSearchConfig {
	return &OpenSearchConfig{
		ClusterName:     clusterName,
		NodeName:        "${NODE_NAME}",
		Namespace:       namespace,
		Replicas:        1,
		HTTPPort:        constants.PortIndexerREST,
		TransportPort:   constants.PortIndexerTransport,
		NetworkHost:     "0.0.0.0",
		PathData:        constants.PathIndexerData,
		PathLogs:        constants.PathIndexerLogs,
		SecurityEnabled: true,
		CertPath:        "certs", // Relative path from /usr/share/wazuh-indexer
		AdminDN:         certificates.DefaultAdminDN(),
		NodesDN:         certificates.DefaultNodesDN(),
		CustomSettings:  make(map[string]string),
	}
}

// WithReplicas sets the number of replicas and generates discovery hosts
func (c *OpenSearchConfig) WithReplicas(replicas int32) *OpenSearchConfig {
	c.Replicas = replicas
	c.generateDiscoveryHosts()
	return c
}

// WithJavaOpts sets custom Java options
func (c *OpenSearchConfig) WithJavaOpts(opts string) *OpenSearchConfig {
	c.JavaOpts = opts
	return c
}

// WithCustomSetting adds a custom setting
func (c *OpenSearchConfig) WithCustomSetting(key, value string) *OpenSearchConfig {
	c.CustomSettings[key] = value
	return c
}

// WithWazuhVersion sets the Wazuh version for feature detection
func (c *OpenSearchConfig) WithWazuhVersion(version string) *OpenSearchConfig {
	c.WazuhVersion = version
	return c
}

// WithNodeRoles sets the OpenSearch node roles
// Valid roles: cluster_manager, data, ingest, ml, remote_cluster_client
// An empty slice means coordinating-only node
func (c *OpenSearchConfig) WithNodeRoles(roles []string) *OpenSearchConfig {
	c.NodeRoles = roles
	return c
}

// WithNodeAttributes sets custom node attributes for shard allocation awareness
// These are rendered as node.attr.<key>: <value> in opensearch.yml
func (c *OpenSearchConfig) WithNodeAttributes(attrs map[string]string) *OpenSearchConfig {
	c.NodeAttributes = attrs
	return c
}

// WithDiscoveryHosts sets custom discovery seed hosts
// This overrides the auto-generated hosts based on replicas
func (c *OpenSearchConfig) WithDiscoveryHosts(hosts []string) *OpenSearchConfig {
	c.DiscoverySeedHosts = hosts
	return c
}

// WithInitialMasterNodes sets the initial master nodes for cluster bootstrap
func (c *OpenSearchConfig) WithInitialMasterNodes(nodes []string) *OpenSearchConfig {
	c.InitialMasterNodes = nodes
	return c
}

// generateDiscoveryHosts generates the discovery seed hosts based on replicas
func (c *OpenSearchConfig) generateDiscoveryHosts() {
	c.DiscoverySeedHosts = make([]string, 0, c.Replicas)
	c.InitialMasterNodes = make([]string, 0, c.Replicas)

	headlessService := fmt.Sprintf("%s-indexer-headless.%s.svc.cluster.local", c.ClusterName, c.Namespace)

	for i := int32(0); i < c.Replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", c.ClusterName, i)
		host := fmt.Sprintf("%s.%s", podName, headlessService)
		c.DiscoverySeedHosts = append(c.DiscoverySeedHosts, host)
		c.InitialMasterNodes = append(c.InitialMasterNodes, podName)
	}
}

// Build generates the opensearch.yml content
func (c *OpenSearchConfig) Build() string {
	// Ensure discovery hosts are generated
	if len(c.DiscoverySeedHosts) == 0 {
		c.generateDiscoveryHosts()
	}

	var sb strings.Builder

	sb.WriteString("# OpenSearch configuration\n")
	sb.WriteString("# Generated by Wazuh Operator\n\n")

	// Cluster settings
	sb.WriteString(fmt.Sprintf("cluster.name: %s\n", c.ClusterName))
	sb.WriteString(fmt.Sprintf("node.name: %s\n", c.NodeName))

	// Node roles (advanced mode - if specified)
	// If NodeRoles is nil/empty and NodeAttributes is nil, we're in simple mode (all roles)
	// If NodeRoles is explicitly set (even if empty), we're in advanced mode
	if c.NodeRoles != nil {
		if len(c.NodeRoles) == 0 {
			// Empty roles = coordinating-only node
			sb.WriteString("node.roles: []\n")
		} else {
			// Filter out "coordinating_only" as it's not a real OpenSearch role
			var actualRoles []string
			for _, role := range c.NodeRoles {
				if role != constants.OpenSearchRoleCoordinatingOnly {
					actualRoles = append(actualRoles, role)
				}
			}
			if len(actualRoles) == 0 {
				sb.WriteString("node.roles: []\n")
			} else {
				sb.WriteString("node.roles: [")
				for i, role := range actualRoles {
					if i > 0 {
						sb.WriteString(", ")
					}
					sb.WriteString(role)
				}
				sb.WriteString("]\n")
			}
		}
	}

	// Node attributes (for shard allocation awareness)
	if len(c.NodeAttributes) > 0 {
		sb.WriteString("\n# Node attributes for shard allocation awareness\n")
		// Sort keys for consistent output
		for key, value := range c.NodeAttributes {
			sb.WriteString(fmt.Sprintf("node.attr.%s: %s\n", key, value))
		}
	}
	sb.WriteString("\n")

	// Path settings
	sb.WriteString(fmt.Sprintf("path.data: %s\n", c.PathData))
	sb.WriteString(fmt.Sprintf("path.logs: %s\n\n", c.PathLogs))

	// Network settings
	sb.WriteString(fmt.Sprintf("network.host: %s\n", c.NetworkHost))
	sb.WriteString(fmt.Sprintf("http.port: %d\n", c.HTTPPort))
	sb.WriteString(fmt.Sprintf("transport.port: %d\n\n", c.TransportPort))

	// Discovery settings
	sb.WriteString("discovery.seed_hosts:\n")
	for _, host := range c.DiscoverySeedHosts {
		sb.WriteString(fmt.Sprintf("  - %s\n", host))
	}

	sb.WriteString("\ncluster.initial_master_nodes:\n")
	for _, node := range c.InitialMasterNodes {
		sb.WriteString(fmt.Sprintf("  - %s\n", node))
	}
	sb.WriteString("\n")

	// Security settings
	if c.SecurityEnabled {
		sb.WriteString("# Security configuration\n")
		sb.WriteString("plugins.security.disabled: false\n")
		sb.WriteString("plugins.security.ssl.transport.enforce_hostname_verification: false\n")
		sb.WriteString("plugins.security.ssl.http.enabled: true\n")
		sb.WriteString("plugins.security.ssl.transport.enabled: true\n")

		// Version-aware SSL certificate hot reload configuration
		// Uses Wazuh version to determine OpenSearch capabilities automatically
		if c.WazuhVersion != "" && utils.SupportsAutomaticHotReload(c.WazuhVersion) {
			// Wazuh 4.12+ / OpenSearch 2.19+: automatic cluster-wide hot reload
			sb.WriteString("# Automatic SSL certificate hot reload (OpenSearch 2.19+)\n")
			sb.WriteString("plugins.security.ssl.certificates_hot_reload.enabled: true\n\n")
		} else if c.WazuhVersion != "" && utils.RequiresAPIReload(c.WazuhVersion) {
			// Wazuh 4.9-4.11 / OpenSearch 2.13-2.18: API-based reload
			sb.WriteString("# SSL certificate reload via API (OpenSearch 2.13-2.18)\n")
			sb.WriteString("plugins.security.ssl_cert_reload_enabled: true\n\n")
		} else {
			// Fallback for older versions or when version is not specified
			sb.WriteString("# Enable hot reload of SSL certificates (no restart required when certs are renewed)\n")
			sb.WriteString("plugins.security.ssl_cert_reload_enabled: true\n\n")
		}

		// TLS certificate paths
		// Certificate files are named according to Kubernetes TLS secret convention:
		// tls.crt, tls.key, ca.crt (enables hot reload when mounted as directory without subPath)
		sb.WriteString(fmt.Sprintf("plugins.security.ssl.transport.pemcert_filepath: %s/tls.crt\n", c.CertPath))
		sb.WriteString(fmt.Sprintf("plugins.security.ssl.transport.pemkey_filepath: %s/tls.key\n", c.CertPath))
		sb.WriteString(fmt.Sprintf("plugins.security.ssl.transport.pemtrustedcas_filepath: %s/ca.crt\n\n", c.CertPath))

		sb.WriteString(fmt.Sprintf("plugins.security.ssl.http.pemcert_filepath: %s/tls.crt\n", c.CertPath))
		sb.WriteString(fmt.Sprintf("plugins.security.ssl.http.pemkey_filepath: %s/tls.key\n", c.CertPath))
		sb.WriteString(fmt.Sprintf("plugins.security.ssl.http.pemtrustedcas_filepath: %s/ca.crt\n\n", c.CertPath))

		// Admin DN settings
		sb.WriteString("plugins.security.authcz.admin_dn:\n")
		sb.WriteString(fmt.Sprintf("  - \"%s\"\n\n", c.AdminDN))

		// Nodes DN settings
		sb.WriteString("plugins.security.nodes_dn:\n")
		sb.WriteString(fmt.Sprintf("  - \"%s\"\n\n", c.NodesDN))

		// Allow initialization
		sb.WriteString("plugins.security.allow_default_init_securityindex: true\n")
		sb.WriteString("plugins.security.allow_unsafe_democertificates: false\n\n")

		// Enable REST API for all_access role (allows admin to manage security via API)
		sb.WriteString("# REST API access control\n")
		sb.WriteString("plugins.security.restapi.roles_enabled: [\"all_access\", \"security_rest_api_access\"]\n\n")
	}

	// Compatibility settings
	sb.WriteString("# Compatibility settings\n")
	sb.WriteString("compatibility.override_main_response_version: true\n\n")

	// Custom settings
	if len(c.CustomSettings) > 0 {
		sb.WriteString("# Custom settings\n")
		for key, value := range c.CustomSettings {
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	return sb.String()
}

// BuildIndexerConfig is a convenience function to build opensearch.yml for indexer
// The wazuhVersion parameter enables version-aware configuration (e.g., SSL hot reload settings)
func BuildIndexerConfig(clusterName, namespace string, replicas int32, wazuhVersion string) string {
	config := DefaultOpenSearchConfig(clusterName, namespace)
	config.WithReplicas(replicas)
	if wazuhVersion != "" {
		config.WithWazuhVersion(wazuhVersion)
	}
	return config.Build()
}

// NodePoolConfigParams holds parameters for building a nodePool opensearch.yml
type NodePoolConfigParams struct {
	ClusterName        string
	Namespace          string
	PoolName           string
	Roles              []string
	Attributes         map[string]string
	DiscoverySeedHosts []string
	InitialMasterNodes []string
	WazuhVersion       string
}

// BuildNodePoolConfig builds opensearch.yml for a specific nodePool
// This is used in advanced topology mode where each nodePool has different roles/attributes
func BuildNodePoolConfig(params NodePoolConfigParams) string {
	config := DefaultOpenSearchConfig(params.ClusterName, params.Namespace)

	// Set node roles
	config.WithNodeRoles(params.Roles)

	// Set node attributes for shard allocation awareness
	if len(params.Attributes) > 0 {
		config.WithNodeAttributes(params.Attributes)
	}

	// Set discovery hosts (pointing to cluster_manager nodes)
	if len(params.DiscoverySeedHosts) > 0 {
		config.WithDiscoveryHosts(params.DiscoverySeedHosts)
	}

	// Set initial master nodes
	if len(params.InitialMasterNodes) > 0 {
		config.WithInitialMasterNodes(params.InitialMasterNodes)
	}

	// Set Wazuh version for feature detection
	if params.WazuhVersion != "" {
		config.WithWazuhVersion(params.WazuhVersion)
	}

	return config.Build()
}

// GenerateDiscoveryHostsForNodePools generates discovery seed hosts for a multi-pool cluster
// It returns hosts pointing to the cluster_manager nodePool's headless service
func GenerateDiscoveryHostsForNodePools(clusterName, namespace string, clusterManagerPools []struct {
	Name     string
	Replicas int32
}) []string {
	var hosts []string
	for _, pool := range clusterManagerPools {
		headlessService := constants.IndexerNodePoolHeadlessServiceFQDN(clusterName, pool.Name, namespace)
		for i := int32(0); i < pool.Replicas; i++ {
			podName := constants.IndexerNodePoolPodName(clusterName, pool.Name, int(i))
			host := fmt.Sprintf("%s.%s", podName, headlessService)
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// GenerateInitialMasterNodesForNodePools generates the initial master nodes list
// for cluster bootstrap in a multi-pool cluster
func GenerateInitialMasterNodesForNodePools(clusterName string, clusterManagerPools []struct {
	Name     string
	Replicas int32
}) []string {
	var nodes []string
	for _, pool := range clusterManagerPools {
		for i := int32(0); i < pool.Replicas; i++ {
			nodeName := constants.IndexerNodePoolPodName(clusterName, pool.Name, int(i))
			nodes = append(nodes, nodeName)
		}
	}
	return nodes
}
