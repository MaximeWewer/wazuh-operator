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
	"strings"
	"testing"
)

func TestOpenSearchConfig_VersionAwareHotReload(t *testing.T) {
	tests := []struct {
		name           string
		wazuhVersion   string
		expectedConfig string
		notExpected    string
	}{
		{
			name:           "Wazuh 4.14.1 should use automatic hot reload",
			wazuhVersion:   "4.14.1",
			expectedConfig: "plugins.security.ssl.certificates_hot_reload.enabled: true",
			notExpected:    "plugins.security.ssl_cert_reload_enabled: true",
		},
		{
			name:           "Wazuh 4.12.0 should use automatic hot reload",
			wazuhVersion:   "4.12.0",
			expectedConfig: "plugins.security.ssl.certificates_hot_reload.enabled: true",
			notExpected:    "plugins.security.ssl_cert_reload_enabled: true",
		},
		{
			name:           "Wazuh 4.10.0 should use API-based reload",
			wazuhVersion:   "4.10.0",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
		{
			name:           "Wazuh 4.9.0 should use API-based reload",
			wazuhVersion:   "4.9.0",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
		{
			name:           "Empty version should use legacy fallback",
			wazuhVersion:   "",
			expectedConfig: "plugins.security.ssl_cert_reload_enabled: true",
			notExpected:    "plugins.security.ssl.certificates_hot_reload.enabled: true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultOpenSearchConfig("test-cluster", "test-ns")
			if tt.wazuhVersion != "" {
				config.WithWazuhVersion(tt.wazuhVersion)
			}

			result := config.Build()

			if !strings.Contains(result, tt.expectedConfig) {
				t.Errorf("Expected config to contain %q for Wazuh version %q, but it did not.\nConfig:\n%s",
					tt.expectedConfig, tt.wazuhVersion, result)
			}

			if tt.notExpected != "" && strings.Contains(result, tt.notExpected) {
				t.Errorf("Expected config NOT to contain %q for Wazuh version %q, but it did.\nConfig:\n%s",
					tt.notExpected, tt.wazuhVersion, result)
			}
		})
	}
}

func TestOpenSearchConfig_WithWazuhVersion(t *testing.T) {
	config := DefaultOpenSearchConfig("test-cluster", "test-ns")

	// Test chaining
	result := config.WithWazuhVersion("4.14.1")

	if result != config {
		t.Error("WithWazuhVersion should return the same config for chaining")
	}

	if config.WazuhVersion != "4.14.1" {
		t.Errorf("Expected WazuhVersion to be 4.14.1, got %s", config.WazuhVersion)
	}
}

func TestBuildIndexerConfig(t *testing.T) {
	config := BuildIndexerConfig("test-cluster", "test-ns", 3, "4.14.1")

	// Should contain basic cluster configuration
	if !strings.Contains(config, "cluster.name: test-cluster") {
		t.Error("Expected config to contain cluster name")
	}

	// Should contain discovery hosts for 3 replicas
	if !strings.Contains(config, "test-cluster-indexer-0") {
		t.Error("Expected config to contain first discovery host")
	}
	if !strings.Contains(config, "test-cluster-indexer-2") {
		t.Error("Expected config to contain third discovery host")
	}

	// Should have security enabled by default
	if !strings.Contains(config, "plugins.security.disabled: false") {
		t.Error("Expected security to be enabled by default")
	}

	// With Wazuh 4.14.1, should use automatic hot reload
	if !strings.Contains(config, "plugins.security.ssl.certificates_hot_reload.enabled: true") {
		t.Error("Expected automatic hot reload for Wazuh 4.14.1")
	}
}

func TestBuildIndexerConfig_NoVersion(t *testing.T) {
	// When no version is provided, should use fallback (legacy setting)
	config := BuildIndexerConfig("test-cluster", "test-ns", 1, "")

	if !strings.Contains(config, "plugins.security.ssl_cert_reload_enabled: true") {
		t.Error("Expected fallback hot reload setting when no version provided")
	}

	if strings.Contains(config, "plugins.security.ssl.certificates_hot_reload.enabled: true") {
		t.Error("Should NOT use automatic hot reload when no version provided")
	}
}

// =============================================================================
// NodePool Config Tests (Advanced Topology Mode)
// =============================================================================

func TestOpenSearchConfig_WithNodeRoles(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		expected string
	}{
		{
			name:     "cluster_manager role only",
			roles:    []string{"cluster_manager"},
			expected: "node.roles: [cluster_manager]",
		},
		{
			name:     "data role only",
			roles:    []string{"data"},
			expected: "node.roles: [data]",
		},
		{
			name:     "multiple roles",
			roles:    []string{"cluster_manager", "data", "ingest"},
			expected: "node.roles: [cluster_manager, data, ingest]",
		},
		{
			name:     "empty roles (coordinating-only)",
			roles:    []string{},
			expected: "node.roles: []",
		},
		{
			name:     "coordinating_only pseudo-role",
			roles:    []string{"coordinating_only"},
			expected: "node.roles: []", // coordinating_only is filtered out
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultOpenSearchConfig("cluster", "ns")
			config.WithNodeRoles(tt.roles)

			result := config.Build()

			if !strings.Contains(result, tt.expected) {
				t.Errorf("Expected config to contain %q, but it did not.\nConfig:\n%s", tt.expected, result)
			}
		})
	}
}

func TestOpenSearchConfig_WithNodeAttributes(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string]string
		expected   []string
	}{
		{
			name:       "hot/warm tier attribute",
			attributes: map[string]string{"temp": "hot"},
			expected:   []string{"node.attr.temp: hot"},
		},
		{
			name:       "availability zone",
			attributes: map[string]string{"zone": "us-east-1a"},
			expected:   []string{"node.attr.zone: us-east-1a"},
		},
		{
			name: "multiple attributes",
			attributes: map[string]string{
				"temp": "warm",
				"rack": "rack-1",
			},
			expected: []string{
				"node.attr.temp: warm",
				"node.attr.rack: rack-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultOpenSearchConfig("cluster", "ns")
			config.WithNodeAttributes(tt.attributes)

			result := config.Build()

			for _, exp := range tt.expected {
				if !strings.Contains(result, exp) {
					t.Errorf("Expected config to contain %q, but it did not.\nConfig:\n%s", exp, result)
				}
			}
		})
	}
}

func TestOpenSearchConfig_NoNodeRoles_SimpleMode(t *testing.T) {
	// When NodeRoles is nil (not set), node.roles should NOT appear in config
	// This is the default for simple mode where all nodes have all roles
	config := DefaultOpenSearchConfig("cluster", "ns")

	result := config.Build()

	if strings.Contains(result, "node.roles:") {
		t.Errorf("Simple mode config should NOT contain node.roles.\nConfig:\n%s", result)
	}
}

func TestBuildNodePoolConfig(t *testing.T) {
	tests := []struct {
		name     string
		params   NodePoolConfigParams
		expected []string
	}{
		{
			name: "cluster_manager pool",
			params: NodePoolConfigParams{
				ClusterName:        "test-cluster",
				Namespace:          "default",
				PoolName:           "masters",
				Roles:              []string{"cluster_manager"},
				DiscoverySeedHosts: []string{"master-0.test.svc", "master-1.test.svc", "master-2.test.svc"},
				InitialMasterNodes: []string{"master-0", "master-1", "master-2"},
			},
			expected: []string{
				"cluster.name: test-cluster",
				"node.roles: [cluster_manager]",
				"master-0.test.svc",
				"master-1.test.svc",
				"master-2.test.svc",
			},
		},
		{
			name: "data pool with hot tier",
			params: NodePoolConfigParams{
				ClusterName:        "test-cluster",
				Namespace:          "default",
				PoolName:           "data-hot",
				Roles:              []string{"data", "ingest"},
				Attributes:         map[string]string{"temp": "hot"},
				DiscoverySeedHosts: []string{"master-0.test.svc"},
				InitialMasterNodes: []string{"master-0"},
			},
			expected: []string{
				"node.roles: [data, ingest]",
				"node.attr.temp: hot",
			},
		},
		{
			name: "coordinating-only pool",
			params: NodePoolConfigParams{
				ClusterName:        "test-cluster",
				Namespace:          "default",
				PoolName:           "coord",
				Roles:              []string{}, // Empty = coordinating-only
				DiscoverySeedHosts: []string{"master-0.test.svc"},
				InitialMasterNodes: []string{"master-0"},
			},
			expected: []string{
				"node.roles: []",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildNodePoolConfig(tt.params)

			for _, exp := range tt.expected {
				if !strings.Contains(result, exp) {
					t.Errorf("Expected config to contain %q, but it did not.\nConfig:\n%s", exp, result)
				}
			}
		})
	}
}

func TestGenerateDiscoveryHostsForNodePools(t *testing.T) {
	clusterName := "test-cluster"
	namespace := "default"

	pools := []struct {
		Name     string
		Replicas int32
	}{
		{Name: "masters", Replicas: 3},
	}

	hosts := GenerateDiscoveryHostsForNodePools(clusterName, namespace, pools)

	if len(hosts) != 3 {
		t.Fatalf("Expected 3 discovery hosts, got %d", len(hosts))
	}

	// Verify host format
	for i, host := range hosts {
		expected := "test-cluster-indexer-masters-" + string(rune('0'+i))
		if !strings.Contains(host, expected) {
			t.Errorf("Expected host %d to contain %q, got %q", i, expected, host)
		}
	}
}

func TestGenerateInitialMasterNodesForNodePools(t *testing.T) {
	clusterName := "test-cluster"

	pools := []struct {
		Name     string
		Replicas int32
	}{
		{Name: "masters", Replicas: 3},
	}

	nodes := GenerateInitialMasterNodesForNodePools(clusterName, pools)

	if len(nodes) != 3 {
		t.Fatalf("Expected 3 initial master nodes, got %d", len(nodes))
	}

	// Verify node names
	for i, node := range nodes {
		expected := "test-cluster-indexer-masters-" + string(rune('0'+i))
		if node != expected {
			t.Errorf("Expected node %d to be %q, got %q", i, expected, node)
		}
	}
}

func TestOpenSearchConfig_WithDiscoveryHosts(t *testing.T) {
	hosts := []string{
		"master-0.cluster.svc",
		"master-1.cluster.svc",
		"master-2.cluster.svc",
	}

	config := DefaultOpenSearchConfig("cluster", "ns")
	config.WithDiscoveryHosts(hosts)

	result := config.Build()

	for _, host := range hosts {
		if !strings.Contains(result, host) {
			t.Errorf("Expected config to contain discovery host %q.\nConfig:\n%s", host, result)
		}
	}
}

func TestOpenSearchConfig_WithInitialMasterNodes(t *testing.T) {
	nodes := []string{"custom-master-0", "custom-master-1", "custom-master-2"}
	hosts := []string{"custom-master-0.svc", "custom-master-1.svc", "custom-master-2.svc"}

	config := DefaultOpenSearchConfig("cluster", "ns")
	// Must set both discovery hosts and initial master nodes to override auto-generation
	config.WithDiscoveryHosts(hosts)
	config.WithInitialMasterNodes(nodes)

	result := config.Build()

	for _, node := range nodes {
		if !strings.Contains(result, node) {
			t.Errorf("Expected config to contain initial master node %q.\nConfig:\n%s", node, result)
		}
	}
}
