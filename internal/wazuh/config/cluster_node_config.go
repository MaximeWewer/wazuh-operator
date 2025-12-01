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
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ClusterNodeConfig holds configuration for a Wazuh cluster node
type ClusterNodeConfig struct {
	// ClusterName is the name of the Wazuh cluster
	ClusterName string
	// NodeType is the type of node (master or worker)
	NodeType string
	// NodeName is the name of the node
	NodeName string
	// ClusterKey is the shared cluster key
	ClusterKey string
	// MasterAddress is the address of the master node (for workers)
	MasterAddress string
	// MasterPort is the port of the master node (for workers)
	MasterPort int
	// BindAddress is the address to bind to
	BindAddress string
	// ClusterPort is the port for cluster communication
	ClusterPort int
	// APIPort is the port for the API
	APIPort int
	// AgentPort is the port for agent connections
	AgentPort int
	// RegistrationPort is the port for agent registration
	RegistrationPort int
	// Namespace is the Kubernetes namespace
	Namespace string
}

// DefaultMasterNodeConfig returns a default ClusterNodeConfig for a master node
func DefaultMasterNodeConfig(clusterName, namespace string) *ClusterNodeConfig {
	return &ClusterNodeConfig{
		ClusterName:      clusterName,
		NodeType:         NodeTypeMaster,
		NodeName:         fmt.Sprintf("%s-manager-master", clusterName),
		ClusterKey:       "",
		MasterAddress:    "",
		MasterPort:       int(constants.PortManagerCluster),
		BindAddress:      "0.0.0.0",
		ClusterPort:      int(constants.PortManagerCluster),
		APIPort:          int(constants.PortManagerAPI),
		AgentPort:        int(constants.PortManagerAgentEvents),
		RegistrationPort: int(constants.PortManagerAgentAuth),
		Namespace:        namespace,
	}
}

// DefaultWorkerNodeConfig returns a default ClusterNodeConfig for a worker node
func DefaultWorkerNodeConfig(clusterName, namespace string, workerIndex int) *ClusterNodeConfig {
	masterService := fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", clusterName, namespace)
	return &ClusterNodeConfig{
		ClusterName:      clusterName,
		NodeType:         NodeTypeWorker,
		NodeName:         fmt.Sprintf("%s-manager-workers-%d", clusterName, workerIndex),
		ClusterKey:       "",
		MasterAddress:    masterService,
		MasterPort:       int(constants.PortManagerCluster),
		BindAddress:      "0.0.0.0",
		ClusterPort:      int(constants.PortManagerCluster),
		APIPort:          int(constants.PortManagerAPI),
		AgentPort:        int(constants.PortManagerAgentEvents),
		RegistrationPort: int(constants.PortManagerAgentAuth),
		Namespace:        namespace,
	}
}

// ClusterNodeConfigBuilder builds configuration for a cluster node
type ClusterNodeConfigBuilder struct {
	config *ClusterNodeConfig
}

// NewClusterNodeConfigBuilder creates a new ClusterNodeConfigBuilder
func NewClusterNodeConfigBuilder(config *ClusterNodeConfig) *ClusterNodeConfigBuilder {
	if config == nil {
		config = DefaultMasterNodeConfig("wazuh", "default")
	}
	return &ClusterNodeConfigBuilder{config: config}
}

// SetClusterKey sets the cluster key
func (b *ClusterNodeConfigBuilder) SetClusterKey(key string) *ClusterNodeConfigBuilder {
	b.config.ClusterKey = key
	return b
}

// SetMasterAddress sets the master address for workers
func (b *ClusterNodeConfigBuilder) SetMasterAddress(address string) *ClusterNodeConfigBuilder {
	b.config.MasterAddress = address
	return b
}

// SetNodeName sets the node name
func (b *ClusterNodeConfigBuilder) SetNodeName(name string) *ClusterNodeConfigBuilder {
	b.config.NodeName = name
	return b
}

// GetConfig returns the current configuration
func (b *ClusterNodeConfigBuilder) GetConfig() *ClusterNodeConfig {
	return b.config
}

// BuildOSSECConfig builds the ossec.conf content for this node
func (b *ClusterNodeConfigBuilder) BuildOSSECConfig(extraConfig string) (string, error) {
	if b.config.NodeType == NodeTypeMaster {
		return BuildMasterConfig(b.config.ClusterName, b.config.Namespace, b.config.NodeName, b.config.ClusterKey, extraConfig)
	}
	return BuildWorkerConfig(b.config.ClusterName, b.config.Namespace, b.config.NodeName, b.config.ClusterKey, b.config.MasterAddress, b.config.MasterPort, extraConfig)
}

// GenerateClusterKey generates a new random cluster key
// Equivalent to: openssl rand -hex 16 (generates 32 hex characters from 16 random bytes)
func GenerateClusterKey() (string, error) {
	// Generate 16 random bytes (will produce 32 hex characters)
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate cluster key: %w", err)
	}
	// Encode to hex string (32 characters)
	return hex.EncodeToString(key), nil
}

// GetMasterServiceAddress returns the full service address for the master node
func GetMasterServiceAddress(clusterName, namespace string) string {
	return fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", clusterName, namespace)
}

// GetWorkerServiceAddress returns the full service address for worker nodes
func GetWorkerServiceAddress(clusterName, namespace string) string {
	return fmt.Sprintf("%s-manager-workers.%s.svc.cluster.local", clusterName, namespace)
}

// GetIndexerServiceAddress returns the full service address for the indexer
func GetIndexerServiceAddress(clusterName, namespace string) string {
	return fmt.Sprintf("%s-indexer.%s.svc.cluster.local", clusterName, namespace)
}

// GetDashboardServiceAddress returns the full service address for the dashboard
func GetDashboardServiceAddress(clusterName, namespace string) string {
	return fmt.Sprintf("%s-dashboard.%s.svc.cluster.local", clusterName, namespace)
}

// GetPodDNSName returns the DNS name for a specific pod
func GetPodDNSName(statefulSetName, namespace string, ordinal int) string {
	return fmt.Sprintf("%s-%d.%s.%s.svc.cluster.local", statefulSetName, ordinal, statefulSetName, namespace)
}

// GetHeadlessServiceAddress returns the headless service address for StatefulSet pod discovery
func GetHeadlessServiceAddress(serviceName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace)
}

// NodeConfigMap represents the configuration for all nodes in a cluster
type NodeConfigMap struct {
	// Master node configuration
	Master *ClusterNodeConfig
	// Worker node configurations indexed by ordinal
	Workers map[int]*ClusterNodeConfig
}

// NewNodeConfigMap creates a new NodeConfigMap
func NewNodeConfigMap(clusterName, namespace string, workerReplicas int) *NodeConfigMap {
	ncm := &NodeConfigMap{
		Master:  DefaultMasterNodeConfig(clusterName, namespace),
		Workers: make(map[int]*ClusterNodeConfig),
	}

	for i := 0; i < workerReplicas; i++ {
		ncm.Workers[i] = DefaultWorkerNodeConfig(clusterName, namespace, i)
	}

	return ncm
}

// SetClusterKey sets the cluster key for all nodes
func (ncm *NodeConfigMap) SetClusterKey(key string) {
	ncm.Master.ClusterKey = key
	for _, worker := range ncm.Workers {
		worker.ClusterKey = key
	}
}

// GetMaster returns the master node configuration
func (ncm *NodeConfigMap) GetMaster() *ClusterNodeConfig {
	return ncm.Master
}

// GetWorker returns a worker node configuration by ordinal
func (ncm *NodeConfigMap) GetWorker(ordinal int) *ClusterNodeConfig {
	return ncm.Workers[ordinal]
}
