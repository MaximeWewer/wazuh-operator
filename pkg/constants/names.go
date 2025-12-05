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

import "fmt"

// Resource name suffixes
const (
	// SuffixIndexer is the suffix for indexer resources
	SuffixIndexer = "-indexer"

	// SuffixIndexerHeadless is the suffix for indexer headless service
	SuffixIndexerHeadless = "-indexer-headless"

	// SuffixIndexerConfig is the suffix for indexer configmap
	SuffixIndexerConfig = "-indexer-config"

	// SuffixIndexerNodePool is the suffix pattern for nodePool resources
	// Full pattern: {cluster}-indexer-{poolName}
	SuffixIndexerNodePool = "-indexer-"

	// SuffixNodePoolHeadless is the suffix for nodePool headless services
	// Full pattern: {cluster}-indexer-{poolName}-headless
	SuffixNodePoolHeadless = "-headless"

	// SuffixNodePoolConfig is the suffix for nodePool configmaps
	// Full pattern: {cluster}-indexer-{poolName}-config
	SuffixNodePoolConfig = "-config"

	// SuffixNodePoolPDB is the suffix for nodePool PodDisruptionBudgets
	// Full pattern: {cluster}-indexer-{poolName}-pdb
	SuffixNodePoolPDB = "-pdb"

	// SuffixIndexerCerts is the suffix for indexer certificates secret
	SuffixIndexerCerts = "-indexer-certs"

	// SuffixIndexerSecurity is the suffix for indexer security config secret
	SuffixIndexerSecurity = "-indexer-security"

	// SuffixIndexerCredentials is the suffix for indexer credentials secret
	SuffixIndexerCredentials = "-indexer-credentials"

	// SuffixIndexerMetrics is the suffix for indexer metrics service monitor
	SuffixIndexerMetrics = "-indexer-metrics"

	// SuffixManagerMaster is the suffix for manager master resources
	SuffixManagerMaster = "-manager-master"

	// SuffixManagerWorkers is the suffix for manager workers resources
	SuffixManagerWorkers = "-manager-workers"

	// SuffixManagerWorker is the suffix for manager worker service (singular)
	SuffixManagerWorker = "-manager-worker"

	// SuffixDashboard is the suffix for dashboard resources
	SuffixDashboard = "-dashboard"

	// SuffixDashboardConfig is the suffix for dashboard configmap
	SuffixDashboardConfig = "-dashboard-config"

	// SuffixDashboardCerts is the suffix for dashboard certificates secret
	SuffixDashboardCerts = "-dashboard-certs"

	// SuffixDashboardCA is the suffix for dashboard CA
	SuffixDashboardCA = "-dashboard-ca"

	// SuffixDashboardAuthConfig is the suffix for dashboard auth configmap
	SuffixDashboardAuthConfig = "-dashboard-auth-config"
)

// Resource naming functions - Indexer

// IndexerName returns the name for indexer resources
func IndexerName(clusterName string) string {
	return clusterName + SuffixIndexer
}

// IndexerHeadlessName returns the name for indexer headless service
func IndexerHeadlessName(clusterName string) string {
	return clusterName + SuffixIndexerHeadless
}

// IndexerConfigName returns the name for indexer configmap
func IndexerConfigName(clusterName string) string {
	return clusterName + SuffixIndexerConfig
}

// IndexerCertsName returns the name for indexer certificates secret
func IndexerCertsName(clusterName string) string {
	return clusterName + SuffixIndexerCerts
}

// IndexerSecurityName returns the name for indexer security config secret
func IndexerSecurityName(clusterName string) string {
	return clusterName + SuffixIndexerSecurity
}

// IndexerCredentialsName returns the name for indexer credentials secret
func IndexerCredentialsName(clusterName string) string {
	return clusterName + SuffixIndexerCredentials
}

// IndexerMetricsName returns the name for indexer metrics service monitor
func IndexerMetricsName(clusterName string) string {
	return clusterName + SuffixIndexerMetrics
}

// IndexerPodName returns the name for a specific indexer pod
func IndexerPodName(clusterName string, ordinal int) string {
	return fmt.Sprintf("%s%s-%d", clusterName, SuffixIndexer, ordinal)
}

// IndexerServiceFQDN returns the fully qualified domain name for indexer service
func IndexerServiceFQDN(clusterName, namespace string) string {
	return fmt.Sprintf("%s%s.%s.svc.cluster.local", clusterName, SuffixIndexer, namespace)
}

// IndexerHeadlessServiceFQDN returns the FQDN for indexer headless service
func IndexerHeadlessServiceFQDN(clusterName, namespace string) string {
	return fmt.Sprintf("%s%s.%s.svc.cluster.local", clusterName, SuffixIndexerHeadless, namespace)
}

// IndexerPodFQDN returns the FQDN for a specific indexer pod
func IndexerPodFQDN(clusterName, namespace string, ordinal int) string {
	podName := IndexerPodName(clusterName, ordinal)
	return fmt.Sprintf("%s.%s%s.%s.svc.cluster.local", podName, clusterName, SuffixIndexerHeadless, namespace)
}

// Resource naming functions - Manager

// ManagerMasterName returns the name for manager master resources
func ManagerMasterName(clusterName string) string {
	return clusterName + SuffixManagerMaster
}

// ManagerWorkersName returns the name for manager workers resources
func ManagerWorkersName(clusterName string) string {
	return clusterName + SuffixManagerWorkers
}

// ManagerWorkerName returns the name for manager worker service (singular)
func ManagerWorkerName(clusterName string) string {
	return clusterName + SuffixManagerWorker
}

// ManagerMasterPodName returns the name for a specific manager master pod
func ManagerMasterPodName(clusterName string, ordinal int) string {
	return fmt.Sprintf("%s%s-%d", clusterName, SuffixManagerMaster, ordinal)
}

// ManagerWorkerPodName returns the name for a specific manager worker pod
func ManagerWorkerPodName(clusterName string, ordinal int) string {
	return fmt.Sprintf("%s%s-%d", clusterName, SuffixManagerWorkers, ordinal)
}

// ManagerMasterServiceFQDN returns the FQDN for manager master service
func ManagerMasterServiceFQDN(clusterName, namespace string) string {
	return fmt.Sprintf("%s%s.%s.svc.cluster.local", clusterName, SuffixManagerMaster, namespace)
}

// ManagerWorkersServiceFQDN returns the FQDN for manager workers service
func ManagerWorkersServiceFQDN(clusterName, namespace string) string {
	return fmt.Sprintf("%s%s.%s.svc.cluster.local", clusterName, SuffixManagerWorkers, namespace)
}

// ManagerMasterPodFQDN returns the FQDN for a specific manager master pod
func ManagerMasterPodFQDN(clusterName, namespace string, ordinal int) string {
	podName := ManagerMasterPodName(clusterName, ordinal)
	return fmt.Sprintf("%s.%s%s.%s.svc.cluster.local", podName, clusterName, SuffixManagerMaster, namespace)
}

// ManagerWorkerPodFQDN returns the FQDN for a specific manager worker pod
func ManagerWorkerPodFQDN(clusterName, namespace string, ordinal int) string {
	podName := ManagerWorkerPodName(clusterName, ordinal)
	return fmt.Sprintf("%s.%s%s.%s.svc.cluster.local", podName, clusterName, SuffixManagerWorkers, namespace)
}

// Resource naming functions - Dashboard

// DashboardName returns the name for dashboard resources
func DashboardName(clusterName string) string {
	return clusterName + SuffixDashboard
}

// DashboardConfigName returns the name for dashboard configmap
func DashboardConfigName(clusterName string) string {
	return clusterName + SuffixDashboardConfig
}

// DashboardCertsName returns the name for dashboard certificates secret
func DashboardCertsName(clusterName string) string {
	return clusterName + SuffixDashboardCerts
}

// DashboardCAName returns the name for dashboard CA
func DashboardCAName(clusterName string) string {
	return clusterName + SuffixDashboardCA
}

// DashboardAuthConfigName returns the name for dashboard auth configmap
func DashboardAuthConfigName(clusterName string) string {
	return clusterName + SuffixDashboardAuthConfig
}

// DashboardServiceFQDN returns the FQDN for dashboard service
func DashboardServiceFQDN(clusterName, namespace string) string {
	return fmt.Sprintf("%s%s.%s.svc.cluster.local", clusterName, SuffixDashboard, namespace)
}

// Additional resource name suffixes
const (
	// SuffixManagerMasterCerts is the suffix for manager master certificates
	SuffixManagerMasterCerts = "-manager-master-certs"

	// SuffixManagerWorkerCerts is the suffix for manager worker certificates
	SuffixManagerWorkerCerts = "-manager-worker-certs"

	// SuffixFilebeatCerts is the suffix for filebeat certificates
	SuffixFilebeatCerts = "-filebeat-certs"

	// SuffixAdminCerts is the suffix for admin certificates
	SuffixAdminCerts = "-admin-certs"

	// SuffixClusterKey is the suffix for cluster key secret
	SuffixClusterKey = "-cluster-key"

	// SuffixAPICredentials is the suffix for API credentials secret
	SuffixAPICredentials = "-api-credentials"

	// SuffixFilebeatConfig is the suffix for filebeat configmap
	SuffixFilebeatConfig = "-filebeat-config"

	// SuffixManagerConfig is the suffix for manager configmap (with node type)
	SuffixManagerConfig = "-config"

	// SuffixManagerSharedConfig is the suffix for manager shared configmap
	SuffixManagerSharedConfig = "-manager-shared-config"
)

// Resource naming functions - Manager Certificates

// ManagerMasterCertsName returns the name for manager master certificates secret
func ManagerMasterCertsName(clusterName string) string {
	return clusterName + SuffixManagerMasterCerts
}

// ManagerWorkerCertsName returns the name for manager worker certificates secret
func ManagerWorkerCertsName(clusterName string) string {
	return clusterName + SuffixManagerWorkerCerts
}

// ManagerCertsName returns the name for manager certificates secret based on node type
func ManagerCertsName(clusterName, nodeType string) string {
	return fmt.Sprintf("%s-manager-%s-certs", clusterName, nodeType)
}

// FilebeatCertsName returns the name for filebeat certificates secret
func FilebeatCertsName(clusterName string) string {
	return clusterName + SuffixFilebeatCerts
}

// AdminCertsName returns the name for admin certificates secret
func AdminCertsName(clusterName string) string {
	return clusterName + SuffixAdminCerts
}

// Resource naming functions - Credentials and Keys

// ClusterKeyName returns the name for cluster key secret
func ClusterKeyName(clusterName string) string {
	return clusterName + SuffixClusterKey
}

// APICredentialsName returns the name for API credentials secret
func APICredentialsName(clusterName string) string {
	return clusterName + SuffixAPICredentials
}

// Resource naming functions - ConfigMaps

// FilebeatConfigName returns the name for filebeat configmap
func FilebeatConfigName(clusterName string) string {
	return clusterName + SuffixFilebeatConfig
}

// ManagerConfigName returns the name for manager configmap with node type
func ManagerConfigName(clusterName, nodeType string) string {
	return fmt.Sprintf("%s-manager-%s%s", clusterName, nodeType, SuffixManagerConfig)
}

// ManagerSharedConfigName returns the name for manager shared configmap
func ManagerSharedConfigName(clusterName string) string {
	return clusterName + SuffixManagerSharedConfig
}

// NodePool naming functions

// IndexerNodePoolName returns the name for a nodePool StatefulSet
// Pattern: {cluster}-indexer-{poolName}
func IndexerNodePoolName(clusterName, poolName string) string {
	return fmt.Sprintf("%s%s%s", clusterName, SuffixIndexerNodePool, poolName)
}

// IndexerNodePoolHeadlessName returns the name for a nodePool headless service
// Pattern: {cluster}-indexer-{poolName}-headless
func IndexerNodePoolHeadlessName(clusterName, poolName string) string {
	return IndexerNodePoolName(clusterName, poolName) + SuffixNodePoolHeadless
}

// IndexerNodePoolConfigName returns the name for a nodePool configmap
// Pattern: {cluster}-indexer-{poolName}-config
func IndexerNodePoolConfigName(clusterName, poolName string) string {
	return IndexerNodePoolName(clusterName, poolName) + SuffixNodePoolConfig
}

// IndexerNodePoolPDBName returns the name for a nodePool PodDisruptionBudget
// Pattern: {cluster}-indexer-{poolName}-pdb
func IndexerNodePoolPDBName(clusterName, poolName string) string {
	return IndexerNodePoolName(clusterName, poolName) + SuffixNodePoolPDB
}

// IndexerNodePoolPodName returns the name for a specific pod in a nodePool
// Pattern: {cluster}-indexer-{poolName}-{ordinal}
func IndexerNodePoolPodName(clusterName, poolName string, ordinal int) string {
	return fmt.Sprintf("%s-%d", IndexerNodePoolName(clusterName, poolName), ordinal)
}

// IndexerNodePoolHeadlessServiceFQDN returns the FQDN for a nodePool headless service
func IndexerNodePoolHeadlessServiceFQDN(clusterName, poolName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", IndexerNodePoolHeadlessName(clusterName, poolName), namespace)
}

// IndexerNodePoolPodFQDN returns the FQDN for a specific pod in a nodePool
func IndexerNodePoolPodFQDN(clusterName, poolName, namespace string, ordinal int) string {
	podName := IndexerNodePoolPodName(clusterName, poolName, ordinal)
	headlessService := IndexerNodePoolHeadlessName(clusterName, poolName)
	return fmt.Sprintf("%s.%s.%s.svc.cluster.local", podName, headlessService, namespace)
}
