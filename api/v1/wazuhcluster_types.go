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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhClusterSpec defines the desired state of WazuhCluster
// Supports two modes:
// 1. Inline mode (default): Define manager, indexer, dashboard specs inline
// 2. Reference mode: Use managerRef, indexerRef, dashboardRef to reference separate CRDs
type WazuhClusterSpec struct {
	// Version of Wazuh to deploy
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+\.[0-9]+$`
	Version string `json:"version"`

	// License type for the cluster
	// +optional
	// +kubebuilder:default="basic"
	License string `json:"license,omitempty"`

	// Manager configuration (inline mode)
	// +optional
	Manager *WazuhManagerClusterSpec `json:"manager,omitempty"`

	// Reference to a WazuhManager resource (reference mode)
	// +optional
	ManagerRef *ComponentRef `json:"managerRef,omitempty"`

	// Indexer configuration (inline mode)
	// +optional
	Indexer *WazuhIndexerClusterSpec `json:"indexer,omitempty"`

	// Reference to a WazuhIndexer resource (reference mode)
	// +optional
	IndexerRef *ComponentRef `json:"indexerRef,omitempty"`

	// Dashboard configuration (inline mode)
	// +optional
	Dashboard *WazuhDashboardClusterSpec `json:"dashboard,omitempty"`

	// Reference to a WazuhDashboard resource (reference mode)
	// +optional
	DashboardRef *ComponentRef `json:"dashboardRef,omitempty"`

	// Image pull secrets for private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Storage class to use for all PVCs
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// TLS configuration
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Monitoring configuration
	// +optional
	Monitoring *MonitoringConfig `json:"monitoring,omitempty"`

	// Drain strategy configuration for safe scale-down operations
	// +optional
	Drain *DrainConfiguration `json:"drain,omitempty"`
}

// WazuhManagerClusterSpec defines the Wazuh manager cluster configuration (inline in WazuhCluster)
type WazuhManagerClusterSpec struct {
	// Master node configuration
	// +kubebuilder:validation:Required
	Master WazuhMasterSpec `json:"master"`

	// Worker nodes configuration
	// +kubebuilder:validation:Required
	Workers WazuhWorkerSpec `json:"workers"`

	// Cluster key for internal communication
	// +optional
	ClusterKeySecretRef *corev1.SecretKeySelector `json:"clusterKeySecretRef,omitempty"`

	// API credentials
	// +optional
	APICredentials *CredentialsSecretRef `json:"apiCredentials,omitempty"`

	// Agent registration password
	// +optional
	AuthdPasswordSecretRef *corev1.SecretKeySelector `json:"authdPasswordSecretRef,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Custom configuration overlay
	// +optional
	Config *WazuhConfigSpec `json:"config,omitempty"`

	// Filebeat SSL verification mode
	// +optional
	// +kubebuilder:default="full"
	// +kubebuilder:validation:Enum=full;none;certificate
	FilebeatSSLVerificationMode string `json:"filebeatSSLVerificationMode,omitempty"`

	// Log rotation configuration for cleaning up old log files
	// +optional
	LogRotation *LogRotationSpec `json:"logRotation,omitempty"`

	// Pod Disruption Budget for manager pods
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// AntiAffinity configures pod anti-affinity rules for manager pods
	// When enabled, manager pods are spread across different nodes or zones
	// This helps ensure high availability by preventing all managers from running on the same node
	// +optional
	AntiAffinity *AntiAffinitySpec `json:"antiAffinity,omitempty"`

	// Network policy for manager pods
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`
}

// GetTotalReplicas returns the total number of manager nodes (1 master + N workers)
func (s *WazuhManagerClusterSpec) GetTotalReplicas() int32 {
	if s == nil {
		return 0
	}
	return 1 + s.Workers.GetReplicas()
}

// IsHA returns true if the manager cluster has enough nodes for high availability (3+)
// A minimum of 3 nodes is recommended for HA to tolerate single node failures
func (s *WazuhManagerClusterSpec) IsHA() bool {
	if s == nil {
		return false
	}
	return s.GetTotalReplicas() >= 3
}

// LogRotationSpec defines the configuration for log rotation CronJob
type LogRotationSpec struct {
	// Enabled enables log rotation for manager pods
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Schedule is a cron expression for when to run log rotation
	// Default: "0 0 * * 1" (weekly on Monday at midnight)
	// +optional
	// +kubebuilder:default="0 0 * * 1"
	Schedule string `json:"schedule,omitempty"`

	// RetentionDays is the number of days to retain log files
	// Files older than this will be deleted
	// Default: 7
	// +optional
	// +kubebuilder:default=7
	// +kubebuilder:validation:Minimum=1
	RetentionDays *int32 `json:"retentionDays,omitempty"`

	// MaxFileSizeMB is the maximum file size in MB
	// Files larger than this will be deleted (0 = disabled)
	// +optional
	// +kubebuilder:validation:Minimum=0
	MaxFileSizeMB *int32 `json:"maxFileSizeMB,omitempty"`

	// CombinationMode defines how age and size filters combine
	// "or" = delete if old OR large (default)
	// "and" = delete only if old AND large
	// +optional
	// +kubebuilder:default="or"
	// +kubebuilder:validation:Enum=or;and
	CombinationMode string `json:"combinationMode,omitempty"`

	// Paths is the list of paths to clean
	// Default: ["/var/ossec/logs/alerts/", "/var/ossec/logs/archives/"]
	// +optional
	Paths []string `json:"paths,omitempty"`

	// Image is the kubectl image to use for the CronJob
	// Default: "bitnami/kubectl:latest"
	// +optional
	Image string `json:"image,omitempty"`
}

// WazuhIndexerClusterSpec defines the indexer configuration (inline in WazuhCluster)
// Supports two mutually exclusive modes:
// - Simple mode: Use "replicas" field for a single StatefulSet where all nodes have all roles
// - Advanced mode: Use "nodePools" field for multiple StatefulSets with different roles/configs
type WazuhIndexerClusterSpec struct {
	// Number of indexer replicas (simple mode)
	// Mutually exclusive with NodePools - cannot use both
	// In simple mode, all nodes have all roles (cluster_manager, data, ingest)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas,omitempty"`

	// NodePools defines multiple node groups with different roles/configs (advanced mode)
	// Mutually exclusive with Replicas - cannot use both
	// Each nodePool becomes a separate StatefulSet with its own configuration
	// +optional
	NodePools []IndexerNodePoolSpec `json:"nodePools,omitempty"`

	// Resources for indexer nodes (simple mode only, ignored if nodePools used)
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for indexer nodes (simple mode only, ignored if nodePools used)
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Java options
	// +optional
	// +kubebuilder:default="-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"
	JavaOpts string `json:"javaOpts,omitempty"`

	// Cluster name
	// +optional
	// +kubebuilder:default="wazuh"
	ClusterName string `json:"clusterName,omitempty"`

	// Credentials for indexer
	// +optional
	Credentials *CredentialsSecretRef `json:"credentials,omitempty"`

	// Service configuration
	// +optional
	Service *ServiceSpec `json:"service,omitempty"`

	// Node selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Topology spread constraints for pod scheduling
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Pod Disruption Budget
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// AntiAffinity configures pod anti-affinity rules for indexer pods
	// When enabled, indexer pods are spread across different nodes or zones
	// This helps ensure high availability by preventing all indexers from running on the same node
	// +optional
	AntiAffinity *AntiAffinitySpec `json:"antiAffinity,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// GatewayAPI configuration (alternative to Ingress)
	// +optional
	GatewayAPI *GatewayAPISpec `json:"gatewayAPI,omitempty"`

	// Network policy
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Update strategy
	// +optional
	// +kubebuilder:default="RollingUpdate"
	UpdateStrategy string `json:"updateStrategy,omitempty"`

	// Init containers
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	InitContainers []corev1.Container `json:"initContainers,omitempty"`

	// Environment variables
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Environment variables from ConfigMaps or Secrets
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Security context for the pod
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Security context for the container
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// ClusterSettings defines cluster-level settings to apply via the Cluster Settings API
	// These settings are applied after the cluster is healthy (green/yellow)
	// +optional
	ClusterSettings *ClusterSettingsSpec `json:"clusterSettings,omitempty"`

	// HorizontalPodAutoscaler configuration for automatic scaling
	// Note: HPA for StatefulSet requires careful consideration as OpenSearch
	// needs shard rebalancing after scaling. Use with caution.
	// +optional
	HPA *HPASpec `json:"hpa,omitempty"`

	// Termination grace period in seconds for pods
	// OpenSearch needs time to flush and transfer shards before shutdown
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
}

// WazuhDashboardClusterSpec defines the dashboard configuration (inline in WazuhCluster)
type WazuhDashboardClusterSpec struct {
	// Number of dashboard replicas
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	Replicas int32 `json:"replicas,omitempty"`

	// Resources for dashboard
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Enable SSL
	// +optional
	// +kubebuilder:default=true
	EnableSSL bool `json:"enableSSL,omitempty"`

	// Service configuration
	// +optional
	Service *ServiceSpec `json:"service,omitempty"`

	// Wazuh plugin configuration for the dashboard
	// +optional
	WazuhPlugin *WazuhPluginConfig `json:"wazuhPlugin,omitempty"`

	// Node selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Topology spread constraints for pod scheduling
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Pod Disruption Budget
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// Annotations for the Deployment
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// GatewayAPI configuration (alternative to Ingress)
	// +optional
	GatewayAPI *GatewayAPISpec `json:"gatewayAPI,omitempty"`

	// Network policy
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Environment variables
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Environment variables from ConfigMaps or Secrets
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Security context for the pod
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Security context for the container
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// HorizontalPodAutoscaler configuration for automatic scaling
	// When enabled, the Dashboard will scale based on CPU/memory utilization
	// +optional
	HPA *HPASpec `json:"hpa,omitempty"`

	// Termination grace period in seconds for pods
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
}

// TLSConfig defines TLS configuration
type TLSConfig struct {
	// Enable TLS
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// Certificate configuration
	// +optional
	CertConfig *CertificateConfig `json:"certConfig,omitempty"`

	// Custom certificates
	// +optional
	CustomCerts *CustomCertsConfig `json:"customCerts,omitempty"`

	// HotReload configuration for certificate renewal without pod restart
	// Requires Wazuh >= 4.9.0 (OpenSearch >= 2.13)
	// +optional
	HotReload *HotReloadConfig `json:"hotReload,omitempty"`

	// CAMaintenance configures when CA certificate renewal can trigger cluster restarts
	// CA renewal requires full cluster restart as trust stores need to be reloaded
	// +optional
	CAMaintenance *CAMaintenanceConfig `json:"caMaintenance,omitempty"`
}

// HotReloadConfig defines hot reload behavior for TLS certificates
// Version behavior:
// - Wazuh 4.9.x (OpenSearch 2.13-2.18): Hot reload via config + API call required
// - Wazuh 5.0+ (OpenSearch 2.19+): Fully automatic hot reload via config only
type HotReloadConfig struct {
	// Enable hot reload of TLS certificates without pod restart
	// When enabled, OpenSearch will automatically detect certificate file changes
	// Requires Wazuh >= 4.9.0 (OpenSearch >= 2.13)
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// ForceAPIReload forces the operator to call the reload certificates API
	// even for versions that support automatic reload (OpenSearch >= 2.19)
	// This can be useful if automatic file-based detection doesn't work reliably
	// +optional
	// +kubebuilder:default=false
	ForceAPIReload bool `json:"forceAPIReload,omitempty"`
}

// CAMaintenanceConfig defines maintenance window configuration for CA certificate renewal
// CA renewal requires full cluster restart because trust stores need to be reloaded
// This configuration controls when and how the restart happens
type CAMaintenanceConfig struct {
	// AutoRestart enables automatic cluster restart when CA is renewed
	// If false, operator emits an event and waits for manual intervention
	// +optional
	// +kubebuilder:default=true
	AutoRestart bool `json:"autoRestart,omitempty"`

	// MaintenanceWindows specifies time windows when CA renewal restarts are allowed
	// Format: cron expression for the start of the window
	// If empty, restarts can happen immediately when CA is renewed
	// Example: "0 2 * * 6" allows restarts only on Saturdays at 2 AM
	// +optional
	MaintenanceWindows []MaintenanceWindow `json:"maintenanceWindows,omitempty"`

	// MaxWaitDuration specifies how long to wait for a maintenance window
	// before forcing a restart anyway (to prevent running with an expired CA)
	// Format: duration string (e.g., "7d", "168h")
	// Default: 7d (7 days)
	// +optional
	// +kubebuilder:default="7d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	MaxWaitDuration string `json:"maxWaitDuration,omitempty"`
}

// MaintenanceWindow defines a time window for maintenance operations
type MaintenanceWindow struct {
	// Schedule defines when the maintenance window starts
	// Format: cron expression (e.g., "0 2 * * 6" for Saturdays at 2 AM)
	// +kubebuilder:validation:Required
	Schedule string `json:"schedule"`

	// Duration specifies how long the maintenance window lasts
	// Format: duration string (e.g., "4h", "2h")
	// Default: 4h
	// +optional
	// +kubebuilder:default="4h"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	Duration string `json:"duration,omitempty"`

	// Timezone for the schedule (e.g., "UTC", "Europe/Paris")
	// +optional
	// +kubebuilder:default="UTC"
	Timezone string `json:"timezone,omitempty"`
}

// CertificateConfig defines certificate generation configuration
// Note: CommonName (CN) is auto-generated based on certificate type and cannot be configured:
//   - CA: "<cluster>-ca"
//   - Indexer: "<cluster>-indexer"
//   - Admin: "admin" (required by OpenSearch security plugin)
//   - Dashboard: "<cluster>-dashboard"
//   - Filebeat: "<cluster>-filebeat"
type CertificateConfig struct {
	// Country code (2-letter ISO 3166-1 alpha-2)
	// +optional
	// +kubebuilder:default="US"
	Country string `json:"country,omitempty"`

	// State or Province
	// +optional
	// +kubebuilder:default="California"
	State string `json:"state,omitempty"`

	// Locality (city)
	// +optional
	// +kubebuilder:default="San Francisco"
	Locality string `json:"locality,omitempty"`

	// Organization name
	// +optional
	// +kubebuilder:default="Wazuh"
	Organization string `json:"organization,omitempty"`

	// OrganizationalUnit
	// +optional
	// +kubebuilder:default="Security"
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`

	// Validity for node certificates as a duration string
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// Examples: "365d" (1 year), "24h" (1 day), "30m" (30 minutes)
	// +optional
	// +kubebuilder:default="365d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	Validity string `json:"validity,omitempty"`

	// RenewalThreshold for node certificates as a duration string
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// Examples: "30d", "12h", "30m"
	// Certificates will be renewed when they expire within this duration
	// +optional
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	RenewalThreshold string `json:"renewalThreshold,omitempty"`

	// CAValidity for the Certificate Authority certificate as a duration string
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// Examples: "3650d" (10 years), "730d" (2 years)
	// CA certificates should have longer validity as CA renewal requires pod restart
	// +optional
	// +kubebuilder:default="3650d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	CAValidity string `json:"caValidity,omitempty"`

	// CARenewalThreshold for the Certificate Authority as a duration string
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// Examples: "60d", "24h"
	// CA will be renewed when it expires within this duration
	// +optional
	// +kubebuilder:default="60d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	CARenewalThreshold string `json:"caRenewalThreshold,omitempty"`

	// AdminValidity for admin certificates as a duration string
	// Admin certs are used for OpenSearch security API authentication
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// +optional
	// +kubebuilder:default="365d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	AdminValidity string `json:"adminValidity,omitempty"`

	// AdminRenewalThreshold for admin certificates as a duration string
	// Admin certificates will be renewed when they expire within this duration
	// +optional
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	AdminRenewalThreshold string `json:"adminRenewalThreshold,omitempty"`

	// DashboardValidity for dashboard certificates as a duration string
	// Dashboard certs are used for HTTPS on the Wazuh Dashboard
	// Renewal requires dashboard pod restart
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// +optional
	// +kubebuilder:default="365d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	DashboardValidity string `json:"dashboardValidity,omitempty"`

	// DashboardRenewalThreshold for dashboard certificates as a duration string
	// Dashboard certificates will be renewed when they expire within this duration
	// +optional
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	DashboardRenewalThreshold string `json:"dashboardRenewalThreshold,omitempty"`

	// FilebeatValidity for filebeat certificates as a duration string
	// Filebeat certs are used for TLS between managers and indexer
	// Renewal requires manager pod restart
	// Format: "<value><unit>" where unit is d (days), h (hours), or m (minutes)
	// +optional
	// +kubebuilder:default="365d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	FilebeatValidity string `json:"filebeatValidity,omitempty"`

	// FilebeatRenewalThreshold for filebeat certificates as a duration string
	// Filebeat certificates will be renewed when they expire within this duration
	// +optional
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^\d+[dhm]$`
	FilebeatRenewalThreshold string `json:"filebeatRenewalThreshold,omitempty"`

	// KeyAlgorithm specifies the algorithm for key generation
	// Supported values: RSA (default), ECDSA
	// ECDSA provides smaller keys with equivalent security
	// +optional
	// +kubebuilder:default="RSA"
	// +kubebuilder:validation:Enum=RSA;ECDSA
	KeyAlgorithm string `json:"keyAlgorithm,omitempty"`

	// ECDSACurve specifies the elliptic curve for ECDSA keys
	// Only used when KeyAlgorithm is ECDSA
	// Supported values: P256 (default), P384, P521
	// P256 offers ~128 bits security with best performance
	// P384 offers ~192 bits security with larger keys
	// P521 offers ~256 bits security (highest level, largest keys)
	// +optional
	// +kubebuilder:default="P256"
	// +kubebuilder:validation:Enum=P256;P384;P521
	ECDSACurve string `json:"ecdsaCurve,omitempty"`
}

// CustomCertsConfig defines custom certificate configuration
type CustomCertsConfig struct {
	// CA certificate secret
	CASecretRef *corev1.SecretKeySelector `json:"caSecretRef,omitempty"`

	// Node certificates secret
	NodeSecretRef *corev1.SecretKeySelector `json:"nodeSecretRef,omitempty"`

	// Admin certificates secret
	AdminSecretRef *corev1.SecretKeySelector `json:"adminSecretRef,omitempty"`

	// Filebeat certificates secret
	FilebeatSecretRef *corev1.SecretKeySelector `json:"filebeatSecretRef,omitempty"`
}

// MonitoringConfig defines monitoring configuration
type MonitoringConfig struct {
	// Enable monitoring
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Wazuh exporter configuration
	// +optional
	WazuhExporter *WazuhExporterConfig `json:"wazuhExporter,omitempty"`

	// Indexer exporter configuration
	// +optional
	IndexerExporter *IndexerExporterConfig `json:"indexerExporter,omitempty"`

	// ServiceMonitor configuration
	// +optional
	ServiceMonitor *ServiceMonitorConfig `json:"serviceMonitor,omitempty"`
}

// WazuhExporterConfig defines Wazuh Prometheus exporter configuration
type WazuhExporterConfig struct {
	// Enable Wazuh exporter sidecar
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Image for the exporter
	// +optional
	// +kubebuilder:default="pytoshka/wazuh-prometheus-exporter:latest"
	Image string `json:"image,omitempty"`

	// Port for metrics endpoint
	// +optional
	// +kubebuilder:default=9090
	Port int32 `json:"port,omitempty"`

	// Resources for the exporter container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// API protocol
	// +optional
	// +kubebuilder:default="https"
	APIProtocol string `json:"apiProtocol,omitempty"`

	// Verify SSL certificates
	// +optional
	// +kubebuilder:default=false
	APIVerifySSL bool `json:"apiVerifySSL,omitempty"`

	// Log level
	// +optional
	// +kubebuilder:default="INFO"
	LogLevel string `json:"logLevel,omitempty"`

	// Skip last logs metrics
	// +optional
	SkipLastLogs bool `json:"skipLastLogs,omitempty"`

	// Skip last registered agent metrics
	// +optional
	SkipLastRegisteredAgent bool `json:"skipLastRegisteredAgent,omitempty"`

	// Skip Wazuh API info metrics
	// +optional
	SkipWazuhAPIInfo bool `json:"skipWazuhAPIInfo,omitempty"`
}

// IndexerExporterConfig defines OpenSearch Prometheus exporter configuration
type IndexerExporterConfig struct {
	// Enable OpenSearch Prometheus plugin
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Version of the exporter plugin
	// +optional
	Version string `json:"version,omitempty"`
}

// ServiceMonitorConfig defines ServiceMonitor configuration
type ServiceMonitorConfig struct {
	// Enable ServiceMonitor creation
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Labels for ServiceMonitor
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Scrape interval
	// +optional
	// +kubebuilder:default="30s"
	Interval string `json:"interval,omitempty"`

	// Scrape timeout
	// +optional
	// +kubebuilder:default="10s"
	ScrapeTimeout string `json:"scrapeTimeout,omitempty"`
}

// VolumeExpansionStatus tracks storage expansion progress for all components
type VolumeExpansionStatus struct {
	// IndexerExpansion tracks indexer PVC expansion status
	// +optional
	IndexerExpansion *ComponentExpansionStatus `json:"indexerExpansion,omitempty"`

	// ManagerMasterExpansion tracks manager master PVC expansion status
	// +optional
	ManagerMasterExpansion *ComponentExpansionStatus `json:"managerMasterExpansion,omitempty"`

	// ManagerWorkersExpansion tracks manager workers PVC expansion status
	// +optional
	ManagerWorkersExpansion *ComponentExpansionStatus `json:"managerWorkersExpansion,omitempty"`
}

// ComponentExpansionStatus tracks expansion progress for a single component type
type ComponentExpansionStatus struct {
	// Phase indicates the current expansion phase
	// +kubebuilder:validation:Enum=Pending;InProgress;Completed;Failed
	Phase ExpansionPhase `json:"phase"`

	// RequestedSize is the new requested storage size
	// +optional
	RequestedSize string `json:"requestedSize,omitempty"`

	// CurrentSize is the current actual storage size
	// +optional
	CurrentSize string `json:"currentSize,omitempty"`

	// Message provides details about the expansion status
	// +optional
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when the phase last changed
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`

	// PVCsExpanded lists which PVCs have completed expansion
	// +optional
	PVCsExpanded []string `json:"pvcsExpanded,omitempty"`

	// PVCsPending lists PVCs still pending expansion
	// +optional
	PVCsPending []string `json:"pvcsPending,omitempty"`
}

// RollingRestartStatus tracks quorum-safe rolling restart progress across components
type RollingRestartStatus struct {
	// Indexer rolling restart status
	// +optional
	Indexer *ComponentRollingRestart `json:"indexer,omitempty"`

	// ManagerMaster rolling restart status
	// +optional
	ManagerMaster *ComponentRollingRestart `json:"managerMaster,omitempty"`

	// ManagerWorker rolling restart status
	// +optional
	ManagerWorker *ComponentRollingRestart `json:"managerWorker,omitempty"`

	// InProgress indicates if any component has an active rolling restart
	// +optional
	InProgress bool `json:"inProgress,omitempty"`
}

// ComponentRollingRestart tracks rolling restart progress for a single component
type ComponentRollingRestart struct {
	// Phase is the current rolling restart phase (Idle, InProgress, Complete)
	// +optional
	Phase string `json:"phase,omitempty"`

	// TotalPods is the total number of pods in the component
	// +optional
	TotalPods int32 `json:"totalPods,omitempty"`

	// UpdatedPods is the number of pods already on the target revision
	// +optional
	UpdatedPods int32 `json:"updatedPods,omitempty"`

	// CurrentPod is the name of the pod currently being restarted
	// +optional
	CurrentPod string `json:"currentPod,omitempty"`

	// Message is a human-readable status message
	// +optional
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when the phase last changed
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// StartTime is when the rolling restart started
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
}

// WazuhClusterStatus defines the observed state of WazuhCluster
type WazuhClusterStatus struct {
	// Phase of the cluster
	// +optional
	Phase ClusterPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Manager status
	// +optional
	Manager *ComponentStatus `json:"manager,omitempty"`

	// Indexer status
	// +optional
	Indexer *ComponentStatus `json:"indexer,omitempty"`

	// Dashboard status
	// +optional
	Dashboard *ComponentStatus `json:"dashboard,omitempty"`

	// Security holds security-related status
	// +optional
	Security *SecurityStatus `json:"security,omitempty"`

	// CertificateRollouts tracks pending certificate-related rollouts
	// +optional
	CertificateRollouts *CertificateRolloutStatus `json:"certificateRollouts,omitempty"`

	// Upgrade tracks version upgrade progress
	// +optional
	Upgrade *UpgradeStatus `json:"upgrade,omitempty"`

	// VolumeExpansion tracks storage expansion progress for all components
	// +optional
	VolumeExpansion *VolumeExpansionStatus `json:"volumeExpansion,omitempty"`

	// Drain tracks drain operation status for scale-down operations
	// +optional
	Drain *DrainStatus `json:"drain,omitempty"`

	// RollingRestart tracks quorum-safe rolling restart progress
	// +optional
	RollingRestart *RollingRestartStatus `json:"rollingRestart,omitempty"`

	// Observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Last update time
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Version currently deployed
	// +optional
	Version string `json:"version,omitempty"`
}

// UpgradeStatus tracks version upgrade progress
type UpgradeStatus struct {
	// InProgress indicates if a version upgrade is currently in progress
	// +optional
	InProgress bool `json:"inProgress,omitempty"`

	// FromVersion is the version being upgraded from
	// +optional
	FromVersion string `json:"fromVersion,omitempty"`

	// ToVersion is the version being upgraded to
	// +optional
	ToVersion string `json:"toVersion,omitempty"`

	// StartTime is when the upgrade was initiated
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletedTime is when the upgrade completed
	// +optional
	CompletedTime *metav1.Time `json:"completedTime,omitempty"`

	// ComponentsUpgraded lists components that have been upgraded
	// +optional
	ComponentsUpgraded []string `json:"componentsUpgraded,omitempty"`

	// ComponentsPending lists components that are still pending upgrade
	// +optional
	ComponentsPending []string `json:"componentsPending,omitempty"`
}

// CertificateRolloutStatus tracks pending certificate rollouts
type CertificateRolloutStatus struct {
	// PendingRollouts lists components with pending certificate rollouts
	// +optional
	PendingRollouts []PendingCertRollout `json:"pendingRollouts,omitempty"`

	// LastRolloutTime is when the last rollout was initiated
	// +optional
	LastRolloutTime *metav1.Time `json:"lastRolloutTime,omitempty"`

	// RolloutsInProgress indicates if any rollouts are currently in progress
	// +optional
	RolloutsInProgress bool `json:"rolloutsInProgress,omitempty"`
}

// PendingCertRollout represents a single pending certificate rollout
type PendingCertRollout struct {
	// Component name (e.g., "indexer", "manager-master", "manager-worker", "dashboard")
	Component string `json:"component"`

	// WorkloadName is the name of the StatefulSet or Deployment
	WorkloadName string `json:"workloadName"`

	// WorkloadType is "StatefulSet" or "Deployment"
	WorkloadType string `json:"workloadType"`

	// StartTime when the rollout was initiated
	StartTime metav1.Time `json:"startTime"`

	// Reason for the rollout (e.g., "certificate-renewal", "ca-renewal")
	Reason string `json:"reason,omitempty"`

	// Ready indicates if this specific rollout is complete
	// +optional
	Ready bool `json:"ready,omitempty"`
}

// SecurityStatus holds security-related status information
type SecurityStatus struct {
	// Initialized indicates if security plugin is ready
	// +optional
	Initialized bool `json:"initialized"`

	// InitializationTime is when security became ready
	// +optional
	InitializationTime *metav1.Time `json:"initializationTime,omitempty"`

	// LastSyncTime is when CRDs were last synced
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// DefaultAdminUser is the username of the default admin
	// +optional
	DefaultAdminUser string `json:"defaultAdminUser,omitempty"`

	// DefaultAdminSource indicates where admin comes from (auto/crd)
	// +optional
	DefaultAdminSource string `json:"defaultAdminSource,omitempty"`

	// SyncedUsers count of synced user CRDs
	// +optional
	SyncedUsers int `json:"syncedUsers,omitempty"`

	// SyncedRoles count of synced role CRDs
	// +optional
	SyncedRoles int `json:"syncedRoles,omitempty"`

	// SyncedRoleMappings count of synced role mapping CRDs
	// +optional
	SyncedRoleMappings int `json:"syncedRoleMappings,omitempty"`

	// SyncedTenants count of synced tenant CRDs
	// +optional
	SyncedTenants int `json:"syncedTenants,omitempty"`

	// SyncedActionGroups count of synced action group CRDs
	// +optional
	SyncedActionGroups int `json:"syncedActionGroups,omitempty"`

	// IndexerRestartCount tracks indexer restarts for re-sync detection
	// +optional
	IndexerRestartCount int32 `json:"indexerRestartCount,omitempty"`

	// CredentialsHash is the hash of the last synced credentials secret
	// Used to detect when credentials change and need to be re-synced to OpenSearch
	// +optional
	CredentialsHash string `json:"credentialsHash,omitempty"`
}

// ClusterPhase represents the phase of the cluster
// +kubebuilder:validation:Enum=Pending;Creating;Running;Failed;Updating;Deleting;Upgrading
type ClusterPhase string

const (
	ClusterPhasePending   ClusterPhase = "Pending"
	ClusterPhaseCreating  ClusterPhase = "Creating"
	ClusterPhaseRunning   ClusterPhase = "Running"
	ClusterPhaseFailed    ClusterPhase = "Failed"
	ClusterPhaseUpdating  ClusterPhase = "Updating"
	ClusterPhaseDeleting  ClusterPhase = "Deleting"
	ClusterPhaseUpgrading ClusterPhase = "Upgrading"
)

// ComponentStatus represents the status of a component
type ComponentStatus struct {
	// Phase of the component
	// +optional
	Phase ComponentStatusPhase `json:"phase,omitempty"`

	// Ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Replicas is the current number of replicas
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// DesiredReplicas is the number of replicas requested in the spec
	// +optional
	DesiredReplicas int32 `json:"desiredReplicas,omitempty"`

	// Message
	// +optional
	Message string `json:"message,omitempty"`

	// SpecHash is the hash of the component's spec for change detection
	// +optional
	SpecHash string `json:"specHash,omitempty"`

	// ConfigHash is the hash of the component's ConfigMap for change detection
	// +optional
	ConfigHash string `json:"configHash,omitempty"`

	// AppliedSettingsHash is the hash of successfully applied cluster settings (indexer only)
	// Used for change detection to avoid unnecessary API calls
	// +optional
	AppliedSettingsHash string `json:"appliedSettingsHash,omitempty"`

	// LastReconcileTime is when the component was last reconciled
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// LastChangeType indicates what triggered the last update
	// +optional
	LastChangeType string `json:"lastChangeType,omitempty"`

	// NodePoolStatuses tracks status of each nodePool (advanced mode only)
	// Key is the nodePool name
	// +optional
	NodePoolStatuses map[string]NodePoolStatus `json:"nodePoolStatuses,omitempty"`

	// TopologyMode indicates simple or advanced indexer topology mode
	// "simple" = using replicas field (single StatefulSet)
	// "advanced" = using nodePools field (multiple StatefulSets)
	// +optional
	// +kubebuilder:validation:Enum=simple;advanced
	TopologyMode string `json:"topologyMode,omitempty"`
}

// Condition types
const (
	ConditionTypeReady         = "Ready"
	ConditionTypeProgressing   = "Progressing"
	ConditionTypeDegraded      = "Degraded"
	ConditionTypeAvailable     = "Available"
	ConditionTypeSecurityReady = "SecurityReady"
)

// Security status source constants
const (
	SecuritySourceAuto = "auto"
	SecuritySourceCRD  = "crd"
)

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wc
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Manager",type=string,JSONPath=`.status.manager.phase`
// +kubebuilder:printcolumn:name="Indexer",type=string,JSONPath=`.status.indexer.phase`
// +kubebuilder:printcolumn:name="Dashboard",type=string,JSONPath=`.status.dashboard.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhCluster is the Schema for the wazuhclusters API
type WazuhCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhClusterSpec   `json:"spec,omitempty"`
	Status WazuhClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhClusterList contains a list of WazuhCluster
type WazuhClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhCluster{}, &WazuhClusterList{})
}

// WazuhCluster helper methods for configuration mode detection

// IsInlineMode returns true if the cluster uses inline component specifications
// Inline mode means Manager, Indexer, or Dashboard specs are defined directly in the WazuhCluster
func (c *WazuhCluster) IsInlineMode() bool {
	return c.Spec.Manager != nil ||
		c.Spec.Indexer != nil ||
		c.Spec.Dashboard != nil
}

// IsReferenceMode returns true if the cluster uses component references
// Reference mode means ManagerRef, IndexerRef, or DashboardRef point to separate CRs
func (c *WazuhCluster) IsReferenceMode() bool {
	return c.Spec.ManagerRef != nil ||
		c.Spec.IndexerRef != nil ||
		c.Spec.DashboardRef != nil
}

// IsMixedMode returns true if the cluster mixes inline and reference modes
// Mixed mode is invalid and should be rejected by validation
func (c *WazuhCluster) IsMixedMode() bool {
	return c.IsInlineMode() && c.IsReferenceMode()
}

// WazuhIndexerClusterSpec helper methods for topology mode detection

// IsAdvancedMode returns true if the indexer is using nodePools configuration
func (s *WazuhIndexerClusterSpec) IsAdvancedMode() bool {
	return len(s.NodePools) > 0
}

// IsSimpleMode returns true if the indexer is using simple replicas configuration
func (s *WazuhIndexerClusterSpec) IsSimpleMode() bool {
	return s.Replicas > 0 && len(s.NodePools) == 0
}

// GetTotalReplicas returns total node count across all pools or simple replicas
func (s *WazuhIndexerClusterSpec) GetTotalReplicas() int32 {
	if s.IsAdvancedMode() {
		var total int32
		for _, pool := range s.NodePools {
			total += pool.Replicas
		}
		return total
	}
	return s.Replicas
}

// IsHA returns true if the indexer cluster has enough nodes for high availability (3+)
func (s *WazuhIndexerClusterSpec) IsHA() bool {
	if s == nil {
		return false
	}
	return s.GetTotalReplicas() >= 3
}

// GetClusterManagerPoolNames returns the names of all nodePools with cluster_manager role
func (s *WazuhIndexerClusterSpec) GetClusterManagerPoolNames() []string {
	var names []string
	for _, pool := range s.NodePools {
		if pool.HasClusterManagerRole() {
			names = append(names, pool.Name)
		}
	}
	return names
}

// GetDataPoolNames returns the names of all nodePools with data role
func (s *WazuhIndexerClusterSpec) GetDataPoolNames() []string {
	var names []string
	for _, pool := range s.NodePools {
		if pool.HasDataRole() {
			names = append(names, pool.Name)
		}
	}
	return names
}

// CountClusterManagerNodes returns the total number of cluster_manager nodes across all pools
func (s *WazuhIndexerClusterSpec) CountClusterManagerNodes() int32 {
	var count int32
	for _, pool := range s.NodePools {
		if pool.HasClusterManagerRole() {
			count += pool.Replicas
		}
	}
	return count
}

// CountDataNodes returns the total number of data nodes across all pools
func (s *WazuhIndexerClusterSpec) CountDataNodes() int32 {
	var count int32
	for _, pool := range s.NodePools {
		if pool.HasDataRole() {
			count += pool.Replicas
		}
	}
	return count
}

// GetNodePoolByName returns a nodePool by name, or nil if not found
func (s *WazuhIndexerClusterSpec) GetNodePoolByName(name string) *IndexerNodePoolSpec {
	for i := range s.NodePools {
		if s.NodePools[i].Name == name {
			return &s.NodePools[i]
		}
	}
	return nil
}
