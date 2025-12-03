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

package v1alpha1

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
type WazuhIndexerClusterSpec struct {
	// Number of indexer replicas
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas,omitempty"`

	// Resources for indexer nodes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for indexer nodes
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

	// Pod Disruption Budget
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

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
	// +kubebuilder:default=false
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

	// Use cert-manager for certificate management
	// +optional
	CertManager *CertManagerConfig `json:"certManager,omitempty"`

	// Custom certificates
	// +optional
	CustomCerts *CustomCertsConfig `json:"customCerts,omitempty"`

	// HotReload configuration for certificate renewal without pod restart
	// Requires Wazuh >= 4.9.0 (OpenSearch >= 2.13)
	// +optional
	HotReload *HotReloadConfig `json:"hotReload,omitempty"`
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

// CertificateConfig defines certificate generation configuration
type CertificateConfig struct {
	// Country
	// +optional
	// +kubebuilder:default="US"
	Country string `json:"country,omitempty"`

	// State
	// +optional
	// +kubebuilder:default="California"
	State string `json:"state,omitempty"`

	// Locality
	// +optional
	// +kubebuilder:default="California"
	Locality string `json:"locality,omitempty"`

	// Organization
	// +optional
	// +kubebuilder:default="Wazuh"
	Organization string `json:"organization,omitempty"`

	// OrganizationalUnit
	// +optional
	// +kubebuilder:default="Wazuh"
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`

	// CommonName
	// +optional
	// +kubebuilder:default="admin"
	CommonName string `json:"commonName,omitempty"`

	// ValidityDays for node certificates (indexer, dashboard, filebeat, admin)
	// Node certificates can be renewed more frequently without service disruption
	// using OpenSearch's hot reload feature (plugins.security.ssl_cert_reload_enabled)
	// +optional
	// +kubebuilder:default=365
	ValidityDays int `json:"validityDays,omitempty"`

	// RenewalThresholdDays for node certificates
	// Certificates will be renewed when they expire within this many days
	// +optional
	// +kubebuilder:default=30
	RenewalThresholdDays int `json:"renewalThresholdDays,omitempty"`

	// CAValidityDays for the Certificate Authority certificate
	// CA certificates should have longer validity (1-2 years) as CA renewal
	// requires restarting the OpenSearch indexer to reload the trust store
	// +optional
	// +kubebuilder:default=730
	CAValidityDays int `json:"caValidityDays,omitempty"`

	// CARenewalThresholdDays for the Certificate Authority
	// CA will be renewed when it expires within this many days
	// +optional
	// +kubebuilder:default=60
	CARenewalThresholdDays int `json:"caRenewalThresholdDays,omitempty"`
}

// CertManagerConfig defines cert-manager configuration
type CertManagerConfig struct {
	// Enable cert-manager integration
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Issuer name
	// +optional
	IssuerName string `json:"issuerName,omitempty"`

	// Issuer kind
	// +optional
	// +kubebuilder:validation:Enum=Issuer;ClusterIssuer
	IssuerKind string `json:"issuerKind,omitempty"`
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
	Phase string `json:"phase"`

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

// WazuhClusterStatus defines the observed state of WazuhCluster
type WazuhClusterStatus struct {
	// Phase of the cluster
	// +optional
	Phase ClusterPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
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
	Phase string `json:"phase,omitempty"`

	// Ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Total replicas
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Message
	// +optional
	Message string `json:"message,omitempty"`

	// SpecHash is the hash of the component's spec for change detection
	// +optional
	SpecHash string `json:"specHash,omitempty"`

	// ConfigHash is the hash of the component's ConfigMap for change detection
	// +optional
	ConfigHash string `json:"configHash,omitempty"`

	// LastReconcileTime is when the component was last reconciled
	// +optional
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// LastChangeType indicates what triggered the last update
	// +optional
	LastChangeType string `json:"lastChangeType,omitempty"`
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
