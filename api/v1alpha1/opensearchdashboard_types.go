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

// OpenSearchDashboardSpec defines the desired state of OpenSearchDashboard
type OpenSearchDashboardSpec struct {
	// Version of OpenSearch Dashboards to deploy
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+\.[0-9]+$`
	Version string `json:"version"`

	// Reference to a WazuhCluster (optional)
	// +optional
	ClusterRef string `json:"clusterRef,omitempty"`

	// Reference to the OpenSearchIndexer to connect to
	// +kubebuilder:validation:Required
	IndexerRef string `json:"indexerRef"`

	// Number of dashboard replicas
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
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

	// Environment variables to add to the container
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

	// Image pull secrets for private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Wazuh plugin configuration
	// +optional
	WazuhPlugin *WazuhPluginConfig `json:"wazuhPlugin,omitempty"`

	// Custom dashboards configuration
	// +optional
	Config *DashboardConfigSpec `json:"config,omitempty"`
}

// WazuhPluginConfig defines Wazuh plugin configuration for the dashboard
// Corresponds to /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
type WazuhPluginConfig struct {
	// Enable Wazuh plugin
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Default API endpoint configuration (used when apiEndpoints is empty)
	// This allows configuring the default Wazuh Manager API connection with credentials from a secret
	// +optional
	DefaultAPIEndpoint *DefaultAPIEndpointConfig `json:"defaultApiEndpoint,omitempty"`

	// Wazuh API endpoints (manager URLs) - hosts configuration
	// If specified, overrides defaultApiEndpoint
	// +optional
	APIEndpoints []WazuhAPIEndpoint `json:"apiEndpoints,omitempty"`

	// Default index pattern to use on the Wazuh dashboard
	// +optional
	// +kubebuilder:default="wazuh-alerts-*"
	Pattern string `json:"pattern,omitempty"`

	// Maximum milliseconds for API responses (minimum: 1500)
	// +optional
	// +kubebuilder:default=20000
	// +kubebuilder:validation:Minimum=1500
	Timeout int32 `json:"timeout,omitempty"`

	// User ability to change index pattern from menu
	// +optional
	// +kubebuilder:default=true
	IPSelector bool `json:"ipSelector,omitempty"`

	// Index pattern names disabled from availability
	// +optional
	IPIgnore []string `json:"ipIgnore,omitempty"`

	// Display/hide manager alerts in visualizations
	// +optional
	// +kubebuilder:default=false
	HideManagerAlerts bool `json:"hideManagerAlerts,omitempty"`

	// Sample alert index name prefix
	// +optional
	// +kubebuilder:default="wazuh-alerts-4.x-"
	AlertsSamplePrefix string `json:"alertsSamplePrefix,omitempty"`

	// Registration server for agent enrollment
	// +optional
	EnrollmentDNS string `json:"enrollmentDns,omitempty"`

	// Authentication password during enrollment
	// +optional
	EnrollmentPassword string `json:"enrollmentPassword,omitempty"`

	// Index prefix for predefined cron jobs
	// +optional
	// +kubebuilder:default="wazuh"
	CronPrefix string `json:"cronPrefix,omitempty"`

	// Enable/disable update check service
	// +optional
	// +kubebuilder:default=false
	UpdatesDisabled bool `json:"updatesDisabled,omitempty"`

	// Monitoring configuration
	// +optional
	Monitoring *WazuhMonitoringConfig `json:"monitoring,omitempty"`

	// Health check configuration
	// +optional
	Checks *WazuhChecksConfig `json:"checks,omitempty"`

	// Cron statistics configuration
	// +optional
	CronStatistics *WazuhCronStatisticsConfig `json:"cronStatistics,omitempty"`
}

// WazuhMonitoringConfig defines Wazuh monitoring settings
type WazuhMonitoringConfig struct {
	// Enable agent connection states visualization
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// API request frequency in seconds (minimum: 60)
	// +optional
	// +kubebuilder:default=900
	// +kubebuilder:validation:Minimum=60
	Frequency int32 `json:"frequency,omitempty"`

	// Index pattern for monitoring tasks
	// +optional
	// +kubebuilder:default="wazuh-monitoring-*"
	Pattern string `json:"pattern,omitempty"`

	// Index creation interval (h=hourly, d=daily, w=weekly, m=monthly)
	// +optional
	// +kubebuilder:default="w"
	// +kubebuilder:validation:Enum=h;d;w;m
	Creation string `json:"creation,omitempty"`

	// Shard count for monitoring indices
	// +optional
	// +kubebuilder:default=1
	Shards int32 `json:"shards,omitempty"`

	// Replica count for monitoring indices
	// +optional
	// +kubebuilder:default=0
	Replicas int32 `json:"replicas,omitempty"`
}

// WazuhChecksConfig defines Wazuh health check settings
type WazuhChecksConfig struct {
	// Validate index patterns on dashboard load
	// +optional
	// +kubebuilder:default=true
	Pattern bool `json:"pattern,omitempty"`

	// Verify index template validity
	// +optional
	// +kubebuilder:default=true
	Template bool `json:"template,omitempty"`

	// Test Wazuh server API connectivity
	// +optional
	// +kubebuilder:default=true
	API bool `json:"api,omitempty"`

	// Confirm version compatibility
	// +optional
	// +kubebuilder:default=true
	Setup bool `json:"setup,omitempty"`

	// Verify mapped document fields
	// +optional
	// +kubebuilder:default=true
	Fields bool `json:"fields,omitempty"`

	// Check special metadata fields
	// +optional
	// +kubebuilder:default=true
	MetaFields bool `json:"metaFields,omitempty"`

	// Ensure time range is configured
	// +optional
	// +kubebuilder:default=true
	TimeFilter bool `json:"timeFilter,omitempty"`

	// Verify aggregation bucket limits
	// +optional
	// +kubebuilder:default=true
	MaxBuckets bool `json:"maxBuckets,omitempty"`
}

// WazuhCronStatisticsConfig defines Wazuh cron statistics settings
type WazuhCronStatisticsConfig struct {
	// Enable/disable statistics task execution
	// +optional
	// +kubebuilder:default=true
	Status bool `json:"status,omitempty"`

	// Specific API hosts for statistics
	// +optional
	APIs []string `json:"apis,omitempty"`

	// Cron schedule expression
	// +optional
	// +kubebuilder:default="0 */5 * * * *"
	Interval string `json:"interval,omitempty"`

	// Statistics index destination
	// +optional
	// +kubebuilder:default="statistics"
	IndexName string `json:"indexName,omitempty"`

	// Statistics index creation interval (h=hourly, d=daily, w=weekly, m=monthly)
	// +optional
	// +kubebuilder:default="w"
	// +kubebuilder:validation:Enum=h;d;w;m
	IndexCreation string `json:"indexCreation,omitempty"`

	// Statistics index shard count
	// +optional
	// +kubebuilder:default=1
	Shards int32 `json:"shards,omitempty"`

	// Statistics index replica count
	// +optional
	// +kubebuilder:default=0
	Replicas int32 `json:"replicas,omitempty"`
}

// DefaultAPIEndpointConfig defines the default Wazuh API endpoint configuration
// Used when no explicit apiEndpoints are defined
type DefaultAPIEndpointConfig struct {
	// Credentials from a secret for the default API endpoint
	// The secret should have keys for username and password
	// +optional
	CredentialsSecret *CredentialsSecretRef `json:"credentialsSecret,omitempty"`

	// Port for the Wazuh API (default: 55000)
	// +optional
	// +kubebuilder:default=55000
	Port int32 `json:"port,omitempty"`

	// Run as another user (RBAC)
	// +optional
	// +kubebuilder:default=false
	RunAs bool `json:"runAs,omitempty"`
}

// WazuhAPIEndpoint defines a Wazuh API endpoint for the dashboard plugin
type WazuhAPIEndpoint struct {
	// Endpoint ID (used as the host identifier in wazuh.yml)
	// +kubebuilder:validation:Required
	ID string `json:"id"`

	// Endpoint URL (without port)
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// Endpoint port
	// +kubebuilder:default=55000
	Port int32 `json:"port,omitempty"`

	// Username for authentication (plain text, prefer CredentialsSecretRef)
	// +optional
	// +kubebuilder:default="wazuh-wui"
	Username string `json:"username,omitempty"`

	// Password for authentication (plain text, prefer CredentialsSecretRef)
	// +optional
	Password string `json:"password,omitempty"`

	// Credentials reference from a secret (contains both username and password)
	// The secret should have keys: 'username' and 'password' (or custom keys via usernameKey/passwordKey)
	// +optional
	CredentialsSecretRef *CredentialsSecretRef `json:"credentialsSecretRef,omitempty"`

	// Run as another user (RBAC)
	// +optional
	// +kubebuilder:default=false
	RunAs bool `json:"runAs,omitempty"`
}

// DashboardConfigSpec defines custom dashboard configuration
type DashboardConfigSpec struct {
	// Custom opensearch_dashboards.yml content
	// +optional
	DashboardsYml string `json:"dashboardsYml,omitempty"`

	// Base path for the dashboard
	// +optional
	BasePath string `json:"basePath,omitempty"`

	// Default route
	// +optional
	// +kubebuilder:default="/app/wazuh"
	DefaultRoute string `json:"defaultRoute,omitempty"`
}

// OpenSearchDashboardStatus defines the observed state of OpenSearchDashboard
type OpenSearchDashboardStatus struct {
	// Phase of the dashboard
	// +optional
	Phase ComponentPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Total replicas
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Last update time
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Version currently deployed
	// +optional
	Version string `json:"version,omitempty"`

	// Message provides additional information
	// +optional
	Message string `json:"message,omitempty"`

	// URL to access the dashboard
	// +optional
	URL string `json:"url,omitempty"`

	// Connected to indexer
	// +optional
	IndexerConnected bool `json:"indexerConnected,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osdash
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.status.replicas`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.status.url`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchDashboard is the Schema for the opensearchdashboards API
type OpenSearchDashboard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchDashboardSpec   `json:"spec,omitempty"`
	Status OpenSearchDashboardStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchDashboardList contains a list of OpenSearchDashboard
type OpenSearchDashboardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchDashboard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchDashboard{}, &OpenSearchDashboardList{})
}
