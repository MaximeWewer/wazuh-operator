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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// OpenSearchClusterStatus reports the reconciliation state for one target
// OpenSearch cluster of a multi-cluster CR (User, Role, Tenant, etc.).
// The aggregate Status.Phase reflects the worst case across entries.
type OpenSearchClusterStatus struct {
	// Name of the target WazuhCluster
	Name string `json:"name"`

	// Namespace of the target WazuhCluster
	Namespace string `json:"namespace"`

	// Phase on this cluster (Pending, Ready, Failed, Conflict)
	// +optional
	Phase OpenSearchResourcePhase `json:"phase,omitempty"`

	// LastSyncTime is the last time the resource was synced to this cluster
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastAppliedHash is the hash of the last spec applied to this cluster
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Message provides additional information about this cluster's state
	// +optional
	Message string `json:"message,omitempty"`
}

// ClusterSettingsSpec defines cluster-level OpenSearch settings applied via the Cluster Settings API
type ClusterSettingsSpec struct {
	// Persistent settings survive cluster restarts
	// Common settings: cluster.routing.allocation.enable, indices.recovery.max_bytes_per_sec
	// +optional
	Persistent map[string]string `json:"persistent,omitempty"`

	// Transient settings are cleared on cluster restart
	// Useful for temporary maintenance settings
	// +optional
	Transient map[string]string `json:"transient,omitempty"`
}

// WazuhPluginConfig defines Wazuh plugin configuration for the OpenSearch Dashboard
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

// WazuhChecksConfig defines health check settings
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

// WazuhCronStatisticsConfig defines cron statistics settings
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

// DefaultAPIEndpointConfig defines the default API endpoint configuration
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
