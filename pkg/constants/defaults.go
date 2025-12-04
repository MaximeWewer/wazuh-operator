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

import (
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

// Default version strings
const (
	// DefaultWazuhVersion is the default Wazuh version
	// This is the single source of truth for version defaults
	// All other version defaults (OpenSearch, plugins) are derived from this
	DefaultWazuhVersion = "4.9.0"
)

// GetDefaultOpenSearchVersion returns the default OpenSearch version
// corresponding to the DefaultWazuhVersion
func GetDefaultOpenSearchVersion() string {
	version, err := utils.GetOpenSearchVersionFromWazuh(DefaultWazuhVersion)
	if err != nil {
		// Fallback for safety - should never happen with valid DefaultWazuhVersion
		return "2.13.0"
	}
	return version
}

// GetDefaultPrometheusExporterPluginVersion returns the default OpenSearch
// Prometheus exporter plugin version corresponding to the DefaultWazuhVersion
func GetDefaultPrometheusExporterPluginVersion() string {
	version, err := utils.GetPrometheusExporterPluginVersion(DefaultWazuhVersion)
	if err != nil {
		// Fallback for safety - should never happen with valid DefaultWazuhVersion
		return "2.13.0.0"
	}
	return version
}

// GetOpenSearchVersionForWazuh returns the OpenSearch version for a given Wazuh version
// This is a convenience wrapper for use in the constants package
func GetOpenSearchVersionForWazuh(wazuhVersion string) string {
	version, err := utils.GetOpenSearchVersionFromWazuh(wazuhVersion)
	if err != nil {
		// Fallback to default if version is not found
		return GetDefaultOpenSearchVersion()
	}
	return version
}

// GetPrometheusExporterPluginVersionForWazuh returns the Prometheus exporter plugin version
// for a given Wazuh version
func GetPrometheusExporterPluginVersionForWazuh(wazuhVersion string) string {
	version, err := utils.GetPrometheusExporterPluginVersion(wazuhVersion)
	if err != nil {
		// Fallback to default if version is not found
		return GetDefaultPrometheusExporterPluginVersion()
	}
	return version
}

// GetVersionInfo returns complete version information for a given Wazuh version
// Returns nil if the version is not supported
func GetVersionInfo(wazuhVersion string) *utils.WazuhVersionInfo {
	info, err := utils.GetWazuhVersionInfo(wazuhVersion)
	if err != nil {
		return nil
	}
	return info
}

// Default replica counts
const (
	// DefaultManagerMasterReplicas is always 1 (single master)
	DefaultManagerMasterReplicas int32 = 1

	// DefaultManagerWorkerReplicas is the default number of worker nodes
	DefaultManagerWorkerReplicas int32 = 2

	// DefaultIndexerReplicas is the default number of indexer nodes
	DefaultIndexerReplicas int32 = 3

	// DefaultDashboardReplicas is the default number of dashboard replicas
	DefaultDashboardReplicas int32 = 1
)

// Default storage sizes
const (
	// DefaultManagerStorageSize is the default storage for manager nodes
	DefaultManagerStorageSize = "10Gi"

	// DefaultWorkerStorageSize is the default storage for worker nodes
	DefaultWorkerStorageSize = "10Gi"

	// DefaultIndexerStorageSize is the default storage for indexer nodes
	DefaultIndexerStorageSize = "10Gi"
)

// Default JVM options
const (
	// DefaultIndexerJavaOpts is the default JVM options for indexer
	DefaultIndexerJavaOpts = "-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"
)

// Default resource requirements
const (
	// DefaultManagerCPURequest is the default CPU request for manager
	DefaultManagerCPURequest = "500m"

	// DefaultManagerMemoryRequest is the default memory request for manager
	DefaultManagerMemoryRequest = "512Mi"

	// DefaultManagerCPULimit is the default CPU limit for manager
	DefaultManagerCPULimit = "1000m"

	// DefaultManagerMemoryLimit is the default memory limit for manager
	DefaultManagerMemoryLimit = "1Gi"

	// DefaultIndexerCPURequest is the default CPU request for indexer
	DefaultIndexerCPURequest = "500m"

	// DefaultIndexerMemoryRequest is the default memory request for indexer
	DefaultIndexerMemoryRequest = "1Gi"

	// DefaultIndexerCPULimit is the default CPU limit for indexer
	DefaultIndexerCPULimit = "1000m"

	// DefaultIndexerMemoryLimit is the default memory limit for indexer
	DefaultIndexerMemoryLimit = "2Gi"

	// DefaultDashboardCPURequest is the default CPU request for dashboard
	DefaultDashboardCPURequest = "250m"

	// DefaultDashboardMemoryRequest is the default memory request for dashboard
	DefaultDashboardMemoryRequest = "512Mi"

	// DefaultDashboardCPULimit is the default CPU limit for dashboard
	DefaultDashboardCPULimit = "500m"

	// DefaultDashboardMemoryLimit is the default memory limit for dashboard
	DefaultDashboardMemoryLimit = "1Gi"

	// DefaultInitContainerCPURequest is the default CPU request for init containers
	DefaultInitContainerCPURequest = "100m"

	// DefaultInitContainerMemoryRequest is the default memory request for init containers
	DefaultInitContainerMemoryRequest = "128Mi"

	// DefaultInitContainerCPULimit is the default CPU limit for init containers
	DefaultInitContainerCPULimit = "200m"

	// DefaultInitContainerMemoryLimit is the default memory limit for init containers
	DefaultInitContainerMemoryLimit = "256Mi"

	// DefaultExporterCPURequest is the default CPU request for exporter sidecars
	DefaultExporterCPURequest = "100m"

	// DefaultExporterMemoryRequest is the default memory request for exporter sidecars
	DefaultExporterMemoryRequest = "128Mi"

	// DefaultExporterCPULimit is the default CPU limit for exporter sidecars
	DefaultExporterCPULimit = "200m"

	// DefaultExporterMemoryLimit is the default memory limit for exporter sidecars
	DefaultExporterMemoryLimit = "256Mi"
)

// Certificate defaults
const (
	// DefaultCertificateValidity is the default certificate validity period
	DefaultCertificateValidity = 365 * 24 * time.Hour // 1 year

	// DefaultCertificateRenewalBefore is the time before expiry to renew
	DefaultCertificateRenewalBefore = 30 * 24 * time.Hour // 30 days

	// DefaultCAValidity is the CA certificate validity
	DefaultCAValidity = 10 * 365 * 24 * time.Hour // 10 years
)

// Reconciliation defaults
const (
	// DefaultReconcileInterval is the default interval between reconciliations
	DefaultReconcileInterval = 30 * time.Second

	// DefaultRequeueAfter is the default requeue duration after success
	DefaultRequeueAfter = 5 * time.Minute

	// DefaultErrorRequeueAfter is the default requeue duration after error
	DefaultErrorRequeueAfter = 30 * time.Second

	// DefaultMaxRetries is the maximum number of retries for failed operations
	DefaultMaxRetries = 5
)

// Image registry defaults
const (
	// DefaultWazuhRegistry is the default registry for Wazuh images
	DefaultWazuhRegistry = "wazuh"

	// DefaultWazuhIndexerImage is the default image for Wazuh indexer
	DefaultWazuhIndexerImage = "wazuh/wazuh-indexer"

	// DefaultWazuhDashboardImage is the default image for Wazuh dashboard
	DefaultWazuhDashboardImage = "wazuh/wazuh-dashboard"

	// DefaultWazuhManagerImage is the default image for Wazuh manager
	DefaultWazuhManagerImage = "wazuh/wazuh-manager"
)

// Default credentials
// These are the default usernames used when no custom credentials are provided
// Passwords are ALWAYS generated dynamically for security reasons
const (
	// DefaultWazuhAPIUsername is the default Wazuh API admin username
	// This is also used by the dashboard to authenticate with Wazuh API
	DefaultWazuhAPIUsername = "wazuh"

	// DefaultOpenSearchAdminUsername is the default OpenSearch admin username
	DefaultOpenSearchAdminUsername = "admin"

	// DefaultKibanaServerUsername is the default kibanaserver username for OpenSearch
	DefaultKibanaServerUsername = "kibanaserver"
)

// Log rotation defaults
// These configure the CronJob that cleans up old log files on Manager pods
const (
	// DefaultLogRotationSchedule is the cron expression for log rotation
	// Default: weekly on Monday at midnight
	DefaultLogRotationSchedule = "0 0 * * 1"

	// DefaultLogRotationRetentionDays is the number of days to retain log files
	// Files older than this will be deleted
	DefaultLogRotationRetentionDays int32 = 7

	// DefaultLogRotationCombinationMode defines how age and size filters combine
	// "or" = delete if old OR large (default)
	// "and" = delete only if old AND large
	DefaultLogRotationCombinationMode = "or"

	// DefaultLogRotationImage is the kubectl image used for the CronJob
	DefaultLogRotationImage = "bitnami/kubectl:latest"
)

// Filebeat defaults
// These configure the Filebeat sidecar in Manager pods
const (
	// DefaultFilebeatLoggingLevel is the default Filebeat logging level
	DefaultFilebeatLoggingLevel = "info"

	// DefaultFilebeatLoggingKeepFiles is the default number of log files to retain
	DefaultFilebeatLoggingKeepFiles int32 = 7

	// DefaultFilebeatSSLVerification is the default SSL verification mode
	DefaultFilebeatSSLVerification = "full"

	// DefaultFilebeatIndexPrefix is the default index prefix for Wazuh alerts
	// Note: This is without the trailing dash, used in pipeline configuration
	DefaultFilebeatIndexPrefix = "wazuh-alerts-4.x"

	// DefaultFilebeatTimestampFormat is the default timestamp format for parsing
	DefaultFilebeatTimestampFormat = "ISO8601"

	// DefaultFilebeatTemplateShards is the default number of primary shards
	DefaultFilebeatTemplateShards int32 = 3

	// DefaultFilebeatTemplateReplicas is the default number of replica shards
	DefaultFilebeatTemplateReplicas int32 = 0

	// DefaultFilebeatTemplateRefreshInterval is the default index refresh interval
	DefaultFilebeatTemplateRefreshInterval = "5s"

	// DefaultFilebeatTemplateFieldLimit is the default maximum fields per document
	DefaultFilebeatTemplateFieldLimit int32 = 10000
)

// Protocol constants
const (
	// ProtocolHTTPS is the HTTPS protocol
	ProtocolHTTPS = "https"

	// ProtocolHTTP is the HTTP protocol
	ProtocolHTTP = "http"
)

// DefaultLogRotationPaths are the paths to clean during log rotation
var DefaultLogRotationPaths = []string{
	"/var/ossec/logs/alerts/",
	"/var/ossec/logs/archives/",
}
