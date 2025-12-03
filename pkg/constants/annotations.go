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

// Wazuh operator annotations (wazuh.com/*)
const (
	// AnnotationLastAppliedConfig stores the last applied configuration hash
	AnnotationLastAppliedConfig = "wazuh.com/last-applied-config"

	// AnnotationRestartedAt stores the timestamp when a pod was last restarted
	AnnotationRestartedAt = "wazuh.com/restarted-at"

	// AnnotationManagedBy indicates which CR manages this resource (namespace/name)
	AnnotationManagedBy = "wazuh.com/managed-by"

	// AnnotationOwnership tracks resource ownership for conflict detection
	AnnotationOwnership = "wazuh.com/ownership"

	// AnnotationSecurityConfigUpdated indicates when security config was last synced
	AnnotationSecurityConfigUpdated = "wazuh.com/security-config-updated"

	// AnnotationCertificateExpiry stores certificate expiration timestamp
	AnnotationCertificateExpiry = "wazuh.com/certificate-expiry"

	// AnnotationCertificateRenewalTime stores when certificate should be renewed
	AnnotationCertificateRenewalTime = "wazuh.com/certificate-renewal-time"

	// AnnotationConfigGeneration tracks config version for rolling updates
	AnnotationConfigGeneration = "wazuh.com/config-generation"

	// AnnotationSecretGeneration tracks secret version for cert rotation
	AnnotationSecretGeneration = "wazuh.com/secret-generation"

	// AnnotationPauseReconciliation pauses reconciliation when set to "true"
	AnnotationPauseReconciliation = "wazuh.com/pause-reconciliation"

	// AnnotationRollingRestartTriggered indicates a rolling restart is in progress
	AnnotationRollingRestartTriggered = "wazuh.com/rolling-restart-triggered"

	// AnnotationClusterInitialized indicates cluster initialization is complete
	AnnotationClusterInitialized = "wazuh.com/cluster-initialized"

	// AnnotationSecurityInitialized indicates security config has been applied
	AnnotationSecurityInitialized = "wazuh.com/security-initialized"
)

// OpenSearch specific annotations (opensearch.com/*)
const (
	// AnnotationOpenSearchLastAppliedHash stores the last applied resource hash in OpenSearch
	AnnotationOpenSearchLastAppliedHash = "opensearch.com/last-applied-hash"

	// AnnotationOpenSearchSyncStatus indicates sync status with OpenSearch
	AnnotationOpenSearchSyncStatus = "opensearch.com/sync-status"

	// AnnotationOpenSearchDriftDetected indicates drift was detected
	AnnotationOpenSearchDriftDetected = "opensearch.com/drift-detected"

	// AnnotationOpenSearchConflict indicates resource ownership conflict
	AnnotationOpenSearchConflict = "opensearch.com/conflict"
)

// Resource Patch Detection annotations (wazuh.com/*)
const (
	// AnnotationAppliedGeneration stores the CRD generation when resources were last applied
	AnnotationAppliedGeneration = "wazuh.com/applied-generation"

	// AnnotationSpecHash stores the hash of CRD spec fields that affect this resource
	AnnotationSpecHash = "wazuh.com/spec-hash"

	// AnnotationConfigHash stores the hash of ConfigMap/Secret content for pod restart detection
	AnnotationConfigHash = "wazuh.com/config-hash"

	// NOTE: AnnotationCertHash is defined in labels.go as "wazuh.com/cert-hash"
)

// Prometheus annotations
const (
	// AnnotationPrometheusPort specifies the metrics port
	AnnotationPrometheusPort = "prometheus.io/port"

	// AnnotationPrometheusScrape enables prometheus scraping
	AnnotationPrometheusScrape = "prometheus.io/scrape"

	// AnnotationPrometheusPath specifies the metrics path
	AnnotationPrometheusPath = "prometheus.io/path"
)

// Volume expansion annotations
const (
	// AnnotationRequestedStorageSize tracks the requested storage size for expansion
	// This is used to detect when a storage size change has been requested
	AnnotationRequestedStorageSize = "wazuh.com/requested-storage-size"

	// AnnotationLastExpansionTime tracks when expansion was last requested
	// Format: RFC3339 timestamp
	AnnotationLastExpansionTime = "wazuh.com/last-expansion-time"
)
