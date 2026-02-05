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

package constants

// Event reasons for Kubernetes events emitted by the operator
const (
	// EventReasonReconcileSuccess indicates successful reconciliation
	EventReasonReconcileSuccess = "ReconcileSuccess"

	// EventReasonReconcileFailed indicates failed reconciliation
	EventReasonReconcileFailed = "ReconcileFailed"

	// EventReasonResourceCreated indicates a resource was created
	EventReasonResourceCreated = "ResourceCreated"

	// EventReasonResourceUpdated indicates a resource was updated
	EventReasonResourceUpdated = "ResourceUpdated"

	// EventReasonResourceDeleted indicates a resource was deleted
	EventReasonResourceDeleted = "ResourceDeleted"

	// EventReasonCertificateRenewed indicates a certificate was renewed
	EventReasonCertificateRenewed = "CertificateRenewed"

	// EventReasonCertificateExpiring indicates a certificate is about to expire
	EventReasonCertificateExpiring = "CertificateExpiring"

	// EventReasonSecurityInitialized indicates security configuration was initialized
	EventReasonSecurityInitialized = "SecurityInitialized"

	// EventReasonSecuritySyncFailed indicates security synchronization failed
	EventReasonSecuritySyncFailed = "SecuritySyncFailed"

	// EventReasonUpgradeStarted indicates a version upgrade has started
	EventReasonUpgradeStarted = "UpgradeStarted"

	// EventReasonUpgradeCompleted indicates a version upgrade completed successfully
	EventReasonUpgradeCompleted = "UpgradeCompleted"

	// EventReasonUpgradeFailed indicates a version upgrade failed
	EventReasonUpgradeFailed = "UpgradeFailed"
)

// Volume expansion event reasons
const (
	// EventReasonVolumeExpansionStarted indicates PVC volume expansion has started
	EventReasonVolumeExpansionStarted = "VolumeExpansionStarted"

	// EventReasonVolumeExpansionCompleted indicates all PVCs have been expanded successfully
	EventReasonVolumeExpansionCompleted = "VolumeExpansionCompleted"

	// EventReasonVolumeExpansionFailed indicates PVC volume expansion failed
	EventReasonVolumeExpansionFailed = "VolumeExpansionFailed"

	// EventReasonStorageClassNotExpandable indicates the StorageClass does not support volume expansion
	EventReasonStorageClassNotExpandable = "StorageClassNotExpandable"

	// EventReasonStorageSizeDecreaseRejected indicates an attempt to decrease storage size was rejected
	// Kubernetes does not support shrinking PVCs natively
	EventReasonStorageSizeDecreaseRejected = "StorageSizeDecreaseRejected"
)

// Filebeat configuration event reasons
const (
	// EventReasonFilebeatConfigCreated indicates Filebeat ConfigMap was created
	EventReasonFilebeatConfigCreated = "FilebeatConfigCreated"

	// EventReasonFilebeatConfigUpdated indicates Filebeat ConfigMap was updated
	EventReasonFilebeatConfigUpdated = "FilebeatConfigUpdated"

	// EventReasonFilebeatConfigFailed indicates Filebeat ConfigMap creation/update failed
	EventReasonFilebeatConfigFailed = "FilebeatConfigFailed"

	// EventReasonTemplateApplied indicates index template configuration was applied
	EventReasonTemplateApplied = "TemplateApplied"

	// EventReasonPipelineApplied indicates ingest pipeline configuration was applied
	EventReasonPipelineApplied = "PipelineApplied"

	// EventReasonCustomTemplateLoaded indicates custom template was loaded from ConfigMap
	EventReasonCustomTemplateLoaded = "CustomTemplateLoaded"

	// EventReasonCustomPipelineLoaded indicates custom pipeline was loaded from ConfigMap
	EventReasonCustomPipelineLoaded = "CustomPipelineLoaded"

	// EventReasonClusterNotFound indicates the referenced WazuhCluster was not found
	EventReasonClusterNotFound = "ClusterNotFound"

	// EventReasonClusterNotReady indicates the referenced WazuhCluster is not ready
	EventReasonClusterNotReady = "ClusterNotReady"
)

// Certificate hot reload event reasons
const (
	// EventReasonCertificateHotReloadStarted indicates certificate hot reload has started
	EventReasonCertificateHotReloadStarted = "CertificateHotReloadStarted"

	// EventReasonCertificateHotReloadSucceeded indicates certificate hot reload completed successfully
	EventReasonCertificateHotReloadSucceeded = "CertificateHotReloadSucceeded"

	// EventReasonCertificateHotReloadFailed indicates certificate hot reload failed
	EventReasonCertificateHotReloadFailed = "CertificateHotReloadFailed"

	// EventReasonCertificateHotReloadSkipped indicates certificate hot reload was skipped
	// (e.g., automatic reload for version 4.12+)
	EventReasonCertificateHotReloadSkipped = "CertificateHotReloadSkipped"

	// EventReasonCertificateHotReloadFallback indicates fallback to rolling restart was triggered
	// because hot reload failed
	EventReasonCertificateHotReloadFallback = "CertificateHotReloadFallback"
)

// CA Certificate lifecycle event reasons
const (
	// EventReasonCARenewing indicates the CA certificate renewal has started
	EventReasonCARenewing = "CARenewing"

	// EventReasonCARenewed indicates the CA certificate was successfully renewed
	EventReasonCARenewed = "CARenewed"

	// EventReasonCARenewalFailed indicates the CA certificate renewal failed
	EventReasonCARenewalFailed = "CARenewalFailed"

	// EventReasonCAExpiring indicates the CA certificate is approaching expiry
	EventReasonCAExpiring = "CAExpiring"
)

// Indexer/Node Certificate lifecycle event reasons
const (
	// EventReasonNodeCertRenewing indicates node certificate renewal has started
	EventReasonNodeCertRenewing = "NodeCertRenewing"

	// EventReasonNodeCertRenewed indicates node certificate was successfully renewed
	EventReasonNodeCertRenewed = "NodeCertRenewed"

	// EventReasonNodeCertRenewalFailed indicates node certificate renewal failed
	EventReasonNodeCertRenewalFailed = "NodeCertRenewalFailed"

	// EventReasonNodeCertExpiring indicates node certificate is approaching expiry
	EventReasonNodeCertExpiring = "NodeCertExpiring"
)

// Admin Certificate lifecycle event reasons
const (
	// EventReasonAdminCertRenewing indicates admin certificate renewal has started
	EventReasonAdminCertRenewing = "AdminCertRenewing"

	// EventReasonAdminCertRenewed indicates admin certificate was successfully renewed
	EventReasonAdminCertRenewed = "AdminCertRenewed"

	// EventReasonAdminCertRenewalFailed indicates admin certificate renewal failed
	EventReasonAdminCertRenewalFailed = "AdminCertRenewalFailed"

	// EventReasonAdminCertExpiring indicates admin certificate is approaching expiry
	EventReasonAdminCertExpiring = "AdminCertExpiring"
)

// Filebeat Certificate lifecycle event reasons
const (
	// EventReasonFilebeatCertRenewing indicates filebeat certificate renewal has started
	EventReasonFilebeatCertRenewing = "FilebeatCertRenewing"

	// EventReasonFilebeatCertRenewed indicates filebeat certificate was successfully renewed
	EventReasonFilebeatCertRenewed = "FilebeatCertRenewed"

	// EventReasonFilebeatCertRenewalFailed indicates filebeat certificate renewal failed
	EventReasonFilebeatCertRenewalFailed = "FilebeatCertRenewalFailed"

	// EventReasonFilebeatCertExpiring indicates filebeat certificate is approaching expiry
	EventReasonFilebeatCertExpiring = "FilebeatCertExpiring"
)

// Dashboard Certificate lifecycle event reasons
const (
	// EventReasonDashboardCertRenewing indicates dashboard certificate renewal has started
	EventReasonDashboardCertRenewing = "DashboardCertRenewing"

	// EventReasonDashboardCertRenewed indicates dashboard certificate was successfully renewed
	EventReasonDashboardCertRenewed = "DashboardCertRenewed"

	// EventReasonDashboardCertRenewalFailed indicates dashboard certificate renewal failed
	EventReasonDashboardCertRenewalFailed = "DashboardCertRenewalFailed"

	// EventReasonDashboardCertExpiring indicates dashboard certificate is approaching expiry
	EventReasonDashboardCertExpiring = "DashboardCertExpiring"
)

// Certificate maintenance window event reasons
const (
	// EventReasonCertMaintenanceScheduled indicates certificate renewal is waiting for maintenance window
	EventReasonCertMaintenanceScheduled = "CertMaintenanceScheduled"

	// EventReasonCertMaintenanceWindowActive indicates a maintenance window is now active
	EventReasonCertMaintenanceWindowActive = "CertMaintenanceWindowActive"

	// EventReasonCertRollingRestartStarted indicates rolling restart has started after cert renewal
	EventReasonCertRollingRestartStarted = "CertRollingRestartStarted"

	// EventReasonCertRollingRestartCompleted indicates rolling restart has completed
	EventReasonCertRollingRestartCompleted = "CertRollingRestartCompleted"

	// EventReasonCertRollingRestartFailed indicates rolling restart failed
	EventReasonCertRollingRestartFailed = "CertRollingRestartFailed"
)

// Configuration change detection event reasons
const (
	// EventReasonConfigChangeDetected indicates a configuration change was detected
	EventReasonConfigChangeDetected = "ConfigChangeDetected"

	// EventReasonEnvFromChanged indicates an EnvFrom reference (ConfigMap/Secret) has changed
	EventReasonEnvFromChanged = "EnvFromChanged"

	// EventReasonTLSConfigChanged indicates TLS configuration has changed
	EventReasonTLSConfigChanged = "TLSConfigChanged"

	// EventReasonCertConfigChanged indicates certificate configuration has changed
	EventReasonCertConfigChanged = "CertConfigChanged"

	// EventReasonSpecHashChanged indicates the spec hash has changed
	EventReasonSpecHashChanged = "SpecHashChanged"

	// EventReasonConfigHashChanged indicates the config hash has changed
	EventReasonConfigHashChanged = "ConfigHashChanged"
)

// Workload recreation event reasons
const (
	// EventReasonWorkloadRecreating indicates a workload was deleted due to immutable field changes
	// and will be re-created on the next reconciliation cycle
	EventReasonWorkloadRecreating = "WorkloadRecreating"
)

// Certificate propagation event reasons
const (
	// EventReasonCertificatePropagationWait indicates waiting for certificate propagation to pods
	EventReasonCertificatePropagationWait = "CertificatePropagationWait"

	// EventReasonCertificatePropagationComplete indicates certificate propagation completed
	EventReasonCertificatePropagationComplete = "CertificatePropagationComplete"

	// EventReasonCertificatePropagationTimeout indicates certificate propagation timed out
	EventReasonCertificatePropagationTimeout = "CertificatePropagationTimeout"

	// EventReasonPodCertSyncStarted indicates pod certificate sync verification started
	EventReasonPodCertSyncStarted = "PodCertSyncStarted"

	// EventReasonPodCertSyncComplete indicates all pods have synced certificates
	EventReasonPodCertSyncComplete = "PodCertSyncComplete"

	// EventReasonPodCertSyncFailed indicates some pods failed to sync certificates
	EventReasonPodCertSyncFailed = "PodCertSyncFailed"
)
