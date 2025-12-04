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
