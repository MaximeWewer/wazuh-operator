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

import "time"

// Snapshot repository type constants
// Note: S3 type requires repository-s3 plugin to be installed in OpenSearch
// See: https://docs.opensearch.org/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/#amazon-s3
const (
	// RepositoryTypeS3 is the S3 repository type (including MinIO)
	// Requires repository-s3 plugin
	RepositoryTypeS3 = "s3"

	// RepositoryTypeAzure is the Azure Blob Storage repository type
	// Requires repository-azure plugin
	RepositoryTypeAzure = "azure"

	// RepositoryTypeFS is the filesystem repository type (shared storage required)
	RepositoryTypeFS = "fs"
)

// Repository phase constants
const (
	// RepositoryPhasePending indicates the repository is pending creation
	RepositoryPhasePending = "Pending"

	// RepositoryPhaseCreating indicates the repository is being created
	RepositoryPhaseCreating = "Creating"

	// RepositoryPhaseVerifying indicates the repository is being verified
	RepositoryPhaseVerifying = "Verifying"

	// RepositoryPhaseReady indicates the repository is ready for use
	RepositoryPhaseReady = "Ready"

	// RepositoryPhaseFailed indicates the repository failed to create or verify
	RepositoryPhaseFailed = "Failed"

	// RepositoryPhaseDeleting indicates the repository is being deleted
	RepositoryPhaseDeleting = "Deleting"
)

// Snapshot phase constants
const (
	// SnapshotPhasePending indicates the snapshot is pending
	SnapshotPhasePending = "Pending"

	// SnapshotPhaseInProgress indicates the snapshot is in progress
	SnapshotPhaseInProgress = "InProgress"

	// SnapshotPhaseCompleted indicates the snapshot completed successfully
	SnapshotPhaseCompleted = "Completed"

	// SnapshotPhaseFailed indicates the snapshot failed
	SnapshotPhaseFailed = "Failed"

	// SnapshotPhasePartial indicates the snapshot completed with some failures
	SnapshotPhasePartial = "Partial"
)

// OpenSearch snapshot state constants (from OpenSearch API)
const (
	// OpenSearchSnapshotStateInProgress indicates snapshot is in progress
	OpenSearchSnapshotStateInProgress = "IN_PROGRESS"

	// OpenSearchSnapshotStateSuccess indicates snapshot completed successfully
	OpenSearchSnapshotStateSuccess = "SUCCESS"

	// OpenSearchSnapshotStateFailed indicates snapshot failed
	OpenSearchSnapshotStateFailed = "FAILED"

	// OpenSearchSnapshotStatePartial indicates snapshot completed with some failures
	OpenSearchSnapshotStatePartial = "PARTIAL"
)

// Restore phase constants
const (
	// RestorePhasePending indicates the restore is pending
	RestorePhasePending = "Pending"

	// RestorePhaseValidating indicates the restore is validating the snapshot
	RestorePhaseValidating = "Validating"

	// RestorePhaseInProgress indicates the restore is in progress
	RestorePhaseInProgress = "InProgress"

	// RestorePhaseCompleted indicates the restore completed successfully
	RestorePhaseCompleted = "Completed"

	// RestorePhaseFailed indicates the restore failed
	RestorePhaseFailed = "Failed"
)

// Wazuh backup phase constants
const (
	// WazuhBackupPhasePending indicates the backup configuration is pending
	WazuhBackupPhasePending = "Pending"

	// WazuhBackupPhaseActive indicates the backup is active and scheduled
	WazuhBackupPhaseActive = "Active"

	// WazuhBackupPhaseSuspended indicates the backup is suspended
	WazuhBackupPhaseSuspended = "Suspended"

	// WazuhBackupPhaseFailed indicates the backup configuration failed
	WazuhBackupPhaseFailed = "Failed"
)

// Wazuh restore phase constants
const (
	// WazuhRestorePhasePending indicates the restore is pending
	WazuhRestorePhasePending = "Pending"

	// WazuhRestorePhaseValidating indicates validating source backup
	WazuhRestorePhaseValidating = "Validating"

	// WazuhRestorePhaseStopping indicates stopping the manager
	WazuhRestorePhaseStopping = "Stopping"

	// WazuhRestorePhaseBackingUp indicates creating pre-restore backup
	WazuhRestorePhaseBackingUp = "BackingUp"

	// WazuhRestorePhaseRestoring indicates restoring data
	WazuhRestorePhaseRestoring = "Restoring"

	// WazuhRestorePhaseStarting indicates starting the manager
	WazuhRestorePhaseStarting = "Starting"

	// WazuhRestorePhaseCompleted indicates the restore completed
	WazuhRestorePhaseCompleted = "Completed"

	// WazuhRestorePhaseFailed indicates the restore failed
	WazuhRestorePhaseFailed = "Failed"
)

// Backup info status constants
const (
	// BackupStatusSuccess indicates the backup succeeded
	BackupStatusSuccess = "Success"

	// BackupStatusFailed indicates the backup failed
	BackupStatusFailed = "Failed"
)

// Default timeout values
const (
	// DefaultBackupTimeout is the default timeout for backup operations
	DefaultBackupTimeout = 30 * time.Minute

	// DefaultRestoreTimeout is the default timeout for restore operations
	DefaultRestoreTimeout = 30 * time.Minute

	// DefaultSnapshotWaitTimeout is the default timeout for snapshot completion
	DefaultSnapshotWaitTimeout = 1 * time.Hour

	// DefaultRepositoryVerifyTimeout is the timeout for repository verification
	DefaultRepositoryVerifyTimeout = 5 * time.Minute
)

// Default retention values
const (
	// DefaultBackupRetentionMaxBackups is the default max backups to retain
	DefaultBackupRetentionMaxBackups int32 = 14

	// DefaultBackupRetentionMaxAge is the default max age for backups
	DefaultBackupRetentionMaxAge = "30d"
)

// Backup event reasons
const (
	// BackupEventReasonCreated is emitted when a backup resource is created
	BackupEventReasonCreated = "BackupCreated"

	// BackupEventReasonStarted is emitted when a backup operation starts
	BackupEventReasonStarted = "BackupStarted"

	// BackupEventReasonCompleted is emitted when a backup completes successfully
	BackupEventReasonCompleted = "BackupCompleted"

	// BackupEventReasonFailed is emitted when a backup fails
	BackupEventReasonFailed = "BackupFailed"

	// BackupEventReasonScheduled is emitted when a CronJob is created/updated
	BackupEventReasonScheduled = "BackupScheduled"

	// BackupEventReasonRetentionApplied is emitted when old backups are cleaned up
	BackupEventReasonRetentionApplied = "RetentionApplied"
)

// Restore event reasons
const (
	// RestoreEventReasonStarted is emitted when a restore starts
	RestoreEventReasonStarted = "RestoreStarted"

	// RestoreEventReasonCompleted is emitted when a restore completes
	RestoreEventReasonCompleted = "RestoreCompleted"

	// RestoreEventReasonFailed is emitted when a restore fails
	RestoreEventReasonFailed = "RestoreFailed"

	// RestoreEventReasonValidationFailed is emitted when source validation fails
	RestoreEventReasonValidationFailed = "RestoreValidationFailed"

	// RestoreEventReasonPreRestoreBackup is emitted when pre-restore backup is created
	RestoreEventReasonPreRestoreBackup = "PreRestoreBackup"
)

// Repository event reasons
const (
	// RepositoryEventReasonCreated is emitted when a repository is created
	RepositoryEventReasonCreated = "RepositoryCreated"

	// RepositoryEventReasonVerified is emitted when a repository is verified
	RepositoryEventReasonVerified = "RepositoryVerified"

	// RepositoryEventReasonVerificationFailed is emitted when verification fails
	RepositoryEventReasonVerificationFailed = "RepositoryVerificationFailed"

	// RepositoryEventReasonDeleted is emitted when a repository is deleted
	RepositoryEventReasonDeleted = "RepositoryDeleted"
)

// Snapshot event reasons
const (
	// SnapshotEventReasonCreated is emitted when a snapshot is created
	SnapshotEventReasonCreated = "SnapshotCreated"

	// SnapshotEventReasonCompleted is emitted when a snapshot completes
	SnapshotEventReasonCompleted = "SnapshotCompleted"

	// SnapshotEventReasonFailed is emitted when a snapshot fails
	SnapshotEventReasonFailed = "SnapshotFailed"
)

// Condition types for backup/restore CRDs
const (
	// ConditionTypeRepositoryReady indicates the repository is ready
	ConditionTypeRepositoryReady = "RepositoryReady"

	// ConditionTypeSnapshotComplete indicates the snapshot is complete
	ConditionTypeSnapshotComplete = "SnapshotComplete"

	// ConditionTypeRestoreComplete indicates the restore is complete
	ConditionTypeRestoreComplete = "RestoreComplete"

	// ConditionTypeBackupScheduled indicates the backup CronJob is scheduled
	ConditionTypeBackupScheduled = "BackupScheduled"

	// ConditionTypeCredentialsValid indicates credentials are valid
	ConditionTypeCredentialsValid = "CredentialsValid"
)

// Finalizer names
const (
	// RepositoryFinalizer is the finalizer for OpenSearchSnapshotRepository
	RepositoryFinalizer = "opensearchsnapshotrepository.resources.wazuh.com/finalizer"

	// SnapshotFinalizer is the finalizer for OpenSearchSnapshot
	SnapshotFinalizer = "opensearchsnapshot.resources.wazuh.com/finalizer"

	// WazuhBackupFinalizer is the finalizer for WazuhBackup
	WazuhBackupFinalizer = "wazuhbackup.wazuh.com/finalizer"
)

// Default credential Secret keys
const (
	// DefaultAccessKeyKey is the default Secret key for access key ID
	DefaultAccessKeyKey = "access-key"

	// DefaultSecretKeyKey is the default Secret key for secret access key
	DefaultSecretKeyKey = "secret-key"
)

// Backup Job/CronJob naming
const (
	// BackupJobNameSuffix is the suffix for backup Job names
	BackupJobNameSuffix = "-backup"

	// BackupCronJobNameSuffix is the suffix for backup CronJob names
	BackupCronJobNameSuffix = "-backup"

	// RestoreJobNameSuffix is the suffix for restore Job names
	RestoreJobNameSuffix = "-restore"
)

// Backup container names
const (
	// BackupContainerName is the name of the backup container
	BackupContainerName = "backup"

	// RestoreContainerName is the name of the restore container
	RestoreContainerName = "restore"
)

// Default index patterns for Wazuh
var (
	// DefaultWazuhSnapshotIndices are the default indices to snapshot
	DefaultWazuhSnapshotIndices = []string{
		"wazuh-alerts-*",
		"wazuh-archives-*",
		"wazuh-monitoring-*",
		"wazuh-statistics-*",
	}
)

// Default backup image
const (
	// DefaultBackupImage is the default image for backup jobs
	// This image should include aws-cli, kubectl, and tar
	DefaultBackupImage = "amazon/aws-cli:2.15.0"
)

// Wazuh backup paths for component-based backups
const (
	// WazuhBackupPathAgentKeys is the path to agent registration keys (client.keys)
	WazuhBackupPathAgentKeys = "/var/ossec/etc/client.keys"

	// WazuhBackupPathFIMDatabase is the path to FIM database
	WazuhBackupPathFIMDatabase = "/var/ossec/queue/fim/db/"

	// WazuhBackupPathAgentDatabase is the path to agent databases
	WazuhBackupPathAgentDatabase = "/var/ossec/queue/db/"

	// WazuhBackupPathIntegrations is the path to integration scripts
	WazuhBackupPathIntegrations = "/var/ossec/integrations/"

	// WazuhBackupPathAlertLogs is the path to alert logs
	WazuhBackupPathAlertLogs = "/var/ossec/logs/alerts/"
)
