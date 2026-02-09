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

// WazuhBackupSpec defines the desired state of WazuhBackup
type WazuhBackupSpec struct {
	// ClusterRef references the WazuhCluster to backup
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Components defines what Wazuh Manager data to backup
	// +kubebuilder:validation:Required
	Components BackupComponents `json:"components"`

	// Schedule is a cron expression for scheduled backups
	// If empty, a one-shot backup Job is created instead of CronJob
	// Example: "0 2 * * *" for daily at 2 AM
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// Retention defines backup retention policy
	// +optional
	Retention *BackupRetention `json:"retention,omitempty"`

	// Storage defines where backups are stored
	// +kubebuilder:validation:Required
	Storage BackupStorage `json:"storage"`

	// Suspend pauses scheduled backups when true
	// Only applies when Schedule is set
	// +kubebuilder:default=false
	Suspend bool `json:"suspend,omitempty"`

	// BackupTimeout is the maximum duration for a backup operation
	// +kubebuilder:default="30m"
	BackupTimeout string `json:"backupTimeout,omitempty"`

	// Image specifies a custom backup container image
	// If not set, uses a default image with mc (MinIO Client), kubectl and tar
	// +optional
	Image *BackupImage `json:"image,omitempty"`

	// Resources for the backup Job/CronJob container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ServiceAccountAnnotations are merged into the backup job ServiceAccount
	// Useful for cloud identity integrations (GKE Workload Identity, AWS IRSA, Azure Workload Identity)
	// +optional
	ServiceAccountAnnotations map[string]string `json:"serviceAccountAnnotations,omitempty"`
}

// BackupComponents defines what Wazuh Manager data to backup
type BackupComponents struct {
	// AgentKeys backs up /var/ossec/etc/client.keys (agent registrations)
	// Critical for agent reconnection after restore
	// +kubebuilder:default=true
	AgentKeys bool `json:"agentKeys,omitempty"`

	// FIMDatabase backs up /var/ossec/queue/fim/db/ (File Integrity Monitoring)
	// Contains FIM state and baselines
	// +kubebuilder:default=true
	FIMDatabase bool `json:"fimDatabase,omitempty"`

	// AgentDatabase backs up /var/ossec/queue/db/ (agent databases)
	// Contains agent state information
	// +kubebuilder:default=true
	AgentDatabase bool `json:"agentDatabase,omitempty"`

	// Integrations backs up /var/ossec/integrations/
	// Contains integration scripts
	// +kubebuilder:default=false
	Integrations bool `json:"integrations,omitempty"`

	// AlertLogs backs up /var/ossec/logs/alerts/
	// Can be large - consider using OpenSearch snapshots instead
	// +kubebuilder:default=false
	AlertLogs bool `json:"alertLogs,omitempty"`

	// CustomPaths allows specifying additional paths to backup
	// Paths must be within /var/ossec/
	// +optional
	CustomPaths []string `json:"customPaths,omitempty"`
}

// BackupRetention defines backup retention policy
type BackupRetention struct {
	// MaxBackups is the maximum number of backups to retain
	// Oldest backups are deleted when this limit is exceeded
	// +kubebuilder:default=14
	MaxBackups int32 `json:"maxBackups,omitempty"`

	// MaxAge is the maximum age of backups to retain
	// Format: number + unit (d=days, w=weeks, m=months)
	// Example: "30d" for 30 days
	// +optional
	MaxAge string `json:"maxAge,omitempty"`
}

// BackupStorage defines where backups are stored
type BackupStorage struct {
	// Type is the storage backend type
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=s3;gcs;azure;hdfs
	Type string `json:"type"`

	// Bucket is the bucket or container name (S3, GCS, Azure)
	// +optional
	Bucket string `json:"bucket,omitempty"`

	// Prefix is the path prefix within the bucket
	// Supports Go templates: {{ .ClusterName }}, {{ .Namespace }}, {{ .Date }}
	// +kubebuilder:default="{{ .ClusterName }}/{{ .Namespace }}"
	Prefix string `json:"prefix,omitempty"`

	// Region is the AWS region (S3 only)
	// +optional
	Region string `json:"region,omitempty"`

	// Endpoint is a custom S3 endpoint (for MinIO)
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ForcePathStyle enables path-style S3 access (required for MinIO)
	// +optional
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// CredentialsSecret references the Secret containing storage credentials
	// Optional for GCS Workload Identity or HDFS simple auth
	// +optional
	CredentialsSecret *RepositoryCredentialsRef `json:"credentialsSecret,omitempty"`

	// GCS contains GCS-specific backup configuration
	// +optional
	GCS *GCSBackupConfig `json:"gcs,omitempty"`

	// Azure contains Azure-specific backup configuration
	// +optional
	Azure *AzureBackupConfig `json:"azure,omitempty"`

	// HDFS contains HDFS-specific backup configuration
	// +optional
	HDFS *HDFSBackupConfig `json:"hdfs,omitempty"`
}

// GCSBackupConfig defines GCS-specific backup storage configuration
type GCSBackupConfig struct {
	// Project is the GCP project ID
	// +optional
	Project string `json:"project,omitempty"`
}

// AzureBackupConfig defines Azure-specific backup storage configuration
type AzureBackupConfig struct {
	// Container is the Azure Blob Storage container name (overrides Bucket)
	// +optional
	Container string `json:"container,omitempty"`

	// AccountName is the Azure Storage account name
	// +optional
	AccountName string `json:"accountName,omitempty"`

	// EndpointSuffix is the Azure endpoint suffix for sovereign clouds
	// +optional
	EndpointSuffix string `json:"endpointSuffix,omitempty"`
}

// HDFSBackupConfig defines HDFS-specific backup storage configuration
type HDFSBackupConfig struct {
	// URI is the HDFS namenode WebHDFS URI
	// Example: "http://namenode:9870/webhdfs/v1"
	// +kubebuilder:validation:Required
	URI string `json:"uri"`

	// Path is the HDFS directory path for backups
	// +kubebuilder:validation:Required
	Path string `json:"path"`
}

// BackupImage specifies the backup container image
type BackupImage struct {
	// Repository is the image repository
	// +optional
	Repository string `json:"repository,omitempty"`

	// Tag is the image tag
	// +optional
	Tag string `json:"tag,omitempty"`

	// PullPolicy is the image pull policy
	// +optional
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}

// WazuhBackupStatus defines the observed state of WazuhBackup
type WazuhBackupStatus struct {
	// Phase is the current phase (Pending, Active, Suspended, Failed)
	// +optional
	Phase BackupPhase `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// LastBackup contains information about the last backup
	// +optional
	LastBackup *BackupInfo `json:"lastBackup,omitempty"`

	// NextScheduledBackup is when the next backup will run
	// Only set for scheduled backups
	// +optional
	NextScheduledBackup *metav1.Time `json:"nextScheduledBackup,omitempty"`

	// BackupHistory contains recent backup results (last N backups)
	// +optional
	BackupHistory []BackupInfo `json:"backupHistory,omitempty"`

	// BackupCount is the total number of backups currently stored
	// +optional
	BackupCount int32 `json:"backupCount,omitempty"`

	// TotalSize is the total size of all backups (human-readable)
	// +optional
	TotalSize string `json:"totalSize,omitempty"`

	// CronJobName is the name of the generated CronJob
	// Only set for scheduled backups
	// +optional
	CronJobName string `json:"cronJobName,omitempty"`

	// JobName is the name of the generated one-shot Job
	// Only set for one-shot backups
	// +optional
	JobName string `json:"jobName,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wbak
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Last Backup",type=date,JSONPath=`.status.lastBackup.time`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhBackup is the Schema for scheduling Wazuh Manager data backups
type WazuhBackup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhBackupSpec   `json:"spec,omitempty"`
	Status WazuhBackupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhBackupList contains a list of WazuhBackup
type WazuhBackupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhBackup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhBackup{}, &WazuhBackupList{})
}

// IsScheduled returns true if this is a scheduled backup (has cron expression)
func (b *WazuhBackup) IsScheduled() bool {
	return b.Spec.Schedule != ""
}
