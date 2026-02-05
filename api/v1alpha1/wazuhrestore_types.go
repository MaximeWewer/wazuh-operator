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

// WazuhRestoreSpec defines the desired state of WazuhRestore
type WazuhRestoreSpec struct {
	// ClusterRef references the WazuhCluster to restore to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Source defines where to restore from
	// +kubebuilder:validation:Required
	Source RestoreSource `json:"source"`

	// Components defines what data to restore
	// If not specified, restores all components that exist in the backup
	// +optional
	Components *RestoreComponents `json:"components,omitempty"`

	// PreRestoreBackup creates a backup of current data before restore
	// +kubebuilder:default=true
	PreRestoreBackup bool `json:"preRestoreBackup,omitempty"`

	// StopManager stops the manager during restore
	// Recommended for data consistency
	// +kubebuilder:default=true
	StopManager bool `json:"stopManager,omitempty"`

	// RestartAfterRestore restarts the manager after successful restore
	// +kubebuilder:default=true
	RestartAfterRestore bool `json:"restartAfterRestore,omitempty"`

	// RestoreTimeout is the maximum duration for the restore operation
	// +kubebuilder:default="30m"
	RestoreTimeout string `json:"restoreTimeout,omitempty"`

	// Image specifies a custom restore container image
	// If not set, uses a default image with aws-cli and tar
	// +optional
	Image *BackupImage `json:"image,omitempty"`

	// Resources for the restore Job container
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// RestoreSource defines where to restore data from
type RestoreSource struct {
	// S3 defines S3/MinIO source configuration
	// +optional
	S3 *S3RestoreSource `json:"s3,omitempty"`

	// WazuhBackupRef references an existing WazuhBackup to restore from
	// Uses the last successful backup from that WazuhBackup
	// +optional
	WazuhBackupRef *WazuhBackupReference `json:"wazuhBackupRef,omitempty"`
}

// S3RestoreSource defines S3/MinIO restore source configuration
type S3RestoreSource struct {
	// Bucket is the S3 bucket name
	// +kubebuilder:validation:Required
	Bucket string `json:"bucket"`

	// Key is the full S3 key (path) to the backup archive
	// Example: "wazuh-cluster/wazuh/daily-backup-20250105-020000.tar.gz"
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Region is the AWS region
	// +optional
	Region string `json:"region,omitempty"`

	// Endpoint is a custom S3 endpoint (for MinIO)
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ForcePathStyle enables path-style S3 access (required for MinIO)
	// +optional
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// CredentialsSecret references the Secret containing S3 credentials
	// +kubebuilder:validation:Required
	CredentialsSecret RepositoryCredentialsRef `json:"credentialsSecret"`
}

// WazuhBackupReference references a WazuhBackup resource
type WazuhBackupReference struct {
	// Name is the WazuhBackup name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// BackupTimestamp optionally specifies which backup to restore
	// If not specified, uses the most recent successful backup
	// +optional
	BackupTimestamp string `json:"backupTimestamp,omitempty"`
}

// RestoreComponents defines what data to restore
type RestoreComponents struct {
	// AgentKeys restores /var/ossec/etc/client.keys
	// +kubebuilder:default=true
	AgentKeys bool `json:"agentKeys,omitempty"`

	// FIMDatabase restores /var/ossec/queue/fim/db/
	// +kubebuilder:default=true
	FIMDatabase bool `json:"fimDatabase,omitempty"`

	// AgentDatabase restores /var/ossec/queue/db/
	// +kubebuilder:default=true
	AgentDatabase bool `json:"agentDatabase,omitempty"`

	// Integrations restores /var/ossec/integrations/
	// +kubebuilder:default=false
	Integrations bool `json:"integrations,omitempty"`

	// AlertLogs restores /var/ossec/logs/alerts/
	// +kubebuilder:default=false
	AlertLogs bool `json:"alertLogs,omitempty"`

	// CustomPaths additional paths to restore
	// +optional
	CustomPaths []string `json:"customPaths,omitempty"`
}

// WazuhRestoreStatus defines the observed state of WazuhRestore
type WazuhRestoreStatus struct {
	// Phase is the current phase
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// StartTime is when the restore started
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// EndTime is when the restore completed
	// +optional
	EndTime *metav1.Time `json:"endTime,omitempty"`

	// Duration is how long the restore took
	// +optional
	Duration string `json:"duration,omitempty"`

	// SourceBackup contains info about the source backup
	// +optional
	SourceBackup *RestoreSourceInfo `json:"sourceBackup,omitempty"`

	// PreRestoreBackupLocation is where the pre-restore backup was saved
	// +optional
	PreRestoreBackupLocation string `json:"preRestoreBackupLocation,omitempty"`

	// RestoredComponents lists what was actually restored
	// +optional
	RestoredComponents []string `json:"restoredComponents,omitempty"`

	// JobName is the name of the restore Job
	// +optional
	JobName string `json:"jobName,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// RestoreSourceInfo contains information about the source backup
type RestoreSourceInfo struct {
	// Location is the S3 URL or reference
	// +optional
	Location string `json:"location,omitempty"`

	// BackupTime is when the source backup was created
	// +optional
	BackupTime *metav1.Time `json:"backupTime,omitempty"`

	// Size is the backup size
	// +optional
	Size string `json:"size,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wrest
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Duration",type=string,JSONPath=`.status.duration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhRestore is the Schema for restoring Wazuh Manager data from backups
type WazuhRestore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhRestoreSpec   `json:"spec,omitempty"`
	Status WazuhRestoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhRestoreList contains a list of WazuhRestore
type WazuhRestoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhRestore `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhRestore{}, &WazuhRestoreList{})
}

// IsFromS3 returns true if restoring from S3 directly
func (r *WazuhRestore) IsFromS3() bool {
	return r.Spec.Source.S3 != nil
}

// IsFromWazuhBackup returns true if restoring from a WazuhBackup reference
func (r *WazuhRestore) IsFromWazuhBackup() bool {
	return r.Spec.Source.WazuhBackupRef != nil
}
