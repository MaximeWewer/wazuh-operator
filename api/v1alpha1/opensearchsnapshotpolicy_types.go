/*
Copyright 2024.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenSearchSnapshotPolicySpec defines the desired state of OpenSearchSnapshotPolicy
type OpenSearchSnapshotPolicySpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Description is a human-readable description
	// +optional
	Description string `json:"description,omitempty"`

	// Repository configures the snapshot repository
	// +kubebuilder:validation:Required
	Repository SnapshotRepository `json:"repository"`

	// SnapshotConfig defines what to snapshot
	// +optional
	SnapshotConfig *SnapshotConfig `json:"snapshotConfig,omitempty"`

	// Creation defines the snapshot creation schedule
	// +kubebuilder:validation:Required
	Creation SnapshotCreation `json:"creation"`

	// Deletion defines the snapshot deletion policy
	// +optional
	Deletion *SnapshotDeletion `json:"deletion,omitempty"`

	// Notification configures alerts for snapshot events
	// +optional
	Notification *SnapshotNotification `json:"notification,omitempty"`
}

// SnapshotRepository defines a snapshot repository configuration
type SnapshotRepository struct {
	// Name is the repository name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Type is the repository type (fs, s3, azure, gcs)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=fs;s3;azure;gcs
	Type string `json:"type"`

	// Settings are repository-specific settings
	// +optional
	Settings *RepositorySettings `json:"settings,omitempty"`
}

// RepositorySettings contains repository-specific configuration
type RepositorySettings struct {
	// Location is the filesystem path (for fs type)
	// +optional
	Location string `json:"location,omitempty"`

	// Bucket is the S3/GCS/Azure bucket name
	// +optional
	Bucket string `json:"bucket,omitempty"`

	// BasePath is the path within the bucket
	// +optional
	BasePath string `json:"basePath,omitempty"`

	// Compress enables compression
	// +optional
	Compress bool `json:"compress,omitempty"`

	// Region is the AWS region (for s3 type)
	// +optional
	Region string `json:"region,omitempty"`

	// Endpoint is a custom S3 endpoint
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// CredentialsSecretRef references a Secret with repository credentials
	// +optional
	CredentialsSecretRef *SecretKeyRef `json:"credentialsSecretRef,omitempty"`
}

// SnapshotConfig defines what indices to snapshot
type SnapshotConfig struct {
	// Indices are index patterns to include
	// +optional
	Indices []string `json:"indices,omitempty"`

	// IgnoreUnavailable skips unavailable indices
	// +optional
	IgnoreUnavailable bool `json:"ignoreUnavailable,omitempty"`

	// IncludeGlobalState includes cluster state
	// +optional
	IncludeGlobalState bool `json:"includeGlobalState,omitempty"`

	// Partial allows partial snapshots
	// +optional
	Partial bool `json:"partial,omitempty"`
}

// SnapshotCreation defines the creation schedule
type SnapshotCreation struct {
	// Schedule defines when to create snapshots
	// +kubebuilder:validation:Required
	Schedule CronSchedule `json:"schedule"`

	// TimeLimit is the maximum time allowed for snapshot creation
	// +optional
	TimeLimit string `json:"timeLimit,omitempty"`
}

// SnapshotDeletion defines the retention policy
type SnapshotDeletion struct {
	// Schedule defines when to run deletion
	// +optional
	Schedule *CronSchedule `json:"schedule,omitempty"`

	// Condition defines when to delete snapshots
	// +optional
	Condition *DeletionCondition `json:"condition,omitempty"`
}

// CronSchedule defines a cron-based schedule
type CronSchedule struct {
	// Expression is the cron expression (e.g., "0 0 * * *")
	// +kubebuilder:validation:Required
	Expression string `json:"expression"`

	// Timezone is the timezone (e.g., "UTC", "America/New_York")
	// +optional
	// +kubebuilder:default="UTC"
	Timezone string `json:"timezone,omitempty"`
}

// DeletionCondition defines when to delete snapshots
type DeletionCondition struct {
	// MaxAge is the maximum age of snapshots to retain (e.g., "30d")
	// +optional
	MaxAge string `json:"maxAge,omitempty"`

	// MaxCount is the maximum number of snapshots to retain
	// +optional
	MaxCount *int32 `json:"maxCount,omitempty"`

	// MinCount is the minimum number of snapshots to keep
	// +optional
	MinCount *int32 `json:"minCount,omitempty"`
}

// SnapshotNotification configures snapshot event notifications
type SnapshotNotification struct {
	// Channel is the notification channel configuration
	// +optional
	Channel *NotificationChannel `json:"channel,omitempty"`

	// Conditions define when to send notifications
	// +optional
	Conditions *NotificationConditions `json:"conditions,omitempty"`
}

// NotificationChannel defines a notification channel
type NotificationChannel struct {
	// ID is the notification channel ID
	// +kubebuilder:validation:Required
	ID string `json:"id"`
}

// NotificationConditions define which events trigger notifications
type NotificationConditions struct {
	// Creation triggers notification on snapshot creation
	// +optional
	Creation bool `json:"creation,omitempty"`

	// Deletion triggers notification on snapshot deletion
	// +optional
	Deletion bool `json:"deletion,omitempty"`

	// Failure triggers notification on failures
	// +optional
	Failure bool `json:"failure,omitempty"`
}

// OpenSearchSnapshotPolicyStatus defines the observed state
type OpenSearchSnapshotPolicyStatus struct {
	// Phase is the current phase (Pending, Ready, Failed, Conflict)
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the resource was last synced to OpenSearch
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastAppliedHash is the hash of the last applied spec for drift detection
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// DriftDetected indicates if manual modification was detected
	// +optional
	DriftDetected bool `json:"driftDetected,omitempty"`

	// LastDriftTime is when drift was last detected
	// +optional
	LastDriftTime *metav1.Time `json:"lastDriftTime,omitempty"`

	// ConflictsWith is the namespace/name of a conflicting CRD
	// +optional
	ConflictsWith string `json:"conflictsWith,omitempty"`

	// OwnershipClaimed indicates if this CRD owns the OpenSearch resource
	// +optional
	OwnershipClaimed bool `json:"ownershipClaimed,omitempty"`

	// RepositoryStatus is the status of the snapshot repository
	// +optional
	RepositoryStatus string `json:"repositoryStatus,omitempty"`

	// LastSnapshotTime is when the last snapshot was taken
	// +optional
	LastSnapshotTime *metav1.Time `json:"lastSnapshotTime,omitempty"`

	// SnapshotCount is the number of snapshots
	// +optional
	SnapshotCount int32 `json:"snapshotCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ossnap
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Snapshots",type=integer,JSONPath=`.status.snapshotCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchSnapshotPolicy is the Schema for the opensearchsnapshotpolicies API
type OpenSearchSnapshotPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchSnapshotPolicySpec   `json:"spec,omitempty"`
	Status OpenSearchSnapshotPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchSnapshotPolicyList contains a list of OpenSearchSnapshotPolicy
type OpenSearchSnapshotPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchSnapshotPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchSnapshotPolicy{}, &OpenSearchSnapshotPolicyList{})
}
