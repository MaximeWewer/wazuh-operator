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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenSearchSnapshotRepositorySpec defines the desired state of OpenSearchSnapshotRepository
type OpenSearchSnapshotRepositorySpec struct {
	// ClusterRef references the WazuhCluster this repository belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Type is the repository type
	// Note: s3 type requires repository-s3 plugin to be installed in OpenSearch
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=s3;azure;fs
	Type string `json:"type"`

	// Settings contains type-specific repository configuration
	// +kubebuilder:validation:Required
	Settings SnapshotRepositorySettings `json:"settings"`

	// Verify enables repository verification after creation
	// +kubebuilder:default=true
	Verify bool `json:"verify,omitempty"`
}

// SnapshotRepositorySettings contains repository configuration
type SnapshotRepositorySettings struct {
	// Bucket is the bucket name (s3, gcs, azure)
	// +optional
	Bucket string `json:"bucket,omitempty"`

	// BasePath is the path within the bucket
	// +optional
	BasePath string `json:"basePath,omitempty"`

	// Region is the cloud region (s3)
	// +optional
	Region string `json:"region,omitempty"`

	// Endpoint is a custom endpoint (MinIO, S3-compatible)
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// PathStyleAccess enables path-style access (MinIO)
	// +optional
	PathStyleAccess bool `json:"pathStyleAccess,omitempty"`

	// Compress enables snapshot compression
	// +kubebuilder:default=true
	Compress bool `json:"compress,omitempty"`

	// ChunkSize is the chunk size for large files (e.g., "1gb")
	// +optional
	ChunkSize string `json:"chunkSize,omitempty"`

	// MaxRestoreBytesPerSec limits restore bandwidth (e.g., "40mb")
	// +optional
	MaxRestoreBytesPerSec string `json:"maxRestoreBytesPerSec,omitempty"`

	// MaxSnapshotBytesPerSec limits snapshot bandwidth (e.g., "40mb")
	// +optional
	MaxSnapshotBytesPerSec string `json:"maxSnapshotBytesPerSec,omitempty"`

	// Location is the filesystem path (fs type only)
	// +optional
	Location string `json:"location,omitempty"`

	// CredentialsSecret references credentials for cloud storage
	// +optional
	CredentialsSecret *RepositoryCredentialsRef `json:"credentialsSecret,omitempty"`

	// Container is the Azure container name
	// +optional
	Container string `json:"container,omitempty"`

	// ServerSideEncryption enables server-side encryption (s3)
	// +optional
	ServerSideEncryption bool `json:"serverSideEncryption,omitempty"`

	// StorageClass is the S3 storage class (e.g., "standard", "reduced_redundancy")
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// CannedACL is the S3 canned ACL (e.g., "private", "public-read")
	// +optional
	CannedACL string `json:"cannedAcl,omitempty"`

	// ReadOnly marks the repository as read-only
	// +optional
	ReadOnly bool `json:"readonly,omitempty"`
}

// OpenSearchSnapshotRepositoryStatus defines the observed state of OpenSearchSnapshotRepository
type OpenSearchSnapshotRepositoryStatus struct {
	// Phase is the current phase (Pending, Creating, Verifying, Ready, Failed, Deleting)
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Verified indicates if the repository was successfully verified
	// +optional
	Verified bool `json:"verified,omitempty"`

	// LastVerifiedTime is when verification last succeeded
	// +optional
	LastVerifiedTime *metav1.Time `json:"lastVerifiedTime,omitempty"`

	// SnapshotCount is the number of snapshots in the repository
	// +optional
	SnapshotCount int32 `json:"snapshotCount,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastSyncTime is when the resource was last synced to OpenSearch
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osrepo
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Bucket",type=string,JSONPath=`.spec.settings.bucket`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Verified",type=boolean,JSONPath=`.status.verified`
// +kubebuilder:printcolumn:name="Snapshots",type=integer,JSONPath=`.status.snapshotCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchSnapshotRepository is the Schema for the opensearchsnapshotrepositories API
type OpenSearchSnapshotRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchSnapshotRepositorySpec   `json:"spec,omitempty"`
	Status OpenSearchSnapshotRepositoryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchSnapshotRepositoryList contains a list of OpenSearchSnapshotRepository
type OpenSearchSnapshotRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchSnapshotRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchSnapshotRepository{}, &OpenSearchSnapshotRepositoryList{})
}
