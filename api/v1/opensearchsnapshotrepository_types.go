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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenSearchSnapshotRepositorySpec defines the desired state of OpenSearchSnapshotRepository
type OpenSearchSnapshotRepositorySpec struct {
	// ClusterRefs lists the WazuhCluster instances this resource targets.
	// Each entry must specify both name and namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Type is the repository type
	// Note: s3/gcs/azure/hdfs types require the corresponding repository plugin to be installed
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=s3;azure;fs;gcs;hdfs
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

	// Protocol is the connection protocol (s3 type only)
	// Use "http" for MinIO or other S3-compatible services without TLS
	// +optional
	// +kubebuilder:validation:Enum=http;https
	Protocol string `json:"protocol,omitempty"`

	// ReadOnly marks the repository as read-only
	// +optional
	ReadOnly bool `json:"readonly,omitempty"`

	// Client is the named client for keystore-based credentials
	// Corresponds to the clientName in RepositoryPluginConfig
	// Used by S3, GCS, and Azure repository types
	// +optional
	// +kubebuilder:default="default"
	Client string `json:"client,omitempty"`

	// UseKeystore indicates that credentials are stored in the OpenSearch keystore
	// When true, inline credentials (access_key/secret_key) are not set in repository settings
	// The operator expects the keystore to be populated via RepositoryPlugins in WazuhCluster
	// +optional
	UseKeystore bool `json:"useKeystore,omitempty"`

	// ApplicationName is the GCS application name (gcs type only)
	// +optional
	ApplicationName string `json:"applicationName,omitempty"`

	// EndpointSuffix is the Azure endpoint suffix for sovereign clouds (azure type only)
	// Example: "core.chinacloudapi.cn" for Azure China
	// +optional
	EndpointSuffix string `json:"endpointSuffix,omitempty"`

	// URI is the HDFS namenode URI (hdfs type only)
	// Example: "hdfs://namenode:8020"
	// +optional
	URI string `json:"uri,omitempty"`

	// Path is the HDFS directory path (hdfs type only)
	// +optional
	Path string `json:"path,omitempty"`

	// SecurityPrincipal is the Kerberos principal for HDFS (hdfs type only)
	// +optional
	SecurityPrincipal string `json:"securityPrincipal,omitempty"`

	// HadoopConf is extra Hadoop configuration for HDFS (hdfs type only)
	// Keys are prefixed with "conf." when sent to OpenSearch
	// +optional
	HadoopConf map[string]string `json:"hadoopConf,omitempty"`
}

// OpenSearchSnapshotRepositoryStatus defines the observed state of OpenSearchSnapshotRepository
type OpenSearchSnapshotRepositoryStatus struct {
	// Phase is the current phase (Pending, Creating, Verifying, Ready, Failed, Deleting)
	// +optional
	Phase RepositoryPhase `json:"phase,omitempty"`

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
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []OpenSearchClusterStatus `json:"clusterStatuses,omitempty"`

	// LastSyncTime is when the resource was last synced to OpenSearch
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osrepo
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
