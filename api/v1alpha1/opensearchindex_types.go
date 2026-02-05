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
	"k8s.io/apimachinery/pkg/runtime"
)

// OpenSearchIndexSpec defines the desired state of OpenSearchIndex
type OpenSearchIndexSpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Settings are the index settings
	// +optional
	Settings *IndexSettings `json:"settings,omitempty"`

	// Mappings define the index field mappings
	// +optional
	Mappings *IndexMappings `json:"mappings,omitempty"`

	// Aliases define index aliases
	// +optional
	Aliases []OpenSearchIndexAlias `json:"aliases,omitempty"`
}

// IndexSettings defines index configuration settings
type IndexSettings struct {
	// NumberOfShards is the number of primary shards
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	NumberOfShards *int32 `json:"numberOfShards,omitempty"`

	// NumberOfReplicas is the number of replica shards
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	NumberOfReplicas *int32 `json:"numberOfReplicas,omitempty"`

	// RefreshInterval is how often to refresh the index
	// +optional
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// Codec is the compression codec (default or best_compression)
	// +optional
	// +kubebuilder:validation:Enum=default;best_compression
	Codec string `json:"codec,omitempty"`

	// Custom contains additional settings as raw JSON
	// +optional
	Custom *runtime.RawExtension `json:"custom,omitempty"`
}

// IndexMappings defines the index field mappings
type IndexMappings struct {
	// Properties define the field mappings
	// +optional
	Properties *runtime.RawExtension `json:"properties,omitempty"`

	// Dynamic controls dynamic mapping behavior (true, false, strict)
	// +optional
	// +kubebuilder:validation:Enum=true;false;strict
	Dynamic string `json:"dynamic,omitempty"`

	// DateDetection enables automatic date detection
	// +optional
	DateDetection *bool `json:"dateDetection,omitempty"`

	// NumericDetection enables automatic numeric detection
	// +optional
	NumericDetection *bool `json:"numericDetection,omitempty"`
}

// OpenSearchIndexAlias defines an alias for an OpenSearchIndex
type OpenSearchIndexAlias struct {
	// Name is the alias name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Filter is an optional filter query for the alias
	// +optional
	Filter *runtime.RawExtension `json:"filter,omitempty"`

	// Routing is the routing value for the alias
	// +optional
	Routing string `json:"routing,omitempty"`

	// IsWriteIndex marks this as the write index for the alias
	// +optional
	IsWriteIndex bool `json:"isWriteIndex,omitempty"`
}

// OpenSearchIndexStatus defines the observed state of OpenSearchIndex
type OpenSearchIndexStatus struct {
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

	// Health is the index health (green, yellow, red)
	// +optional
	Health string `json:"health,omitempty"`

	// DocsCount is the number of documents in the index
	// +optional
	DocsCount int64 `json:"docsCount,omitempty"`

	// StorageSize is the storage size of the index
	// +optional
	StorageSize string `json:"storageSize,omitempty"`

	// PrimaryShards is the actual number of primary shards
	// +optional
	PrimaryShards int32 `json:"primaryShards,omitempty"`

	// ReplicaShards is the actual number of replica shards
	// +optional
	ReplicaShards int32 `json:"replicaShards,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osidx
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.health`
// +kubebuilder:printcolumn:name="Docs",type=integer,JSONPath=`.status.docsCount`
// +kubebuilder:printcolumn:name="Size",type=string,JSONPath=`.status.storageSize`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchIndex is the Schema for the opensearchindices API
type OpenSearchIndex struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchIndexSpec   `json:"spec,omitempty"`
	Status OpenSearchIndexStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchIndexList contains a list of OpenSearchIndex
type OpenSearchIndexList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchIndex `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchIndex{}, &OpenSearchIndexList{})
}
