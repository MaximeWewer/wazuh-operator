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

// OpenSearchIndexTemplateSpec defines the desired state of OpenSearchIndexTemplate
type OpenSearchIndexTemplateSpec struct {
	// WazuhCluster reference
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Index patterns that the template applies to
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	IndexPatterns []string `json:"indexPatterns"`

	// Template definition
	// +optional
	Template *IndexTemplate `json:"template,omitempty"`

	// Component templates to be applied
	// +optional
	ComposedOf []string `json:"composedOf,omitempty"`

	// Priority of the index template
	// +optional
	Priority int32 `json:"priority,omitempty"`

	// Version of the index template
	// +optional
	Version int64 `json:"version,omitempty"`

	// Metadata about the index template
	// +optional
	Metadata *runtime.RawExtension `json:"_meta,omitempty"`

	// Data stream configuration
	// +optional
	DataStream *DataStreamConfig `json:"dataStream,omitempty"`
}

// IndexTemplate defines the template structure
type IndexTemplate struct {
	// Settings for the index template
	// +optional
	Settings *runtime.RawExtension `json:"settings,omitempty"`

	// Mappings for the index template
	// +optional
	Mappings *runtime.RawExtension `json:"mappings,omitempty"`

	// Aliases for the index template
	// +optional
	Aliases map[string]IndexAlias `json:"aliases,omitempty"`
}

// IndexAlias defines an index alias
type IndexAlias struct {
	// Filter for the alias
	// +optional
	Filter *runtime.RawExtension `json:"filter,omitempty"`

	// Index routing
	// +optional
	IndexRouting string `json:"index_routing,omitempty"`

	// Search routing
	// +optional
	SearchRouting string `json:"search_routing,omitempty"`

	// Is write index
	// +optional
	IsWriteIndex *bool `json:"is_write_index,omitempty"`
}

// DataStreamConfig defines data stream configuration
type DataStreamConfig struct {
	// Timestamp field for data stream
	// +optional
	TimestampField *TimestampField `json:"timestamp_field,omitempty"`

	// Hidden flag for data stream
	// +optional
	Hidden bool `json:"hidden,omitempty"`
}

// TimestampField defines the timestamp field configuration
type TimestampField struct {
	// Name of the timestamp field
	// +kubebuilder:validation:Required
	// +kubebuilder:default="@timestamp"
	Name string `json:"name"`
}

// OpenSearchIndexTemplateStatus defines the observed state of OpenSearchIndexTemplate
type OpenSearchIndexTemplateStatus struct {
	// Phase represents the current phase of the index template
	// +optional
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the index template's state
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

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osidxt
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Patterns",type=string,JSONPath=`.spec.indexPatterns`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchIndexTemplate is the Schema for the opensearchindextemplates API
type OpenSearchIndexTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchIndexTemplateSpec   `json:"spec,omitempty"`
	Status OpenSearchIndexTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchIndexTemplateList contains a list of OpenSearchIndexTemplate
type OpenSearchIndexTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchIndexTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchIndexTemplate{}, &OpenSearchIndexTemplateList{})
}
