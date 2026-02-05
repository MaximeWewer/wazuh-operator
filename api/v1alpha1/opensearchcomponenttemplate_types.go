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

// OpenSearchComponentTemplateSpec defines the desired state of OpenSearchComponentTemplate
type OpenSearchComponentTemplateSpec struct {
	// WazuhCluster reference
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Template definition
	// +kubebuilder:validation:Required
	Template ComponentTemplate `json:"template"`

	// Version of the component template
	// +optional
	Version int64 `json:"version,omitempty"`

	// Metadata about the component template
	// +optional
	Metadata *runtime.RawExtension `json:"_meta,omitempty"`
}

// ComponentTemplate defines the template structure
type ComponentTemplate struct {
	// Settings for the component template
	// +optional
	Settings *runtime.RawExtension `json:"settings,omitempty"`

	// Mappings for the component template
	// +optional
	Mappings *runtime.RawExtension `json:"mappings,omitempty"`

	// Aliases for the component template
	// +optional
	Aliases map[string]ComponentAlias `json:"aliases,omitempty"`
}

// ComponentAlias defines an index alias
type ComponentAlias struct {
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

// OpenSearchComponentTemplateStatus defines the observed state of OpenSearchComponentTemplate
type OpenSearchComponentTemplateStatus struct {
	// Phase represents the current phase of the component template
	// +optional
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the component template's state
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
// +kubebuilder:resource:scope=Namespaced,shortName=osctpl
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchComponentTemplate is the Schema for the opensearchcomponenttemplates API
type OpenSearchComponentTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchComponentTemplateSpec   `json:"spec,omitempty"`
	Status OpenSearchComponentTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchComponentTemplateList contains a list of OpenSearchComponentTemplate
type OpenSearchComponentTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchComponentTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchComponentTemplate{}, &OpenSearchComponentTemplateList{})
}
