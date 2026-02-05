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

// OpenSearchActionGroupSpec defines the desired state of OpenSearchActionGroup
type OpenSearchActionGroupSpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// AllowedActions are the actions or action groups to include
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	AllowedActions []string `json:"allowedActions"`

	// Type is the action group type (cluster, index, or all)
	// +optional
	// +kubebuilder:validation:Enum=cluster;index;all
	Type string `json:"type,omitempty"`

	// Description is a human-readable description
	// +optional
	Description string `json:"description,omitempty"`
}

// OpenSearchActionGroupStatus defines the observed state of OpenSearchActionGroup
type OpenSearchActionGroupStatus struct {
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
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osag
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchActionGroup is the Schema for the opensearchactiongroups API
type OpenSearchActionGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchActionGroupSpec   `json:"spec,omitempty"`
	Status OpenSearchActionGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchActionGroupList contains a list of OpenSearchActionGroup
type OpenSearchActionGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchActionGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchActionGroup{}, &OpenSearchActionGroupList{})
}
