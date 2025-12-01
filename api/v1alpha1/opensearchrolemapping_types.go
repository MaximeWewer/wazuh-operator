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

// OpenSearchRoleMappingSpec defines the desired state of OpenSearchRoleMapping
type OpenSearchRoleMappingSpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Users are the internal users to map to this role
	// +optional
	Users []string `json:"users,omitempty"`

	// BackendRoles are backend roles to map
	// +optional
	BackendRoles []string `json:"backendRoles,omitempty"`

	// Hosts are host patterns to map
	// +optional
	Hosts []string `json:"hosts,omitempty"`

	// AndBackendRoles requires all listed backend roles (AND logic)
	// +optional
	AndBackendRoles []string `json:"andBackendRoles,omitempty"`

	// Description is a human-readable description
	// +optional
	Description string `json:"description,omitempty"`
}

// OpenSearchRoleMappingStatus defines the observed state of OpenSearchRoleMapping
type OpenSearchRoleMappingStatus struct {
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
// +kubebuilder:resource:scope=Namespaced,shortName=osrmap
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchRoleMapping is the Schema for the opensearchrolemappings API
// The CR name is used as the role name in OpenSearch
type OpenSearchRoleMapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchRoleMappingSpec   `json:"spec,omitempty"`
	Status OpenSearchRoleMappingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchRoleMappingList contains a list of OpenSearchRoleMapping
type OpenSearchRoleMappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchRoleMapping `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchRoleMapping{}, &OpenSearchRoleMappingList{})
}
