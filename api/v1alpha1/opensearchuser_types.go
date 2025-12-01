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

// OpenSearchUserSpec defines the desired state of OpenSearchUser
type OpenSearchUserSpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// DefaultAdmin marks this user as the default admin for the cluster.
	// Only one user per cluster can be marked as defaultAdmin.
	// If multiple users are marked, the first one (by creation timestamp) is used
	// and warnings are emitted for the others.
	// +optional
	DefaultAdmin bool `json:"defaultAdmin,omitempty"`

	// PasswordSecret references a Secret containing the user password
	// Uses CredentialsSecretRef for consistency - only the passwordKey is used
	// +optional
	PasswordSecret *CredentialsSecretRef `json:"passwordSecret,omitempty"`

	// Hash is a pre-computed password hash (alternative to PasswordSecret)
	// +optional
	Hash string `json:"hash,omitempty"`

	// BackendRoles are the backend roles for this user
	// +optional
	BackendRoles []string `json:"backendRoles,omitempty"`

	// OpenSearchRoles are the OpenSearch security roles to assign to the user
	// +optional
	OpenSearchRoles []string `json:"openSearchRoles,omitempty"`

	// Attributes are custom attributes for the user
	// +optional
	Attributes map[string]string `json:"attributes,omitempty"`

	// Description is a human-readable description of the user
	// +optional
	Description string `json:"description,omitempty"`
}

// OpenSearchUserStatus defines the observed state of OpenSearchUser
type OpenSearchUserStatus struct {
	// Phase is the current phase of the user (Pending, Ready, Failed, Conflict)
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
// +kubebuilder:resource:scope=Namespaced,shortName=osuser
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchUser is the Schema for the opensearchusers API
type OpenSearchUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchUserSpec   `json:"spec,omitempty"`
	Status OpenSearchUserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchUserList contains a list of OpenSearchUser
type OpenSearchUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchUser{}, &OpenSearchUserList{})
}
