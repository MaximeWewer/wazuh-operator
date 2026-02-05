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

// OpenSearchRoleSpec defines the desired state of OpenSearchRole
type OpenSearchRoleSpec struct {
	// ClusterRef references the WazuhCluster this resource belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// ClusterPermissions are cluster-level permissions
	// +optional
	ClusterPermissions []string `json:"clusterPermissions,omitempty"`

	// IndexPermissions define index-level permissions
	// +optional
	IndexPermissions []IndexPermission `json:"indexPermissions,omitempty"`

	// TenantPermissions define tenant-level permissions
	// +optional
	TenantPermissions []TenantPermission `json:"tenantPermissions,omitempty"`

	// Description is a human-readable description of the role
	// +optional
	Description string `json:"description,omitempty"`
}

// IndexPermission defines permissions for indices
type IndexPermission struct {
	// IndexPatterns are index name patterns (e.g., "logs-*")
	// +kubebuilder:validation:Required
	IndexPatterns []string `json:"indexPatterns"`

	// AllowedActions are the permitted actions
	// +kubebuilder:validation:Required
	AllowedActions []string `json:"allowedActions"`

	// DLS is the document-level security query
	// +optional
	DLS string `json:"dls,omitempty"`

	// FLS is the field-level security configuration
	// +optional
	FLS []string `json:"fls,omitempty"`

	// MaskedFields are fields to be masked
	// +optional
	MaskedFields []string `json:"maskedFields,omitempty"`
}

// TenantPermission defines permissions for tenants
type TenantPermission struct {
	// TenantPatterns are tenant name patterns
	// +kubebuilder:validation:Required
	TenantPatterns []string `json:"tenantPatterns"`

	// AllowedActions are the permitted actions (e.g., "kibana_all_read", "kibana_all_write")
	// +kubebuilder:validation:Required
	AllowedActions []string `json:"allowedActions"`
}

// OpenSearchRoleStatus defines the observed state of OpenSearchRole
type OpenSearchRoleStatus struct {
	// Phase is the current phase of the role (Pending, Ready, Failed, Conflict)
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
// +kubebuilder:resource:scope=Namespaced,shortName=osrole
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchRole is the Schema for the opensearchroles API
type OpenSearchRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchRoleSpec   `json:"spec,omitempty"`
	Status OpenSearchRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchRoleList contains a list of OpenSearchRole
type OpenSearchRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchRole{}, &OpenSearchRoleList{})
}
