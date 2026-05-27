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

// WazuhUserSpec defines the desired state of an internal Wazuh Manager API user.
// The user is created on the Wazuh API and linked to the referenced roles.
type WazuhUserSpec struct {
	// ClusterRefs lists the WazuhCluster instances this user targets.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Username for the Wazuh API user. Defaults to metadata.name.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=64
	Username string `json:"username,omitempty"`

	// PasswordSecret references a Secret (in the CR namespace) holding the
	// user password. Only the password key is used (default "password").
	// +kubebuilder:validation:Required
	PasswordSecret *CredentialsSecretRef `json:"passwordSecret"`

	// Roles are the Wazuh API role names to assign to the user. These should
	// match the resolved roleName of a WazuhRole (or an existing role).
	// +optional
	Roles []string `json:"roles,omitempty"`

	// AllowRunAs permits this user to be impersonated via run_as / auth-context.
	// +optional
	AllowRunAs bool `json:"allowRunAs,omitempty"`
}

// WazuhUserStatus defines the observed state of WazuhUser.
type WazuhUserStatus struct {
	// Phase is the aggregate phase across all target clusters.
	// +optional
	Phase WazuhRBACPhase `json:"phase,omitempty"`

	// Conditions represent the latest aggregate observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional aggregate information about the current state.
	// +optional
	Message string `json:"message,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []WazuhRBACClusterStatus `json:"clusterStatuses,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wuser
// +kubebuilder:printcolumn:name="Username",type=string,JSONPath=`.spec.username`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhUser is the Schema for the wazuhusers API (internal Wazuh Manager API user).
type WazuhUser struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhUser
	// +required
	Spec WazuhUserSpec `json:"spec"`

	// status defines the observed state of WazuhUser
	// +optional
	Status WazuhUserStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhUserList contains a list of WazuhUser
type WazuhUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhUser `json:"items"`
}

// ResolveUsername returns the effective Wazuh API username (spec or CR name).
func (w *WazuhUser) ResolveUsername() string {
	if w.Spec.Username != "" {
		return w.Spec.Username
	}
	return w.Name
}

func init() {
	SchemeBuilder.Register(&WazuhUser{}, &WazuhUserList{})
}
