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
	"k8s.io/apimachinery/pkg/runtime"
)

// WazuhRoleSpec defines the desired state of a Wazuh Manager API RBAC role.
// The role, its inline policies and its auth-context rules are pushed to the
// Wazuh Manager API (port 55000) on each target cluster.
type WazuhRoleSpec struct {
	// ClusterRefs lists the WazuhCluster instances this role targets.
	// Each entry must specify both name and namespace. The CR itself can live
	// in any namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// RoleName is the Wazuh API role name. Defaults to metadata.name.
	// Use a distinct name to avoid colliding with reserved Wazuh roles.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=64
	RoleName string `json:"roleName,omitempty"`

	// Policies are RBAC policies created inline and linked to this role.
	// +optional
	// +listType=map
	// +listMapKey=name
	Policies []WazuhRolePolicy `json:"policies,omitempty"`

	// Rules are auth-context matcher rules created inline and linked to this
	// role. Used with run_as to map an authenticated dashboard user onto this
	// role (e.g. body {"FIND":{"user_name":"jdoe"}}).
	// +optional
	// +listType=map
	// +listMapKey=name
	Rules []WazuhRoleRule `json:"rules,omitempty"`
}

// WazuhRolePolicy is an inline Wazuh API policy definition.
type WazuhRolePolicy struct {
	// Name is the Wazuh API policy name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=64
	Name string `json:"name"`

	// Actions are the Wazuh API actions (e.g. "agent:read", "rules:read").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Actions []string `json:"actions"`

	// Resources are the targeted resources (e.g. "*:*:*", "agent:group:default").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Resources []string `json:"resources"`

	// Effect is allow or deny.
	// +optional
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=allow
	Effect string `json:"effect,omitempty"`
}

// WazuhRoleRule is an inline Wazuh API authentication-context rule.
type WazuhRoleRule struct {
	// Name is the Wazuh API rule name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	// +kubebuilder:validation:MaxLength=64
	Name string `json:"name"`

	// Body is the auth-context matcher pushed as the rule definition, e.g.
	// {"FIND":{"user_name":"jdoe"}} or {"MATCH":{"backend_roles":"admins"}}.
	// The structure is free-form Wazuh rule syntax (FIND/MATCH/AND/OR) and is
	// validated by the Wazuh API on apply.
	// +kubebuilder:validation:Required
	// +kubebuilder:pruning:PreserveUnknownFields
	Body *runtime.RawExtension `json:"body"`
}

// WazuhRoleStatus defines the observed state of WazuhRole.
type WazuhRoleStatus struct {
	// Phase is the aggregate phase across all target clusters.
	// Ready when every cluster is Ready; Failed if any is Failed; Pending otherwise.
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

// WazuhRBACPhase represents the phase of a Wazuh API RBAC resource.
// +kubebuilder:validation:Enum=Pending;Ready;Failed
type WazuhRBACPhase string

const (
	WazuhRBACPhasePending WazuhRBACPhase = "Pending"
	WazuhRBACPhaseReady   WazuhRBACPhase = "Ready"
	WazuhRBACPhaseFailed  WazuhRBACPhase = "Failed"
)

// WazuhRBACClusterStatus reports reconciliation state for a single cluster.
// Wazuh API object IDs differ per cluster, so they are tracked per entry and
// used for unlink/delete on cleanup.
type WazuhRBACClusterStatus struct {
	// Name of the target WazuhCluster.
	Name string `json:"name"`

	// Namespace of the target WazuhCluster.
	Namespace string `json:"namespace"`

	// Phase of this cluster's reconciliation (Pending, Ready, Failed).
	// +optional
	Phase WazuhRBACPhase `json:"phase,omitempty"`

	// LastSyncTime is the last time this cluster was synced with its Wazuh API.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastAppliedHash is the hash of the last spec applied to this cluster.
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// RoleID is the resolved Wazuh API role ID on this cluster (WazuhRole only).
	// +optional
	RoleID int `json:"roleId,omitempty"`

	// PolicyIDs maps policy name to its resolved Wazuh API ID (WazuhRole only).
	// +optional
	PolicyIDs map[string]int `json:"policyIds,omitempty"`

	// RuleIDs maps rule name to its resolved Wazuh API ID (WazuhRole only).
	// +optional
	RuleIDs map[string]int `json:"ruleIds,omitempty"`

	// UserID is the resolved Wazuh API user ID on this cluster (WazuhUser only).
	// +optional
	UserID int `json:"userId,omitempty"`

	// AssignedRoleIDs maps role name to its resolved Wazuh API role ID for the
	// roles linked to this user (WazuhUser only). Used to prune removed roles.
	// +optional
	AssignedRoleIDs map[string]int `json:"assignedRoleIds,omitempty"`

	// Message provides additional information about this cluster's state.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wrole
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.roleName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhRole is the Schema for the wazuhroles API (Wazuh Manager API RBAC role).
type WazuhRole struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhRole
	// +required
	Spec WazuhRoleSpec `json:"spec"`

	// status defines the observed state of WazuhRole
	// +optional
	Status WazuhRoleStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhRoleList contains a list of WazuhRole
type WazuhRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhRole `json:"items"`
}

// ResolveRoleName returns the effective Wazuh API role name (spec or CR name).
func (w *WazuhRole) ResolveRoleName() string {
	if w.Spec.RoleName != "" {
		return w.Spec.RoleName
	}
	return w.Name
}

func init() {
	SchemeBuilder.Register(&WazuhRole{}, &WazuhRoleList{})
}
