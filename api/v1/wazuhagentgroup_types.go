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

// WazuhAgentGroupSpec defines the desired state of WazuhAgentGroup
type WazuhAgentGroupSpec struct {
	// ClusterRef references the WazuhCluster this agent group belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// GroupName is the name of the Wazuh agent group.
	// If empty, defaults to metadata.name.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._-]+$`
	GroupName string `json:"groupName,omitempty"`

	// Description of the agent group
	// +optional
	Description string `json:"description,omitempty"`

	// AgentConf is the XML content of agent.conf for this group
	// +optional
	AgentConf string `json:"agentConf,omitempty"`

	// Files is a map of filename → content to place in /var/ossec/etc/shared/<groupName>/
	// These files are mounted via ConfigMap (the Wazuh API only supports agent.conf writes).
	// +optional
	Files map[string]string `json:"files,omitempty"`
}

// WazuhAgentGroupStatus defines the observed state of WazuhAgentGroup
type WazuhAgentGroupStatus struct {
	// Phase of the agent group (Pending, Ready, Failed)
	// +optional
	Phase AgentGroupPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is the last time the group was synced with the Wazuh API
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed spec
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastAppliedHash is the hash of the last applied spec for drift detection
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// AgentCount is the number of agents currently in this group
	// +optional
	AgentCount int `json:"agentCount,omitempty"`
}

// AgentGroupPhase represents the phase of the agent group
// +kubebuilder:validation:Enum=Pending;Ready;Failed
type AgentGroupPhase string

const (
	AgentGroupPhasePending AgentGroupPhase = "Pending"
	AgentGroupPhaseReady   AgentGroupPhase = "Ready"
	AgentGroupPhaseFailed  AgentGroupPhase = "Failed"
)

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wagentgroup
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=`.spec.groupName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Agents",type=integer,JSONPath=`.status.agentCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhAgentGroup is the Schema for the wazuhagentgroups API
type WazuhAgentGroup struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhAgentGroup
	// +required
	Spec WazuhAgentGroupSpec `json:"spec"`

	// status defines the observed state of WazuhAgentGroup
	// +optional
	Status WazuhAgentGroupStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhAgentGroupList contains a list of WazuhAgentGroup
type WazuhAgentGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhAgentGroup `json:"items"`
}

// ResolveGroupName returns the effective group name (spec or CR name)
func (w *WazuhAgentGroup) ResolveGroupName() string {
	if w.Spec.GroupName != "" {
		return w.Spec.GroupName
	}
	return w.Name
}

func init() {
	SchemeBuilder.Register(&WazuhAgentGroup{}, &WazuhAgentGroupList{})
}
