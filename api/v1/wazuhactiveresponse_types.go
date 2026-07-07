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

// WazuhActiveResponseSpec defines the desired state of WazuhActiveResponse.
//
// A WazuhActiveResponse provisions a Wazuh custom active response: it ships an
// executable script to /var/ossec/active-response/bin/<script> on the target
// manager nodes AND injects the matching <command> and <active-response> blocks
// into ossec.conf so wazuh-execd runs the script when the trigger matches.
// See https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
type WazuhActiveResponseSpec struct {
	// ClusterRefs lists the WazuhCluster instances the active response must be applied to.
	// Each entry must specify both name and namespace. The CR can live in any
	// namespace; the script ConfigMap is created in each target cluster's namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Name is the active response identifier. It is used as the ossec.conf
	// <command> <name> and referenced by the <active-response> <command>.
	// It is also the base of the script filename (see ScriptName).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9_-]+$`
	// +kubebuilder:validation:MaxLength=50
	Name string `json:"name"`

	// ScriptExtension is the optional file extension (without the leading dot)
	// appended to the script filename, e.g. "sh" → <name>.sh, "py" → <name>.py.
	// The <executable> tag always matches the resulting filename.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]+$`
	// +kubebuilder:validation:MaxLength=10
	ScriptExtension string `json:"scriptExtension,omitempty"`

	// Script is the content of the active response executable. It is mounted with
	// mode 0750 (root:wazuh) at /var/ossec/active-response/bin/<script>. The first
	// line must be a shebang (e.g. "#!/usr/bin/env python3" or "#!/bin/sh").
	// +kubebuilder:validation:Required
	Script string `json:"script"`

	// TimeoutAllowed enables the stateful timeout mechanism for the command
	// (<timeout_allowed>). Set to true for scripts that revert their action after
	// <timeout> seconds (add/delete style).
	// +optional
	// +kubebuilder:default=false
	TimeoutAllowed bool `json:"timeoutAllowed,omitempty"`

	// ExtraArgs are static arguments passed to the script (<extra_args>).
	// +optional
	ExtraArgs string `json:"extraArgs,omitempty"`

	// Disabled sets <disabled>yes</disabled> on the active-response block, keeping
	// the command defined but inactive.
	// +optional
	// +kubebuilder:default=false
	Disabled bool `json:"disabled,omitempty"`

	// Location selects where the response runs (<location>):
	// "local" (the agent that triggered the alert), "server" (the manager),
	// "defined-agent" (the agent in AgentID), or "all" (every agent).
	// +optional
	// +kubebuilder:validation:Enum=local;server;defined-agent;all
	// +kubebuilder:default="local"
	Location string `json:"location,omitempty"`

	// AgentID is the target agent id (<agent_id>), required when Location is
	// "defined-agent".
	// +optional
	AgentID string `json:"agentID,omitempty"`

	// Level triggers the response when an alert of at least this severity fires (<level>).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	Level *int32 `json:"level,omitempty"`

	// RulesID triggers the response for the listed rule IDs (<rules_id>), rendered comma-separated.
	// +optional
	RulesID []int32 `json:"rulesID,omitempty"`

	// RulesGroup triggers the response for alerts in this rule group (<rules_group>).
	// +optional
	RulesGroup string `json:"rulesGroup,omitempty"`

	// Timeout is the number of seconds after which a stateful response is reverted
	// (<timeout>). Requires TimeoutAllowed on the command.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Timeout *int32 `json:"timeout,omitempty"`

	// RepeatedOffenders is the escalating timeout schedule in minutes for repeat
	// offenders (<repeated_offenders>), rendered comma-separated (e.g. 30,60,120).
	// +optional
	RepeatedOffenders []int32 `json:"repeatedOffenders,omitempty"`

	// TargetNodes selects which manager nodes receive the active response (master, workers, or all).
	// +optional
	// +kubebuilder:validation:Enum=master;workers;all
	// +kubebuilder:default="all"
	TargetNodes string `json:"targetNodes,omitempty"`
}

// WazuhActiveResponseStatus defines the observed state of WazuhActiveResponse.
type WazuhActiveResponseStatus struct {
	// Phase is the aggregate phase across all target clusters.
	// +optional
	Phase ActiveResponsePhase `json:"phase,omitempty"`

	// Conditions represent the latest aggregate observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed active response.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional aggregate information about the current state.
	// +optional
	Message string `json:"message,omitempty"`

	// ValidationErrors contains any validation errors encountered.
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []ActiveResponseClusterStatus `json:"clusterStatuses,omitempty"`
}

// ActiveResponseClusterStatus reports the reconciliation state for a single target cluster.
type ActiveResponseClusterStatus struct {
	// Name of the target WazuhCluster.
	Name string `json:"name"`

	// Namespace of the target WazuhCluster.
	Namespace string `json:"namespace"`

	// Phase on this cluster.
	// +optional
	Phase ActiveResponsePhase `json:"phase,omitempty"`

	// AppliedToNodes lists the nodes where this active response has been applied on this cluster.
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the script ConfigMap created in this cluster's namespace.
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the active response was applied to this cluster.
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// Message provides additional information about this cluster's state.
	// +optional
	Message string `json:"message,omitempty"`
}

// ActiveResponsePhase represents the phase of the active response.
// +kubebuilder:validation:Enum=Pending;Applied;Failed;Updating
type ActiveResponsePhase string

const (
	ActiveResponsePhasePending  ActiveResponsePhase = "Pending"
	ActiveResponsePhaseApplied  ActiveResponsePhase = "Applied"
	ActiveResponsePhaseFailed   ActiveResponsePhase = "Failed"
	ActiveResponsePhaseUpdating ActiveResponsePhase = "Updating"
)

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=war
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Location",type=string,JSONPath=`.spec.location`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhActiveResponse is the Schema for the wazuhactiveresponses API.
type WazuhActiveResponse struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhActiveResponse
	// +required
	Spec WazuhActiveResponseSpec `json:"spec"`

	// status defines the observed state of WazuhActiveResponse
	// +optional
	Status WazuhActiveResponseStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhActiveResponseList contains a list of WazuhActiveResponse.
type WazuhActiveResponseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhActiveResponse `json:"items"`
}

// ScriptName returns the active response script filename placed in
// /var/ossec/active-response/bin/. It is <name> with an optional .<scriptExtension>.
// This is also the value used for the <executable> tag.
func (s *WazuhActiveResponseSpec) ScriptName() string {
	name := s.Name
	if s.ScriptExtension != "" {
		name += "." + s.ScriptExtension
	}
	return name
}

func init() {
	SchemeBuilder.Register(&WazuhActiveResponse{}, &WazuhActiveResponseList{})
}
