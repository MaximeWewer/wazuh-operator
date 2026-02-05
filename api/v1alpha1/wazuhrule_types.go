/*
Copyright 2025.

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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// WazuhRuleSpec defines the desired state of WazuhRule
type WazuhRuleSpec struct {
	// ClusterRef references the WazuhCluster this rule belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// RuleName is the name of the rule
	// +kubebuilder:validation:Required
	RuleName string `json:"ruleName"`

	// Rules contain the actual rule definitions in XML format
	// +kubebuilder:validation:Required
	Rules string `json:"rules"`

	// Description of the rule set
	// +optional
	Description string `json:"description,omitempty"`

	// TargetNodes specifies which nodes should receive this rule (master, workers, or all)
	// +optional
	// +kubebuilder:validation:Enum=master;workers;all
	// +kubebuilder:default="all"
	TargetNodes string `json:"targetNodes,omitempty"`

	// Level specifies the rule level (0-15)
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=15
	Level int32 `json:"level,omitempty"`

	// RuleID is the starting rule ID for rules in this set
	// +optional
	// +kubebuilder:validation:Minimum=100000
	// +kubebuilder:validation:Maximum=999999
	RuleID int32 `json:"ruleID,omitempty"`

	// Groups are the rule groups this rule set belongs to
	// +optional
	Groups []string `json:"groups,omitempty"`

	// Overwrite determines if this rule should overwrite existing rules
	// +optional
	Overwrite bool `json:"overwrite,omitempty"`

	// Priority determines the order in which rules are applied (lower values = higher priority)
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +kubebuilder:default=500
	Priority int32 `json:"priority,omitempty"`

	// IfSID references parent rule IDs
	// +optional
	IfSID []int32 `json:"ifSID,omitempty"`

	// IfGroup references parent rule groups
	// +optional
	IfGroup []string `json:"ifGroup,omitempty"`
}

// WazuhRuleStatus defines the observed state of WazuhRule.
type WazuhRuleStatus struct {
	// Phase of the rule (Pending, Applied, Failed)
	// +optional
	Phase RulePhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// AppliedToNodes lists the nodes where this rule has been applied
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the ConfigMap containing the rule
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the rule was applied
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed rule
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// ValidationErrors contains any validation errors encountered
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`
}

// RulePhase represents the phase of the rule
// +kubebuilder:validation:Enum=Pending;Applied;Failed;Updating
type RulePhase string

const (
	RulePhasePending  RulePhase = "Pending"
	RulePhaseApplied  RulePhase = "Applied"
	RulePhaseFailed   RulePhase = "Failed"
	RulePhaseUpdating RulePhase = "Updating"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wrule
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Rule",type=string,JSONPath=`.spec.ruleName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhRule is the Schema for the wazuhrules API
type WazuhRule struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhRule
	// +required
	Spec WazuhRuleSpec `json:"spec"`

	// status defines the observed state of WazuhRule
	// +optional
	Status WazuhRuleStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhRuleList contains a list of WazuhRule
type WazuhRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhRule{}, &WazuhRuleList{})
}
