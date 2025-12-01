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

// OpenSearchISMPolicySpec defines the desired state of OpenSearchISMPolicy
type OpenSearchISMPolicySpec struct {
	// WazuhCluster reference
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Description of the ISM policy
	// +optional
	Description string `json:"description,omitempty"`

	// Default state for the policy
	// +kubebuilder:validation:Required
	DefaultState string `json:"defaultState"`

	// States in the ISM policy
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	States []ISMState `json:"states"`

	// ISM template for automatic policy assignment
	// +optional
	ISMTemplate []ISMTemplateConfig `json:"ismTemplate,omitempty"`
}

// ISMState defines a state in the ISM policy
type ISMState struct {
	// Name of the state
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Actions to perform in this state
	// +optional
	Actions []ISMAction `json:"actions,omitempty"`

	// Transitions to other states
	// +optional
	Transitions []ISMTransition `json:"transitions,omitempty"`
}

// ISMAction defines an action in an ISM state
type ISMAction struct {
	// Action configuration (raw JSON)
	// +kubebuilder:validation:Required
	Config *runtime.RawExtension `json:"config"`

	// Timeout for the action
	// +optional
	Timeout string `json:"timeout,omitempty"`

	// Retry configuration
	// +optional
	Retry *ISMRetryConfig `json:"retry,omitempty"`
}

// ISMRetryConfig defines retry configuration for an action
type ISMRetryConfig struct {
	// Number of retries
	// +optional
	// +kubebuilder:default=3
	Count int32 `json:"count,omitempty"`

	// Backoff strategy
	// +optional
	// +kubebuilder:validation:Enum=exponential;linear;constant
	// +kubebuilder:default="exponential"
	Backoff string `json:"backoff,omitempty"`

	// Delay between retries
	// +optional
	Delay string `json:"delay,omitempty"`
}

// ISMTransition defines a transition to another state
type ISMTransition struct {
	// State to transition to
	// +kubebuilder:validation:Required
	StateName string `json:"stateName"`

	// Conditions for the transition
	// +optional
	Conditions *ISMTransitionConditions `json:"conditions,omitempty"`
}

// ISMTransitionConditions defines conditions for state transition
type ISMTransitionConditions struct {
	// Minimum index age for transition
	// +optional
	MinIndexAge string `json:"minIndexAge,omitempty"`

	// Minimum document count for transition
	// +optional
	MinDocCount int64 `json:"minDocCount,omitempty"`

	// Minimum size for transition
	// +optional
	MinSize string `json:"minSize,omitempty"`

	// CRON expression for scheduled transition
	// +optional
	Cron *CronCondition `json:"cron,omitempty"`
}

// CronCondition defines a CRON-based condition
type CronCondition struct {
	// CRON expression
	// +kubebuilder:validation:Required
	Expression string `json:"expression"`

	// Timezone for CRON expression
	// +optional
	// +kubebuilder:default="UTC"
	Timezone string `json:"timezone,omitempty"`
}

// ISMTemplateConfig defines automatic policy assignment configuration
type ISMTemplateConfig struct {
	// Index patterns for automatic assignment
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	IndexPatterns []string `json:"indexPatterns"`

	// Priority for template matching
	// +optional
	Priority int32 `json:"priority,omitempty"`
}

// OpenSearchISMPolicyStatus defines the observed state of OpenSearchISMPolicy
type OpenSearchISMPolicyStatus struct {
	// Phase represents the current phase of the ISM policy
	// +optional
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations of the ISM policy's state
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

	// PolicyID in OpenSearch
	// +optional
	PolicyID string `json:"policyID,omitempty"`

	// AffectedIndices is the number of indices using this policy
	// +optional
	AffectedIndices int32 `json:"affectedIndices,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osism
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Default State",type=string,JSONPath=`.spec.defaultState`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drift",type=boolean,JSONPath=`.status.driftDetected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchISMPolicy is the Schema for the opensearchismpolicies API
type OpenSearchISMPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchISMPolicySpec   `json:"spec,omitempty"`
	Status OpenSearchISMPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchISMPolicyList contains a list of OpenSearchISMPolicy
type OpenSearchISMPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchISMPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchISMPolicy{}, &OpenSearchISMPolicyList{})
}
