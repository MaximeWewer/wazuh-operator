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

// WazuhAgentGroupAssignmentSpec defines the desired state of a group assignment.
//
// Semantics are authoritative-UNION and cluster-global: several
// WazuhAgentGroupAssignment CRs may match the same agent, and a matched agent is
// reconciled to the UNION of Spec.Groups across every CR whose selector matches
// it on that cluster. Any group on a managed agent that no matching CR asks for
// is removed (so an agent is authoritatively pinned to the union, dropping
// stray default/linux/manual groups). An agent matched by NO CR is left entirely
// untouched. Agents are matched dynamically, so newly registered agents matching
// a pattern are picked up on the next reconcile without a spec change.
//
// Note: membership is not historically tracked. If an agent stops being matched
// by any CR (e.g. the CR is deleted or its selector changes), the agent is left
// as-is on the next global reconcile; only a finalizer delete actively reverts
// this CR's own group contributions.
type WazuhAgentGroupAssignmentSpec struct {
	// ClusterRefs lists the WazuhCluster instances this assignment targets.
	// Each entry must specify both name and namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Groups is the exact set of groups every matched agent must belong to.
	// Membership is authoritative: groups on an agent that are not listed here
	// are removed (Wazuh reassigns "default" if an agent ends up group-less).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Groups []string `json:"groups"`

	// Selector describes how agents are matched by name. At least one of the
	// three lists must be non-empty (enforced by the validating webhook). An
	// agent matches if ANY entry in ANY list matches its name.
	// +kubebuilder:validation:Required
	Selector AgentSelector `json:"selector"`

	// ReconcileIntervalSeconds controls how often agents are re-scanned. Agents
	// register dynamically, so a new agent matching a pattern must be picked up
	// without a spec change. Minimum 15 seconds.
	// +kubebuilder:validation:Minimum=15
	// +kubebuilder:default=60
	ReconcileIntervalSeconds int `json:"reconcileIntervalSeconds,omitempty"`
}

// AgentSelector matches Wazuh agents by name.
type AgentSelector struct {
	// AgentNames matches agents by exact name.
	// +optional
	AgentNames []string `json:"agentNames,omitempty"`

	// NamePatterns matches agents by shell glob (Go path.Match semantics),
	// e.g. "web-*".
	// +optional
	NamePatterns []string `json:"namePatterns,omitempty"`

	// NameRegex matches agents by RE2 regular expression, e.g. "^web-\\d+$".
	// +optional
	NameRegex []string `json:"nameRegex,omitempty"`

	// OSPlatforms matches the agent's reported os.platform (the controlled short value:
	// ubuntu, debian, centos, redhat, amzn, windows, darwin, ...). Case-insensitive.
	// Note: macOS reports as "darwin"; the aliases "macos" and "osx" are accepted and
	// normalized to "darwin". os.version is intentionally NOT a selector - it is a
	// freeform string (e.g. "16.04.6 LTS (Xenial Xerus)") and cannot be matched reliably.
	// +optional
	OSPlatforms []string `json:"osPlatforms,omitempty"`

	// RequireOSPlatform turns osPlatforms into a restrictive filter (AND) instead
	// of an additive list (OR). When false (default), an agent matches if its name
	// OR its os.platform matches. When true, an agent must match osPlatforms and,
	// if any name list is set, a name entry too - e.g. "web-* but only on linux".
	// Requires osPlatforms to be non-empty (enforced by the validating webhook).
	// +optional
	RequireOSPlatform bool `json:"requireOsPlatform,omitempty"`

	// Exclude removes agents from the match. An agent matching ANY entry in ANY of
	// the exclude lists is never assigned, even if it matched the lists above.
	// +optional
	Exclude *AgentSelectorExclude `json:"exclude,omitempty"`
}

// AgentSelectorExclude lists agents to remove from a selector's match. An agent
// matching ANY entry in ANY list is excluded (OR semantics). Fields mirror the
// positive selector; there is no requireOsPlatform here - matching any excluded
// name or os.platform is enough to drop the agent.
type AgentSelectorExclude struct {
	// AgentNames excludes agents by exact name.
	// +optional
	AgentNames []string `json:"agentNames,omitempty"`

	// NamePatterns excludes agents by shell glob (Go path.Match semantics).
	// +optional
	NamePatterns []string `json:"namePatterns,omitempty"`

	// NameRegex excludes agents by RE2 regular expression.
	// +optional
	NameRegex []string `json:"nameRegex,omitempty"`

	// OSPlatforms excludes agents by reported os.platform (same controlled values
	// and aliases as the positive selector).
	// +optional
	OSPlatforms []string `json:"osPlatforms,omitempty"`
}

// WazuhAgentGroupAssignmentStatus defines the observed state.
type WazuhAgentGroupAssignmentStatus struct {
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
	ClusterStatuses []AgentGroupAssignmentClusterStatus `json:"clusterStatuses,omitempty"`
}

// AgentGroupAssignmentClusterStatus reports reconciliation state for a single
// cluster. Matched agent IDs are tracked per entry so the finalizer can revert
// this assignment's changes on delete.
type AgentGroupAssignmentClusterStatus struct {
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
	// Informational only: the reconciler always re-scans so dynamically
	// registered agents are picked up.
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// MatchedAgentCount is the number of agents matched on this cluster.
	// +optional
	MatchedAgentCount int32 `json:"matchedAgentCount,omitempty"`

	// ManagedAgentIDs are the agent IDs this CR currently manages on this
	// cluster. Used by the finalizer to revert group membership on delete.
	// +optional
	ManagedAgentIDs []string `json:"managedAgentIds,omitempty"`

	// Message provides additional information about this cluster's state.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=waga
// +kubebuilder:printcolumn:name="Groups",type=string,JSONPath=`.spec.groups`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhAgentGroupAssignment is the Schema for the wazuhagentgroupassignments API.
// It assigns Wazuh agents to groups (authoritative/exclusive) by matching agent
// names, via the Wazuh Manager API.
type WazuhAgentGroupAssignment struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhAgentGroupAssignment
	// +required
	Spec WazuhAgentGroupAssignmentSpec `json:"spec"`

	// status defines the observed state of WazuhAgentGroupAssignment
	// +optional
	Status WazuhAgentGroupAssignmentStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhAgentGroupAssignmentList contains a list of WazuhAgentGroupAssignment.
type WazuhAgentGroupAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhAgentGroupAssignment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhAgentGroupAssignment{}, &WazuhAgentGroupAssignmentList{})
}
