package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhIntegrationSpec defines the desired state of WazuhIntegration.
//
// A WazuhIntegration provisions a Wazuh "custom integration": it ships an
// executable script to /var/ossec/integrations/<integrationName> on the target
// manager nodes AND injects the matching <integration> block into ossec.conf so
// wazuh-integratord forwards alerts to the script.
// See https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html
type WazuhIntegrationSpec struct {
	// ClusterRefs lists the WazuhCluster instances the integration must be applied to.
	// Each entry must specify both name and namespace. The CR can live in any
	// namespace; the script ConfigMap is created in each target cluster's namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Name is the integration's logical name WITHOUT the "custom-" prefix
	// (e.g. "jira"). The operator forces the Wazuh custom-integration convention:
	// the script filename and the <integration> <name> tag are both derived as
	// custom-<name>[.<scriptExtension>] (see ScriptName).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9_-]+$`
	// +kubebuilder:validation:MaxLength=50
	Name string `json:"name"`

	// ScriptExtension is the optional file extension (without the leading dot)
	// appended to the generated script filename, e.g. "py" → custom-<name>.py,
	// "sh" → custom-<name>.sh. When empty the script is named custom-<name>.
	// wazuh-integratord executes the file named exactly like the <name> tag, so
	// the operator keeps both in sync.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]+$`
	// +kubebuilder:validation:MaxLength=10
	ScriptExtension string `json:"scriptExtension,omitempty"`

	// Script is the content of the integration executable. It is mounted with
	// mode 0750 at /var/ossec/integrations/<integrationName>. The first line
	// must be a shebang (e.g. "#!/usr/bin/env python3" or "#!/bin/sh").
	// +kubebuilder:validation:Required
	Script string `json:"script"`

	// HookURL is the endpoint passed to the script (argv[3]) and rendered as
	// <hook_url>. Use HookURLSecretRef instead when the URL is sensitive.
	// +optional
	HookURL string `json:"hookURL,omitempty"`

	// HookURLSecretRef reads the hook URL from a Secret in the target cluster's
	// namespace. When set, it overrides HookURL.
	// +optional
	HookURLSecretRef *corev1.SecretKeySelector `json:"hookURLSecretRef,omitempty"`

	// APIKeySecretRef reads the integration API key from a Secret in the target
	// cluster's namespace. The resolved value is rendered as <api_key> in
	// ossec.conf and passed to the script (argv[2]).
	// +optional
	APIKeySecretRef *corev1.SecretKeySelector `json:"apiKeySecretRef,omitempty"`

	// Level filters alerts by minimum severity level before they reach the integration.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=16
	Level *int32 `json:"level,omitempty"`

	// RuleID filters alerts so only the listed rule IDs are forwarded (<rule_id>).
	// +optional
	RuleID []int32 `json:"ruleID,omitempty"`

	// Group filters alerts by rule group (<group>). Comma-separated groups are allowed.
	// +optional
	Group string `json:"group,omitempty"`

	// EventLocation filters alerts by their source location (<location>).
	// +optional
	EventLocation string `json:"eventLocation,omitempty"`

	// AlertFormat controls the format of the alert handed to the script (<alert_format>).
	// "json" passes a JSON alert file (recommended for custom scripts).
	// +optional
	// +kubebuilder:validation:Enum=json;full_log
	// +kubebuilder:default="json"
	AlertFormat string `json:"alertFormat,omitempty"`

	// Options is an optional raw JSON string rendered inside <options>...</options>,
	// forwarded verbatim to the integration.
	// +optional
	Options string `json:"options,omitempty"`

	// TargetNodes selects which manager nodes receive the integration (master, workers, or all).
	// +optional
	// +kubebuilder:validation:Enum=master;workers;all
	// +kubebuilder:default="all"
	TargetNodes string `json:"targetNodes,omitempty"`
}

// WazuhIntegrationStatus defines the observed state of WazuhIntegration.
type WazuhIntegrationStatus struct {
	// Phase is the aggregate phase across all target clusters.
	// +optional
	Phase IntegrationPhase `json:"phase,omitempty"`

	// Conditions represent the latest aggregate observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed integration.
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
	ClusterStatuses []IntegrationClusterStatus `json:"clusterStatuses,omitempty"`
}

// IntegrationClusterStatus reports the reconciliation state for a single target cluster.
type IntegrationClusterStatus struct {
	// Name of the target WazuhCluster.
	Name string `json:"name"`

	// Namespace of the target WazuhCluster.
	Namespace string `json:"namespace"`

	// Phase on this cluster.
	// +optional
	Phase IntegrationPhase `json:"phase,omitempty"`

	// AppliedToNodes lists the nodes where this integration has been applied on this cluster.
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the script ConfigMap created in this cluster's namespace.
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the integration was applied to this cluster.
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// Message provides additional information about this cluster's state.
	// +optional
	Message string `json:"message,omitempty"`
}

// IntegrationPhase represents the phase of the integration.
// +kubebuilder:validation:Enum=Pending;Applied;Failed;Updating
type IntegrationPhase string

const (
	IntegrationPhasePending  IntegrationPhase = "Pending"
	IntegrationPhaseApplied  IntegrationPhase = "Applied"
	IntegrationPhaseFailed   IntegrationPhase = "Failed"
	IntegrationPhaseUpdating IntegrationPhase = "Updating"
)

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wintegration
// +kubebuilder:printcolumn:name="Integration",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhIntegration is the Schema for the wazuhintegrations API.
type WazuhIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhIntegrationSpec   `json:"spec,omitempty"`
	Status WazuhIntegrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhIntegrationList contains a list of WazuhIntegration.
type WazuhIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhIntegration `json:"items"`
}

// ScriptName returns the Wazuh custom-integration script filename, which is also
// the value used for the <integration> <name> tag so that wazuh-integratord
// executes the right file. It is custom-<name> with an optional .<scriptExtension>.
func (s *WazuhIntegrationSpec) ScriptName() string {
	name := "custom-" + s.Name
	if s.ScriptExtension != "" {
		name += "." + s.ScriptExtension
	}
	return name
}

func init() {
	SchemeBuilder.Register(&WazuhIntegration{}, &WazuhIntegrationList{})
}
