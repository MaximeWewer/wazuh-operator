package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhDecoderSpec defines the desired state of WazuhDecoder
type WazuhDecoderSpec struct {
	// ClusterRef references the WazuhCluster this decoder belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Name of the decoder
	// +kubebuilder:validation:Required
	DecoderName string `json:"decoderName"`

	// Decoders contain the actual decoder definitions in XML format
	// +kubebuilder:validation:Required
	Decoders string `json:"decoders"`

	// Description of the decoder set
	// +optional
	Description string `json:"description,omitempty"`

	// TargetNodes specifies which nodes should receive this decoder (master, workers, or all)
	// +optional
	// +kubebuilder:validation:Enum=master;workers;all
	// +kubebuilder:default="all"
	TargetNodes string `json:"targetNodes,omitempty"`

	// Priority determines the order in which decoders are applied (lower values = higher priority)
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	// +kubebuilder:default=500
	Priority int32 `json:"priority,omitempty"`

	// Overwrite determines if this decoder should overwrite existing decoders
	// +optional
	Overwrite bool `json:"overwrite,omitempty"`

	// ParentDecoder specifies the parent decoder if this is a child decoder
	// +optional
	ParentDecoder string `json:"parentDecoder,omitempty"`
}

// WazuhDecoderStatus defines the observed state of WazuhDecoder
type WazuhDecoderStatus struct {
	// Phase of the decoder (Pending, Applied, Failed)
	// +optional
	Phase DecoderPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// AppliedToNodes lists the nodes where this decoder has been applied
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the ConfigMap containing the decoder
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the decoder was applied
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed decoder
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// ValidationErrors contains any validation errors encountered
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`
}

// DecoderPhase represents the phase of the decoder
// +kubebuilder:validation:Enum=Pending;Applied;Failed;Updating
type DecoderPhase string

const (
	DecoderPhasePending  DecoderPhase = "Pending"
	DecoderPhaseApplied  DecoderPhase = "Applied"
	DecoderPhaseFailed   DecoderPhase = "Failed"
	DecoderPhaseUpdating DecoderPhase = "Updating"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wdecoder
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Decoder",type=string,JSONPath=`.spec.decoderName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhDecoder is the Schema for the wazuhdecoders API
type WazuhDecoder struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhDecoderSpec   `json:"spec,omitempty"`
	Status WazuhDecoderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhDecoderList contains a list of WazuhDecoder
type WazuhDecoderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhDecoder `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhDecoder{}, &WazuhDecoderList{})
}
