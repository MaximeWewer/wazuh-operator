package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhDecoderSpec defines the desired state of WazuhDecoder
type WazuhDecoderSpec struct {
	// ClusterRefs lists the WazuhCluster instances the decoder must be applied to.
	// Each entry must specify both name and namespace. The CR can live in any
	// namespace; decoder ConfigMaps are created in each target cluster's namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

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
	// Phase is the aggregate phase across all target clusters.
	// +optional
	Phase DecoderPhase `json:"phase,omitempty"`

	// Conditions represent the latest aggregate observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed decoder
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional aggregate information about the current state
	// +optional
	Message string `json:"message,omitempty"`

	// ValidationErrors contains any validation errors encountered
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []DecoderClusterStatus `json:"clusterStatuses,omitempty"`
}

// DecoderClusterStatus reports the reconciliation state for a single target cluster.
type DecoderClusterStatus struct {
	// Name of the target WazuhCluster
	Name string `json:"name"`

	// Namespace of the target WazuhCluster
	Namespace string `json:"namespace"`

	// Phase on this cluster
	// +optional
	Phase DecoderPhase `json:"phase,omitempty"`

	// AppliedToNodes lists the nodes where this decoder has been applied on this cluster
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the ConfigMap created in this cluster's namespace
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the decoder was applied to this cluster
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// Message provides additional information about this cluster's state
	// +optional
	Message string `json:"message,omitempty"`
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
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wdecoder
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
