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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WazuhManagerSpec defines the desired state of WazuhManager
type WazuhManagerSpec struct {
	// Version of Wazuh Manager to deploy
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+\.[0-9]+$`
	Version string `json:"version"`

	// Master node configuration
	// +kubebuilder:validation:Required
	Master WazuhMasterSpec `json:"master"`

	// Worker nodes configuration
	// +kubebuilder:validation:Required
	Workers WazuhWorkerSpec `json:"workers"`

	// Cluster key for internal communication
	// +optional
	ClusterKeySecretRef *corev1.SecretKeySelector `json:"clusterKeySecretRef,omitempty"`

	// API credentials
	// +optional
	APICredentials *CredentialsSecretRef `json:"apiCredentials,omitempty"`

	// Agent registration password
	// +optional
	AuthdPasswordSecretRef *corev1.SecretKeySelector `json:"authdPasswordSecretRef,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Custom configuration overlay
	// +optional
	Config *WazuhConfigSpec `json:"config,omitempty"`

	// Filebeat SSL verification mode
	// +optional
	// +kubebuilder:default="full"
	// +kubebuilder:validation:Enum=full;none;certificate
	FilebeatSSLVerificationMode string `json:"filebeatSSLVerificationMode,omitempty"`

	// Reference to the parent WazuhCluster
	// +optional
	ClusterRef *WazuhClusterReference `json:"clusterRef,omitempty"`

	// Image pull secrets for private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// Storage class to use for PVCs
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// WazuhManagerStatus defines the observed state of WazuhManager
type WazuhManagerStatus struct {
	// Phase of the manager (Pending, Creating, Running, Failed, Updating)
	// +optional
	Phase ComponentPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Master status
	// +optional
	Master *NodeStatus `json:"master,omitempty"`

	// Workers status
	// +optional
	Workers *NodeStatus `json:"workers,omitempty"`

	// Observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Last update time
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Version currently deployed
	// +optional
	Version string `json:"version,omitempty"`

	// Message provides additional information
	// +optional
	Message string `json:"message,omitempty"`
}

// NodeStatus represents the status of a node group
type NodeStatus struct {
	// Ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Total replicas
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Phase
	// +optional
	Phase string `json:"phase,omitempty"`
}

// ComponentPhase represents the phase of a component
// +kubebuilder:validation:Enum=Pending;Creating;Running;Failed;Updating;Upgrading
type ComponentPhase string

const (
	ComponentPhasePending   ComponentPhase = "Pending"
	ComponentPhaseCreating  ComponentPhase = "Creating"
	ComponentPhaseRunning   ComponentPhase = "Running"
	ComponentPhaseFailed    ComponentPhase = "Failed"
	ComponentPhaseUpdating  ComponentPhase = "Updating"
	ComponentPhaseUpgrading ComponentPhase = "Upgrading"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wmgr
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Master",type=string,JSONPath=`.status.master.phase`
// +kubebuilder:printcolumn:name="Workers",type=integer,JSONPath=`.status.workers.readyReplicas`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhManager is the Schema for the wazuhmanagers API
type WazuhManager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhManagerSpec   `json:"spec,omitempty"`
	Status WazuhManagerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhManagerList contains a list of WazuhManager
type WazuhManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhManager `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhManager{}, &WazuhManagerList{})
}
