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

// WazuhWorkerCRDSpec defines the desired state of WazuhWorker CRD
// This is different from WazuhWorkerSpec which is used inline in WazuhManager
type WazuhWorkerCRDSpec struct {
	// Reference to the WazuhManager this worker belongs to
	// +kubebuilder:validation:Required
	ManagerRef string `json:"managerRef"`

	// Number of worker replicas
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=2
	Replicas int32 `json:"replicas,omitempty"`

	// Resources for worker nodes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for worker nodes
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// Storage class to use for PVCs
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Service configuration
	// +optional
	Service *ServiceSpec `json:"service,omitempty"`

	// Node selector
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Pod Disruption Budget
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Pod annotations
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Additional volumes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`

	// Additional volume mounts
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// Extra configuration to inject into ossec.conf
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`

	// Filebeat configuration
	// +optional
	Filebeat *FilebeatConfig `json:"filebeat,omitempty"`

	// Environment variables
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Environment variables from ConfigMaps or Secrets
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// Security context for the pod
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// Security context for the container
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// Image pull secrets for private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// FilebeatConfig defines Filebeat sidecar configuration for workers
type FilebeatConfig struct {
	// Enable Filebeat sidecar
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Filebeat resources
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Image override for Filebeat
	// +optional
	Image *ImageSpec `json:"image,omitempty"`
}

// WazuhWorkerStatus defines the observed state of WazuhWorker
type WazuhWorkerStatus struct {
	// Phase of the worker (Pending, Creating, Running, Failed, Updating)
	// +optional
	Phase ComponentPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Ready replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Total replicas
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

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

	// Node names where workers are running
	// +optional
	Nodes []string `json:"nodes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wwork
// +kubebuilder:printcolumn:name="Manager",type=string,JSONPath=`.spec.managerRef`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.status.replicas`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhWorker is the Schema for the wazuhworkers API
type WazuhWorker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhWorkerCRDSpec `json:"spec,omitempty"`
	Status WazuhWorkerStatus  `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhWorkerList contains a list of WazuhWorker
type WazuhWorkerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhWorker `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhWorker{}, &WazuhWorkerList{})
}
