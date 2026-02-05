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

// OpenSearchIndexerSpec defines the desired state of OpenSearchIndexer
type OpenSearchIndexerSpec struct {
	// Version of OpenSearch to deploy (auto-derived from Wazuh if clusterRef set)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[0-9]+\.[0-9]+\.[0-9]+$`
	Version string `json:"version"`

	// Reference to a WazuhCluster (optional)
	// +optional
	ClusterRef string `json:"clusterRef,omitempty"`

	// Number of indexer replicas
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas,omitempty"`

	// Resources for indexer nodes
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// Storage size for indexer nodes
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// Storage class to use for PVCs
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Image override
	// +optional
	Image *ImageSpec `json:"image,omitempty"`

	// Java options
	// +optional
	// +kubebuilder:default="-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"
	JavaOpts string `json:"javaOpts,omitempty"`

	// OpenSearch cluster name
	// +optional
	// +kubebuilder:default="wazuh"
	ClusterName string `json:"clusterName,omitempty"`

	// Credentials for indexer (admin user)
	// +optional
	Credentials *CredentialsSecretRef `json:"credentials,omitempty"`

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

	// Ingress configuration
	// +optional
	Ingress *IngressSpec `json:"ingress,omitempty"`

	// Network policy
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Update strategy
	// +optional
	// +kubebuilder:default="RollingUpdate"
	UpdateStrategy string `json:"updateStrategy,omitempty"`

	// Init containers for the indexer pods
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	InitContainers []corev1.Container `json:"initContainers,omitempty"`

	// Environment variables to add to the container
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

	// TLS configuration
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Custom opensearch.yml content
	// +optional
	Config *OpenSearchConfigSpec `json:"config,omitempty"`
}

// OpenSearchConfigSpec defines custom OpenSearch configuration
type OpenSearchConfigSpec struct {
	// Custom opensearch.yml content to merge with defaults
	// +optional
	OpenSearchYml string `json:"opensearchYml,omitempty"`

	// Custom JVM options
	// +optional
	JvmOptions string `json:"jvmOptions,omitempty"`

	// Custom log4j2.properties
	// +optional
	Log4j2Properties string `json:"log4j2Properties,omitempty"`
}

// OpenSearchIndexerStatus defines the observed state of OpenSearchIndexer
type OpenSearchIndexerStatus struct {
	// Phase of the indexer
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

	// Cluster health (green, yellow, red)
	// +optional
	Health string `json:"health,omitempty"`

	// Cluster UUID assigned by OpenSearch
	// +optional
	ClusterUUID string `json:"clusterUUID,omitempty"`

	// Number of nodes in the cluster
	// +optional
	NodesCount int32 `json:"nodesCount,omitempty"`

	// Data nodes count
	// +optional
	DataNodesCount int32 `json:"dataNodesCount,omitempty"`

	// Number of shards
	// +optional
	ActiveShards int32 `json:"activeShards,omitempty"`

	// Number of primary shards
	// +optional
	ActivePrimaryShards int32 `json:"activePrimaryShards,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osidxr
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.status.replicas`
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.health`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchIndexer is the Schema for the opensearchindexers API
type OpenSearchIndexer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchIndexerSpec   `json:"spec,omitempty"`
	Status OpenSearchIndexerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchIndexerList contains a list of OpenSearchIndexer
type OpenSearchIndexerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchIndexer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchIndexer{}, &OpenSearchIndexerList{})
}
