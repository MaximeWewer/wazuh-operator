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

// IndexerNodeRole represents an OpenSearch node role
// +kubebuilder:validation:Enum=cluster_manager;data;ingest;search;coordinating_only;ml;remote_cluster_client
type IndexerNodeRole string

const (
	// IndexerNodeRoleClusterManager is the cluster manager (master) role
	IndexerNodeRoleClusterManager IndexerNodeRole = "cluster_manager"

	// IndexerNodeRoleData is the data node role
	IndexerNodeRoleData IndexerNodeRole = "data"

	// IndexerNodeRoleIngest is the ingest pipeline role
	IndexerNodeRoleIngest IndexerNodeRole = "ingest"

	// IndexerNodeRoleSearch is the search node role
	// Dedicated nodes for search operations
	IndexerNodeRoleSearch IndexerNodeRole = "search"

	// IndexerNodeRoleCoordinatingOnly is the coordinating-only role
	// Note: In OpenSearch, this is represented by an empty roles array
	IndexerNodeRoleCoordinatingOnly IndexerNodeRole = "coordinating_only"

	// IndexerNodeRoleML is the machine learning role
	IndexerNodeRoleML IndexerNodeRole = "ml"

	// IndexerNodeRoleRemoteClusterClient is for cross-cluster operations
	IndexerNodeRoleRemoteClusterClient IndexerNodeRole = "remote_cluster_client"
)

// IndexerNodePoolSpec defines a pool of OpenSearch indexer nodes with identical configuration
type IndexerNodePoolSpec struct {
	// Name is the unique identifier for this nodePool
	// Used in StatefulSet naming: {cluster}-indexer-{name}
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=15
	Name string `json:"name"`

	// Replicas is the number of nodes in this pool
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	Replicas int32 `json:"replicas"`

	// Roles defines the OpenSearch roles for nodes in this pool
	// Valid values: cluster_manager, data, ingest, coordinating_only, ml, remote_cluster_client
	// Empty array means coordinating-only node
	// +kubebuilder:validation:Optional
	Roles []IndexerNodeRole `json:"roles,omitempty"`

	// Attributes are custom key-value pairs for shard allocation awareness
	// Rendered as node.attr.<key>: <value> in opensearch.yml
	// Common uses: {temp: hot}, {zone: az-1}, {rack: rack-1}
	// +optional
	Attributes map[string]string `json:"attributes,omitempty"`

	// Resources defines CPU/memory requests and limits
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// StorageSize is the PVC storage request for data nodes
	// +kubebuilder:default="50Gi"
	StorageSize string `json:"storageSize,omitempty"`

	// StorageClass is the StorageClass name for PVCs
	// If not specified, uses cluster default
	// +optional
	StorageClass *string `json:"storageClass,omitempty"`

	// JavaOpts sets JVM options for nodes in this pool
	// +optional
	// +kubebuilder:default="-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"
	JavaOpts string `json:"javaOpts,omitempty"`

	// NodeSelector for pod scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for pod scheduling
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity for pod scheduling
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// PodDisruptionBudget configuration for this pool
	// +optional
	PodDisruptionBudget *PodDisruptionBudgetSpec `json:"podDisruptionBudget,omitempty"`

	// Annotations for the StatefulSet
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// PodAnnotations for pods in this pool
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`
}

// NodePoolStatus represents the observed state of a nodePool
type NodePoolStatus struct {
	// Name matches the nodePool spec name
	Name string `json:"name"`

	// Replicas is the desired replica count
	Replicas int32 `json:"replicas"`

	// ReadyReplicas is the number of ready pods
	ReadyReplicas int32 `json:"readyReplicas"`

	// Phase indicates the nodePool state
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Scaling;Draining;Failed
	Phase string `json:"phase,omitempty"`

	// Message provides additional status information
	// +optional
	Message string `json:"message,omitempty"`

	// StatefulSetName is the name of the associated StatefulSet
	// +optional
	StatefulSetName string `json:"statefulSetName,omitempty"`

	// LastTransitionTime is when the phase last changed
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// NodePool phase constants
const (
	NodePoolPhasePending  = "Pending"
	NodePoolPhaseCreating = "Creating"
	NodePoolPhaseRunning  = "Running"
	NodePoolPhaseScaling  = "Scaling"
	NodePoolPhaseDraining = "Draining"
	NodePoolPhaseFailed   = "Failed"
)

// GetRolesAsStrings returns the roles as a slice of strings
func (p *IndexerNodePoolSpec) GetRolesAsStrings() []string {
	roles := make([]string, 0, len(p.Roles))
	for _, role := range p.Roles {
		roles = append(roles, string(role))
	}
	return roles
}

// HasRole checks if the nodePool has a specific role
func (p *IndexerNodePoolSpec) HasRole(role IndexerNodeRole) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasClusterManagerRole checks if the nodePool has the cluster_manager role
func (p *IndexerNodePoolSpec) HasClusterManagerRole() bool {
	return p.HasRole(IndexerNodeRoleClusterManager)
}

// HasDataRole checks if the nodePool has the data role
func (p *IndexerNodePoolSpec) HasDataRole() bool {
	return p.HasRole(IndexerNodeRoleData)
}

// IsCoordinatingOnly checks if the nodePool is a coordinating-only node
// In OpenSearch, coordinating-only nodes have an empty roles array
func (p *IndexerNodePoolSpec) IsCoordinatingOnly() bool {
	if len(p.Roles) == 0 {
		return true
	}
	// Also check if only coordinating_only is specified (for CRD clarity)
	return len(p.Roles) == 1 && p.Roles[0] == IndexerNodeRoleCoordinatingOnly
}
