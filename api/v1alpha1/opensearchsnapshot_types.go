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

// OpenSearchSnapshotSpec defines the desired state of OpenSearchSnapshot
type OpenSearchSnapshotSpec struct {
	// ClusterRef references the WazuhCluster this snapshot belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Repository is the name of the snapshot repository
	// The repository must exist (OpenSearchSnapshotRepository CRD)
	// +kubebuilder:validation:Required
	Repository string `json:"repository"`

	// Indices are index patterns to include in the snapshot
	// +kubebuilder:default={"wazuh-*"}
	Indices []string `json:"indices,omitempty"`

	// IgnoreUnavailable skips missing indices during snapshot
	// +kubebuilder:default=true
	IgnoreUnavailable bool `json:"ignoreUnavailable,omitempty"`

	// IncludeGlobalState includes cluster state in the snapshot
	// +kubebuilder:default=false
	IncludeGlobalState bool `json:"includeGlobalState,omitempty"`

	// Partial allows partial snapshots (some shards may fail)
	// +kubebuilder:default=false
	Partial bool `json:"partial,omitempty"`

	// WaitForCompletion blocks until snapshot completes
	// If false, snapshot is created asynchronously
	// +kubebuilder:default=true
	WaitForCompletion bool `json:"waitForCompletion,omitempty"`
}

// OpenSearchSnapshotStatus defines the observed state of OpenSearchSnapshot
type OpenSearchSnapshotStatus struct {
	// Phase is the current phase (Pending, InProgress, Completed, Failed, Partial)
	// +optional
	Phase string `json:"phase,omitempty"`

	// SnapshotName is the generated snapshot name in OpenSearch
	// Format: {crd-name}-{yyyyMMdd}-{HHmmss}
	// +optional
	SnapshotName string `json:"snapshotName,omitempty"`

	// State is the OpenSearch snapshot state (IN_PROGRESS, SUCCESS, FAILED, PARTIAL)
	// +optional
	State string `json:"state,omitempty"`

	// StartTime is when the snapshot started
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// EndTime is when the snapshot completed
	// +optional
	EndTime *metav1.Time `json:"endTime,omitempty"`

	// Duration is the snapshot duration (human-readable)
	// +optional
	Duration string `json:"duration,omitempty"`

	// Indices are the indices included in the snapshot
	// +optional
	Indices []string `json:"indices,omitempty"`

	// Shards contains shard statistics
	// +optional
	Shards *ShardStats `json:"shards,omitempty"`

	// TotalSize is the total snapshot size (human-readable)
	// +optional
	TotalSize string `json:"totalSize,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ossnapshot
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Size",type=string,JSONPath=`.status.totalSize`
// +kubebuilder:printcolumn:name="Duration",type=string,JSONPath=`.status.duration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchSnapshot is the Schema for triggering manual OpenSearch snapshots
type OpenSearchSnapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchSnapshotSpec   `json:"spec,omitempty"`
	Status OpenSearchSnapshotStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchSnapshotList contains a list of OpenSearchSnapshot
type OpenSearchSnapshotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchSnapshot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchSnapshot{}, &OpenSearchSnapshotList{})
}
