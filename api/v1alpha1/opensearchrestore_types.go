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

// OpenSearchRestoreSpec defines the desired state of OpenSearchRestore
type OpenSearchRestoreSpec struct {
	// ClusterRef references the WazuhCluster this restore belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Repository is the name of the snapshot repository
	// +kubebuilder:validation:Required
	Repository string `json:"repository"`

	// Snapshot is the name of the snapshot to restore
	// +kubebuilder:validation:Required
	Snapshot string `json:"snapshot"`

	// Indices are index patterns to restore
	// If empty, all indices from the snapshot are restored
	// +optional
	Indices []string `json:"indices,omitempty"`

	// IgnoreUnavailable skips missing indices during restore
	// +kubebuilder:default=true
	IgnoreUnavailable bool `json:"ignoreUnavailable,omitempty"`

	// IncludeGlobalState restores cluster state from the snapshot
	// +kubebuilder:default=false
	IncludeGlobalState bool `json:"includeGlobalState,omitempty"`

	// RenamePattern is a regex pattern to match index names
	// Used with RenameReplacement to rename indices during restore
	// Example: "(.+)" to match all indices
	// +optional
	RenamePattern string `json:"renamePattern,omitempty"`

	// RenameReplacement is the replacement string for renamed indices
	// Example: "restored-$1" to prefix with "restored-"
	// +optional
	RenameReplacement string `json:"renameReplacement,omitempty"`

	// IndexSettings are settings to override during restore
	// Example: {"index.number_of_replicas": "0"} for faster restore
	// +optional
	IndexSettings map[string]string `json:"indexSettings,omitempty"`

	// Partial allows restoring partial snapshots (some shards may fail)
	// +kubebuilder:default=false
	Partial bool `json:"partial,omitempty"`

	// WaitForCompletion blocks until restore completes
	// +kubebuilder:default=true
	WaitForCompletion bool `json:"waitForCompletion,omitempty"`
}

// OpenSearchRestoreStatus defines the observed state of OpenSearchRestore
type OpenSearchRestoreStatus struct {
	// Phase is the current phase (Pending, Validating, InProgress, Completed, Failed)
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// StartTime is when the restore started
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// EndTime is when the restore completed
	// +optional
	EndTime *metav1.Time `json:"endTime,omitempty"`

	// Duration is the restore duration (human-readable)
	// +optional
	Duration string `json:"duration,omitempty"`

	// RestoredIndices are the indices that were restored
	// +optional
	RestoredIndices []string `json:"restoredIndices,omitempty"`

	// Shards contains shard statistics
	// +optional
	Shards *ShardStats `json:"shards,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osrestore
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Snapshot",type=string,JSONPath=`.spec.snapshot`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Duration",type=string,JSONPath=`.status.duration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchRestore is the Schema for restoring indices from OpenSearch snapshots
type OpenSearchRestore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchRestoreSpec   `json:"spec,omitempty"`
	Status OpenSearchRestoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchRestoreList contains a list of OpenSearchRestore
type OpenSearchRestoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchRestore `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchRestore{}, &OpenSearchRestoreList{})
}
