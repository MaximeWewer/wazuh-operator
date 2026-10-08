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

// OpenSearchDashboardObjectSpec defines the desired state of OpenSearchDashboardObject
type OpenSearchDashboardObjectSpec struct {
	// ClusterRefs lists the WazuhCluster instances this resource targets.
	// Each entry must specify both name and namespace.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// Tenant is the OpenSearch Dashboards tenant the objects are imported into: "global"
	// (shared, the default), "private" (the operator admin user's private tenant) or the
	// name of a custom tenant (see OpenSearchTenant). An empty value sends no tenant and
	// lets the dashboard pick the admin user's default tenant - its private one when
	// multi-tenancy is enabled, as on a stock Wazuh dashboard - so the objects would not be
	// visible to other users.
	// +optional
	// +kubebuilder:default="global"
	// +kubebuilder:validation:MaxLength=128
	Tenant string `json:"tenant,omitempty"`

	// Source holds the saved objects, as an NDJSON export from Dashboards
	// (Stack Management > Saved objects > Export).
	// +kubebuilder:validation:Required
	Source DashboardObjectSource `json:"source"`

	// ResyncInterval is how often the objects are re-imported even when the source did
	// not change. The source is the truth: any change made in the Dashboards UI to a
	// managed object is overwritten at the next sync.
	// +optional
	// +kubebuilder:default="10m"
	ResyncInterval *metav1.Duration `json:"resyncInterval,omitempty"`

	// Prune deletes the objects previously imported by this resource that are no longer
	// in the source. Objects that never came from this resource are never deleted.
	// +optional
	// +kubebuilder:default=true
	Prune *bool `json:"prune,omitempty"`
}

// DashboardObjectSource provides the NDJSON saved objects export, inline or from a
// ConfigMap in the resource's namespace. Exactly one must be set.
// +kubebuilder:validation:XValidation:rule="has(self.ndjson) != has(self.configMapRef)",message="exactly one of ndjson or configMapRef must be set"
type DashboardObjectSource struct {
	// NDJSON is the saved objects export, one JSON object per line.
	// +optional
	NDJSON string `json:"ndjson,omitempty"`

	// ConfigMapRef reads the export from a ConfigMap key in the resource's namespace;
	// changes to the ConfigMap are picked up immediately.
	// +optional
	ConfigMapRef *DashboardObjectConfigMapRef `json:"configMapRef,omitempty"`
}

// DashboardObjectConfigMapRef references a key of a ConfigMap in the resource's namespace.
type DashboardObjectConfigMapRef struct {
	// Name of the ConfigMap.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key holding the NDJSON export.
	// +optional
	// +kubebuilder:default="export.ndjson"
	Key string `json:"key,omitempty"`
}

// DashboardObjectStatusRef identifies a saved object managed by the resource.
type DashboardObjectStatusRef struct {
	// Type of the saved object (dashboard, visualization, index-pattern, search...).
	Type string `json:"type"`

	// ID of the saved object.
	ID string `json:"id"`
}

// OpenSearchDashboardObjectStatus defines the observed state of OpenSearchDashboardObject
type OpenSearchDashboardObjectStatus struct {
	// Phase is the current phase (Pending, Ready, Failed)
	// +optional
	Phase OpenSearchResourcePhase `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the objects were last imported on every target cluster
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []OpenSearchClusterStatus `json:"clusterStatuses,omitempty"`

	// LastAppliedHash is the hash of the last imported source content
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Tenant is the tenant the managed objects were imported into
	// +optional
	Tenant string `json:"tenant,omitempty"`

	// ObjectCount is the number of saved objects managed by this resource
	// +optional
	ObjectCount int `json:"objectCount,omitempty"`

	// Objects lists the saved objects managed by this resource, used to prune objects
	// removed from the source and to clean up on deletion.
	// +optional
	Objects []DashboardObjectStatusRef `json:"objects,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osdashobj
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.status.tenant`
// +kubebuilder:printcolumn:name="Objects",type=integer,JSONPath=`.status.objectCount`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchDashboardObject manages OpenSearch Dashboards saved objects (dashboards,
// visualizations, index patterns, saved searches) from an NDJSON export kept in Git.
type OpenSearchDashboardObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchDashboardObjectSpec   `json:"spec,omitempty"`
	Status OpenSearchDashboardObjectStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchDashboardObjectList contains a list of OpenSearchDashboardObject
type OpenSearchDashboardObjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchDashboardObject `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchDashboardObject{}, &OpenSearchDashboardObjectList{})
}
