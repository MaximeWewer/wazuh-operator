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

// CDBListFormat describes how raw content (from content or source) is interpreted.
// +kubebuilder:validation:Enum=cdb;iplist;keylist
type CDBListFormat string

const (
	// CDBListFormatCDB means the content is already in CDB list format (key:value lines).
	CDBListFormatCDB CDBListFormat = "cdb"
	// CDBListFormatIPList means the content is a plain IP/CIDR list that the operator
	// converts to CDB list format (equivalent to Wazuh's iplist-to-cdblist.py script).
	CDBListFormatIPList CDBListFormat = "iplist"
	// CDBListFormatKeyList means the content is a plain list of keys (one per line) that
	// the operator converts to key-only CDB entries ("key:"). Generic converter for hash
	// lists (e.g. VirusShare MD5 dumps), domain lists, user lists, etc. Lines that already
	// contain ":" are kept as-is.
	CDBListFormatKeyList CDBListFormat = "keylist"
)

// CDBListEntry is a single key/value pair in a CDB list.
type CDBListEntry struct {
	// Key is the lookup key (left side of the "key:value" line). Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// Value is the optional value associated with the key (right side of "key:value").
	// Leave empty for key-only lists (e.g. IP blocklists), which render as "key:".
	// +optional
	Value string `json:"value,omitempty"`
}

// CDBListSource fetches the CDB list content from a remote URL.
// Wazuh managers cannot fetch URLs themselves: the operator performs the GET and
// bakes the resulting content into the mounted ConfigMap.
type CDBListSource struct {
	// URL to fetch the list content from (http or https).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://.+`
	URL string `json:"url"`

	// RefreshInterval controls how often the operator re-fetches the URL.
	// Omit or set to "0" to fetch once (re-fetch only when the CR spec changes).
	// Format is a Go duration string, e.g. "1h", "30m".
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`

	// InsecureSkipVerify disables TLS certificate verification for https URLs.
	// +optional
	// +kubebuilder:default=false
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// HeadersSecretRef references a Secret whose key/value pairs are sent as HTTP
	// request headers (e.g. an "Authorization" key). The Secret must live in the
	// same namespace as the WazuhCDBList CR.
	// +optional
	HeadersSecretRef *SecretReference `json:"headersSecretRef,omitempty"`
}

// WazuhCDBListSpec defines the desired state of WazuhCDBList.
// Exactly one content source must be provided: entries, content, or source.
type WazuhCDBListSpec struct {
	// ClusterRefs lists the WazuhCluster instances the CDB list must be applied to.
	// Each entry must specify both name and namespace. The CR can live in any
	// namespace; list ConfigMaps are created in each target cluster's namespace and
	// the operator injects the matching <list> entry into each manager's ossec.conf.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	ClusterRefs []WazuhClusterRef `json:"clusterRefs"`

	// ListName is the CDB list path (without extension) created under
	// /var/ossec/etc/lists/ on the manager. A single filename (e.g. "blocked-ips")
	// or a subdirectory path (e.g. "malicious-ioc/malicious-ip") is allowed; the
	// operator mounts the file at /var/ossec/etc/lists/<listName> and injects the
	// matching <list>etc/lists/<listName></list> entry. Each path segment must be a
	// safe name (no ".", "..", leading/trailing/double slash).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`
	ListName string `json:"listName"`

	// Description of the CDB list.
	// +optional
	Description string `json:"description,omitempty"`

	// TargetNodes specifies which manager nodes receive this list (master, workers, or all).
	// +optional
	// +kubebuilder:validation:Enum=master;workers;all
	// +kubebuilder:default="all"
	TargetNodes string `json:"targetNodes,omitempty"`

	// Entries is a static, inline list of key/value pairs. Mutually exclusive with
	// content and source. The format field is ignored for entries.
	// +optional
	// +listType=atomic
	Entries []CDBListEntry `json:"entries,omitempty"`

	// Content is raw inline list content. Interpreted according to format
	// (CDB format as-is, or an IP list converted to CDB). Mutually exclusive with
	// entries and source.
	// +optional
	Content string `json:"content,omitempty"`

	// Source fetches raw list content from a URL. Interpreted according to format.
	// Mutually exclusive with entries and content.
	// +optional
	Source *CDBListSource `json:"source,omitempty"`

	// Format controls how raw content (content or source) is interpreted:
	// "cdb" (already CDB-formatted, default), "iplist" (a plain IP/CIDR list the operator
	// converts to CDB format), or "keylist" (a plain list of keys - hashes, domains,
	// users - converted to key-only entries). Ignored when entries is used.
	// +optional
	// +kubebuilder:default="cdb"
	Format CDBListFormat `json:"format,omitempty"`

	// SkipLines drops the first N lines of raw content (content or source) before
	// conversion, e.g. to strip a file header (VirusShare hash dumps start with a
	// commented header). Ignored when entries is used.
	// +optional
	// +kubebuilder:validation:Minimum=0
	SkipLines int32 `json:"skipLines,omitempty"`
}

// WazuhCDBListStatus defines the observed state of WazuhCDBList.
type WazuhCDBListStatus struct {
	// Phase is the aggregate phase across all target clusters.
	// +optional
	Phase CDBListPhase `json:"phase,omitempty"`

	// Conditions represent the latest aggregate observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration reflects the generation of the most recently observed list.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional aggregate information about the current state.
	// +optional
	Message string `json:"message,omitempty"`

	// ValidationErrors contains any validation errors encountered.
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`

	// EntryCount is the number of key/value entries in the resolved list.
	// +optional
	EntryCount int32 `json:"entryCount,omitempty"`

	// ContentHash is a short hash of the resolved list content, used for change detection.
	// +optional
	ContentHash string `json:"contentHash,omitempty"`

	// LastFetchTime is the last time source content was fetched from the URL.
	// +optional
	LastFetchTime *metav1.Time `json:"lastFetchTime,omitempty"`

	// ClusterStatuses reports per-target-cluster reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +listMapKey=namespace
	// +optional
	ClusterStatuses []CDBListClusterStatus `json:"clusterStatuses,omitempty"`
}

// CDBListClusterStatus reports the reconciliation state for a single target cluster.
type CDBListClusterStatus struct {
	// Name of the target WazuhCluster.
	Name string `json:"name"`

	// Namespace of the target WazuhCluster.
	Namespace string `json:"namespace"`

	// Phase on this cluster.
	// +optional
	Phase CDBListPhase `json:"phase,omitempty"`

	// DeliveryMode reports how the list is delivered to the manager on this cluster:
	// "configmap" (content baked into a mounted ConfigMap) or "initFetch" (content over
	// the ConfigMap size limit, fetched by a busybox init container into the PVC).
	// +optional
	// +kubebuilder:validation:Enum=configmap;initFetch
	DeliveryMode string `json:"deliveryMode,omitempty"`

	// AppliedToNodes lists the nodes where this list has been applied on this cluster.
	// +optional
	AppliedToNodes []string `json:"appliedToNodes,omitempty"`

	// ConfigMapRef references the ConfigMap created in this cluster's namespace.
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is the last time the list was applied to this cluster.
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// Message provides additional information about this cluster's state.
	// +optional
	Message string `json:"message,omitempty"`
}

// CDBListPhase represents the phase of the CDB list.
// +kubebuilder:validation:Enum=Pending;Applied;Failed;Updating
type CDBListPhase string

const (
	CDBListPhasePending  CDBListPhase = "Pending"
	CDBListPhaseApplied  CDBListPhase = "Applied"
	CDBListPhaseFailed   CDBListPhase = "Failed"
	CDBListPhaseUpdating CDBListPhase = "Updating"
)

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wcdb
// +kubebuilder:printcolumn:name="List",type=string,JSONPath=`.spec.listName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Entries",type=integer,JSONPath=`.status.entryCount`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhCDBList is the Schema for the wazuhcdblists API.
type WazuhCDBList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhCDBList
	// +required
	Spec WazuhCDBListSpec `json:"spec"`

	// status defines the observed state of WazuhCDBList
	// +optional
	Status WazuhCDBListStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhCDBListList contains a list of WazuhCDBList.
type WazuhCDBListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhCDBList `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhCDBList{}, &WazuhCDBListList{})
}
