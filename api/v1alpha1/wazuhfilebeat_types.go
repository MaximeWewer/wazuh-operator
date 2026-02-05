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
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// WazuhFilebeatSpec defines the desired state of WazuhFilebeat
type WazuhFilebeatSpec struct {
	// ClusterRef references the WazuhCluster this configuration belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// Alerts configures the alerts module
	// +optional
	Alerts *FilebeatAlertsConfig `json:"alerts,omitempty"`

	// Archives configures the archives module
	// +optional
	Archives *FilebeatArchivesConfig `json:"archives,omitempty"`

	// Template configures the Wazuh index template
	// +optional
	Template *FilebeatTemplateConfig `json:"template,omitempty"`

	// Pipeline configures the ingest pipeline
	// +optional
	Pipeline *FilebeatPipelineConfig `json:"pipeline,omitempty"`

	// Logging configures Filebeat logging
	// +optional
	Logging *FilebeatLoggingConfig `json:"logging,omitempty"`

	// SSL configures SSL/TLS settings
	// +optional
	SSL *FilebeatSSLConfig `json:"ssl,omitempty"`

	// Output configures the OpenSearch output (optional override)
	// +optional
	Output *FilebeatOutputConfig `json:"output,omitempty"`
}

// FilebeatAlertsConfig configures the alerts module
type FilebeatAlertsConfig struct {
	// Enabled enables/disables alerts shipping
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`
}

// FilebeatArchivesConfig configures the archives module
type FilebeatArchivesConfig struct {
	// Enabled enables/disables archives shipping
	// +optional
	// +kubebuilder:default=false
	Enabled *bool `json:"enabled,omitempty"`
}

// FilebeatTemplateConfig configures the Wazuh index template
type FilebeatTemplateConfig struct {
	// Shards is the number of primary shards
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=3
	Shards *int32 `json:"shards,omitempty"`

	// Replicas is the number of replica shards
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=0
	Replicas *int32 `json:"replicas,omitempty"`

	// RefreshInterval is the index refresh interval
	// +optional
	// +kubebuilder:default="5s"
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// FieldLimit is the maximum number of fields per document
	// +optional
	// +kubebuilder:validation:Minimum=1000
	// +kubebuilder:validation:Maximum=100000
	// +kubebuilder:default=10000
	FieldLimit *int32 `json:"fieldLimit,omitempty"`

	// CustomTemplateRef references a ConfigMap containing a custom template
	// +optional
	CustomTemplateRef *ConfigMapKeySelector `json:"customTemplateRef,omitempty"`

	// AdditionalMappings allows adding custom field mappings
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	AdditionalMappings *runtime.RawExtension `json:"additionalMappings,omitempty"`
}

// FilebeatPipelineConfig configures the ingest pipeline
type FilebeatPipelineConfig struct {
	// GeoIPEnabled enables/disables GeoIP enrichment processors
	// +optional
	// +kubebuilder:default=true
	GeoIPEnabled *bool `json:"geoipEnabled,omitempty"`

	// IndexPrefix is the prefix for index names
	// +optional
	// +kubebuilder:default="wazuh-alerts-4.x"
	IndexPrefix string `json:"indexPrefix,omitempty"`

	// AdditionalRemoveFields specifies additional fields to remove
	// +optional
	AdditionalRemoveFields []string `json:"additionalRemoveFields,omitempty"`

	// TimestampFormat is the format for parsing timestamps
	// +optional
	// +kubebuilder:default="ISO8601"
	TimestampFormat string `json:"timestampFormat,omitempty"`

	// CustomPipelineRef references a ConfigMap containing a custom pipeline
	// +optional
	CustomPipelineRef *ConfigMapKeySelector `json:"customPipelineRef,omitempty"`
}

// FilebeatLoggingConfig configures Filebeat logging
type FilebeatLoggingConfig struct {
	// Level is the logging level
	// +optional
	// +kubebuilder:validation:Enum=debug;info;warning;error
	// +kubebuilder:default="info"
	Level string `json:"level,omitempty"`

	// ToFiles enables logging to files
	// +optional
	// +kubebuilder:default=true
	ToFiles *bool `json:"toFiles,omitempty"`

	// KeepFiles is the number of log files to retain
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=7
	KeepFiles *int32 `json:"keepFiles,omitempty"`
}

// FilebeatSSLConfig configures SSL/TLS settings
type FilebeatSSLConfig struct {
	// VerificationMode is the SSL verification mode
	// +optional
	// +kubebuilder:validation:Enum=full;certificate;none
	// +kubebuilder:default="full"
	VerificationMode string `json:"verificationMode,omitempty"`

	// CACertSecretRef references a Secret containing the CA certificate
	// +optional
	CACertSecretRef *SecretKeyRef `json:"caCertSecretRef,omitempty"`

	// ClientCertSecretRef references a Secret containing the client certificate
	// +optional
	ClientCertSecretRef *SecretKeyRef `json:"clientCertSecretRef,omitempty"`

	// ClientKeySecretRef references a Secret containing the client key
	// +optional
	ClientKeySecretRef *SecretKeyRef `json:"clientKeySecretRef,omitempty"`
}

// FilebeatOutputConfig configures the OpenSearch output
type FilebeatOutputConfig struct {
	// Hosts is a list of OpenSearch hosts
	// +optional
	Hosts []string `json:"hosts,omitempty"`

	// CredentialsSecretRef references a Secret containing credentials
	// +optional
	CredentialsSecretRef *CredentialsSecretRef `json:"credentialsSecretRef,omitempty"`

	// Protocol is the protocol to use (http or https)
	// +optional
	// +kubebuilder:validation:Enum=http;https
	// +kubebuilder:default="https"
	Protocol string `json:"protocol,omitempty"`

	// Port is the OpenSearch port
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=9200
	Port *int32 `json:"port,omitempty"`
}

// ConfigMapKeySelector references a specific key in a ConfigMap
type ConfigMapKeySelector struct {
	// Name is the ConfigMap name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key is the key in the ConfigMap
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// FilebeatPhase represents the phase of the WazuhFilebeat resource
// +kubebuilder:validation:Enum=Pending;Ready;Failed;Updating
type FilebeatPhase string

const (
	FilebeatPhasePending  FilebeatPhase = "Pending"
	FilebeatPhaseReady    FilebeatPhase = "Ready"
	FilebeatPhaseFailed   FilebeatPhase = "Failed"
	FilebeatPhaseUpdating FilebeatPhase = "Updating"
)

// WazuhFilebeatStatus defines the observed state of WazuhFilebeat
type WazuhFilebeatStatus struct {
	// Phase represents the current phase
	// +optional
	Phase FilebeatPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ConfigMapRef references the generated ConfigMap
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`

	// LastAppliedTime is when the config was last applied
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Message provides additional information
	// +optional
	Message string `json:"message,omitempty"`

	// TemplateVersion is the version of the applied template
	// +optional
	TemplateVersion string `json:"templateVersion,omitempty"`

	// PipelineVersion is the version of the applied pipeline
	// +optional
	PipelineVersion string `json:"pipelineVersion,omitempty"`

	// ConfigHash is the hash of the current configuration
	// +optional
	ConfigHash string `json:"configHash,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wfb
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Alerts",type=boolean,JSONPath=`.spec.alerts.enabled`
// +kubebuilder:printcolumn:name="Archives",type=boolean,JSONPath=`.spec.archives.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhFilebeat is the Schema for the wazuhfilebeats API
type WazuhFilebeat struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of WazuhFilebeat
	// +required
	Spec WazuhFilebeatSpec `json:"spec"`

	// status defines the observed state of WazuhFilebeat
	// +optional
	Status WazuhFilebeatStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// WazuhFilebeatList contains a list of WazuhFilebeat
type WazuhFilebeatList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhFilebeat `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhFilebeat{}, &WazuhFilebeatList{})
}
