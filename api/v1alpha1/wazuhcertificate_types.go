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

// WazuhCertificateSpec defines the desired state of WazuhCertificate
type WazuhCertificateSpec struct {
	// Target cluster for certificate management
	// +kubebuilder:validation:Required
	ClusterRef string `json:"clusterRef"`

	// Certificate type (ca, node, admin, filebeat)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ca;node;admin;filebeat
	Type CertificateType `json:"type"`

	// Distinguished Name configuration
	// +optional
	DistinguishedName *DistinguishedNameConfig `json:"distinguishedName,omitempty"`

	// Certificate lifetime in days
	// +optional
	// +kubebuilder:default=365
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3650
	ValidityDays int `json:"validityDays,omitempty"`

	// Auto-renewal configuration
	// +optional
	AutoRenewal *AutoRenewalConfig `json:"autoRenewal,omitempty"`

	// Subject Alternative Names (explicit list)
	// +optional
	SANs []string `json:"sans,omitempty"`

	// Auto-generate SANs based on certificate type and cluster topology
	// When enabled, SANs are automatically generated based on the type:
	// - indexer: *.indexer-nodes.svc, all indexer pod names
	// - admin: localhost only (admin cert)
	// - node: general node SANs (same as indexer)
	// - filebeat: manager master/worker service names
	// - dashboard: dashboard service names
	// +optional
	AutoGenerateSANs *AutoGenerateSANsConfig `json:"autoGenerateSANs,omitempty"`

	// Secret name to store the certificate
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`

	// Enable hot-reload for OpenSearch (requires 2.13+)
	// +optional
	// +kubebuilder:default=false
	HotReload bool `json:"hotReload,omitempty"`

	// Key algorithm and size
	// +optional
	KeyConfig *KeyConfig `json:"keyConfig,omitempty"`
}

// CertificateType represents the type of certificate
// +kubebuilder:validation:Enum=ca;node;admin;filebeat;indexer;dashboard
type CertificateType string

const (
	CertificateTypeCA        CertificateType = "ca"
	CertificateTypeNode      CertificateType = "node"
	CertificateTypeAdmin     CertificateType = "admin"
	CertificateTypeFilebeat  CertificateType = "filebeat"
	CertificateTypeIndexer   CertificateType = "indexer"
	CertificateTypeDashboard CertificateType = "dashboard"
)

// DistinguishedNameConfig defines the X.509 Distinguished Name fields
type DistinguishedNameConfig struct {
	// Common Name (CN)
	// +kubebuilder:validation:Required
	CommonName string `json:"commonName"`

	// Organization (O)
	// +optional
	// +kubebuilder:default="Wazuh"
	Organization string `json:"organization,omitempty"`

	// Organizational Unit (OU)
	// +optional
	// +kubebuilder:default="Wazuh"
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`

	// Locality/City (L)
	// +optional
	// +kubebuilder:default="California"
	Locality string `json:"locality,omitempty"`

	// State/Province (ST)
	// +optional
	// +kubebuilder:default="California"
	State string `json:"state,omitempty"`

	// Country (C) - 2 letter code
	// +optional
	// +kubebuilder:default="US"
	// +kubebuilder:validation:Pattern=`^[A-Z]{2}$`
	Country string `json:"country,omitempty"`

	// Email Address
	// +optional
	EmailAddress string `json:"emailAddress,omitempty"`
}

// AutoRenewalConfig defines auto-renewal behavior
type AutoRenewalConfig struct {
	// Enable automatic renewal
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Renew certificate X days before expiry
	// +optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=365
	ThresholdDays int `json:"thresholdDays,omitempty"`

	// CronJob schedule for renewal checks (default: daily at 2 AM)
	// +optional
	// +kubebuilder:default="0 2 * * *"
	Schedule string `json:"schedule,omitempty"`

	// Number of successful job history to keep
	// +optional
	// +kubebuilder:default=3
	SuccessfulJobsHistoryLimit *int32 `json:"successfulJobsHistoryLimit,omitempty"`

	// Number of failed job history to keep
	// +optional
	// +kubebuilder:default=1
	FailedJobsHistoryLimit *int32 `json:"failedJobsHistoryLimit,omitempty"`
}

// KeyConfig defines key generation parameters
type KeyConfig struct {
	// Key algorithm (RSA, ECDSA)
	// +optional
	// +kubebuilder:default="RSA"
	// +kubebuilder:validation:Enum=RSA;ECDSA
	Algorithm string `json:"algorithm,omitempty"`

	// Key size for RSA (2048, 3072, 4096)
	// +optional
	// +kubebuilder:default=2048
	// +kubebuilder:validation:Enum=2048;3072;4096
	Size int `json:"size,omitempty"`

	// ECDSA curve (P256, P384, P521)
	// +optional
	// +kubebuilder:default="P256"
	// +kubebuilder:validation:Enum=P256;P384;P521
	Curve string `json:"curve,omitempty"`
}

// AutoGenerateSANsConfig defines configuration for auto-generating SANs
type AutoGenerateSANsConfig struct {
	// Enable auto-generation of SANs based on certificate type
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Number of indexer replicas (used to generate pod-specific SANs)
	// +optional
	// +kubebuilder:default=3
	IndexerReplicas int32 `json:"indexerReplicas,omitempty"`

	// Namespace for generating fully-qualified DNS names
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Additional custom SANs to include alongside auto-generated ones
	// +optional
	AdditionalSANs []string `json:"additionalSANs,omitempty"`

	// Include IP SANs (e.g., 127.0.0.1)
	// +optional
	// +kubebuilder:default=false
	IncludeIPSANs bool `json:"includeIPSANs,omitempty"`
}

// WazuhCertificateStatus defines the observed state of WazuhCertificate
type WazuhCertificateStatus struct {
	// Phase of certificate (Pending, Ready, Renewing, Failed)
	// +optional
	Phase CertificatePhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Certificate serial number
	// +optional
	SerialNumber string `json:"serialNumber,omitempty"`

	// Certificate issued at timestamp
	// +optional
	IssuedAt *metav1.Time `json:"issuedAt,omitempty"`

	// Certificate expiry timestamp
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// Days until expiry
	// +optional
	DaysUntilExpiry int `json:"daysUntilExpiry,omitempty"`

	// Renewal status
	// +optional
	RenewalStatus *RenewalStatus `json:"renewalStatus,omitempty"`

	// Last renewal attempt
	// +optional
	LastRenewalAttempt *metav1.Time `json:"lastRenewalAttempt,omitempty"`

	// Secret reference where cert is stored
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// Observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// CertificatePhase represents the certificate lifecycle phase
// +kubebuilder:validation:Enum=Pending;Ready;Renewing;Failed;Expired
type CertificatePhase string

const (
	CertificatePhasePending  CertificatePhase = "Pending"
	CertificatePhaseReady    CertificatePhase = "Ready"
	CertificatePhaseRenewing CertificatePhase = "Renewing"
	CertificatePhaseFailed   CertificatePhase = "Failed"
	CertificatePhaseExpired  CertificatePhase = "Expired"
)

// RenewalStatus represents renewal state
type RenewalStatus struct {
	// Renewal needed
	// +optional
	Needed bool `json:"needed,omitempty"`

	// Last renewal time
	// +optional
	LastRenewed *metav1.Time `json:"lastRenewed,omitempty"`

	// Next scheduled renewal check
	// +optional
	NextCheck *metav1.Time `json:"nextCheck,omitempty"`

	// Renewal job name
	// +optional
	JobName string `json:"jobName,omitempty"`
}

// Condition types
const (
	// CertificateConditionReady indicates certificate is ready
	CertificateConditionReady = "Ready"

	// CertificateConditionRenewing indicates certificate is being renewed
	CertificateConditionRenewing = "Renewing"

	// CertificateConditionExpiring indicates certificate is expiring soon
	CertificateConditionExpiring = "Expiring"

	// CertificateConditionExpired indicates certificate has expired
	CertificateConditionExpired = "Expired"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wzcert
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.expiresAt`
// +kubebuilder:printcolumn:name="Days Left",type=integer,JSONPath=`.status.daysUntilExpiry`
// +kubebuilder:printcolumn:name="Auto-Renew",type=boolean,JSONPath=`.spec.autoRenewal.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WazuhCertificate is the Schema for the wazuhcertificates API
type WazuhCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WazuhCertificateSpec   `json:"spec,omitempty"`
	Status WazuhCertificateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WazuhCertificateList contains a list of WazuhCertificate
type WazuhCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WazuhCertificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WazuhCertificate{}, &WazuhCertificateList{})
}
