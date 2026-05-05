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

// WazuhClusterReference references a WazuhCluster resource
type WazuhClusterReference struct {
	// Name of the WazuhCluster resource
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the WazuhCluster resource
	// If empty, assumes the same namespace as the referencing resource
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// WazuhClusterRef references a WazuhCluster by name and namespace.
// Both fields are mandatory; cross-namespace references are supported and
// require the consuming CR to opt into multi-cluster propagation via
// ClusterRefs lists.
type WazuhClusterRef struct {
	// Name of the WazuhCluster resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the WazuhCluster resource
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// ConfigMapReference references a ConfigMap
type ConfigMapReference struct {
	// Name of the ConfigMap
	Name string `json:"name"`

	// Namespace of the ConfigMap
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key in the ConfigMap
	// +optional
	Key string `json:"key,omitempty"`
}

// SecretKeyRef references a key in a Secret
type SecretKeyRef struct {
	// Name is the secret name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key is the key in the secret
	// +optional
	// +kubebuilder:default="password"
	Key string `json:"key,omitempty"`
}

// SecretReference references a Secret with optional namespace and key
type SecretReference struct {
	// Name is the secret name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the secret (defaults to the resource namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key is the key in the secret (defaults to "password")
	// +optional
	Key string `json:"key,omitempty"`
}

// ExternalSecretRef references an ExternalSecret or SecretStore from External Secrets Operator (ESO)
// This allows integration with external secret providers like HashiCorp Vault, AWS Secrets Manager,
// Azure Key Vault, GCP Secret Manager, etc.
type ExternalSecretRef struct {
	// Name of the ExternalSecret resource that will be created/referenced
	// The ExternalSecret will sync the secret from the external provider to a K8s Secret
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the ExternalSecret (defaults to same namespace as the parent resource)
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// SecretStoreRef references the SecretStore or ClusterSecretStore to use
	// +optional
	SecretStoreRef *SecretStoreReference `json:"secretStoreRef,omitempty"`

	// RemoteRef specifies the remote secret location in the external provider
	// +optional
	RemoteRef *RemoteSecretRef `json:"remoteRef,omitempty"`

	// RefreshInterval is how often to sync the secret (e.g., "1h", "30m")
	// +optional
	// +kubebuilder:default="1h"
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// SecretStoreReference references a SecretStore or ClusterSecretStore
type SecretStoreReference struct {
	// Name of the SecretStore or ClusterSecretStore
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Kind is the kind of secret store (SecretStore or ClusterSecretStore)
	// +optional
	// +kubebuilder:validation:Enum=SecretStore;ClusterSecretStore
	// +kubebuilder:default="SecretStore"
	Kind string `json:"kind,omitempty"`
}

// RemoteSecretRef specifies the remote secret location
type RemoteSecretRef struct {
	// Key is the key/path in the external secret provider
	// For Vault: "secret/data/myapp/config"
	// For AWS SM: "myapp/database-credentials"
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Property is the specific property within the secret to extract
	// If not specified, the entire secret is used
	// +optional
	Property string `json:"property,omitempty"`

	// Version is the version of the secret to fetch (provider-specific)
	// +optional
	Version string `json:"version,omitempty"`
}

// SecretSourceRef provides a flexible way to reference secrets from either
// native Kubernetes Secrets or External Secrets Operator
type SecretSourceRef struct {
	// SecretRef references a native Kubernetes Secret
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`

	// ExternalSecretRef references an ExternalSecret from ESO
	// +optional
	ExternalSecretRef *ExternalSecretRef `json:"externalSecretRef,omitempty"`
}

// GetSecretName returns the name of the secret to use (resolves ExternalSecret to its target)
func (s *SecretSourceRef) GetSecretName() string {
	if s == nil {
		return ""
	}
	if s.SecretRef != nil {
		return s.SecretRef.Name
	}
	if s.ExternalSecretRef != nil {
		// ExternalSecret creates a K8s Secret with the same name
		return s.ExternalSecretRef.Name
	}
	return ""
}

// GetSecretNamespace returns the namespace of the secret
func (s *SecretSourceRef) GetSecretNamespace(defaultNamespace string) string {
	if s == nil {
		return defaultNamespace
	}
	if s.SecretRef != nil && s.SecretRef.Namespace != "" {
		return s.SecretRef.Namespace
	}
	if s.ExternalSecretRef != nil && s.ExternalSecretRef.Namespace != "" {
		return s.ExternalSecretRef.Namespace
	}
	return defaultNamespace
}

// IsExternalSecret returns true if this references an ExternalSecret
func (s *SecretSourceRef) IsExternalSecret() bool {
	return s != nil && s.ExternalSecretRef != nil
}

// IsNativeSecret returns true if this references a native K8s Secret
func (s *SecretSourceRef) IsNativeSecret() bool {
	return s != nil && s.SecretRef != nil
}
