/*
Copyright 2024.

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

// ComponentRef references a component CRD (WazuhManager, WazuhIndexer, WazuhDashboard)
type ComponentRef struct {
	// Name of the component resource
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the component (defaults to same namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}
