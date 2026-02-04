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

package config

import (
	"time"
)

// ChangeType represents the type of configuration change detected
type ChangeType string

const (
	// ChangeTypeEnvFrom indicates a change in envFrom references (ConfigMaps/Secrets)
	ChangeTypeEnvFrom ChangeType = "EnvFrom"
	// ChangeTypeTLSConfig indicates a change in TLS/certificate configuration
	ChangeTypeTLSConfig ChangeType = "TLSConfig"
	// ChangeTypeSpec indicates a change in the main resource specification
	ChangeTypeSpec ChangeType = "Spec"
	// ChangeTypeConfigMap indicates a change in a referenced ConfigMap
	ChangeTypeConfigMap ChangeType = "ConfigMap"
	// ChangeTypeSecret indicates a change in a referenced Secret
	ChangeTypeSecret ChangeType = "Secret"
	// ChangeTypeCertificate indicates a change in certificate content
	ChangeTypeCertificate ChangeType = "Certificate"
)

// ChangeImpact represents the impact level of a configuration change
type ChangeImpact string

const (
	// ChangeImpactNone indicates no impact (no action needed)
	ChangeImpactNone ChangeImpact = "None"
	// ChangeImpactHotReload indicates the change can be applied via hot reload
	ChangeImpactHotReload ChangeImpact = "HotReload"
	// ChangeImpactRollingRestart indicates a rolling restart is required
	ChangeImpactRollingRestart ChangeImpact = "RollingRestart"
	// ChangeImpactFullRestart indicates all pods need to restart simultaneously
	ChangeImpactFullRestart ChangeImpact = "FullRestart"
)

// DetectedChange represents a single detected configuration change
type DetectedChange struct {
	// Type is the type of change detected
	Type ChangeType `json:"type"`
	// Source identifies the source of the change (e.g., "configmap/my-config", "secret/my-secret")
	Source string `json:"source"`
	// OldHash is the previous hash value (empty if new)
	OldHash string `json:"oldHash,omitempty"`
	// NewHash is the new hash value
	NewHash string `json:"newHash"`
	// Impact indicates the required action for this change
	Impact ChangeImpact `json:"impact"`
	// Description provides a human-readable description of the change
	Description string `json:"description,omitempty"`
	// DetectedAt is when the change was detected
	DetectedAt time.Time `json:"detectedAt"`
	// AffectedComponents lists the components affected by this change
	AffectedComponents []string `json:"affectedComponents,omitempty"`
}

// ChangeDetectionResult contains the results of a configuration change detection
type ChangeDetectionResult struct {
	// HasChanges indicates if any changes were detected
	HasChanges bool `json:"hasChanges"`
	// Changes is the list of detected changes
	Changes []DetectedChange `json:"changes,omitempty"`
	// CompositeHash is the combined hash of all monitored configurations
	CompositeHash string `json:"compositeHash"`
	// RequiredAction is the highest-impact action needed
	RequiredAction ChangeImpact `json:"requiredAction"`
	// CheckedAt is when the detection was performed
	CheckedAt time.Time `json:"checkedAt"`
}

// ConfigSource represents a configuration source to monitor
type ConfigSource struct {
	// Type is the type of configuration source
	Type ChangeType `json:"type"`
	// Name is the name of the resource
	Name string `json:"name"`
	// Namespace is the namespace of the resource
	Namespace string `json:"namespace"`
	// Keys are specific keys to monitor (empty means all keys)
	Keys []string `json:"keys,omitempty"`
	// Impact is the impact level when this source changes
	Impact ChangeImpact `json:"impact"`
}

// HashRecord stores hash information for tracking changes
type HashRecord struct {
	// Hash is the computed hash value
	Hash string `json:"hash"`
	// UpdatedAt is when the hash was last updated
	UpdatedAt time.Time `json:"updatedAt"`
	// Source identifies what was hashed
	Source string `json:"source"`
}

// TrackedConfig holds the current tracking state for a resource
type TrackedConfig struct {
	// ResourceName is the name of the tracked resource
	ResourceName string `json:"resourceName"`
	// ResourceNamespace is the namespace of the tracked resource
	ResourceNamespace string `json:"resourceNamespace"`
	// Hashes maps source identifiers to their hash records
	Hashes map[string]HashRecord `json:"hashes"`
	// CompositeHash is the combined hash of all sources
	CompositeHash string `json:"compositeHash"`
	// LastChecked is when the configuration was last checked
	LastChecked time.Time `json:"lastChecked"`
}

// NewTrackedConfig creates a new TrackedConfig for a resource
func NewTrackedConfig(namespace, name string) *TrackedConfig {
	return &TrackedConfig{
		ResourceName:      name,
		ResourceNamespace: namespace,
		Hashes:            make(map[string]HashRecord),
	}
}

// UpdateHash updates a hash record and returns true if it changed
func (tc *TrackedConfig) UpdateHash(source, newHash string) bool {
	now := time.Now()
	tc.LastChecked = now

	existing, exists := tc.Hashes[source]
	if !exists || existing.Hash != newHash {
		tc.Hashes[source] = HashRecord{
			Hash:      newHash,
			UpdatedAt: now,
			Source:    source,
		}
		return true
	}
	return false
}

// GetHash returns the hash for a source, or empty string if not tracked
func (tc *TrackedConfig) GetHash(source string) string {
	if record, exists := tc.Hashes[source]; exists {
		return record.Hash
	}
	return ""
}
