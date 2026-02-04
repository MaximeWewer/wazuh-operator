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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ConfigChangeDetector detects configuration changes across multiple sources
type ConfigChangeDetector struct {
	client client.Client
	// sources lists the configuration sources to monitor
	sources []ConfigSource
	// tracked holds the current tracking state
	tracked *TrackedConfig
}

// NewConfigChangeDetector creates a new ConfigChangeDetector
func NewConfigChangeDetector(c client.Client, namespace, resourceName string) *ConfigChangeDetector {
	return &ConfigChangeDetector{
		client:  c,
		sources: make([]ConfigSource, 0),
		tracked: NewTrackedConfig(namespace, resourceName),
	}
}

// AddConfigMapSource adds a ConfigMap to monitor
func (d *ConfigChangeDetector) AddConfigMapSource(name string, keys []string, impact ChangeImpact) {
	d.sources = append(d.sources, ConfigSource{
		Type:      ChangeTypeConfigMap,
		Name:      name,
		Namespace: d.tracked.ResourceNamespace,
		Keys:      keys,
		Impact:    impact,
	})
}

// AddSecretSource adds a Secret to monitor
func (d *ConfigChangeDetector) AddSecretSource(name string, keys []string, impact ChangeImpact) {
	d.sources = append(d.sources, ConfigSource{
		Type:      ChangeTypeSecret,
		Name:      name,
		Namespace: d.tracked.ResourceNamespace,
		Keys:      keys,
		Impact:    impact,
	})
}

// AddEnvFromSource adds an envFrom reference to monitor
func (d *ConfigChangeDetector) AddEnvFromSource(envFromSource corev1.EnvFromSource, impact ChangeImpact) {
	if envFromSource.ConfigMapRef != nil {
		d.sources = append(d.sources, ConfigSource{
			Type:      ChangeTypeEnvFrom,
			Name:      envFromSource.ConfigMapRef.Name,
			Namespace: d.tracked.ResourceNamespace,
			Impact:    impact,
		})
	}
	if envFromSource.SecretRef != nil {
		d.sources = append(d.sources, ConfigSource{
			Type:      ChangeTypeEnvFrom,
			Name:      envFromSource.SecretRef.Name,
			Namespace: d.tracked.ResourceNamespace,
			Impact:    impact,
		})
	}
}

// AddTLSSecretSource adds a TLS secret to monitor
func (d *ConfigChangeDetector) AddTLSSecretSource(name string, impact ChangeImpact) {
	d.sources = append(d.sources, ConfigSource{
		Type:      ChangeTypeTLSConfig,
		Name:      name,
		Namespace: d.tracked.ResourceNamespace,
		Keys:      []string{"tls.crt", "tls.key", "ca.crt"},
		Impact:    impact,
	})
}

// AddCertificateSecretSource adds a certificate secret to monitor
func (d *ConfigChangeDetector) AddCertificateSecretSource(name string, impact ChangeImpact) {
	d.sources = append(d.sources, ConfigSource{
		Type:      ChangeTypeCertificate,
		Name:      name,
		Namespace: d.tracked.ResourceNamespace,
		Impact:    impact,
	})
}

// SetTrackedHashes loads existing hash records (e.g., from annotations)
func (d *ConfigChangeDetector) SetTrackedHashes(hashes map[string]string) {
	for source, hash := range hashes {
		d.tracked.Hashes[source] = HashRecord{
			Hash:   hash,
			Source: source,
		}
	}
}

// DetectChanges checks all configured sources for changes
func (d *ConfigChangeDetector) DetectChanges(ctx context.Context) (*ChangeDetectionResult, error) {
	logger := log.FromContext(ctx)
	now := time.Now()

	result := &ChangeDetectionResult{
		HasChanges:     false,
		Changes:        make([]DetectedChange, 0),
		RequiredAction: ChangeImpactNone,
		CheckedAt:      now,
	}

	var allHashes []string

	for _, source := range d.sources {
		hash, err := d.computeSourceHash(ctx, source)
		if err != nil {
			logger.Error(err, "Failed to compute hash for source",
				"type", source.Type,
				"name", source.Name)
			continue
		}

		sourceID := d.getSourceID(source)
		allHashes = append(allHashes, fmt.Sprintf("%s=%s", sourceID, hash))

		oldHash := d.tracked.GetHash(sourceID)
		if d.tracked.UpdateHash(sourceID, hash) && oldHash != "" {
			// Change detected (and it's not the first time we're seeing this source)
			change := DetectedChange{
				Type:        source.Type,
				Source:      sourceID,
				OldHash:     oldHash,
				NewHash:     hash,
				Impact:      source.Impact,
				Description: fmt.Sprintf("%s %s changed", source.Type, source.Name),
				DetectedAt:  now,
			}
			result.Changes = append(result.Changes, change)
			result.HasChanges = true

			// Update required action to the highest impact
			if d.isHigherImpact(source.Impact, result.RequiredAction) {
				result.RequiredAction = source.Impact
			}
		}
	}

	// Compute composite hash
	sort.Strings(allHashes)
	result.CompositeHash = d.computeHash(strings.Join(allHashes, ";"))
	d.tracked.CompositeHash = result.CompositeHash

	return result, nil
}

// GetCompositeHash returns the current composite hash
func (d *ConfigChangeDetector) GetCompositeHash() string {
	return d.tracked.CompositeHash
}

// GetHashesForAnnotations returns a map suitable for storing in annotations
func (d *ConfigChangeDetector) GetHashesForAnnotations() map[string]string {
	result := make(map[string]string)
	for source, record := range d.tracked.Hashes {
		// Sanitize the source name for annotation key compatibility
		key := strings.ReplaceAll(source, "/", "-")
		result[key] = record.Hash
	}
	return result
}

// computeSourceHash computes the hash for a configuration source
func (d *ConfigChangeDetector) computeSourceHash(ctx context.Context, source ConfigSource) (string, error) {
	switch source.Type {
	case ChangeTypeConfigMap, ChangeTypeEnvFrom:
		if strings.HasPrefix(source.Name, "secret/") {
			return d.computeSecretHash(ctx, source)
		}
		return d.computeConfigMapHash(ctx, source)
	case ChangeTypeSecret, ChangeTypeTLSConfig, ChangeTypeCertificate:
		return d.computeSecretHash(ctx, source)
	default:
		return "", fmt.Errorf("unsupported source type: %s", source.Type)
	}
}

// computeConfigMapHash computes the hash of a ConfigMap
func (d *ConfigChangeDetector) computeConfigMapHash(ctx context.Context, source ConfigSource) (string, error) {
	cm := &corev1.ConfigMap{}
	err := d.client.Get(ctx, types.NamespacedName{
		Namespace: source.Namespace,
		Name:      source.Name,
	}, cm)
	if err != nil {
		return "", err
	}

	var data []string
	if len(source.Keys) > 0 {
		// Hash only specific keys
		for _, key := range source.Keys {
			if value, exists := cm.Data[key]; exists {
				data = append(data, fmt.Sprintf("%s=%s", key, value))
			}
			if value, exists := cm.BinaryData[key]; exists {
				data = append(data, fmt.Sprintf("%s=%x", key, value))
			}
		}
	} else {
		// Hash all data
		for key, value := range cm.Data {
			data = append(data, fmt.Sprintf("%s=%s", key, value))
		}
		for key, value := range cm.BinaryData {
			data = append(data, fmt.Sprintf("%s=%x", key, value))
		}
	}

	sort.Strings(data)
	return d.computeHash(strings.Join(data, "\n")), nil
}

// computeSecretHash computes the hash of a Secret
func (d *ConfigChangeDetector) computeSecretHash(ctx context.Context, source ConfigSource) (string, error) {
	secret := &corev1.Secret{}
	err := d.client.Get(ctx, types.NamespacedName{
		Namespace: source.Namespace,
		Name:      source.Name,
	}, secret)
	if err != nil {
		return "", err
	}

	var data []string
	if len(source.Keys) > 0 {
		// Hash only specific keys
		for _, key := range source.Keys {
			if value, exists := secret.Data[key]; exists {
				data = append(data, fmt.Sprintf("%s=%x", key, value))
			}
		}
	} else {
		// Hash all data
		for key, value := range secret.Data {
			data = append(data, fmt.Sprintf("%s=%x", key, value))
		}
	}

	sort.Strings(data)
	return d.computeHash(strings.Join(data, "\n")), nil
}

// getSourceID returns a unique identifier for a source
func (d *ConfigChangeDetector) getSourceID(source ConfigSource) string {
	return fmt.Sprintf("%s/%s", source.Type, source.Name)
}

// computeHash computes a SHA256 hash and returns the first 16 hex characters
func (d *ConfigChangeDetector) computeHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

// isHigherImpact returns true if newImpact is higher than currentImpact
func (d *ConfigChangeDetector) isHigherImpact(newImpact, currentImpact ChangeImpact) bool {
	impactOrder := map[ChangeImpact]int{
		ChangeImpactNone:           0,
		ChangeImpactHotReload:      1,
		ChangeImpactRollingRestart: 2,
		ChangeImpactFullRestart:    3,
	}
	return impactOrder[newImpact] > impactOrder[currentImpact]
}

// GetRequiredActionDescription returns a human-readable description of the required action
func GetRequiredActionDescription(impact ChangeImpact) string {
	switch impact {
	case ChangeImpactNone:
		return "No action required"
	case ChangeImpactHotReload:
		return "Configuration can be hot-reloaded without restart"
	case ChangeImpactRollingRestart:
		return "Rolling restart of pods required"
	case ChangeImpactFullRestart:
		return "Full restart of all pods required"
	default:
		return "Unknown action"
	}
}
