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

// Package patch provides utilities for detecting and applying resource changes
package patch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
)

// IndexerSpec contains fields from WazuhCluster.Spec.Indexer used for hash computation
type IndexerSpec struct {
	Replicas     int32                        `json:"replicas,omitempty"`
	Version      string                       `json:"version,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	StorageSize  string                       `json:"storageSize,omitempty"`
	JavaOpts     string                       `json:"javaOpts,omitempty"`
	Image        string                       `json:"image,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	Affinity     *corev1.Affinity             `json:"affinity,omitempty"`
	// Custom pod configuration
	Env         []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom     []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
	// Monitoring configuration
	MonitoringEnabled bool `json:"monitoringEnabled,omitempty"`
}

// DashboardSpec contains fields from WazuhCluster.Spec.Dashboard used for hash computation
type DashboardSpec struct {
	Replicas     int32                        `json:"replicas,omitempty"`
	Version      string                       `json:"version,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	Image        string                       `json:"image,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	Affinity     *corev1.Affinity             `json:"affinity,omitempty"`
	// Custom pod configuration
	Env         []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom     []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
}

// ManagerMasterSpec contains fields from WazuhCluster.Spec.Manager.Master used for hash computation
type ManagerMasterSpec struct {
	Version      string                       `json:"version,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	StorageSize  string                       `json:"storageSize,omitempty"`
	Image        string                       `json:"image,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	Affinity     *corev1.Affinity             `json:"affinity,omitempty"`
	// Custom pod configuration
	Env         []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom     []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
	// Monitoring configuration
	MonitoringEnabled bool `json:"monitoringEnabled,omitempty"`
}

// ManagerWorkersSpec contains fields from WazuhCluster.Spec.Manager.Workers used for hash computation
type ManagerWorkersSpec struct {
	Replicas     int32                        `json:"replicas,omitempty"`
	Version      string                       `json:"version,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	StorageSize  string                       `json:"storageSize,omitempty"`
	Image        string                       `json:"image,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	Affinity     *corev1.Affinity             `json:"affinity,omitempty"`
	// Custom pod configuration
	Env         []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom     []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
}

// ComputeSpecHash computes a SHA256 hash of spec fields for change detection
// The spec must be a struct with JSON tags for deterministic serialization
func ComputeSpecHash(spec interface{}) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal spec for hashing: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:16], nil // Return first 16 chars for shorter annotation
}

// ComputeConfigHash computes a deterministic hash of ConfigMap data
// Keys are sorted for consistent hashing regardless of map iteration order
func ComputeConfigHash(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}

	// Sort keys for deterministic ordering
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build deterministic string representation
	combined := ""
	for _, k := range keys {
		combined += k + "=" + data[k] + "\n"
	}

	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])[:16]
}

// ComputeSecretHash computes a deterministic hash of Secret data
func ComputeSecretHash(data map[string][]byte) string {
	if len(data) == 0 {
		return ""
	}

	// Convert to string map for consistent hashing
	strMap := make(map[string]string, len(data))
	for k, v := range data {
		strMap[k] = string(v)
	}
	return ComputeConfigHash(strMap)
}

// IndexerSpecInput contains all input parameters for computing indexer spec hash
type IndexerSpecInput struct {
	Replicas          int32
	Version           string
	Resources         *corev1.ResourceRequirements
	StorageSize       string
	JavaOpts          string
	Image             string
	NodeSelector      map[string]string
	Tolerations       []corev1.Toleration
	Affinity          *corev1.Affinity
	Env               []corev1.EnvVar
	EnvFrom           []corev1.EnvFromSource
	Labels            map[string]string
	Annotations       map[string]string
	MonitoringEnabled bool
}

// ComputeIndexerSpecHash computes the spec hash for an Indexer component
func ComputeIndexerSpecHash(replicas int32, version string, resources *corev1.ResourceRequirements, storageSize, javaOpts, image string) (string, error) {
	return ComputeIndexerSpecHashFull(IndexerSpecInput{
		Replicas:    replicas,
		Version:     version,
		Resources:   resources,
		StorageSize: storageSize,
		JavaOpts:    javaOpts,
		Image:       image,
	})
}

// ComputeIndexerSpecHashFull computes the spec hash with all fields
func ComputeIndexerSpecHashFull(input IndexerSpecInput) (string, error) {
	spec := IndexerSpec{
		Replicas:          input.Replicas,
		Version:           input.Version,
		Resources:         input.Resources,
		StorageSize:       input.StorageSize,
		JavaOpts:          input.JavaOpts,
		Image:             input.Image,
		NodeSelector:      input.NodeSelector,
		Tolerations:       input.Tolerations,
		Affinity:          input.Affinity,
		Env:               input.Env,
		EnvFrom:           input.EnvFrom,
		Labels:            input.Labels,
		Annotations:       input.Annotations,
		MonitoringEnabled: input.MonitoringEnabled,
	}
	return ComputeSpecHash(spec)
}

// DashboardSpecInput contains all input parameters for computing dashboard spec hash
type DashboardSpecInput struct {
	Replicas     int32
	Version      string
	Resources    *corev1.ResourceRequirements
	Image        string
	NodeSelector map[string]string
	Tolerations  []corev1.Toleration
	Affinity     *corev1.Affinity
	Env          []corev1.EnvVar
	EnvFrom      []corev1.EnvFromSource
	Labels       map[string]string
	Annotations  map[string]string
}

// ComputeDashboardSpecHash computes the spec hash for a Dashboard component
func ComputeDashboardSpecHash(replicas int32, version string, resources *corev1.ResourceRequirements, image string) (string, error) {
	return ComputeDashboardSpecHashFull(DashboardSpecInput{
		Replicas:  replicas,
		Version:   version,
		Resources: resources,
		Image:     image,
	})
}

// ComputeDashboardSpecHashFull computes the spec hash with all fields
func ComputeDashboardSpecHashFull(input DashboardSpecInput) (string, error) {
	spec := DashboardSpec{
		Replicas:     input.Replicas,
		Version:      input.Version,
		Resources:    input.Resources,
		Image:        input.Image,
		NodeSelector: input.NodeSelector,
		Tolerations:  input.Tolerations,
		Affinity:     input.Affinity,
		Env:          input.Env,
		EnvFrom:      input.EnvFrom,
		Labels:       input.Labels,
		Annotations:  input.Annotations,
	}
	return ComputeSpecHash(spec)
}

// ManagerMasterSpecInput contains all input parameters for computing manager master spec hash
type ManagerMasterSpecInput struct {
	Version           string
	Resources         *corev1.ResourceRequirements
	StorageSize       string
	Image             string
	NodeSelector      map[string]string
	Tolerations       []corev1.Toleration
	Affinity          *corev1.Affinity
	Env               []corev1.EnvVar
	EnvFrom           []corev1.EnvFromSource
	Labels            map[string]string
	Annotations       map[string]string
	MonitoringEnabled bool
}

// ComputeManagerMasterSpecHash computes the spec hash for a Manager Master component
func ComputeManagerMasterSpecHash(version string, resources *corev1.ResourceRequirements, storageSize, image string, nodeSelector map[string]string, tolerations []corev1.Toleration, affinity *corev1.Affinity) (string, error) {
	return ComputeManagerMasterSpecHashFull(ManagerMasterSpecInput{
		Version:      version,
		Resources:    resources,
		StorageSize:  storageSize,
		Image:        image,
		NodeSelector: nodeSelector,
		Tolerations:  tolerations,
		Affinity:     affinity,
	})
}

// ComputeManagerMasterSpecHashFull computes the spec hash with all fields
func ComputeManagerMasterSpecHashFull(input ManagerMasterSpecInput) (string, error) {
	spec := ManagerMasterSpec{
		Version:           input.Version,
		Resources:         input.Resources,
		StorageSize:       input.StorageSize,
		Image:             input.Image,
		NodeSelector:      input.NodeSelector,
		Tolerations:       input.Tolerations,
		Affinity:          input.Affinity,
		Env:               input.Env,
		EnvFrom:           input.EnvFrom,
		Labels:            input.Labels,
		Annotations:       input.Annotations,
		MonitoringEnabled: input.MonitoringEnabled,
	}
	return ComputeSpecHash(spec)
}

// ManagerWorkersSpecInput contains all input parameters for computing manager workers spec hash
type ManagerWorkersSpecInput struct {
	Replicas     int32
	Version      string
	Resources    *corev1.ResourceRequirements
	StorageSize  string
	Image        string
	NodeSelector map[string]string
	Tolerations  []corev1.Toleration
	Affinity     *corev1.Affinity
	Env          []corev1.EnvVar
	EnvFrom      []corev1.EnvFromSource
	Labels       map[string]string
	Annotations  map[string]string
}

// ComputeManagerWorkersSpecHash computes the spec hash for Manager Workers component
func ComputeManagerWorkersSpecHash(replicas int32, version string, resources *corev1.ResourceRequirements, storageSize, image string, nodeSelector map[string]string, tolerations []corev1.Toleration, affinity *corev1.Affinity) (string, error) {
	return ComputeManagerWorkersSpecHashFull(ManagerWorkersSpecInput{
		Replicas:     replicas,
		Version:      version,
		Resources:    resources,
		StorageSize:  storageSize,
		Image:        image,
		NodeSelector: nodeSelector,
		Tolerations:  tolerations,
		Affinity:     affinity,
	})
}

// ComputeManagerWorkersSpecHashFull computes the spec hash with all fields
func ComputeManagerWorkersSpecHashFull(input ManagerWorkersSpecInput) (string, error) {
	spec := ManagerWorkersSpec{
		Replicas:     input.Replicas,
		Version:      input.Version,
		Resources:    input.Resources,
		StorageSize:  input.StorageSize,
		Image:        input.Image,
		NodeSelector: input.NodeSelector,
		Tolerations:  input.Tolerations,
		Affinity:     input.Affinity,
		Env:          input.Env,
		EnvFrom:      input.EnvFrom,
		Labels:       input.Labels,
		Annotations:  input.Annotations,
	}
	return ComputeSpecHash(spec)
}

// HashesMatch checks if two hash values are equal
func HashesMatch(hash1, hash2 string) bool {
	return hash1 == hash2
}

// ShortHash returns a truncated hash (first 8 characters)
func ShortHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}
