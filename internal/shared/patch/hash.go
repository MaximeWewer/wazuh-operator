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

// RepositoryPluginHashInput is a mirror of RepositoryPluginConfig for hash computation.
// It avoids importing the API types package to prevent circular dependencies.
type RepositoryPluginHashInput struct {
	Name              string `json:"name"`
	ClientName        string `json:"clientName,omitempty"`
	CredentialsSecret string `json:"credentialsSecret,omitempty"` // Secret name only (for change detection)
}

// WazuhExporterHashInput mirrors WazuhExporterConfig for hash computation.
type WazuhExporterHashInput struct {
	Enabled         bool                         `json:"enabled"`
	Image           string                       `json:"image,omitempty"`
	Port            int32                        `json:"port,omitempty"`
	Resources       *corev1.ResourceRequirements `json:"resources,omitempty"`
	APIProtocol     string                       `json:"apiProtocol,omitempty"`
	APIVerifySSL    bool                         `json:"apiVerifySSL,omitempty"`
	LogLevel        string                       `json:"logLevel,omitempty"`
	CacheTTL        string                       `json:"cacheTTL,omitempty"`
	StartupGrace    string                       `json:"startupGrace,omitempty"`
	APICASecretName string                       `json:"apiCASecretName,omitempty"`
	APICASecretKey  string                       `json:"apiCASecretKey,omitempty"`
}

// IndexerExporterHashInput mirrors IndexerExporterConfig for hash computation.
type IndexerExporterHashInput struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version,omitempty"`
}

// IndexerSpec contains fields from WazuhCluster.Spec.Indexer used for hash computation
type IndexerSpec struct {
	Replicas                  int32                             `json:"replicas,omitempty"`
	Version                   string                            `json:"version,omitempty"`
	Resources                 *corev1.ResourceRequirements      `json:"resources,omitempty"`
	StorageSize               string                            `json:"storageSize,omitempty"`
	JavaOpts                  string                            `json:"javaOpts,omitempty"`
	Image                     string                            `json:"image,omitempty"`
	NodeSelector              map[string]string                 `json:"nodeSelector,omitempty"`
	Tolerations               []corev1.Toleration               `json:"tolerations,omitempty"`
	Affinity                  *corev1.Affinity                  `json:"affinity,omitempty"`
	ImagePullSecrets          []corev1.LocalObjectReference     `json:"imagePullSecrets,omitempty"`
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Custom pod configuration
	Env            []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom        []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	Annotations    map[string]string      `json:"annotations,omitempty"`
	PodAnnotations map[string]string      `json:"podAnnotations,omitempty"`
	// Extra volumes and containers
	ExtraVolumes        []corev1.Volume      `json:"extraVolumes,omitempty"`
	ExtraVolumeMounts   []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	ExtraInitContainers []corev1.Container   `json:"extraInitContainers,omitempty"`
	ExtraContainers     []corev1.Container   `json:"extraContainers,omitempty"`
	// Monitoring configuration
	IndexerExporter *IndexerExporterHashInput `json:"indexerExporter,omitempty"`
	// Repository plugins configuration
	RepositoryPlugins []RepositoryPluginHashInput `json:"repositoryPlugins,omitempty"`
	// ServiceAccount name
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Security and lifecycle
	SecurityContext               *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext    `json:"containerSecurityContext,omitempty"`
	TerminationGracePeriodSeconds *int64                     `json:"terminationGracePeriodSeconds,omitempty"`
	ImagePullPolicy               corev1.PullPolicy          `json:"imagePullPolicy,omitempty"`
	// StatefulSet update strategy
	UpdateStrategy string `json:"updateStrategy,omitempty"`
}

// DashboardSpec contains fields from WazuhCluster.Spec.Dashboard used for hash computation
type DashboardSpec struct {
	Replicas                  int32                             `json:"replicas,omitempty"`
	Version                   string                            `json:"version,omitempty"`
	Resources                 *corev1.ResourceRequirements      `json:"resources,omitempty"`
	Image                     string                            `json:"image,omitempty"`
	NodeSelector              map[string]string                 `json:"nodeSelector,omitempty"`
	Tolerations               []corev1.Toleration               `json:"tolerations,omitempty"`
	Affinity                  *corev1.Affinity                  `json:"affinity,omitempty"`
	ImagePullSecrets          []corev1.LocalObjectReference     `json:"imagePullSecrets,omitempty"`
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Custom pod configuration
	Env            []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom        []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	Annotations    map[string]string      `json:"annotations,omitempty"`
	PodAnnotations map[string]string      `json:"podAnnotations,omitempty"`
	// Extra volumes and containers
	ExtraVolumes        []corev1.Volume      `json:"extraVolumes,omitempty"`
	ExtraVolumeMounts   []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	ExtraInitContainers []corev1.Container   `json:"extraInitContainers,omitempty"`
	ExtraContainers     []corev1.Container   `json:"extraContainers,omitempty"`
	// ServiceAccount name
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Security and lifecycle
	SecurityContext               *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext    `json:"containerSecurityContext,omitempty"`
	TerminationGracePeriodSeconds *int64                     `json:"terminationGracePeriodSeconds,omitempty"`
	ImagePullPolicy               corev1.PullPolicy          `json:"imagePullPolicy,omitempty"`
	EnableSSL                     bool                       `json:"enableSSL,omitempty"`
	RunAs                         bool                       `json:"runAs,omitempty"`
}

// ManagerMasterSpec contains fields from WazuhCluster.Spec.Manager.Master used for hash computation
type ManagerMasterSpec struct {
	Version                   string                            `json:"version,omitempty"`
	Resources                 *corev1.ResourceRequirements      `json:"resources,omitempty"`
	StorageSize               string                            `json:"storageSize,omitempty"`
	Image                     string                            `json:"image,omitempty"`
	NodeSelector              map[string]string                 `json:"nodeSelector,omitempty"`
	Tolerations               []corev1.Toleration               `json:"tolerations,omitempty"`
	Affinity                  *corev1.Affinity                  `json:"affinity,omitempty"`
	ImagePullSecrets          []corev1.LocalObjectReference     `json:"imagePullSecrets,omitempty"`
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Custom pod configuration
	Env            []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom        []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	Annotations    map[string]string      `json:"annotations,omitempty"`
	PodAnnotations map[string]string      `json:"podAnnotations,omitempty"`
	// Extra configuration and volumes
	ExtraConfig         string               `json:"extraConfig,omitempty"`
	ExtraVolumes        []corev1.Volume      `json:"extraVolumes,omitempty"`
	ExtraVolumeMounts   []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	ExtraInitContainers []corev1.Container   `json:"extraInitContainers,omitempty"`
	ExtraContainers     []corev1.Container   `json:"extraContainers,omitempty"`
	// Monitoring configuration
	WazuhExporter *WazuhExporterHashInput `json:"wazuhExporter,omitempty"`
	// ServiceAccount name
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Security and lifecycle
	SecurityContext               *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext    `json:"containerSecurityContext,omitempty"`
	TerminationGracePeriodSeconds *int64                     `json:"terminationGracePeriodSeconds,omitempty"`
	ImagePullPolicy               corev1.PullPolicy          `json:"imagePullPolicy,omitempty"`
	// StatefulSet update strategy
	UpdateStrategy string `json:"updateStrategy,omitempty"`
}

// ManagerWorkersSpec contains fields from WazuhCluster.Spec.Manager.Workers used for hash computation
type ManagerWorkersSpec struct {
	Replicas                  int32                             `json:"replicas,omitempty"`
	Version                   string                            `json:"version,omitempty"`
	Resources                 *corev1.ResourceRequirements      `json:"resources,omitempty"`
	StorageSize               string                            `json:"storageSize,omitempty"`
	Image                     string                            `json:"image,omitempty"`
	NodeSelector              map[string]string                 `json:"nodeSelector,omitempty"`
	Tolerations               []corev1.Toleration               `json:"tolerations,omitempty"`
	Affinity                  *corev1.Affinity                  `json:"affinity,omitempty"`
	ImagePullSecrets          []corev1.LocalObjectReference     `json:"imagePullSecrets,omitempty"`
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Custom pod configuration
	Env            []corev1.EnvVar        `json:"env,omitempty"`
	EnvFrom        []corev1.EnvFromSource `json:"envFrom,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	Annotations    map[string]string      `json:"annotations,omitempty"`
	PodAnnotations map[string]string      `json:"podAnnotations,omitempty"`
	// Extra configuration and volumes
	ExtraConfig         string               `json:"extraConfig,omitempty"`
	ExtraVolumes        []corev1.Volume      `json:"extraVolumes,omitempty"`
	ExtraVolumeMounts   []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	ExtraInitContainers []corev1.Container   `json:"extraInitContainers,omitempty"`
	ExtraContainers     []corev1.Container   `json:"extraContainers,omitempty"`
	// ServiceAccount name
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Security and lifecycle
	SecurityContext               *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	ContainerSecurityContext      *corev1.SecurityContext    `json:"containerSecurityContext,omitempty"`
	TerminationGracePeriodSeconds *int64                     `json:"terminationGracePeriodSeconds,omitempty"`
	ImagePullPolicy               corev1.PullPolicy          `json:"imagePullPolicy,omitempty"`
	// StatefulSet update strategy
	UpdateStrategy string `json:"updateStrategy,omitempty"`
}

// ComputeSpecHash computes a SHA256 hash of spec fields for change detection.
// It uses canonical JSON serialization (marshal → unmarshal to interface{} → re-marshal)
// to guarantee deterministic output regardless of Go map iteration order,
// custom MarshalJSON implementations, or internal type representations.
func ComputeSpecHash(spec any) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal spec for hashing: %w", err)
	}

	// Canonicalize: unmarshal into generic interface{} and re-marshal.
	// This normalizes all types to basic JSON primitives and ensures
	// all map keys (including nested) are sorted alphabetically.
	var canonical any
	if err := json.Unmarshal(data, &canonical); err != nil {
		return "", fmt.Errorf("failed to canonicalize spec for hashing: %w", err)
	}

	canonicalData, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("failed to marshal canonical spec for hashing: %w", err)
	}

	hash := sha256.Sum256(canonicalData)
	return hex.EncodeToString(hash[:])[:16], nil
}

// StampPodTemplateHash computes a hash of the rendered pod template spec, writes
// it into the template's annotations under annoKey, and returns the hash.
//
// This detects pod-template drift (image tag, init-container args, env, resources)
// regardless of its source — including operator-internal values such as the
// versions table — which CR-field-derived spec hashes miss. Hashing tmpl.Spec
// (not the whole template) keeps the comparison desired-vs-desired across
// reconciles and avoids server-defaulting noise; the annotation itself lives in
// tmpl.ObjectMeta so it never feeds back into the hash.
func StampPodTemplateHash(tmpl *corev1.PodTemplateSpec, annoKey string) (string, error) {
	h, err := ComputeSpecHash(tmpl.Spec)
	if err != nil {
		return "", err
	}
	if tmpl.Annotations == nil {
		tmpl.Annotations = map[string]string{}
	}
	tmpl.Annotations[annoKey] = h
	return h, nil
}

// PodTemplateHashChanged reports whether the stored pod-template hash on found
// differs from desiredHash. A nil/absent annotation counts as changed so a
// freshly-adopted object (no stamp yet) gets reconciled once.
func PodTemplateHashChanged(found *corev1.PodTemplateSpec, desiredHash, annoKey string) bool {
	existing := ""
	if found != nil && found.Annotations != nil {
		existing = found.Annotations[annoKey]
	}
	return desiredHash != existing
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
	Replicas                      int32
	Version                       string
	Resources                     *corev1.ResourceRequirements
	StorageSize                   string
	JavaOpts                      string
	Image                         string
	NodeSelector                  map[string]string
	Tolerations                   []corev1.Toleration
	Affinity                      *corev1.Affinity
	ImagePullSecrets              []corev1.LocalObjectReference
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint
	Env                           []corev1.EnvVar
	EnvFrom                       []corev1.EnvFromSource
	Labels                        map[string]string
	Annotations                   map[string]string
	PodAnnotations                map[string]string
	ExtraVolumes                  []corev1.Volume
	ExtraVolumeMounts             []corev1.VolumeMount
	ExtraInitContainers           []corev1.Container
	ExtraContainers               []corev1.Container
	IndexerExporter               *IndexerExporterHashInput
	RepositoryPlugins             []RepositoryPluginHashInput
	ServiceAccountName            string
	SecurityContext               *corev1.PodSecurityContext
	ContainerSecurityContext      *corev1.SecurityContext
	TerminationGracePeriodSeconds *int64
	ImagePullPolicy               corev1.PullPolicy
	UpdateStrategy                string
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
	spec := IndexerSpec(input)
	return ComputeSpecHash(spec)
}

// DashboardSpecInput contains all input parameters for computing dashboard spec hash
type DashboardSpecInput struct {
	Replicas                      int32
	Version                       string
	Resources                     *corev1.ResourceRequirements
	Image                         string
	NodeSelector                  map[string]string
	Tolerations                   []corev1.Toleration
	Affinity                      *corev1.Affinity
	ImagePullSecrets              []corev1.LocalObjectReference
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint
	Env                           []corev1.EnvVar
	EnvFrom                       []corev1.EnvFromSource
	Labels                        map[string]string
	Annotations                   map[string]string
	PodAnnotations                map[string]string
	ExtraVolumes                  []corev1.Volume
	ExtraVolumeMounts             []corev1.VolumeMount
	ExtraInitContainers           []corev1.Container
	ExtraContainers               []corev1.Container
	ServiceAccountName            string
	SecurityContext               *corev1.PodSecurityContext
	ContainerSecurityContext      *corev1.SecurityContext
	TerminationGracePeriodSeconds *int64
	ImagePullPolicy               corev1.PullPolicy
	EnableSSL                     bool
	RunAs                         bool
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
	spec := DashboardSpec(input)
	return ComputeSpecHash(spec)
}

// ManagerMasterSpecInput contains all input parameters for computing manager master spec hash
type ManagerMasterSpecInput struct {
	Version                       string
	Resources                     *corev1.ResourceRequirements
	StorageSize                   string
	Image                         string
	NodeSelector                  map[string]string
	Tolerations                   []corev1.Toleration
	Affinity                      *corev1.Affinity
	ImagePullSecrets              []corev1.LocalObjectReference
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint
	Env                           []corev1.EnvVar
	EnvFrom                       []corev1.EnvFromSource
	Labels                        map[string]string
	Annotations                   map[string]string
	PodAnnotations                map[string]string
	ExtraConfig                   string
	ExtraVolumes                  []corev1.Volume
	ExtraVolumeMounts             []corev1.VolumeMount
	ExtraInitContainers           []corev1.Container
	ExtraContainers               []corev1.Container
	WazuhExporter                 *WazuhExporterHashInput
	ServiceAccountName            string
	SecurityContext               *corev1.PodSecurityContext
	ContainerSecurityContext      *corev1.SecurityContext
	TerminationGracePeriodSeconds *int64
	ImagePullPolicy               corev1.PullPolicy
	UpdateStrategy                string
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
	spec := ManagerMasterSpec(input)
	return ComputeSpecHash(spec)
}

// ManagerWorkersSpecInput contains all input parameters for computing manager workers spec hash
type ManagerWorkersSpecInput struct {
	Replicas                      int32
	Version                       string
	Resources                     *corev1.ResourceRequirements
	StorageSize                   string
	Image                         string
	NodeSelector                  map[string]string
	Tolerations                   []corev1.Toleration
	Affinity                      *corev1.Affinity
	ImagePullSecrets              []corev1.LocalObjectReference
	TopologySpreadConstraints     []corev1.TopologySpreadConstraint
	Env                           []corev1.EnvVar
	EnvFrom                       []corev1.EnvFromSource
	Labels                        map[string]string
	Annotations                   map[string]string
	PodAnnotations                map[string]string
	ExtraConfig                   string
	ExtraVolumes                  []corev1.Volume
	ExtraVolumeMounts             []corev1.VolumeMount
	ExtraInitContainers           []corev1.Container
	ExtraContainers               []corev1.Container
	ServiceAccountName            string
	SecurityContext               *corev1.PodSecurityContext
	ContainerSecurityContext      *corev1.SecurityContext
	TerminationGracePeriodSeconds *int64
	ImagePullPolicy               corev1.PullPolicy
	UpdateStrategy                string
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
	spec := ManagerWorkersSpec(input)
	return ComputeSpecHash(spec)
}
