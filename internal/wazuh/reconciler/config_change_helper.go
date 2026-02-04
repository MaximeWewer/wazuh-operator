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

package reconciler

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MaximeWewer/wazuh-operator/internal/shared/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ConfigChangeHelper provides utilities for detecting and handling configuration changes
// in Wazuh component reconcilers
type ConfigChangeHelper struct {
	client    client.Client
	namespace string
	component string
}

// NewConfigChangeHelper creates a new ConfigChangeHelper
func NewConfigChangeHelper(c client.Client, namespace, component string) *ConfigChangeHelper {
	return &ConfigChangeHelper{
		client:    c,
		namespace: namespace,
		component: component,
	}
}

// ComponentConfigSources holds the configuration sources for a specific component
type ComponentConfigSources struct {
	// ConfigMaps to monitor (name -> impact)
	ConfigMaps map[string]config.ChangeImpact
	// Secrets to monitor (name -> impact)
	Secrets map[string]config.ChangeImpact
	// TLSSecrets to monitor (name -> impact) - specifically for TLS certificates
	TLSSecrets map[string]config.ChangeImpact
	// EnvFromRefs to monitor (from pod spec envFrom)
	EnvFromRefs []corev1.EnvFromSource
	// EnvFromImpact is the impact level for envFrom changes
	EnvFromImpact config.ChangeImpact
}

// DetectChangesForComponent detects configuration changes for a component
func (h *ConfigChangeHelper) DetectChangesForComponent(
	ctx context.Context,
	resourceName string,
	sources *ComponentConfigSources,
	existingHashes map[string]string,
) (*config.ChangeDetectionResult, error) {
	log := logf.FromContext(ctx)

	detector := config.NewConfigChangeDetector(h.client, h.namespace, resourceName)

	// Add ConfigMap sources
	for name, impact := range sources.ConfigMaps {
		detector.AddConfigMapSource(name, nil, impact)
	}

	// Add Secret sources
	for name, impact := range sources.Secrets {
		detector.AddSecretSource(name, nil, impact)
	}

	// Add TLS Secret sources
	for name, impact := range sources.TLSSecrets {
		detector.AddTLSSecretSource(name, impact)
	}

	// Add envFrom sources
	for _, envFrom := range sources.EnvFromRefs {
		detector.AddEnvFromSource(envFrom, sources.EnvFromImpact)
	}

	// Set existing hashes if available
	if len(existingHashes) > 0 {
		detector.SetTrackedHashes(existingHashes)
	}

	// Detect changes
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		log.Error(err, "Failed to detect configuration changes", "component", h.component)
		return nil, err
	}

	if result.HasChanges {
		log.Info("Configuration changes detected",
			"component", h.component,
			"changeCount", len(result.Changes),
			"requiredAction", result.RequiredAction)
		for _, change := range result.Changes {
			log.V(1).Info("Detected change",
				"type", change.Type,
				"source", change.Source,
				"impact", change.Impact)
		}
	}

	return result, nil
}

// GetHashAnnotationsFromPod extracts configuration hash annotations from a pod template
func GetHashAnnotationsFromPod(podAnnotations map[string]string) map[string]string {
	result := make(map[string]string)
	hashAnnotations := []string{
		constants.AnnotationConfigHash,
		constants.AnnotationSpecHash,
		constants.AnnotationEnvFromHash,
		constants.AnnotationTLSConfigHash,
		constants.AnnotationCompositeHash,
	}

	for _, key := range hashAnnotations {
		if value, exists := podAnnotations[key]; exists {
			result[key] = value
		}
	}

	return result
}

// BuildHashAnnotations builds the configuration hash annotations for a pod template
func BuildHashAnnotations(result *config.ChangeDetectionResult) map[string]string {
	annotations := make(map[string]string)

	if result == nil {
		return annotations
	}

	// Set the composite hash
	if result.CompositeHash != "" {
		annotations[constants.AnnotationCompositeHash] = result.CompositeHash
	}

	// Set change detection timestamp if changes were detected
	if result.HasChanges {
		annotations[constants.AnnotationConfigChangeTimestamp] = result.CheckedAt.Format(time.RFC3339)
		annotations[constants.AnnotationRequiredAction] = string(result.RequiredAction)
	}

	return annotations
}

// MergeAnnotations merges new annotations into existing ones
func MergeAnnotations(existing, newAnnotations map[string]string) map[string]string {
	if existing == nil {
		existing = make(map[string]string)
	}
	for k, v := range newAnnotations {
		existing[k] = v
	}
	return existing
}

// ShouldTriggerRestart determines if a restart is required based on change detection result
func ShouldTriggerRestart(result *config.ChangeDetectionResult, allowHotReload bool) bool {
	if result == nil || !result.HasChanges {
		return false
	}

	switch result.RequiredAction {
	case config.ChangeImpactNone:
		return false
	case config.ChangeImpactHotReload:
		return !allowHotReload // Only restart if hot reload is not available
	case config.ChangeImpactRollingRestart, config.ChangeImpactFullRestart:
		return true
	default:
		return false
	}
}

// IndexerConfigSources returns the standard configuration sources for indexer components
func IndexerConfigSources(clusterName string) *ComponentConfigSources {
	return &ComponentConfigSources{
		ConfigMaps: map[string]config.ChangeImpact{
			constants.IndexerConfigName(clusterName): config.ChangeImpactRollingRestart,
		},
		Secrets: map[string]config.ChangeImpact{
			constants.IndexerSecurityName(clusterName):    config.ChangeImpactRollingRestart,
			constants.IndexerCredentialsName(clusterName): config.ChangeImpactRollingRestart,
		},
		TLSSecrets: map[string]config.ChangeImpact{
			constants.IndexerCertsName(clusterName): config.ChangeImpactHotReload, // OpenSearch supports hot reload
			clusterName + "-ca":                     config.ChangeImpactRollingRestart,
		},
		EnvFromImpact: config.ChangeImpactRollingRestart,
	}
}

// ManagerConfigSources returns the standard configuration sources for manager components
func ManagerConfigSources(clusterName string, isMaster bool) *ComponentConfigSources {
	var certsName string
	var nodeType string
	if isMaster {
		certsName = constants.ManagerMasterCertsName(clusterName)
		nodeType = "master"
	} else {
		certsName = constants.ManagerWorkerCertsName(clusterName)
		nodeType = "worker"
	}

	return &ComponentConfigSources{
		ConfigMaps: map[string]config.ChangeImpact{
			constants.ManagerConfigName(clusterName, nodeType): config.ChangeImpactRollingRestart,
			constants.ManagerSharedConfigName(clusterName):     config.ChangeImpactRollingRestart,
		},
		Secrets: map[string]config.ChangeImpact{
			constants.APICredentialsName(clusterName): config.ChangeImpactRollingRestart,
			constants.ClusterKeyName(clusterName):     config.ChangeImpactRollingRestart,
		},
		TLSSecrets: map[string]config.ChangeImpact{
			certsName:           config.ChangeImpactRollingRestart, // Manager needs restart for cert changes
			clusterName + "-ca": config.ChangeImpactRollingRestart,
		},
		EnvFromImpact: config.ChangeImpactRollingRestart,
	}
}

// DashboardConfigSources returns the standard configuration sources for dashboard components
func DashboardConfigSources(clusterName string) *ComponentConfigSources {
	return &ComponentConfigSources{
		ConfigMaps: map[string]config.ChangeImpact{
			constants.DashboardConfigName(clusterName): config.ChangeImpactRollingRestart,
		},
		TLSSecrets: map[string]config.ChangeImpact{
			constants.DashboardCertsName(clusterName): config.ChangeImpactRollingRestart,
			clusterName + "-ca":                       config.ChangeImpactRollingRestart,
		},
		EnvFromImpact: config.ChangeImpactRollingRestart,
	}
}

// ConfigChangeEvent represents an event for configuration changes
type ConfigChangeEvent struct {
	// Component is the affected component
	Component string
	// ChangeType is the type of change
	ChangeType config.ChangeType
	// Source identifies what changed
	Source string
	// Impact is the required action
	Impact config.ChangeImpact
	// Message is a human-readable description
	Message string
}

// EmitConfigChangeEvent emits a Kubernetes event for a configuration change
func EmitConfigChangeEvent(
	object metav1.Object,
	eventType string,
	reason string,
	message string,
) *corev1.Event {
	now := time.Now()
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s.%x", object.GetName(), now.UnixNano()),
			Namespace: object.GetNamespace(),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "WazuhCluster",
			Name:       object.GetName(),
			Namespace:  object.GetNamespace(),
			UID:        object.GetUID(),
			APIVersion: "wazuh.com/v1",
		},
		Reason:         reason,
		Message:        message,
		Type:           eventType,
		FirstTimestamp: metav1.NewTime(now),
		LastTimestamp:  metav1.NewTime(now),
		Count:          1,
	}
}
