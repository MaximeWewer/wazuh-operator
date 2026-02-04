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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/MaximeWewer/wazuh-operator/internal/shared/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestConfigChangeHelper_DetectChangesForComponent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-config",
			Namespace: "default",
		},
		Data: map[string]string{
			"key": "value",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	helper := NewConfigChangeHelper(client, "default", "test-component")

	sources := &ComponentConfigSources{
		ConfigMaps: map[string]config.ChangeImpact{
			"test-config": config.ChangeImpactRollingRestart,
		},
	}

	ctx := context.Background()

	// First detection should not report changes
	result, err := helper.DetectChangesForComponent(ctx, "test-resource", sources, nil)
	if err != nil {
		t.Fatalf("DetectChangesForComponent failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes on first detection")
	}

	// Second detection with same data should not report changes
	existingHashes := map[string]string{
		"ConfigMap/test-config": result.CompositeHash,
	}
	_, err = helper.DetectChangesForComponent(ctx, "test-resource", sources, existingHashes)
	if err != nil {
		t.Fatalf("DetectChangesForComponent failed: %v", err)
	}

	// Update ConfigMap
	cm.Data["key"] = "new-value"
	_ = client.Update(ctx, cm)

	// Third detection should report changes
	result, err = helper.DetectChangesForComponent(ctx, "test-resource", sources, existingHashes)
	if err != nil {
		t.Fatalf("DetectChangesForComponent failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes after ConfigMap modification")
	}
	if result.RequiredAction != config.ChangeImpactRollingRestart {
		t.Errorf("Expected RollingRestart action, got %s", result.RequiredAction)
	}
}

func TestGetHashAnnotationsFromPod(t *testing.T) {
	annotations := map[string]string{
		constants.AnnotationConfigHash:    "hash1",
		constants.AnnotationCompositeHash: "hash2",
		"unrelated-annotation":            "value",
	}

	result := GetHashAnnotationsFromPod(annotations)

	if result[constants.AnnotationConfigHash] != "hash1" {
		t.Errorf("Expected ConfigHash 'hash1', got '%s'", result[constants.AnnotationConfigHash])
	}
	if result[constants.AnnotationCompositeHash] != "hash2" {
		t.Errorf("Expected CompositeHash 'hash2', got '%s'", result[constants.AnnotationCompositeHash])
	}
	if _, exists := result["unrelated-annotation"]; exists {
		t.Error("Unrelated annotation should not be included")
	}
}

func TestBuildHashAnnotations(t *testing.T) {
	result := &config.ChangeDetectionResult{
		CompositeHash:  "test-hash",
		HasChanges:     true,
		RequiredAction: config.ChangeImpactRollingRestart,
	}

	annotations := BuildHashAnnotations(result)

	if annotations[constants.AnnotationCompositeHash] != "test-hash" {
		t.Errorf("Expected CompositeHash 'test-hash', got '%s'", annotations[constants.AnnotationCompositeHash])
	}
	if annotations[constants.AnnotationRequiredAction] != string(config.ChangeImpactRollingRestart) {
		t.Errorf("Expected RequiredAction 'RollingRestart', got '%s'", annotations[constants.AnnotationRequiredAction])
	}

	// Test with nil result
	nilAnnotations := BuildHashAnnotations(nil)
	if len(nilAnnotations) != 0 {
		t.Error("Expected empty annotations for nil result")
	}
}

func TestMergeAnnotations(t *testing.T) {
	existing := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	new := map[string]string{
		"key2": "updated",
		"key3": "value3",
	}

	result := MergeAnnotations(existing, new)

	if result["key1"] != "value1" {
		t.Errorf("Expected key1 'value1', got '%s'", result["key1"])
	}
	if result["key2"] != "updated" {
		t.Errorf("Expected key2 'updated', got '%s'", result["key2"])
	}
	if result["key3"] != "value3" {
		t.Errorf("Expected key3 'value3', got '%s'", result["key3"])
	}

	// Test with nil existing
	nilResult := MergeAnnotations(nil, new)
	if len(nilResult) != 2 {
		t.Errorf("Expected 2 annotations, got %d", len(nilResult))
	}
}

func TestShouldTriggerRestart(t *testing.T) {
	tests := []struct {
		name           string
		result         *config.ChangeDetectionResult
		allowHotReload bool
		expected       bool
	}{
		{
			name:     "Nil result",
			result:   nil,
			expected: false,
		},
		{
			name: "No changes",
			result: &config.ChangeDetectionResult{
				HasChanges:     false,
				RequiredAction: config.ChangeImpactNone,
			},
			expected: false,
		},
		{
			name: "No action impact",
			result: &config.ChangeDetectionResult{
				HasChanges:     true,
				RequiredAction: config.ChangeImpactNone,
			},
			expected: false,
		},
		{
			name: "Hot reload with hot reload allowed",
			result: &config.ChangeDetectionResult{
				HasChanges:     true,
				RequiredAction: config.ChangeImpactHotReload,
			},
			allowHotReload: true,
			expected:       false,
		},
		{
			name: "Hot reload without hot reload allowed",
			result: &config.ChangeDetectionResult{
				HasChanges:     true,
				RequiredAction: config.ChangeImpactHotReload,
			},
			allowHotReload: false,
			expected:       true,
		},
		{
			name: "Rolling restart",
			result: &config.ChangeDetectionResult{
				HasChanges:     true,
				RequiredAction: config.ChangeImpactRollingRestart,
			},
			expected: true,
		},
		{
			name: "Full restart",
			result: &config.ChangeDetectionResult{
				HasChanges:     true,
				RequiredAction: config.ChangeImpactFullRestart,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldTriggerRestart(tt.result, tt.allowHotReload)
			if result != tt.expected {
				t.Errorf("ShouldTriggerRestart() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIndexerConfigSources(t *testing.T) {
	sources := IndexerConfigSources("my-cluster")

	// Check ConfigMaps
	if _, exists := sources.ConfigMaps[constants.IndexerConfigName("my-cluster")]; !exists {
		t.Error("Expected indexer config map in sources")
	}

	// Check TLSSecrets with hot reload support
	if impact, exists := sources.TLSSecrets[constants.IndexerCertsName("my-cluster")]; !exists {
		t.Error("Expected indexer certs in TLS sources")
	} else if impact != config.ChangeImpactHotReload {
		t.Errorf("Expected HotReload impact for indexer certs, got %s", impact)
	}

	// CA should require rolling restart
	if impact, exists := sources.TLSSecrets["my-cluster-ca"]; !exists {
		t.Error("Expected CA in TLS sources")
	} else if impact != config.ChangeImpactRollingRestart {
		t.Errorf("Expected RollingRestart impact for CA, got %s", impact)
	}
}

func TestManagerConfigSources(t *testing.T) {
	// Test master
	masterSources := ManagerConfigSources("my-cluster", true)
	if _, exists := masterSources.ConfigMaps[constants.ManagerConfigName("my-cluster", "master")]; !exists {
		t.Error("Expected manager master config map in sources")
	}
	if _, exists := masterSources.TLSSecrets[constants.ManagerMasterCertsName("my-cluster")]; !exists {
		t.Error("Expected manager master certs in TLS sources")
	}

	// Test worker
	workerSources := ManagerConfigSources("my-cluster", false)
	if _, exists := workerSources.ConfigMaps[constants.ManagerConfigName("my-cluster", "worker")]; !exists {
		t.Error("Expected manager worker config map in sources")
	}
	if _, exists := workerSources.TLSSecrets[constants.ManagerWorkerCertsName("my-cluster")]; !exists {
		t.Error("Expected manager worker certs in TLS sources")
	}
}

func TestDashboardConfigSources(t *testing.T) {
	sources := DashboardConfigSources("my-cluster")

	// Check ConfigMaps
	if _, exists := sources.ConfigMaps[constants.DashboardConfigName("my-cluster")]; !exists {
		t.Error("Expected dashboard config map in sources")
	}

	// Check TLSSecrets
	if _, exists := sources.TLSSecrets[constants.DashboardCertsName("my-cluster")]; !exists {
		t.Error("Expected dashboard certs in TLS sources")
	}
}
