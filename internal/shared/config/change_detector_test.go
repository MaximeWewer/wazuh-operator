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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestConfigChangeDetector_DetectConfigMapChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create a ConfigMap
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-config",
			Namespace: "default",
		},
		Data: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddConfigMapSource("test-config", nil, ChangeImpactRollingRestart)

	ctx := context.Background()

	// First detection should not report changes (no previous state)
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes on first detection")
	}
	if result.CompositeHash == "" {
		t.Error("Expected composite hash to be set")
	}

	initialHash := result.CompositeHash

	// Second detection with same data should not report changes
	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes with unchanged config")
	}
	if result.CompositeHash != initialHash {
		t.Errorf("Composite hash changed unexpectedly: %s != %s", result.CompositeHash, initialHash)
	}

	// Modify the ConfigMap
	cm.Data["key1"] = "modified-value"
	_ = client.Update(ctx, cm)

	// Third detection should report changes
	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes after ConfigMap modification")
	}
	if len(result.Changes) != 1 {
		t.Errorf("Expected 1 change, got %d", len(result.Changes))
	}
	if result.Changes[0].Type != ChangeTypeConfigMap {
		t.Errorf("Expected change type ConfigMap, got %s", result.Changes[0].Type)
	}
	if result.RequiredAction != ChangeImpactRollingRestart {
		t.Errorf("Expected required action RollingRestart, got %s", result.RequiredAction)
	}
	if result.CompositeHash == initialHash {
		t.Error("Composite hash should have changed")
	}
}

func TestConfigChangeDetector_DetectSecretChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("secret-value"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddSecretSource("test-secret", nil, ChangeImpactHotReload)

	ctx := context.Background()

	// First detection
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes on first detection")
	}

	// Modify the secret
	secret.Data["password"] = []byte("new-secret-value")
	_ = client.Update(ctx, secret)

	// Second detection should report changes
	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes after Secret modification")
	}
	if result.RequiredAction != ChangeImpactHotReload {
		t.Errorf("Expected required action HotReload, got %s", result.RequiredAction)
	}
}

func TestConfigChangeDetector_TLSSecretChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("cert-data"),
			"tls.key": []byte("key-data"),
			"ca.crt":  []byte("ca-data"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tlsSecret).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddTLSSecretSource("tls-secret", ChangeImpactRollingRestart)

	ctx := context.Background()

	// First detection
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes on first detection")
	}

	// Modify the TLS certificate
	tlsSecret.Data["tls.crt"] = []byte("new-cert-data")
	_ = client.Update(ctx, tlsSecret)

	// Second detection should report changes
	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes after TLS certificate modification")
	}
	if result.Changes[0].Type != ChangeTypeTLSConfig {
		t.Errorf("Expected change type TLSConfig, got %s", result.Changes[0].Type)
	}
}

func TestConfigChangeDetector_MultipleSourcesHighestImpact(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "default",
		},
		Data: map[string]string{"key": "value"},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "default",
		},
		Data: map[string][]byte{"key": []byte("value")},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm, secret).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddConfigMapSource("config", nil, ChangeImpactHotReload)
	detector.AddSecretSource("secret", nil, ChangeImpactFullRestart)

	ctx := context.Background()

	// First detection
	_, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}

	// Modify both sources
	cm.Data["key"] = "new-value"
	secret.Data["key"] = []byte("new-value")
	_ = client.Update(ctx, cm)
	_ = client.Update(ctx, secret)

	// Detection should report highest impact
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes")
	}
	if len(result.Changes) != 2 {
		t.Errorf("Expected 2 changes, got %d", len(result.Changes))
	}
	// FullRestart is higher than HotReload
	if result.RequiredAction != ChangeImpactFullRestart {
		t.Errorf("Expected highest impact FullRestart, got %s", result.RequiredAction)
	}
}

func TestConfigChangeDetector_SpecificKeys(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "default",
		},
		Data: map[string]string{
			"watched-key":   "value1",
			"unwatched-key": "value2",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	// Only watch specific key
	detector.AddConfigMapSource("config", []string{"watched-key"}, ChangeImpactRollingRestart)

	ctx := context.Background()

	// First detection
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	initialHash := result.CompositeHash

	// Modify unwatched key - should not trigger change
	cm.Data["unwatched-key"] = "modified"
	_ = client.Update(ctx, cm)

	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes when unwatched key modified")
	}
	if result.CompositeHash != initialHash {
		t.Error("Hash should not change when unwatched key modified")
	}

	// Modify watched key - should trigger change
	cm.Data["watched-key"] = "modified"
	_ = client.Update(ctx, cm)

	result, err = detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !result.HasChanges {
		t.Error("Expected changes when watched key modified")
	}
}

func TestConfigChangeDetector_SetTrackedHashes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "default",
		},
		Data: map[string]string{"key": "value"},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddConfigMapSource("config", nil, ChangeImpactRollingRestart)

	// Compute current hash first
	ctx := context.Background()
	result, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	currentHash := result.CompositeHash

	// Create a new detector and set the tracked hashes
	detector2 := NewConfigChangeDetector(client, "default", "test-resource")
	detector2.AddConfigMapSource("config", nil, ChangeImpactRollingRestart)
	detector2.SetTrackedHashes(map[string]string{
		"ConfigMap/config": detector.tracked.Hashes["ConfigMap/config"].Hash,
	})

	// Detection should not report changes since we set the same hash
	result, err = detector2.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if result.HasChanges {
		t.Error("Expected no changes when tracked hashes are pre-set")
	}
	if result.CompositeHash != currentHash {
		t.Errorf("Composite hash mismatch: %s != %s", result.CompositeHash, currentHash)
	}
}

func TestConfigChangeDetector_GetHashesForAnnotations(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-config",
			Namespace: "default",
		},
		Data: map[string]string{"key": "value"},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	detector := NewConfigChangeDetector(client, "default", "test-resource")
	detector.AddConfigMapSource("my-config", nil, ChangeImpactRollingRestart)

	ctx := context.Background()
	_, err := detector.DetectChanges(ctx)
	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}

	annotations := detector.GetHashesForAnnotations()

	// Check that the key is sanitized (/ replaced with -)
	if _, exists := annotations["ConfigMap-my-config"]; !exists {
		t.Errorf("Expected sanitized annotation key 'ConfigMap-my-config', got keys: %v", annotations)
	}
}

func TestTrackedConfig_UpdateHash(t *testing.T) {
	tc := NewTrackedConfig("default", "test")

	// First update should return true
	if !tc.UpdateHash("source1", "hash1") {
		t.Error("Expected UpdateHash to return true for new source")
	}

	// Same hash should return false
	if tc.UpdateHash("source1", "hash1") {
		t.Error("Expected UpdateHash to return false for same hash")
	}

	// Different hash should return true
	if !tc.UpdateHash("source1", "hash2") {
		t.Error("Expected UpdateHash to return true for different hash")
	}

	// Verify the hash is stored correctly
	if tc.GetHash("source1") != "hash2" {
		t.Errorf("Expected hash 'hash2', got '%s'", tc.GetHash("source1"))
	}

	// Non-existent source should return empty string
	if tc.GetHash("nonexistent") != "" {
		t.Error("Expected empty string for non-existent source")
	}
}

func TestGetRequiredActionDescription(t *testing.T) {
	tests := []struct {
		impact   ChangeImpact
		expected string
	}{
		{ChangeImpactNone, "No action required"},
		{ChangeImpactHotReload, "Configuration can be hot-reloaded without restart"},
		{ChangeImpactRollingRestart, "Rolling restart of pods required"},
		{ChangeImpactFullRestart, "Full restart of all pods required"},
		{"Unknown", "Unknown action"},
	}

	for _, tt := range tests {
		t.Run(string(tt.impact), func(t *testing.T) {
			desc := GetRequiredActionDescription(tt.impact)
			if desc != tt.expected {
				t.Errorf("GetRequiredActionDescription(%s) = %s, want %s", tt.impact, desc, tt.expected)
			}
		})
	}
}
