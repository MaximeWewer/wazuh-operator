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

package patch

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// TestComputeManagerMasterSpecHash_VersionChange tests that version changes produce different hashes
func TestComputeManagerMasterSpecHash_VersionChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	// Compute hash with version 4.7
	hash1, err := ComputeManagerMasterSpecHash("4.7", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHash failed for version 4.7: %v", err)
	}

	// Compute hash with version 4.8
	hash2, err := ComputeManagerMasterSpecHash("4.8", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHash failed for version 4.8: %v", err)
	}

	// Hashes should be different when version changes
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different versions, got same hash: %s", hash1)
	}
}

// TestComputeManagerMasterSpecHash_SameVersion tests that same version produces same hash
func TestComputeManagerMasterSpecHash_SameVersion(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	// Compute hash twice with same version
	hash1, err := ComputeManagerMasterSpecHash("4.9.2", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHash failed: %v", err)
	}

	hash2, err := ComputeManagerMasterSpecHash("4.9.2", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHash failed: %v", err)
	}

	// Hashes should be identical for same inputs
	if hash1 != hash2 {
		t.Errorf("Expected same hashes for same inputs, got hash1=%s, hash2=%s", hash1, hash2)
	}
}

// TestComputeManagerWorkersSpecHash_VersionChange tests that version changes produce different hashes for workers
func TestComputeManagerWorkersSpecHash_VersionChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	// Compute hash with version 4.7
	hash1, err := ComputeManagerWorkersSpecHash(2, "4.7", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHash failed for version 4.7: %v", err)
	}

	// Compute hash with version 4.8
	hash2, err := ComputeManagerWorkersSpecHash(2, "4.8", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHash failed for version 4.8: %v", err)
	}

	// Hashes should be different when version changes
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different versions, got same hash: %s", hash1)
	}
}

// TestComputeManagerWorkersSpecHash_ReplicaChange tests that replica count changes produce different hashes
func TestComputeManagerWorkersSpecHash_ReplicaChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	// Compute hash with 2 replicas
	hash1, err := ComputeManagerWorkersSpecHash(2, "4.9.2", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHash failed: %v", err)
	}

	// Compute hash with 3 replicas
	hash2, err := ComputeManagerWorkersSpecHash(3, "4.9.2", resources, "10Gi", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHash failed: %v", err)
	}

	// Hashes should be different when replicas change
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different replica counts, got same hash: %s", hash1)
	}
}

// TestComputeIndexerSpecHash_VersionChange tests that version changes produce different hashes for indexer
func TestComputeIndexerSpecHash_VersionChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}

	// Compute hash with version 2.10
	hash1, err := ComputeIndexerSpecHash(3, "2.10", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed for version 2.10: %v", err)
	}

	// Compute hash with version 2.11
	hash2, err := ComputeIndexerSpecHash(3, "2.11", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed for version 2.11: %v", err)
	}

	// Hashes should be different when version changes
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different versions, got same hash: %s", hash1)
	}
}

// TestComputeIndexerSpecHash_SameVersion tests that same version produces same hash for indexer
func TestComputeIndexerSpecHash_SameVersion(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}

	// Compute hash twice with same version
	hash1, err := ComputeIndexerSpecHash(3, "2.11.1", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	hash2, err := ComputeIndexerSpecHash(3, "2.11.1", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	// Hashes should be identical for same inputs
	if hash1 != hash2 {
		t.Errorf("Expected same hashes for same inputs, got hash1=%s, hash2=%s", hash1, hash2)
	}
}

// TestComputeIndexerSpecHash_ReplicaChange tests that replica count changes produce different hashes for indexer
func TestComputeIndexerSpecHash_ReplicaChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}

	// Compute hash with 3 replicas
	hash1, err := ComputeIndexerSpecHash(3, "2.11.1", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	// Compute hash with 5 replicas
	hash2, err := ComputeIndexerSpecHash(5, "2.11.1", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	// Hashes should be different when replicas change
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different replica counts, got same hash: %s", hash1)
	}
}

// TestComputeIndexerSpecHash_StorageChange tests that storage size changes produce different hashes
func TestComputeIndexerSpecHash_StorageChange(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		},
	}

	// Compute hash with 50Gi storage
	hash1, err := ComputeIndexerSpecHash(3, "2.11.1", resources, "50Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	// Compute hash with 100Gi storage
	hash2, err := ComputeIndexerSpecHash(3, "2.11.1", resources, "100Gi", "-Xms1g -Xmx1g", "")
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHash failed: %v", err)
	}

	// Hashes should be different when storage changes
	if hash1 == hash2 {
		t.Errorf("Expected different hashes for different storage sizes, got same hash: %s", hash1)
	}
}

// TestComputeManagerMasterSpecHash_WazuhExporterChange tests that wazuh exporter config changes produce different hashes
func TestComputeManagerMasterSpecHash_WazuhExporterChange(t *testing.T) {
	base := ManagerMasterSpecInput{
		Version:     "4.9.2",
		StorageSize: "10Gi",
	}

	// No exporter
	hash1, err := ComputeManagerMasterSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHashFull failed: %v", err)
	}

	// With exporter enabled
	withExporter := base
	withExporter.WazuhExporter = &WazuhExporterHashInput{
		Enabled: true,
		Image:   "pytoshka/wazuh-prometheus-exporter:latest",
		Port:    9090,
	}
	hash2, err := ComputeManagerMasterSpecHashFull(withExporter)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when wazuh exporter is added, got same hash: %s", hash1)
	}

	// Change exporter image
	changedImage := withExporter
	changedImage.WazuhExporter = &WazuhExporterHashInput{
		Enabled: true,
		Image:   "pytoshka/wazuh-prometheus-exporter:v2",
		Port:    9090,
	}
	hash3, err := ComputeManagerMasterSpecHashFull(changedImage)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHashFull failed: %v", err)
	}

	if hash2 == hash3 {
		t.Errorf("Expected different hashes when exporter image changes, got same hash: %s", hash2)
	}
}

// TestComputeIndexerSpecHash_IndexerExporterChange tests that indexer exporter config changes produce different hashes
func TestComputeIndexerSpecHash_IndexerExporterChange(t *testing.T) {
	base := IndexerSpecInput{
		Replicas:    3,
		Version:     "2.11.1",
		StorageSize: "50Gi",
		JavaOpts:    "-Xms1g -Xmx1g",
	}

	// No exporter
	hash1, err := ComputeIndexerSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	// With exporter enabled
	withExporter := base
	withExporter.IndexerExporter = &IndexerExporterHashInput{
		Enabled: true,
		Version: "2.11.1.0",
	}
	hash2, err := ComputeIndexerSpecHashFull(withExporter)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when indexer exporter is added, got same hash: %s", hash1)
	}

	// Change exporter version
	changedVersion := base
	changedVersion.IndexerExporter = &IndexerExporterHashInput{
		Enabled: true,
		Version: "2.12.0.0",
	}
	hash3, err := ComputeIndexerSpecHashFull(changedVersion)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	if hash2 == hash3 {
		t.Errorf("Expected different hashes when exporter version changes, got same hash: %s", hash2)
	}
}
