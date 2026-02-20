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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// TestComputeIndexerSpecHash_SecurityContextChange tests that SecurityContext changes produce different hashes
func TestComputeIndexerSpecHash_SecurityContextChange(t *testing.T) {
	base := IndexerSpecInput{
		Replicas:    3,
		Version:     "2.11.1",
		StorageSize: "50Gi",
		JavaOpts:    "-Xms1g -Xmx1g",
	}

	// No SecurityContext
	hash1, err := ComputeIndexerSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	// With SecurityContext
	runAsUser := int64(1000)
	withSC := base
	withSC.SecurityContext = &corev1.PodSecurityContext{
		RunAsUser: &runAsUser,
	}
	hash2, err := ComputeIndexerSpecHashFull(withSC)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when SecurityContext is added, got same hash: %s", hash1)
	}
}

// TestComputeIndexerSpecHash_TerminationGracePeriodChange tests that TerminationGracePeriodSeconds changes produce different hashes
func TestComputeIndexerSpecHash_TerminationGracePeriodChange(t *testing.T) {
	base := IndexerSpecInput{
		Replicas:    3,
		Version:     "2.11.1",
		StorageSize: "50Gi",
		JavaOpts:    "-Xms1g -Xmx1g",
	}

	// No TerminationGracePeriodSeconds
	hash1, err := ComputeIndexerSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	// With TerminationGracePeriodSeconds = 60
	gracePeriod := int64(60)
	withGP := base
	withGP.TerminationGracePeriodSeconds = &gracePeriod
	hash2, err := ComputeIndexerSpecHashFull(withGP)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when TerminationGracePeriodSeconds is set, got same hash: %s", hash1)
	}
}

// TestComputeDashboardSpecHash_EnableSSLChange tests that EnableSSL changes produce different hashes
func TestComputeDashboardSpecHash_EnableSSLChange(t *testing.T) {
	base := DashboardSpecInput{
		Replicas: 1,
		Version:  "2.11.1",
	}

	// EnableSSL = false (zero value, omitted)
	hash1, err := ComputeDashboardSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeDashboardSpecHashFull failed: %v", err)
	}

	// EnableSSL = true
	withSSL := base
	withSSL.EnableSSL = true
	hash2, err := ComputeDashboardSpecHashFull(withSSL)
	if err != nil {
		t.Fatalf("ComputeDashboardSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when EnableSSL changes, got same hash: %s", hash1)
	}
}

// TestComputeManagerMasterSpecHash_SecurityContextChange tests that SecurityContext changes produce different hashes for master
func TestComputeManagerMasterSpecHash_SecurityContextChange(t *testing.T) {
	base := ManagerMasterSpecInput{
		Version:     "4.9.2",
		StorageSize: "10Gi",
	}

	// No SecurityContext
	hash1, err := ComputeManagerMasterSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHashFull failed: %v", err)
	}

	// With SecurityContext
	runAsUser := int64(1000)
	withSC := base
	withSC.SecurityContext = &corev1.PodSecurityContext{
		RunAsUser: &runAsUser,
	}
	hash2, err := ComputeManagerMasterSpecHashFull(withSC)
	if err != nil {
		t.Fatalf("ComputeManagerMasterSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when SecurityContext is added, got same hash: %s", hash1)
	}
}

// TestComputeManagerWorkersSpecHash_TerminationGracePeriodChange tests that TerminationGracePeriodSeconds changes produce different hashes for workers
func TestComputeManagerWorkersSpecHash_TerminationGracePeriodChange(t *testing.T) {
	base := ManagerWorkersSpecInput{
		Replicas:    2,
		Version:     "4.9.2",
		StorageSize: "10Gi",
	}

	// No TerminationGracePeriodSeconds
	hash1, err := ComputeManagerWorkersSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHashFull failed: %v", err)
	}

	// With TerminationGracePeriodSeconds = 120
	gracePeriod := int64(120)
	withGP := base
	withGP.TerminationGracePeriodSeconds = &gracePeriod
	hash2, err := ComputeManagerWorkersSpecHashFull(withGP)
	if err != nil {
		t.Fatalf("ComputeManagerWorkersSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when TerminationGracePeriodSeconds is set, got same hash: %s", hash1)
	}
}

// TestComputeSpecHash_Deterministic verifies that ComputeSpecHash produces identical hashes
// across multiple invocations for the same input, even with map fields and complex nested types.
// This is the regression test for the hot reconciliation loop caused by non-deterministic hashing.
func TestComputeSpecHash_Deterministic(t *testing.T) {
	runAsUser := int64(1000)
	gracePeriod := int64(60)

	input := IndexerSpecInput{
		Replicas:    3,
		Version:     "2.11.1",
		StorageSize: "50Gi",
		JavaOpts:    "-Xms1g -Xmx1g",
		Image:       "wazuh/wazuh-indexer:2.11.1",
		Resources: &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("2Gi"),
				corev1.ResourceCPU:    resource.MustParse("500m"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("4Gi"),
				corev1.ResourceCPU:    resource.MustParse("2"),
			},
		},
		NodeSelector: map[string]string{
			"kubernetes.io/os": "linux",
			"node-role":        "indexer",
			"topology.zone":    "us-east-1a",
			"disktype":         "ssd",
			"environment":      "production",
		},
		Labels: map[string]string{
			"app":        "wazuh-indexer",
			"component":  "indexer",
			"version":    "2.11.1",
			"managed-by": "wazuh-operator",
		},
		Annotations: map[string]string{
			"wazuh.com/cluster":  "my-cluster",
			"wazuh.com/role":     "indexer",
			"prometheus.io/port": "9200",
		},
		PodAnnotations: map[string]string{
			"sidecar.istio.io/inject":          "true",
			"vault.hashicorp.com/agent-inject": "true",
		},
		Affinity: &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
					{
						Weight: 100,
						PodAffinityTerm: corev1.PodAffinityTerm{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app":       "wazuh-indexer",
									"component": "indexer",
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
		},
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser: &runAsUser,
		},
		TerminationGracePeriodSeconds: &gracePeriod,
		ImagePullPolicy:               corev1.PullAlways,
		IndexerExporter: &IndexerExporterHashInput{
			Enabled: true,
			Version: "2.11.1.0",
		},
		RepositoryPlugins: []RepositoryPluginHashInput{
			{Name: "s3", ClientName: "default", CredentialsSecret: "s3-creds"},
		},
	}

	// Compute hash 100 times and verify all are identical
	firstHash, err := ComputeIndexerSpecHashFull(input)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		hash, err := ComputeIndexerSpecHashFull(input)
		if err != nil {
			t.Fatalf("ComputeIndexerSpecHashFull failed on iteration %d: %v", i, err)
		}
		if hash != firstHash {
			t.Fatalf("Non-deterministic hash detected on iteration %d: got %s, expected %s", i, hash, firstHash)
		}
	}
}

// TestComputeIndexerSpecHash_ImagePullPolicyChange tests that ImagePullPolicy changes produce different hashes
func TestComputeIndexerSpecHash_ImagePullPolicyChange(t *testing.T) {
	base := IndexerSpecInput{
		Replicas:    3,
		Version:     "2.11.1",
		StorageSize: "50Gi",
		JavaOpts:    "-Xms1g -Xmx1g",
	}

	// No ImagePullPolicy (empty = omitted)
	hash1, err := ComputeIndexerSpecHashFull(base)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	// With ImagePullPolicy = Always
	withPolicy := base
	withPolicy.ImagePullPolicy = corev1.PullAlways
	hash2, err := ComputeIndexerSpecHashFull(withPolicy)
	if err != nil {
		t.Fatalf("ComputeIndexerSpecHashFull failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes when ImagePullPolicy is set, got same hash: %s", hash1)
	}
}
