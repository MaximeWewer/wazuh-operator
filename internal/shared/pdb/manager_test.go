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

package pdb

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func int32Ptr(i int32) *int32 {
	return &i
}

func TestManagerPDBBuilder_Build(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &v1.WazuhManagerClusterSpec{
				Master: v1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: v1.WazuhWorkerSpec{
					Replicas: int32Ptr(2), // 1 master + 2 workers = 3 total
				},
			},
		},
	}

	builder := NewManagerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify name
	if pdb.Name != "test-cluster-manager" {
		t.Errorf("expected name 'test-cluster-manager', got '%s'", pdb.Name)
	}

	// Verify namespace
	if pdb.Namespace != "default" {
		t.Errorf("expected namespace 'default', got '%s'", pdb.Namespace)
	}

	// Verify minAvailable is set to default (2)
	if pdb.Spec.MinAvailable == nil {
		t.Fatal("expected minAvailable to be set")
	}
	if pdb.Spec.MinAvailable.IntVal != constants.DefaultManagerPDBMinAvailable {
		t.Errorf("expected minAvailable %d, got %d", constants.DefaultManagerPDBMinAvailable, pdb.Spec.MinAvailable.IntVal)
	}

	// Verify selector
	if pdb.Spec.Selector == nil {
		t.Fatal("expected selector to be set")
	}

	// Verify selector matches manager pods (wazuh-manager component)
	expectedLabels := constants.SelectorLabels("test-cluster", "wazuh-manager")
	for k, v := range expectedLabels {
		if pdb.Spec.Selector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s=%s", k, v, k, pdb.Spec.Selector.MatchLabels[k])
		}
	}
}

func TestManagerPDBBuilder_Build_CustomMinAvailable(t *testing.T) {
	minAvailable := int32(3)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &v1.WazuhManagerClusterSpec{
				Master: v1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: v1.WazuhWorkerSpec{
					Replicas: int32Ptr(4), // 1 master + 4 workers = 5 total
				},
				PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
					Enabled:      true,
					MinAvailable: &minAvailable,
				},
			},
		},
	}

	builder := NewManagerPDBBuilder(cluster)
	pdb := builder.Build()

	if pdb.Spec.MinAvailable.IntVal != minAvailable {
		t.Errorf("expected minAvailable %d, got %d", minAvailable, pdb.Spec.MinAvailable.IntVal)
	}
}

func TestManagerPDBBuilder_BuildWithMaxUnavailable(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &v1.WazuhManagerClusterSpec{
				Master: v1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: v1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
			},
		},
	}

	builder := NewManagerPDBBuilder(cluster)
	pdb := builder.BuildWithMaxUnavailable(1)

	// Verify minAvailable is not set
	if pdb.Spec.MinAvailable != nil {
		t.Error("expected minAvailable to be nil when using maxUnavailable")
	}

	// Verify maxUnavailable is set
	if pdb.Spec.MaxUnavailable == nil {
		t.Fatal("expected maxUnavailable to be set")
	}
	if pdb.Spec.MaxUnavailable.IntVal != 1 {
		t.Errorf("expected maxUnavailable 1, got %d", pdb.Spec.MaxUnavailable.IntVal)
	}
}

func TestGetManagerPDBName(t *testing.T) {
	name := GetManagerPDBName("my-cluster")
	if name != "my-cluster-manager" {
		t.Errorf("expected 'my-cluster-manager', got '%s'", name)
	}
}

func TestShouldCreateManagerPDB(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *v1.WazuhCluster
		expectedCreate bool
	}{
		{
			name: "manager with 2 workers (total 3 pods) - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2), // 1 master + 2 workers = 3 total
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "manager with 1 worker (total 2 pods) - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(1), // 1 master + 1 worker = 2 total
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "manager with 0 workers (total 1 pod) - should NOT create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(0), // 1 master + 0 workers = 1 total
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "manager with nil workers replicas (total 1 pod) - should NOT create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							// Replicas is nil, so only master (1 pod)
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "manager not configured",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{},
			},
			expectedCreate: false,
		},
		{
			name: "manager PDB explicitly disabled",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
						PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
							Enabled: false,
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "manager PDB explicitly enabled with sufficient replicas",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Master: v1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: v1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
						PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
							Enabled: true,
						},
					},
				},
			},
			expectedCreate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldCreate := ShouldCreateManagerPDB(tt.cluster)
			if shouldCreate != tt.expectedCreate {
				t.Errorf("ShouldCreateManagerPDB() = %v, expected %v", shouldCreate, tt.expectedCreate)
			}
		})
	}
}

func TestManagerPDBBuilder_Labels(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &v1.WazuhManagerClusterSpec{
				Master: v1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: v1.WazuhWorkerSpec{
					Replicas: int32Ptr(2),
				},
			},
		},
	}

	builder := NewManagerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify labels are set
	if pdb.Labels == nil {
		t.Fatal("expected labels to be set")
	}

	// Verify standard labels
	if pdb.Labels[constants.LabelInstance] != "test-cluster" {
		t.Errorf("expected instance label 'test-cluster', got '%s'", pdb.Labels[constants.LabelInstance])
	}

	if pdb.Labels[constants.LabelComponent] != constants.ComponentManager {
		t.Errorf("expected component label '%s', got '%s'", constants.ComponentManager, pdb.Labels[constants.LabelComponent])
	}

	if pdb.Labels[constants.LabelManagedBy] != constants.OperatorName {
		t.Errorf("expected managed-by label '%s', got '%s'", constants.OperatorName, pdb.Labels[constants.LabelManagedBy])
	}
}
