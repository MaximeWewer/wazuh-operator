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

func TestIndexerPDBBuilder_Build(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 3, // Simple mode with 3 replicas
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify name
	if pdb.Name != "test-cluster-indexer" {
		t.Errorf("expected name 'test-cluster-indexer', got '%s'", pdb.Name)
	}

	// Verify namespace
	if pdb.Namespace != "default" {
		t.Errorf("expected namespace 'default', got '%s'", pdb.Namespace)
	}

	// Verify minAvailable is set to default (2)
	if pdb.Spec.MinAvailable == nil {
		t.Fatal("expected minAvailable to be set")
	}
	if pdb.Spec.MinAvailable.IntVal != constants.DefaultIndexerPDBMinAvailable {
		t.Errorf("expected minAvailable %d, got %d", constants.DefaultIndexerPDBMinAvailable, pdb.Spec.MinAvailable.IntVal)
	}

	// Verify selector
	if pdb.Spec.Selector == nil {
		t.Fatal("expected selector to be set")
	}

	// Verify selector matches indexer pods (ComponentIndexer = "indexer")
	expectedLabels := constants.SelectorLabels("test-cluster", constants.ComponentIndexer)
	for k, v := range expectedLabels {
		if pdb.Spec.Selector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s=%s", k, v, k, pdb.Spec.Selector.MatchLabels[k])
		}
	}
}

func TestIndexerPDBBuilder_Build_CustomMinAvailable(t *testing.T) {
	minAvailable := int32(3)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 5, // Simple mode with 5 replicas
				PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
					Enabled:      true,
					MinAvailable: &minAvailable,
				},
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	if pdb.Spec.MinAvailable.IntVal != minAvailable {
		t.Errorf("expected minAvailable %d, got %d", minAvailable, pdb.Spec.MinAvailable.IntVal)
	}
}

func TestIndexerPDBBuilder_BuildWithMaxUnavailable(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
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

func TestGetIndexerPDBName(t *testing.T) {
	name := GetIndexerPDBName("my-cluster")
	if name != "my-cluster-indexer" {
		t.Errorf("expected 'my-cluster-indexer', got '%s'", name)
	}
}

func TestShouldCreateIndexerPDB(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *v1.WazuhCluster
		expectedCreate bool
	}{
		{
			name: "simple mode with 3 replicas - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "simple mode with 2 replicas - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 2,
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "simple mode with 1 replica - should NOT create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 1,
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "simple mode with 0 replicas - should NOT create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 0,
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "advanced mode with multiple nodePools (total 5 replicas) - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						NodePools: []v1.IndexerNodePoolSpec{
							{
								Name:     "master",
								Replicas: 3,
								Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleClusterManager},
							},
							{
								Name:     "data",
								Replicas: 2,
								Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "advanced mode with single nodePool (2 replicas) - should create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						NodePools: []v1.IndexerNodePoolSpec{
							{
								Name:     "all-roles",
								Replicas: 2,
								Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleClusterManager, v1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "advanced mode with single nodePool (1 replica) - should NOT create PDB",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						NodePools: []v1.IndexerNodePoolSpec{
							{
								Name:     "all-roles",
								Replicas: 1,
								Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleClusterManager, v1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "indexer not configured",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{},
			},
			expectedCreate: false,
		},
		{
			name: "indexer PDB explicitly disabled",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
						PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
							Enabled: false,
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "indexer PDB explicitly enabled with sufficient replicas",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						Replicas: 3,
						PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
							Enabled: true,
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "advanced mode PDB explicitly disabled",
			cluster: &v1.WazuhCluster{
				Spec: v1.WazuhClusterSpec{
					Indexer: &v1.WazuhIndexerClusterSpec{
						NodePools: []v1.IndexerNodePoolSpec{
							{
								Name:     "master",
								Replicas: 3,
								Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleClusterManager},
							},
						},
						PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
							Enabled: false,
						},
					},
				},
			},
			expectedCreate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldCreate := ShouldCreateIndexerPDB(tt.cluster)
			if shouldCreate != tt.expectedCreate {
				t.Errorf("ShouldCreateIndexerPDB() = %v, expected %v", shouldCreate, tt.expectedCreate)
			}
		})
	}
}

func TestIndexerPDBBuilder_Labels(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 3,
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify labels are set
	if pdb.Labels == nil {
		t.Fatal("expected labels to be set")
	}

	// Verify standard labels
	if pdb.Labels[constants.LabelInstance] != "test-cluster" {
		t.Errorf("expected instance label 'test-cluster', got '%s'", pdb.Labels[constants.LabelInstance])
	}

	if pdb.Labels[constants.LabelComponent] != constants.ComponentIndexer {
		t.Errorf("expected component label '%s', got '%s'", constants.ComponentIndexer, pdb.Labels[constants.LabelComponent])
	}

	if pdb.Labels[constants.LabelManagedBy] != constants.OperatorName {
		t.Errorf("expected managed-by label '%s', got '%s'", constants.OperatorName, pdb.Labels[constants.LabelManagedBy])
	}
}

func TestIndexerPDBBuilder_Build_MaxUnavailableFromSpec(t *testing.T) {
	maxUnavailable := int32(1)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 5,
				PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
					Enabled:        true,
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify minAvailable is NOT set when maxUnavailable is specified
	if pdb.Spec.MinAvailable != nil {
		t.Error("expected minAvailable to be nil when maxUnavailable is set in spec")
	}

	// Verify maxUnavailable is set correctly
	if pdb.Spec.MaxUnavailable == nil {
		t.Fatal("expected maxUnavailable to be set")
	}
	if pdb.Spec.MaxUnavailable.IntVal != maxUnavailable {
		t.Errorf("expected maxUnavailable %d, got %d", maxUnavailable, pdb.Spec.MaxUnavailable.IntVal)
	}
}

func TestIndexerPDBBuilder_Build_MaxUnavailableTakesPriority(t *testing.T) {
	// When both minAvailable and maxUnavailable are set, maxUnavailable takes priority
	minAvailable := int32(3)
	maxUnavailable := int32(1)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 5,
				PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
					Enabled:        true,
					MinAvailable:   &minAvailable,
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify maxUnavailable takes priority
	if pdb.Spec.MinAvailable != nil {
		t.Error("expected minAvailable to be nil when maxUnavailable is set (priority)")
	}

	if pdb.Spec.MaxUnavailable == nil {
		t.Fatal("expected maxUnavailable to be set")
	}
	if pdb.Spec.MaxUnavailable.IntVal != maxUnavailable {
		t.Errorf("expected maxUnavailable %d, got %d", maxUnavailable, pdb.Spec.MaxUnavailable.IntVal)
	}
}

func TestIndexerPDBBuilder_AdvancedMode_Build(t *testing.T) {
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &v1.WazuhIndexerClusterSpec{
				NodePools: []v1.IndexerNodePoolSpec{
					{
						Name:     "master",
						Replicas: 3,
						Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleClusterManager},
					},
					{
						Name:     "data",
						Replicas: 2,
						Roles:    []v1.IndexerNodeRole{v1.IndexerNodeRoleData},
					},
				},
			},
		},
	}

	builder := NewIndexerPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify name
	if pdb.Name != "test-cluster-indexer" {
		t.Errorf("expected name 'test-cluster-indexer', got '%s'", pdb.Name)
	}

	// Verify minAvailable is set to default (2)
	if pdb.Spec.MinAvailable == nil {
		t.Fatal("expected minAvailable to be set")
	}
	if pdb.Spec.MinAvailable.IntVal != constants.DefaultIndexerPDBMinAvailable {
		t.Errorf("expected minAvailable %d, got %d", constants.DefaultIndexerPDBMinAvailable, pdb.Spec.MinAvailable.IntVal)
	}

	// Verify selector matches indexer pods regardless of nodePool
	expectedLabels := constants.SelectorLabels("test-cluster", constants.ComponentIndexer)
	for k, v := range expectedLabels {
		if pdb.Spec.Selector.MatchLabels[k] != v {
			t.Errorf("expected selector label %s=%s, got %s=%s", k, v, k, pdb.Spec.Selector.MatchLabels[k])
		}
	}
}
