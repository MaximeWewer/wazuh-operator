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

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func int32Ptr(i int32) *int32 {
	return new(i)
}

func TestIndexerReconciler_ReconcileIndexerPDB(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = policyv1.AddToScheme(scheme)

	tests := []struct {
		name             string
		cluster          *wazuhv1.WazuhCluster
		existingPDB      *policyv1.PodDisruptionBudget
		wantPDB          bool
		wantMinAvailable int32
		wantErr          bool
	}{
		{
			name: "simple mode: creates PDB when 3+ replicas",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 3,
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultIndexerPDBMinAvailable,
			wantErr:          false,
		},
		{
			name: "simple mode: creates PDB when 2 replicas",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 2,
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultIndexerPDBMinAvailable,
			wantErr:          false,
		},
		{
			name: "simple mode: does not create PDB when only 1 replica",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 1,
					},
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "does not create PDB when indexer not configured",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "deletes existing PDB when no longer needed",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 1, // Only 1 replica, PDB not needed
					},
				},
			},
			existingPDB: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-indexer",
					Namespace: "default",
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "does not create PDB when explicitly disabled",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 3,
						PodDisruptionBudget: &wazuhv1.PodDisruptionBudgetSpec{
							Enabled: false,
						},
					},
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "uses custom minAvailable when specified",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 5,
						PodDisruptionBudget: &wazuhv1.PodDisruptionBudgetSpec{
							Enabled:      true,
							MinAvailable: int32Ptr(3),
						},
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: 3,
			wantErr:          false,
		},
		{
			name: "advanced mode: creates PDB when multiple nodePools total >= 2",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						NodePools: []wazuhv1.IndexerNodePoolSpec{
							{
								Name:     "master",
								Replicas: 3,
								Roles:    []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleClusterManager},
							},
							{
								Name:     "data",
								Replicas: 2,
								Roles:    []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultIndexerPDBMinAvailable,
			wantErr:          false,
		},
		{
			name: "advanced mode: does not create PDB when single nodePool with 1 replica",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						NodePools: []wazuhv1.IndexerNodePoolSpec{
							{
								Name:     "all-roles",
								Replicas: 1,
								Roles:    []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleClusterManager, wazuhv1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "advanced mode: creates PDB when single nodePool with 2+ replicas",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						NodePools: []wazuhv1.IndexerNodePoolSpec{
							{
								Name:     "all-roles",
								Replicas: 3,
								Roles:    []wazuhv1.IndexerNodeRole{wazuhv1.IndexerNodeRoleClusterManager, wazuhv1.IndexerNodeRoleData},
							},
						},
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultIndexerPDBMinAvailable,
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fake client with existing objects
			var objs []runtime.Object
			objs = append(objs, tt.cluster)
			if tt.existingPDB != nil {
				objs = append(objs, tt.existingPDB)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				Build()

			reconciler := NewIndexerReconciler(fakeClient, scheme)

			// Execute reconcileIndexerPDB
			err := reconciler.reconcileIndexerPDB(context.Background(), tt.cluster)
			if (err != nil) != tt.wantErr {
				t.Errorf("reconcileIndexerPDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify PDB state
			pdbName := pdb.GetIndexerPDBName(tt.cluster.Name)
			foundPDB := &policyv1.PodDisruptionBudget{}
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name:      pdbName,
				Namespace: tt.cluster.Namespace,
			}, foundPDB)

			if tt.wantPDB {
				if err != nil {
					t.Errorf("expected PDB to exist, got error: %v", err)
					return
				}
				// Verify minAvailable
				if foundPDB.Spec.MinAvailable != nil {
					if foundPDB.Spec.MinAvailable.IntVal != tt.wantMinAvailable {
						t.Errorf("expected minAvailable %d, got %d", tt.wantMinAvailable, foundPDB.Spec.MinAvailable.IntVal)
					}
				} else {
					t.Error("expected minAvailable to be set")
				}
				// Verify selector targets indexer pods
				expectedLabels := constants.SelectorLabels(tt.cluster.Name, constants.ComponentIndexer)
				for k, v := range expectedLabels {
					if foundPDB.Spec.Selector.MatchLabels[k] != v {
						t.Errorf("expected selector label %s=%s, got %s", k, v, foundPDB.Spec.Selector.MatchLabels[k])
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected PDB to not exist, but found one")
				}
			}
		})
	}
}

func TestIndexerReconciler_ReconcileIndexerPDB_UpdatesExistingPDB(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = policyv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 5,
				PodDisruptionBudget: &wazuhv1.PodDisruptionBudgetSpec{
					Enabled:      true,
					MinAvailable: int32Ptr(3),
				},
			},
		},
	}

	// Create existing PDB with different minAvailable
	existingPDB := pdb.NewIndexerPDBBuilder(cluster).Build()
	existingPDB.Spec.MinAvailable.IntVal = 1 // Old value

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, existingPDB).
		Build()

	reconciler := NewIndexerReconciler(fakeClient, scheme)

	// Execute reconcileIndexerPDB
	err := reconciler.reconcileIndexerPDB(context.Background(), cluster)
	if err != nil {
		t.Errorf("reconcileIndexerPDB() error = %v", err)
		return
	}

	// Verify PDB was updated
	pdbName := pdb.GetIndexerPDBName(cluster.Name)
	foundPDB := &policyv1.PodDisruptionBudget{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      pdbName,
		Namespace: cluster.Namespace,
	}, foundPDB)
	if err != nil {
		t.Errorf("failed to get PDB: %v", err)
		return
	}

	// Verify minAvailable was updated to the new value (3)
	if foundPDB.Spec.MinAvailable.IntVal != 3 {
		t.Errorf("expected minAvailable to be updated to 3, got %d", foundPDB.Spec.MinAvailable.IntVal)
	}
}

func TestIndexerReconciler_ReconcileIndexerPDB_DeletesWhenDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = policyv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Replicas: 3,
				PodDisruptionBudget: &wazuhv1.PodDisruptionBudgetSpec{
					Enabled: false, // Explicitly disabled
				},
			},
		},
	}

	// Create existing PDB that should be deleted
	existingPDB := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, existingPDB).
		Build()

	reconciler := NewIndexerReconciler(fakeClient, scheme)

	// Execute reconcileIndexerPDB
	err := reconciler.reconcileIndexerPDB(context.Background(), cluster)
	if err != nil {
		t.Errorf("reconcileIndexerPDB() error = %v", err)
		return
	}

	// Verify PDB was deleted
	pdbName := pdb.GetIndexerPDBName(cluster.Name)
	foundPDB := &policyv1.PodDisruptionBudget{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      pdbName,
		Namespace: cluster.Namespace,
	}, foundPDB)
	if err == nil {
		t.Errorf("expected PDB to be deleted, but it still exists")
	}
}
