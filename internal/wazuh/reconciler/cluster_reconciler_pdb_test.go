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
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
)

func TestClusterReconciler_ReconcileManagerPDB(t *testing.T) {
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
			name: "creates PDB when 3+ total replicas (1 master + 2 workers)",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultManagerPDBMinAvailable,
			wantErr:          false,
		},
		{
			name: "creates PDB when 2 total replicas (1 master + 1 worker)",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(1),
						},
					},
				},
			},
			wantPDB:          true,
			wantMinAvailable: constants.DefaultManagerPDBMinAvailable,
			wantErr:          false,
		},
		{
			name: "does not create PDB when only 1 replica (0 workers)",
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(0),
						},
					},
				},
			},
			wantPDB: false,
			wantErr: false,
		},
		{
			name: "does not create PDB when manager not configured",
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(0), // Only 1 total replica, PDB not needed
						},
					},
				},
			},
			existingPDB: &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-manager",
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
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
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(4),
						},
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

			reconciler := NewClusterReconciler(fakeClient, scheme)

			// Execute reconcileManagerPDB
			err := reconciler.reconcileManagerPDB(context.Background(), tt.cluster)
			if (err != nil) != tt.wantErr {
				t.Errorf("reconcileManagerPDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify PDB state
			pdbName := pdb.GetManagerPDBName(tt.cluster.Name)
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
				// Verify selector targets manager pods
				expectedLabels := constants.SelectorLabels(tt.cluster.Name, "wazuh-manager")
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

func TestClusterReconciler_ReconcileManagerPDB_UpdatesExistingPDB(t *testing.T) {
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
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Master: wazuhv1.WazuhMasterSpec{
					StorageSize: "10Gi",
				},
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(3),
				},
				PodDisruptionBudget: &wazuhv1.PodDisruptionBudgetSpec{
					Enabled:      true,
					MinAvailable: int32Ptr(3),
				},
			},
		},
	}

	// Create existing PDB with different minAvailable
	existingPDB := pdb.NewManagerPDBBuilder(cluster).Build()
	existingPDB.Spec.MinAvailable.IntVal = 1 // Old value

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(cluster, existingPDB).
		Build()

	reconciler := NewClusterReconciler(fakeClient, scheme)

	// Execute reconcileManagerPDB
	err := reconciler.reconcileManagerPDB(context.Background(), cluster)
	if err != nil {
		t.Errorf("reconcileManagerPDB() error = %v", err)
		return
	}

	// Verify PDB was updated
	pdbName := pdb.GetManagerPDBName(cluster.Name)
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
