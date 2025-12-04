/*
Copyright 2025.

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

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestDashboardPDBBuilder_Build(t *testing.T) {
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1alpha1.WazuhClusterSpec{
			Version: "4.9.0",
			Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
				Replicas: 2,
			},
		},
	}

	builder := NewDashboardPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify name
	if pdb.Name != "test-cluster-dashboard" {
		t.Errorf("expected name 'test-cluster-dashboard', got '%s'", pdb.Name)
	}

	// Verify namespace
	if pdb.Namespace != "default" {
		t.Errorf("expected namespace 'default', got '%s'", pdb.Namespace)
	}

	// Verify minAvailable is set to default (1)
	if pdb.Spec.MinAvailable == nil {
		t.Fatal("expected minAvailable to be set")
	}
	if pdb.Spec.MinAvailable.IntVal != constants.DefaultDashboardPDBMinAvailable {
		t.Errorf("expected minAvailable %d, got %d", constants.DefaultDashboardPDBMinAvailable, pdb.Spec.MinAvailable.IntVal)
	}

	// Verify selector
	if pdb.Spec.Selector == nil {
		t.Fatal("expected selector to be set")
	}
}

func TestDashboardPDBBuilder_Build_CustomMinAvailable(t *testing.T) {
	minAvailable := int32(2)
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1alpha1.WazuhClusterSpec{
			Version: "4.9.0",
			Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
				Replicas: 3,
				PodDisruptionBudget: &v1alpha1.PodDisruptionBudgetSpec{
					Enabled:      true,
					MinAvailable: &minAvailable,
				},
			},
		},
	}

	builder := NewDashboardPDBBuilder(cluster)
	pdb := builder.Build()

	if pdb.Spec.MinAvailable.IntVal != minAvailable {
		t.Errorf("expected minAvailable %d, got %d", minAvailable, pdb.Spec.MinAvailable.IntVal)
	}
}

func TestDashboardPDBBuilder_BuildWithMaxUnavailable(t *testing.T) {
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1alpha1.WazuhClusterSpec{
			Version: "4.9.0",
			Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
				Replicas: 3,
			},
		},
	}

	builder := NewDashboardPDBBuilder(cluster)
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

func TestGetPDBName(t *testing.T) {
	name := GetPDBName("my-cluster")
	if name != "my-cluster-dashboard" {
		t.Errorf("expected 'my-cluster-dashboard', got '%s'", name)
	}
}

func TestShouldCreatePDB(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *v1alpha1.WazuhCluster
		expectedCreate bool
	}{
		{
			name: "dashboard configured",
			cluster: &v1alpha1.WazuhCluster{
				Spec: v1alpha1.WazuhClusterSpec{
					Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
						Replicas: 1,
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "dashboard not configured",
			cluster: &v1alpha1.WazuhCluster{
				Spec: v1alpha1.WazuhClusterSpec{},
			},
			expectedCreate: false,
		},
		{
			name: "dashboard PDB explicitly disabled",
			cluster: &v1alpha1.WazuhCluster{
				Spec: v1alpha1.WazuhClusterSpec{
					Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
						Replicas: 2,
						PodDisruptionBudget: &v1alpha1.PodDisruptionBudgetSpec{
							Enabled: false,
						},
					},
				},
			},
			expectedCreate: false,
		},
		{
			name: "dashboard PDB explicitly enabled",
			cluster: &v1alpha1.WazuhCluster{
				Spec: v1alpha1.WazuhClusterSpec{
					Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
						Replicas: 2,
						PodDisruptionBudget: &v1alpha1.PodDisruptionBudgetSpec{
							Enabled: true,
						},
					},
				},
			},
			expectedCreate: true,
		},
		{
			name: "dashboard with default replicas (0 means 1)",
			cluster: &v1alpha1.WazuhCluster{
				Spec: v1alpha1.WazuhClusterSpec{
					Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
						Replicas: 0, // Should default to 1
					},
				},
			},
			expectedCreate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldCreate := ShouldCreatePDB(tt.cluster)
			if shouldCreate != tt.expectedCreate {
				t.Errorf("ShouldCreatePDB() = %v, expected %v", shouldCreate, tt.expectedCreate)
			}
		})
	}
}

func TestDashboardPDBBuilder_Labels(t *testing.T) {
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1alpha1.WazuhClusterSpec{
			Version: "4.9.0",
			Dashboard: &v1alpha1.WazuhDashboardClusterSpec{
				Replicas: 1,
			},
		},
	}

	builder := NewDashboardPDBBuilder(cluster)
	pdb := builder.Build()

	// Verify labels are set
	if pdb.Labels == nil {
		t.Fatal("expected labels to be set")
	}

	// Verify standard labels
	if pdb.Labels[constants.LabelInstance] != "test-cluster" {
		t.Errorf("expected instance label 'test-cluster', got '%s'", pdb.Labels[constants.LabelInstance])
	}

	if pdb.Labels[constants.LabelComponent] != constants.ComponentDashboard {
		t.Errorf("expected component label '%s', got '%s'", constants.ComponentDashboard, pdb.Labels[constants.LabelComponent])
	}

	if pdb.Labels[constants.LabelManagedBy] != constants.OperatorName {
		t.Errorf("expected managed-by label '%s', got '%s'", constants.OperatorName, pdb.Labels[constants.LabelManagedBy])
	}
}
