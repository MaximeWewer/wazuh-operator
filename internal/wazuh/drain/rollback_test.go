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

package drain

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestRollbackManager_ExecuteRollback_Indexer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	// Create StatefulSet with current (reduced) replica count
	replicas := int32(2)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-indexer",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	manager := NewRollbackManager(fakeClient, getTestLogger())

	// Set up cluster with drain status containing previous replicas
	previousReplicas := int32(3)
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Status: v1alpha1.WazuhClusterStatus{
			Drain: &v1alpha1.DrainStatus{
				Indexer: &v1alpha1.ComponentDrainStatus{
					PreviousReplicas: &previousReplicas,
				},
			},
		},
	}

	err := manager.ExecuteRollback(context.Background(), cluster, constants.DrainComponentIndexer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify StatefulSet was updated
	var updatedSts appsv1.StatefulSet
	if err := fakeClient.Get(context.Background(),
		types.NamespacedName{Name: "test-cluster-indexer", Namespace: "default"}, &updatedSts); err != nil {
		t.Fatalf("failed to get StatefulSet: %v", err)
	}

	if *updatedSts.Spec.Replicas != previousReplicas {
		t.Errorf("expected replicas to be %d, got %d", previousReplicas, *updatedSts.Spec.Replicas)
	}
}

func TestRollbackManager_ExecuteRollback_Manager(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	// Create StatefulSet with current (reduced) replica count
	replicas := int32(1)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-manager-worker",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	manager := NewRollbackManager(fakeClient, getTestLogger())

	// Set up cluster with drain status containing previous replicas
	previousReplicas := int32(2)
	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Status: v1alpha1.WazuhClusterStatus{
			Drain: &v1alpha1.DrainStatus{
				Manager: &v1alpha1.ComponentDrainStatus{
					PreviousReplicas: &previousReplicas,
				},
			},
		},
	}

	err := manager.ExecuteRollback(context.Background(), cluster, constants.DrainComponentManager)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify StatefulSet was updated
	var updatedSts appsv1.StatefulSet
	if err := fakeClient.Get(context.Background(),
		types.NamespacedName{Name: "test-cluster-manager-worker", Namespace: "default"}, &updatedSts); err != nil {
		t.Fatalf("failed to get StatefulSet: %v", err)
	}

	if *updatedSts.Spec.Replicas != previousReplicas {
		t.Errorf("expected replicas to be %d, got %d", previousReplicas, *updatedSts.Spec.Replicas)
	}
}

func TestRollbackManager_ExecuteRollback_UnknownComponent(t *testing.T) {
	fakeClient := fake.NewClientBuilder().Build()
	manager := NewRollbackManager(fakeClient, getTestLogger())

	cluster := &v1alpha1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	err := manager.ExecuteRollback(context.Background(), cluster, "unknown")
	if err == nil {
		t.Error("expected error for unknown component")
	}
}

func TestRollbackManager_VerifyRollbackComplete_Indexer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	tests := []struct {
		name             string
		readyReplicas    int32
		totalReplicas    int32
		previousReplicas int32
		expectedComplete bool
	}{
		{
			name:             "complete - all replicas ready",
			readyReplicas:    3,
			totalReplicas:    3,
			previousReplicas: 3,
			expectedComplete: true,
		},
		{
			name:             "incomplete - not all ready",
			readyReplicas:    2,
			totalReplicas:    3,
			previousReplicas: 3,
			expectedComplete: false,
		},
		{
			name:             "incomplete - still scaling",
			readyReplicas:    2,
			totalReplicas:    2,
			previousReplicas: 3,
			expectedComplete: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sts := &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-indexer",
					Namespace: "default",
				},
				Spec: appsv1.StatefulSetSpec{
					Replicas: &tt.totalReplicas,
				},
				Status: appsv1.StatefulSetStatus{
					ReadyReplicas: tt.readyReplicas,
					Replicas:      tt.totalReplicas,
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(sts).
				Build()

			manager := NewRollbackManager(fakeClient, getTestLogger())

			cluster := &v1alpha1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Status: v1alpha1.WazuhClusterStatus{
					Drain: &v1alpha1.DrainStatus{
						Indexer: &v1alpha1.ComponentDrainStatus{
							PreviousReplicas: &tt.previousReplicas,
						},
					},
				},
			}

			complete, err := manager.VerifyRollbackComplete(context.Background(), cluster, constants.DrainComponentIndexer)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if complete != tt.expectedComplete {
				t.Errorf("expected complete=%v, got %v", tt.expectedComplete, complete)
			}
		})
	}
}
