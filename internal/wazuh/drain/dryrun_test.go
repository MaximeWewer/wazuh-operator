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

package drain

import (
	"context"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// mockIndexerEvaluator is a mock implementation for testing
type mockIndexerEvaluator struct {
	result *v1.DryRunResult
	err    error
}

func (m *mockIndexerEvaluator) EvaluateFeasibility(ctx context.Context, nodeName string) (*v1.DryRunResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// mockManagerEvaluator is a mock implementation for testing
type mockManagerEvaluator struct {
	result *v1.DryRunResult
	err    error
}

func (m *mockManagerEvaluator) EvaluateFeasibility(ctx context.Context, nodeName string) (*v1.DryRunResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestDryRunEvaluator_EvaluateIndexerDrain_NilEvaluator(t *testing.T) {
	evaluator := &DryRunEvaluatorImpl{
		log:              getTestLogger(),
		indexerEvaluator: nil,
	}

	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	result, err := evaluator.EvaluateIndexerDrain(context.Background(), cluster, "test-node-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Feasible {
		t.Error("expected feasible to be false when evaluator is nil")
	}

	if result.Component != constants.DrainComponentIndexer {
		t.Errorf("expected component %s, got %s", constants.DrainComponentIndexer, result.Component)
	}

	if len(result.Blockers) != 1 {
		t.Errorf("expected 1 blocker, got %d", len(result.Blockers))
	}
}

func TestDryRunEvaluator_EvaluateIndexerDrain_Success(t *testing.T) {
	mockResult := &v1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentIndexer,
		Warnings:    []string{"Cluster is yellow"},
	}

	evaluator := &DryRunEvaluatorImpl{
		log: getTestLogger(),
		indexerEvaluator: &mockIndexerEvaluator{
			result: mockResult,
		},
	}

	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	result, err := evaluator.EvaluateIndexerDrain(context.Background(), cluster, "test-node-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Feasible {
		t.Error("expected feasible to be true")
	}

	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestDryRunEvaluator_EvaluateManagerDrain_NilEvaluator(t *testing.T) {
	evaluator := &DryRunEvaluatorImpl{
		log:              getTestLogger(),
		managerEvaluator: nil,
	}

	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	result, err := evaluator.EvaluateManagerDrain(context.Background(), cluster, "test-worker-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Feasible {
		t.Error("expected feasible to be false when evaluator is nil")
	}

	if result.Component != constants.DrainComponentManager {
		t.Errorf("expected component %s, got %s", constants.DrainComponentManager, result.Component)
	}
}

func TestDryRunEvaluator_EvaluateManagerDrain_NotFeasible(t *testing.T) {
	mockResult := &v1.DryRunResult{
		Feasible:    false,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentManager,
		Blockers:    []string{"Only one worker in cluster"},
	}

	evaluator := &DryRunEvaluatorImpl{
		log: getTestLogger(),
		managerEvaluator: &mockManagerEvaluator{
			result: mockResult,
		},
	}

	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	result, err := evaluator.EvaluateManagerDrain(context.Background(), cluster, "test-worker-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Feasible {
		t.Error("expected feasible to be false")
	}

	if len(result.Blockers) != 1 {
		t.Errorf("expected 1 blocker, got %d", len(result.Blockers))
	}
}

func TestDryRunEvaluator_EvaluateAll_AllFeasible(t *testing.T) {
	indexerResult := &v1.DryRunResult{
		Feasible:          true,
		EvaluatedAt:       metav1.Now(),
		Component:         constants.DrainComponentIndexer,
		EstimatedDuration: &metav1.Duration{Duration: 5 * time.Minute},
	}

	managerResult := &v1.DryRunResult{
		Feasible:          true,
		EvaluatedAt:       metav1.Now(),
		Component:         constants.DrainComponentManager,
		EstimatedDuration: &metav1.Duration{Duration: 3 * time.Minute},
	}

	evaluator := &DryRunEvaluatorImpl{
		log: getTestLogger(),
		indexerEvaluator: &mockIndexerEvaluator{
			result: indexerResult,
		},
		managerEvaluator: &mockManagerEvaluator{
			result: managerResult,
		},
	}

	// Create cluster with drain status to simulate scale-down
	prevReplicas := int32(3)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 2, // Scale down from 3 to 2
			},
		},
		Status: v1.WazuhClusterStatus{
			Indexer: &v1.ComponentStatus{
				Replicas: 3,
			},
			Drain: &v1.DrainStatus{
				Indexer: &v1.ComponentDrainStatus{
					TargetPod:        "test-cluster-indexer-2",
					PreviousReplicas: &prevReplicas,
				},
				Manager: &v1.ComponentDrainStatus{
					TargetPod:        "test-cluster-manager-worker-1",
					PreviousReplicas: &prevReplicas,
				},
			},
		},
	}

	result, err := evaluator.EvaluateAll(context.Background(), cluster)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Feasible {
		t.Error("expected combined result to be feasible")
	}

	if result.Component != "all" {
		t.Errorf("expected component 'all', got %s", result.Component)
	}
}

func TestDryRunEvaluator_EvaluateAll_OneNotFeasible(t *testing.T) {
	indexerResult := &v1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentIndexer,
	}

	managerResult := &v1.DryRunResult{
		Feasible:    false,
		EvaluatedAt: metav1.Now(),
		Component:   constants.DrainComponentManager,
		Blockers:    []string{"Only one worker"},
	}

	evaluator := &DryRunEvaluatorImpl{
		log: getTestLogger(),
		indexerEvaluator: &mockIndexerEvaluator{
			result: indexerResult,
		},
		managerEvaluator: &mockManagerEvaluator{
			result: managerResult,
		},
	}

	prevReplicas := int32(2)
	cluster := &v1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: v1.WazuhClusterSpec{
			Indexer: &v1.WazuhIndexerClusterSpec{
				Replicas: 2,
			},
		},
		Status: v1.WazuhClusterStatus{
			Indexer: &v1.ComponentStatus{
				Replicas: 3,
			},
			Drain: &v1.DrainStatus{
				Indexer: &v1.ComponentDrainStatus{
					TargetPod:        "test-cluster-indexer-2",
					PreviousReplicas: &prevReplicas,
				},
				Manager: &v1.ComponentDrainStatus{
					TargetPod:        "test-cluster-manager-worker-1",
					PreviousReplicas: &prevReplicas,
				},
			},
		},
	}

	result, err := evaluator.EvaluateAll(context.Background(), cluster)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Feasible {
		t.Error("expected combined result to be not feasible when one component fails")
	}

	// Should have blocker from manager with [manager] prefix
	foundManagerBlocker := slices.Contains(result.Blockers, "[manager] Only one worker")
	if !foundManagerBlocker {
		t.Error("expected manager blocker with prefix in combined blockers")
	}
}

func TestDryRunEvaluator_GetTargetIndexerNode(t *testing.T) {
	sts := func(name string, replicas int32) *appsv1.StatefulSet {
		return &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Spec: appsv1.StatefulSetSpec{Replicas: &replicas}}
	}
	pools := func(hot, warm int32) *v1.WazuhIndexerClusterSpec {
		return &v1.WazuhIndexerClusterSpec{NodePools: []v1.IndexerNodePoolSpec{{Name: "hot", Replicas: hot}, {Name: "warm", Replicas: warm}}}
	}

	tests := []struct {
		name           string
		indexer        *v1.WazuhIndexerClusterSpec
		drainTarget    string
		statefulSets   []*appsv1.StatefulSet
		expectedTarget string
	}{
		{name: "target from drain status", drainTarget: "test-indexer-2", expectedTarget: "test-indexer-2"},
		{name: "no scale-down detected", indexer: &v1.WazuhIndexerClusterSpec{Replicas: 3},
			statefulSets: []*appsv1.StatefulSet{sts("test-indexer", 3)}},
		{name: "scale-down detected", indexer: &v1.WazuhIndexerClusterSpec{Replicas: 2},
			statefulSets: []*appsv1.StatefulSet{sts("test-indexer", 3)}, expectedTarget: "test-indexer-2"},
		{name: "unset replicas means the default 3", indexer: &v1.WazuhIndexerClusterSpec{},
			statefulSets: []*appsv1.StatefulSet{sts("test-indexer", 4)}, expectedTarget: "test-indexer-3"},
		{name: "nodePool scale-down targets the pool's last pod", indexer: pools(2, 1),
			statefulSets: []*appsv1.StatefulSet{sts("test-indexer-hot", 2), sts("test-indexer-warm", 2)}, expectedTarget: "test-indexer-warm-1"},
		{name: "nodePools unchanged", indexer: pools(2, 2),
			statefulSets: []*appsv1.StatefulSet{sts("test-indexer-hot", 2), sts("test-indexer-warm", 2)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = appsv1.AddToScheme(scheme)
			b := fake.NewClientBuilder().WithScheme(scheme)
			for _, s := range tt.statefulSets {
				b = b.WithObjects(s)
			}
			evaluator := &DryRunEvaluatorImpl{log: getTestLogger(), client: b.Build()}
			cluster := &v1.WazuhCluster{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "ns"}, Spec: v1.WazuhClusterSpec{Indexer: tt.indexer}}
			if tt.drainTarget != "" {
				cluster.Status.Drain = &v1.DrainStatus{Indexer: &v1.ComponentDrainStatus{TargetPod: tt.drainTarget}}
			}
			target := evaluator.getTargetIndexerNode(context.Background(), cluster)
			if target != tt.expectedTarget {
				t.Errorf("expected target %q, got %q", tt.expectedTarget, target)
			}
		})
	}
}

func TestDryRunEvaluator_GetTargetManagerNode(t *testing.T) {
	evaluator := &DryRunEvaluatorImpl{
		log: getTestLogger(),
	}

	prevReplicas := int32(2)
	tests := []struct {
		name           string
		cluster        *v1.WazuhCluster
		expectedTarget string
	}{
		{
			name: "target from drain status",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Status: v1.WazuhClusterStatus{
					Drain: &v1.DrainStatus{
						Manager: &v1.ComponentDrainStatus{
							TargetPod: "test-manager-worker-1",
						},
					},
				},
			},
			expectedTarget: "test-manager-worker-1",
		},
		{
			name: "scale-down detected from previous replicas",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Workers: v1.WazuhWorkerSpec{
							Replicas: func() *int32 { r := int32(1); return &r }(),
						},
					},
				},
				Status: v1.WazuhClusterStatus{
					Drain: &v1.DrainStatus{
						Manager: &v1.ComponentDrainStatus{
							PreviousReplicas: &prevReplicas,
						},
					},
				},
			},
			expectedTarget: "test-manager-worker-1",
		},
		{
			name: "no drain status",
			cluster: &v1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: v1.WazuhClusterSpec{
					Manager: &v1.WazuhManagerClusterSpec{
						Workers: v1.WazuhWorkerSpec{
							Replicas: func() *int32 { r := int32(2); return &r }(),
						},
					},
				},
			},
			expectedTarget: "", // Can't detect without drain status
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := evaluator.getTargetManagerNode(tt.cluster)
			if target != tt.expectedTarget {
				t.Errorf("expected target %s, got %s", tt.expectedTarget, target)
			}
		})
	}
}
