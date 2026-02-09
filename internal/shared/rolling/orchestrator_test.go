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

package rolling

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// mockHealthChecker implements HealthChecker for testing.
type mockHealthChecker struct {
	healthy bool
	message string
	err     error
}

func (m *mockHealthChecker) IsHealthyForRestart(_ context.Context) (bool, string, error) {
	return m.healthy, m.message, m.err
}

func newSTS(name, ns, currentRev, updateRev string, replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID(name + "-uid"),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
		},
		Status: appsv1.StatefulSetStatus{
			Replicas:        replicas,
			CurrentRevision: currentRev,
			UpdateRevision:  updateRev,
		},
	}
}

func newPod(name, ns, stsName, revision string, ready bool) *corev1.Pod {
	conditions := []corev1.PodCondition{}
	if ready {
		conditions = append(conditions, corev1.PodCondition{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"app":                      stsName,
				"controller-revision-hash": revision,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Kind:       "StatefulSet",
					Name:       stsName,
					UID:        types.UID(stsName + "-uid"),
				},
			},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: conditions,
		},
	}
}

func TestOrchestrateRestart_AllUpdated_ReturnsComplete(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-2", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-2", true),
		*newPod("indexer-1", "ns", "indexer", "rev-2", true),
		*newPod("indexer-2", "ns", "indexer", "rev-2", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	result, err := o.OrchestrateRestart(context.Background(), sts, &mockHealthChecker{healthy: true}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// CurrentRevision == UpdateRevision → Idle (no restart needed)
	if result.Phase != RestartPhaseIdle {
		t.Errorf("expected phase Idle, got %s", result.Phase)
	}
}

func TestOrchestrateRestart_AllPodsOnTargetRevision_ReturnsComplete(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-2", true),
		*newPod("indexer-1", "ns", "indexer", "rev-2", true),
		*newPod("indexer-2", "ns", "indexer", "rev-2", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	result, err := o.OrchestrateRestart(context.Background(), sts, &mockHealthChecker{healthy: true}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseComplete {
		t.Errorf("expected phase Complete, got %s", result.Phase)
	}
	if result.UpdatedPods != 3 {
		t.Errorf("expected 3 updated pods, got %d", result.UpdatedPods)
	}
}

func TestOrchestrateRestart_PodNotReady_Waits(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-2", true),
		*newPod("indexer-1", "ns", "indexer", "rev-2", false), // not ready
		*newPod("indexer-2", "ns", "indexer", "rev-1", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	result, err := o.OrchestrateRestart(context.Background(), sts, &mockHealthChecker{healthy: true}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseInProgress {
		t.Errorf("expected phase InProgress, got %s", result.Phase)
	}
	if result.CurrentPod != "indexer-1" {
		t.Errorf("expected current pod indexer-1, got %s", result.CurrentPod)
	}
}

func TestOrchestrateRestart_Unhealthy_Waits(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-2", true),
		*newPod("indexer-1", "ns", "indexer", "rev-1", true),
		*newPod("indexer-2", "ns", "indexer", "rev-1", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	checker := &mockHealthChecker{healthy: false, message: "cluster is RED"}
	result, err := o.OrchestrateRestart(context.Background(), sts, checker, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseInProgress {
		t.Errorf("expected phase InProgress, got %s", result.Phase)
	}
	if result.CurrentPod != "" {
		t.Errorf("expected no current pod (waiting), got %s", result.CurrentPod)
	}
}

func TestOrchestrateRestart_Healthy_DeletesHighestOrdinal(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-2", true),
		*newPod("indexer-1", "ns", "indexer", "rev-1", true),
		*newPod("indexer-2", "ns", "indexer", "rev-1", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	checker := &mockHealthChecker{healthy: true}
	result, err := o.OrchestrateRestart(context.Background(), sts, checker, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseInProgress {
		t.Errorf("expected phase InProgress, got %s", result.Phase)
	}
	if result.CurrentPod != "indexer-2" {
		t.Errorf("expected highest ordinal pod indexer-2 to be deleted, got %s", result.CurrentPod)
	}
}

func TestOrchestrateRestart_Healthy_DeletesLowestOrdinal(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 3)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-1", true),
		*newPod("indexer-1", "ns", "indexer", "rev-1", true),
		*newPod("indexer-2", "ns", "indexer", "rev-2", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	checker := &mockHealthChecker{healthy: true}
	result, err := o.OrchestrateRestart(context.Background(), sts, checker, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseInProgress {
		t.Errorf("expected phase InProgress, got %s", result.Phase)
	}
	if result.CurrentPod != "indexer-0" {
		t.Errorf("expected lowest ordinal pod indexer-0 to be deleted, got %s", result.CurrentPod)
	}
}

func TestOrchestrateRestart_SingleReplica(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("master", "ns", "rev-1", "rev-2", 1)
	pods := []corev1.Pod{
		*newPod("master-0", "ns", "master", "rev-1", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	checker := &mockHealthChecker{healthy: true}
	result, err := o.OrchestrateRestart(context.Background(), sts, checker, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Phase != RestartPhaseInProgress {
		t.Errorf("expected phase InProgress, got %s", result.Phase)
	}
	if result.CurrentPod != "master-0" {
		t.Errorf("expected master-0 to be deleted, got %s", result.CurrentPod)
	}
}

func TestOrchestrateRestart_HealthCheckError_ReturnsError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	sts := newSTS("indexer", "ns", "rev-1", "rev-2", 1)
	pods := []corev1.Pod{
		*newPod("indexer-0", "ns", "indexer", "rev-1", true),
	}

	objects := []runtime.Object{sts}
	for i := range pods {
		objects = append(objects, &pods[i])
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	o := NewOrchestrator(c)

	checker := &mockHealthChecker{err: fmt.Errorf("connection refused")}
	_, err := o.OrchestrateRestart(context.Background(), sts, checker, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExtractOrdinal(t *testing.T) {
	tests := []struct {
		name     string
		expected int
	}{
		{"indexer-0", 0},
		{"indexer-1", 1},
		{"indexer-2", 2},
		{"my-sts-name-10", 10},
		{"no-ordinal-suffix", 0},
		{"", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOrdinal(tt.name)
			if got != tt.expected {
				t.Errorf("extractOrdinal(%q) = %d, want %d", tt.name, got, tt.expected)
			}
		})
	}
}

func TestIsPodReady(t *testing.T) {
	readyPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	notReadyPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse},
			},
		},
	}
	noConditionsPod := &corev1.Pod{
		Status: corev1.PodStatus{},
	}

	if !isPodReady(readyPod) {
		t.Error("expected ready pod to be ready")
	}
	if isPodReady(notReadyPod) {
		t.Error("expected not-ready pod to not be ready")
	}
	if isPodReady(noConditionsPod) {
		t.Error("expected pod with no conditions to not be ready")
	}
}
