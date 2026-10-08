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
			// OnDelete: the strategy under which the operator drives the restart.
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.OnDeleteStatefulSetStrategyType},
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

// runOrchestrator builds a fake client with the StatefulSet and pods and runs one step.
func runOrchestrator(t *testing.T, sts *appsv1.StatefulSet, hc HealthChecker, pods ...*corev1.Pod) (*RestartResult, *corev1.PodList) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	objects := []runtime.Object{sts}
	for _, p := range pods {
		objects = append(objects, p)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	result, err := NewOrchestrator(c).OrchestrateRestart(context.Background(), sts, hc, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	remaining := &corev1.PodList{}
	if err := c.List(context.Background(), remaining); err != nil {
		t.Fatalf("list pods: %v", err)
	}
	return result, remaining
}

func podNames(list *corev1.PodList) map[string]bool {
	names := map[string]bool{}
	for _, p := range list.Items {
		names[p.Name] = true
	}
	return names
}

// TestOrchestrateRestart_OutdatedNotReady_DeletedDespiteUnhealthy guards recovery from a bad
// revision: a pod crash-looping on an old revision (e.g. an invalid rule) must be replaced
// as soon as a fixed revision exists, without waiting for it to become ready (it never
// will) nor for the health check (which counts this very pod as unhealthy).
func TestOrchestrateRestart_OutdatedNotReady_DeletedDespiteUnhealthy(t *testing.T) {
	sts := newSTS("manager", "ns", "rev-1", "rev-3", 2)
	result, remaining := runOrchestrator(t, sts,
		&mockHealthChecker{healthy: false, message: "manager-1 not ready"},
		newPod("manager-0", "ns", "manager", "rev-1", true),
		newPod("manager-1", "ns", "manager", "rev-2", false), // crash-looping on the bad revision
	)
	if result.Phase != RestartPhaseInProgress || result.CurrentPod != "manager-1" {
		t.Fatalf("expected InProgress deleting manager-1, got %+v", result)
	}
	names := podNames(remaining)
	if names["manager-1"] {
		t.Error("not-ready outdated pod manager-1 was not deleted")
	}
	if !names["manager-0"] {
		t.Error("ready pod manager-0 must not be deleted in the same step")
	}
}

// TestOrchestrateRestart_UpdatedNotReady_DoesNotSpread asserts a new revision whose pod does
// not come up is never rolled to the remaining (ready, outdated) pods.
func TestOrchestrateRestart_UpdatedNotReady_DoesNotSpread(t *testing.T) {
	sts := newSTS("manager", "ns", "rev-1", "rev-2", 2)
	result, remaining := runOrchestrator(t, sts, &mockHealthChecker{healthy: true},
		newPod("manager-0", "ns", "manager", "rev-1", true),
		newPod("manager-1", "ns", "manager", "rev-2", false),
	)
	if result.Phase != RestartPhaseInProgress || result.CurrentPod != "manager-1" {
		t.Fatalf("expected InProgress waiting on manager-1, got %+v", result)
	}
	if len(remaining.Items) != 2 {
		t.Errorf("no pod should be deleted while the updated pod is not ready, %d left", len(remaining.Items))
	}
}

// TestOrchestrateRestart_Terminating_Waits asserts no further deletion happens while a pod is
// still terminating.
func TestOrchestrateRestart_Terminating_Waits(t *testing.T) {
	sts := newSTS("manager", "ns", "rev-1", "rev-2", 2)
	terminating := newPod("manager-1", "ns", "manager", "rev-1", false)
	now := metav1.Now()
	terminating.DeletionTimestamp = &now
	terminating.Finalizers = []string{"test/keep"}
	result, remaining := runOrchestrator(t, sts, &mockHealthChecker{healthy: true},
		newPod("manager-0", "ns", "manager", "rev-1", true),
		terminating,
	)
	if result.Phase != RestartPhaseInProgress || result.CurrentPod != "manager-1" {
		t.Fatalf("expected InProgress waiting on terminating manager-1, got %+v", result)
	}
	if !podNames(remaining)["manager-0"] {
		t.Error("manager-0 must not be deleted while manager-1 is terminating")
	}
}

// rollingUpdateSTS returns a StatefulSet left to the Kubernetes RollingUpdate controller.
func rollingUpdateSTS(name, currentRev, updateRev string, replicas int32) *appsv1.StatefulSet {
	sts := newSTS(name, "ns", currentRev, updateRev, replicas)
	sts.Spec.UpdateStrategy.Type = appsv1.RollingUpdateStatefulSetStrategyType
	return sts
}

// TestOrchestrateRestart_RollingUpdate_DoesNotDeleteReadyPods guards the double-restart race:
// under RollingUpdate the StatefulSet controller replaces the pods; a pod the operator also
// deleted came back on the OLD revision and had to restart a second time.
func TestOrchestrateRestart_RollingUpdate_DoesNotDeleteReadyPods(t *testing.T) {
	sts := rollingUpdateSTS("manager", "rev-1", "rev-2", 2)
	result, remaining := runOrchestrator(t, sts, &mockHealthChecker{healthy: true},
		newPod("manager-0", "ns", "manager", "rev-1", true),
		newPod("manager-1", "ns", "manager", "rev-1", true),
	)
	if result.Phase != RestartPhaseInProgress || result.CurrentPod != "" {
		t.Fatalf("expected InProgress without a deleted pod, got %+v", result)
	}
	if len(remaining.Items) != 2 {
		t.Errorf("operator deleted a pod under RollingUpdate, %d left", len(remaining.Items))
	}
}

// TestOrchestrateRestart_RollingUpdate_UnsticksIntermediateRevision asserts the operator still
// recovers the documented StatefulSet deadlock: a pod crash-looping on a reverted/fixed-up
// intermediate revision is deleted so the controller recreates it on the update revision.
func TestOrchestrateRestart_RollingUpdate_UnsticksIntermediateRevision(t *testing.T) {
	sts := rollingUpdateSTS("manager", "rev-1", "rev-3", 2)
	result, remaining := runOrchestrator(t, sts, &mockHealthChecker{healthy: false},
		newPod("manager-0", "ns", "manager", "rev-1", true),
		newPod("manager-1", "ns", "manager", "rev-2", false),
	)
	if result.CurrentPod != "manager-1" || podNames(remaining)["manager-1"] {
		t.Fatalf("stuck pod manager-1 not deleted: %+v", result)
	}
}

// TestOrchestrateRestart_RollingUpdate_KeepsNotReadyCurrentRevisionPod asserts a not-ready pod
// on the current revision is left alone under RollingUpdate: the controller would recreate
// it on that same revision, so deleting it only adds a restart.
func TestOrchestrateRestart_RollingUpdate_KeepsNotReadyCurrentRevisionPod(t *testing.T) {
	sts := rollingUpdateSTS("manager", "rev-1", "rev-2", 2)
	_, remaining := runOrchestrator(t, sts, &mockHealthChecker{healthy: true},
		newPod("manager-0", "ns", "manager", "rev-1", false),
		newPod("manager-1", "ns", "manager", "rev-2", true),
	)
	if len(remaining.Items) != 2 {
		t.Errorf("not-ready current-revision pod deleted under RollingUpdate, %d left", len(remaining.Items))
	}
}

// TestStatefulSetUpdateStrategyHasPartition guards the rollout loop seen on a live cluster:
// without an explicit rollingUpdate.partition the StatefulSet controller recreated pods on
// the old revision every ~90s during a rollout.
func TestStatefulSetUpdateStrategyHasPartition(t *testing.T) {
	s := StatefulSetUpdateStrategy(appsv1.RollingUpdateStatefulSetStrategyType)
	if s.RollingUpdate == nil || s.RollingUpdate.Partition == nil || *s.RollingUpdate.Partition != 0 {
		t.Fatalf("RollingUpdate strategy must carry partition 0, got %+v", s)
	}
	if s := StatefulSetUpdateStrategy(appsv1.OnDeleteStatefulSetStrategyType); s.RollingUpdate != nil {
		t.Fatalf("OnDelete must not carry a rollingUpdate block, got %+v", s)
	}
}

// TestOrchestrateRestart_RevertedChange_ReplacesStrayPod reproduces the lab scenario: a bad
// change left worker-1 Pending on revision B, then the change was reverted, so the template
// is back to the current revision A (UpdateRevision == CurrentRevision). The StatefulSet
// controller never replaces worker-1; the orchestrator must, without touching ready pods.
func TestOrchestrateRestart_RevertedChange_ReplacesStrayPod(t *testing.T) {
	sts := rollingUpdateSTS("worker", "rev-a", "rev-a", 2)
	result, remaining := runOrchestrator(t, sts, nil,
		newPod("worker-0", "ns", "worker", "rev-a", true),
		newPod("worker-1", "ns", "worker", "rev-b", false),
	)
	if result.CurrentPod != "worker-1" || podNames(remaining)["worker-1"] {
		t.Fatalf("stray pod worker-1 not replaced: %+v", result)
	}
	if !podNames(remaining)["worker-0"] {
		t.Error("ready pod worker-0 must not be deleted")
	}

	// A ready pod on another revision while no rollout runs is left alone.
	_, remaining = runOrchestrator(t, sts, nil,
		newPod("worker-0", "ns", "worker", "rev-a", true),
		newPod("worker-1", "ns", "worker", "rev-b", true),
	)
	if len(remaining.Items) != 2 {
		t.Errorf("ready pods deleted while no rollout is in progress: %d left", len(remaining.Items))
	}
}
