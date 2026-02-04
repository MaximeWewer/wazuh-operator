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

package utils

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewRolloutWaiter(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	waiter := NewRolloutWaiter(client)

	if waiter == nil {
		t.Fatal("Expected non-nil waiter")
	}

	if waiter.timeout != DefaultRolloutTimeout {
		t.Errorf("Expected default timeout %v, got %v", DefaultRolloutTimeout, waiter.timeout)
	}
}

func TestRolloutWaiter_WithTimeout(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	waiter := NewRolloutWaiter(client)

	customTimeout := 5 * time.Minute
	waiter.WithTimeout(customTimeout)

	if waiter.timeout != customTimeout {
		t.Errorf("Expected timeout %v, got %v", customTimeout, waiter.timeout)
	}
}

func TestRolloutWaiter_CheckStatefulSetStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sts",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
		Status: appsv1.StatefulSetStatus{
			ReadyReplicas:   3,
			UpdatedReplicas: 3,
			CurrentRevision: "revision-1",
			UpdateRevision:  "revision-1",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test-sts",
		Namespace: "default",
		Type:      RolloutTypeStatefulSet,
		StartTime: time.Now().Add(-1 * time.Minute),
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error != nil {
		t.Fatalf("Unexpected error: %v", status.Error)
	}

	if !status.Complete {
		t.Error("Expected rollout to be complete")
	}

	if !status.Ready {
		t.Error("Expected rollout to be ready")
	}

	if status.ReadyReplicas != 3 {
		t.Errorf("Expected 3 ready replicas, got %d", status.ReadyReplicas)
	}

	if status.Desired != 3 {
		t.Errorf("Expected 3 desired replicas, got %d", status.Desired)
	}
}

func TestRolloutWaiter_CheckStatefulSetStatus_InProgress(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sts",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
		Status: appsv1.StatefulSetStatus{
			ReadyReplicas:   2,
			UpdatedReplicas: 2,
			CurrentRevision: "revision-1",
			UpdateRevision:  "revision-2",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test-sts",
		Namespace: "default",
		Type:      RolloutTypeStatefulSet,
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error != nil {
		t.Fatalf("Unexpected error: %v", status.Error)
	}

	if status.Complete {
		t.Error("Expected rollout to not be complete")
	}

	if status.Ready {
		t.Error("Expected rollout to not be ready")
	}
}

func TestRolloutWaiter_CheckDeploymentStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(2)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-deploy",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
		},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas:      2,
			UpdatedReplicas:    2,
			AvailableReplicas:  2,
			ObservedGeneration: 2,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deployment).
		Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test-deploy",
		Namespace: "default",
		Type:      RolloutTypeDeployment,
		StartTime: time.Now().Add(-30 * time.Second),
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error != nil {
		t.Fatalf("Unexpected error: %v", status.Error)
	}

	if !status.Complete {
		t.Error("Expected rollout to be complete")
	}

	if !status.Ready {
		t.Error("Expected rollout to be ready")
	}
}

func TestRolloutWaiter_CheckDeploymentStatus_InProgress(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(3)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-deploy",
			Namespace:  "default",
			Generation: 2,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
		},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas:      1,
			UpdatedReplicas:    2,
			AvailableReplicas:  1,
			ObservedGeneration: 1, // Old generation
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deployment).
		Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test-deploy",
		Namespace: "default",
		Type:      RolloutTypeDeployment,
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error != nil {
		t.Fatalf("Unexpected error: %v", status.Error)
	}

	if status.Complete {
		t.Error("Expected rollout to not be complete")
	}
}

func TestRolloutWaiter_CheckRolloutStatus_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "nonexistent",
		Namespace: "default",
		Type:      RolloutTypeStatefulSet,
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error == nil {
		t.Error("Expected error for non-existent StatefulSet")
	}
}

func TestRolloutWaiter_CheckRolloutStatus_UnknownType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test",
		Namespace: "default",
		Type:      RolloutType("UnknownType"),
	}

	ctx := context.Background()
	status := waiter.CheckRolloutStatus(ctx, rollout)

	if status.Error == nil {
		t.Error("Expected error for unknown rollout type")
	}
}

func TestRolloutWaiter_IsRolloutComplete(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)

	replicas := int32(1)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sts",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
		},
		Status: appsv1.StatefulSetStatus{
			ReadyReplicas:   1,
			UpdatedReplicas: 1,
			CurrentRevision: "rev-1",
			UpdateRevision:  "rev-1",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sts).
		Build()

	waiter := NewRolloutWaiter(client)
	rollout := &PendingRollout{
		Name:      "test-sts",
		Namespace: "default",
		Type:      RolloutTypeStatefulSet,
	}

	ctx := context.Background()

	if !waiter.IsRolloutComplete(ctx, rollout) {
		t.Error("Expected IsRolloutComplete to return true")
	}
}

func TestPendingRollout_Fields(t *testing.T) {
	now := time.Now()
	rollout := PendingRollout{
		Name:       "test-rollout",
		Namespace:  "test-namespace",
		Type:       RolloutTypeStatefulSet,
		Component:  "indexer",
		Reason:     "certificate renewal",
		StartTime:  now,
		Generation: 5,
	}

	if rollout.Name != "test-rollout" {
		t.Errorf("Expected name 'test-rollout', got %s", rollout.Name)
	}

	if rollout.Namespace != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got %s", rollout.Namespace)
	}

	if rollout.Type != RolloutTypeStatefulSet {
		t.Errorf("Expected type StatefulSet, got %s", rollout.Type)
	}

	if rollout.Component != "indexer" {
		t.Errorf("Expected component 'indexer', got %s", rollout.Component)
	}

	if rollout.Reason != "certificate renewal" {
		t.Errorf("Expected reason 'certificate renewal', got %s", rollout.Reason)
	}

	if rollout.Generation != 5 {
		t.Errorf("Expected generation 5, got %d", rollout.Generation)
	}
}

func TestRolloutStatus_Fields(t *testing.T) {
	status := RolloutStatus{
		Complete:      true,
		Ready:         true,
		ReadyReplicas: 3,
		Desired:       3,
		Updated:       3,
		Duration:      5 * time.Minute,
		Message:       "Rollout complete",
		Error:         nil,
	}

	if !status.Complete {
		t.Error("Expected Complete to be true")
	}

	if !status.Ready {
		t.Error("Expected Ready to be true")
	}

	if status.ReadyReplicas != 3 {
		t.Errorf("Expected ReadyReplicas 3, got %d", status.ReadyReplicas)
	}

	if status.Message != "Rollout complete" {
		t.Errorf("Expected message 'Rollout complete', got %s", status.Message)
	}

	if status.Duration != 5*time.Minute {
		t.Errorf("Expected duration 5m, got %v", status.Duration)
	}
}

func TestRolloutWaitResult_Fields(t *testing.T) {
	result := RolloutWaitResult{
		Success:  true,
		TimedOut: false,
		Error:    nil,
		Duration: 2 * time.Minute,
		FinalStatus: RolloutStatus{
			Complete: true,
			Ready:    true,
		},
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}

	if result.TimedOut {
		t.Error("Expected TimedOut to be false")
	}

	if result.Duration != 2*time.Minute {
		t.Errorf("Expected duration 2m, got %v", result.Duration)
	}

	if !result.FinalStatus.Complete {
		t.Error("Expected FinalStatus.Complete to be true")
	}
}
