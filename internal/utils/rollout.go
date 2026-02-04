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
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RolloutType represents the type of Kubernetes workload being rolled out
type RolloutType string

const (
	// RolloutTypeStatefulSet represents a StatefulSet rollout
	RolloutTypeStatefulSet RolloutType = "StatefulSet"
	// RolloutTypeDeployment represents a Deployment rollout
	RolloutTypeDeployment RolloutType = "Deployment"
)

// DefaultRolloutTimeout is the default timeout for waiting on rollouts
const DefaultRolloutTimeout = 10 * time.Minute

// PendingRollout represents a rollout that was initiated but not yet complete
type PendingRollout struct {
	// Name is the name of the workload
	Name string
	// Namespace is the namespace of the workload
	Namespace string
	// Type is the type of workload (StatefulSet or Deployment)
	Type RolloutType
	// Component is the component name (e.g., "indexer", "dashboard", "manager-master")
	Component string
	// Reason explains why the rollout was triggered
	Reason string
	// StartTime is when the rollout was initiated
	StartTime time.Time
	// Generation is the observed generation when the rollout was initiated
	Generation int64
}

// RolloutStatus represents the current status of a rollout
type RolloutStatus struct {
	// Complete indicates if the rollout is complete (alias for Ready for backwards compat)
	Complete bool
	// Ready indicates if the rollout is complete and all pods are ready
	Ready bool
	// ReadyReplicas is the number of ready replicas
	ReadyReplicas int32
	// Desired is the desired number of replicas
	Desired int32
	// Updated is the number of updated replicas
	Updated int32
	// Duration is how long the rollout has been in progress
	Duration time.Duration
	// Message provides a human-readable status message
	Message string
	// Error if any occurred checking the status
	Error error
}

// RolloutWaiter provides methods for waiting on Kubernetes rollouts
type RolloutWaiter struct {
	client  client.Client
	timeout time.Duration
}

// NewRolloutWaiter creates a new RolloutWaiter with the default timeout
func NewRolloutWaiter(c client.Client) *RolloutWaiter {
	return &RolloutWaiter{
		client:  c,
		timeout: DefaultRolloutTimeout,
	}
}

// WithTimeout sets a custom timeout for the waiter
func (w *RolloutWaiter) WithTimeout(timeout time.Duration) *RolloutWaiter {
	w.timeout = timeout
	return w
}

// CheckRolloutStatus checks the status of a pending rollout
func (w *RolloutWaiter) CheckRolloutStatus(ctx context.Context, rollout *PendingRollout) RolloutStatus {
	switch rollout.Type {
	case RolloutTypeStatefulSet:
		return w.checkStatefulSetStatus(ctx, rollout)
	case RolloutTypeDeployment:
		return w.checkDeploymentStatus(ctx, rollout)
	default:
		return RolloutStatus{Error: fmt.Errorf("unknown rollout type: %s", rollout.Type)}
	}
}

// WaitForRollout waits for a rollout to complete
func (w *RolloutWaiter) WaitForRollout(ctx context.Context, rollout *PendingRollout) error {
	log := logf.FromContext(ctx)
	deadline := time.Now().Add(w.timeout)

	log.Info("Waiting for rollout to complete",
		"name", rollout.Name,
		"namespace", rollout.Namespace,
		"type", rollout.Type,
		"timeout", w.timeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for rollout of %s/%s", rollout.Type, rollout.Name)
		}

		status := w.CheckRolloutStatus(ctx, rollout)
		if status.Error != nil {
			return status.Error
		}

		if status.Complete {
			log.Info("Rollout completed",
				"name", rollout.Name,
				"ready", status.Ready,
				"desired", status.Desired)
			return nil
		}

		log.V(1).Info("Rollout in progress",
			"name", rollout.Name,
			"ready", status.Ready,
			"updated", status.Updated,
			"desired", status.Desired)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			continue
		}
	}
}

// checkStatefulSetStatus checks the status of a StatefulSet rollout
func (w *RolloutWaiter) checkStatefulSetStatus(ctx context.Context, rollout *PendingRollout) RolloutStatus {
	sts := &appsv1.StatefulSet{}
	if err := w.client.Get(ctx, types.NamespacedName{
		Name:      rollout.Name,
		Namespace: rollout.Namespace,
	}, sts); err != nil {
		return RolloutStatus{Error: err}
	}

	desired := int32(1)
	if sts.Spec.Replicas != nil {
		desired = *sts.Spec.Replicas
	}

	// Calculate duration if start time is available
	var duration time.Duration
	if !rollout.StartTime.IsZero() {
		duration = time.Since(rollout.StartTime)
	}

	status := RolloutStatus{
		ReadyReplicas: sts.Status.ReadyReplicas,
		Updated:       sts.Status.UpdatedReplicas,
		Desired:       desired,
		Duration:      duration,
		Message:       fmt.Sprintf("%d/%d pods ready, %d updated", sts.Status.ReadyReplicas, desired, sts.Status.UpdatedReplicas),
	}

	// Check if rollout is complete
	// A StatefulSet rollout is complete when:
	// 1. UpdatedReplicas == desired
	// 2. ReadyReplicas == desired
	// 3. CurrentRevision == UpdateRevision
	if sts.Status.UpdatedReplicas == desired &&
		sts.Status.ReadyReplicas == desired &&
		sts.Status.CurrentRevision == sts.Status.UpdateRevision {
		status.Complete = true
		status.Ready = true
		status.Message = fmt.Sprintf("Rollout complete: %d/%d pods ready", desired, desired)
	}

	return status
}

// checkDeploymentStatus checks the status of a Deployment rollout
func (w *RolloutWaiter) checkDeploymentStatus(ctx context.Context, rollout *PendingRollout) RolloutStatus {
	deployment := &appsv1.Deployment{}
	if err := w.client.Get(ctx, types.NamespacedName{
		Name:      rollout.Name,
		Namespace: rollout.Namespace,
	}, deployment); err != nil {
		return RolloutStatus{Error: err}
	}

	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}

	// Calculate duration if start time is available
	var duration time.Duration
	if !rollout.StartTime.IsZero() {
		duration = time.Since(rollout.StartTime)
	}

	status := RolloutStatus{
		ReadyReplicas: deployment.Status.ReadyReplicas,
		Updated:       deployment.Status.UpdatedReplicas,
		Desired:       desired,
		Duration:      duration,
		Message:       fmt.Sprintf("%d/%d pods ready, %d updated", deployment.Status.ReadyReplicas, desired, deployment.Status.UpdatedReplicas),
	}

	// Check if rollout is complete
	// A Deployment rollout is complete when:
	// 1. UpdatedReplicas == desired
	// 2. ReadyReplicas == desired
	// 3. AvailableReplicas == desired
	// 4. ObservedGeneration >= spec.generation
	if deployment.Status.UpdatedReplicas == desired &&
		deployment.Status.ReadyReplicas == desired &&
		deployment.Status.AvailableReplicas == desired &&
		deployment.Status.ObservedGeneration >= deployment.Generation {
		status.Complete = true
		status.Ready = true
		status.Message = fmt.Sprintf("Rollout complete: %d/%d pods ready", desired, desired)
	}

	return status
}

// IsRolloutComplete checks if a pending rollout is complete
func (w *RolloutWaiter) IsRolloutComplete(ctx context.Context, rollout *PendingRollout) bool {
	status := w.CheckRolloutStatus(ctx, rollout)
	return status.Complete && status.Error == nil
}

// RolloutWaitResult contains the result of waiting for a rollout
type RolloutWaitResult struct {
	// Success indicates if the rollout completed successfully
	Success bool
	// TimedOut indicates if the wait timed out
	TimedOut bool
	// Error if any occurred during the wait
	Error error
	// Duration is how long we waited
	Duration time.Duration
	// FinalStatus is the final status of the rollout
	FinalStatus RolloutStatus
}

// WaitForStatefulSetReadyWithResult waits for a StatefulSet rollout and returns detailed result
func (w *RolloutWaiter) WaitForStatefulSetReadyWithResult(ctx context.Context, namespace, name string) *RolloutWaitResult {
	start := time.Now()
	result := &RolloutWaitResult{}

	rollout := &PendingRollout{
		Name:      name,
		Namespace: namespace,
		Type:      RolloutTypeStatefulSet,
	}

	err := w.WaitForRollout(ctx, rollout)

	result.Duration = time.Since(start)
	result.FinalStatus = w.CheckRolloutStatus(ctx, rollout)

	if err != nil {
		result.Error = err
		result.Success = false
		// Check if it was a timeout error
		if err.Error() == fmt.Sprintf("timeout waiting for rollout of %s/%s", rollout.Type, rollout.Name) {
			result.TimedOut = true
		}
	} else {
		result.Success = true
	}

	return result
}

// WaitForDeploymentReadyWithResult waits for a Deployment rollout and returns detailed result
func (w *RolloutWaiter) WaitForDeploymentReadyWithResult(ctx context.Context, namespace, name string) *RolloutWaitResult {
	start := time.Now()
	result := &RolloutWaitResult{}

	rollout := &PendingRollout{
		Name:      name,
		Namespace: namespace,
		Type:      RolloutTypeDeployment,
	}

	err := w.WaitForRollout(ctx, rollout)

	result.Duration = time.Since(start)
	result.FinalStatus = w.CheckRolloutStatus(ctx, rollout)

	if err != nil {
		result.Error = err
		result.Success = false
		// Check if it was a timeout error
		if err.Error() == fmt.Sprintf("timeout waiting for rollout of %s/%s", rollout.Type, rollout.Name) {
			result.TimedOut = true
		}
	} else {
		result.Success = true
	}

	return result
}
