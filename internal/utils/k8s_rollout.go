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

package utils

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// DefaultRolloutTimeout is the default timeout for waiting for a rollout to complete
	DefaultRolloutTimeout = 5 * time.Minute

	// DefaultRolloutPollInterval is the default interval between status checks during rollout
	DefaultRolloutPollInterval = 5 * time.Second
)

// RolloutWaiter provides methods to wait for Kubernetes rollouts to complete
type RolloutWaiter struct {
	client.Client
	Timeout      time.Duration
	PollInterval time.Duration
}

// NewRolloutWaiter creates a new RolloutWaiter with default settings
func NewRolloutWaiter(c client.Client) *RolloutWaiter {
	return &RolloutWaiter{
		Client:       c,
		Timeout:      DefaultRolloutTimeout,
		PollInterval: DefaultRolloutPollInterval,
	}
}

// WithTimeout sets the timeout for waiting
func (w *RolloutWaiter) WithTimeout(timeout time.Duration) *RolloutWaiter {
	w.Timeout = timeout
	return w
}

// WithPollInterval sets the poll interval for status checks
func (w *RolloutWaiter) WithPollInterval(interval time.Duration) *RolloutWaiter {
	w.PollInterval = interval
	return w
}

// WaitForDeploymentReady waits for a Deployment to have all replicas ready
// It returns an error if the timeout is exceeded or if there's an error fetching the Deployment
func (w *RolloutWaiter) WaitForDeploymentReady(ctx context.Context, namespace, name string) error {
	log := logf.FromContext(ctx)
	log.Info("Waiting for Deployment to be ready", "namespace", namespace, "name", name)

	return wait.PollUntilContextTimeout(ctx, w.PollInterval, w.Timeout, true, func(ctx context.Context) (bool, error) {
		deployment := &appsv1.Deployment{}
		if err := w.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, deployment); err != nil {
			return false, err
		}

		// Check if the deployment is ready
		// A deployment is ready when:
		// 1. UpdatedReplicas == Replicas (all replicas are updated to the latest spec)
		// 2. ReadyReplicas == Replicas (all replicas are ready)
		// 3. AvailableReplicas == Replicas (all replicas are available)
		if deployment.Status.UpdatedReplicas == *deployment.Spec.Replicas &&
			deployment.Status.ReadyReplicas == *deployment.Spec.Replicas &&
			deployment.Status.AvailableReplicas == *deployment.Spec.Replicas {
			log.Info("Deployment is ready",
				"namespace", namespace,
				"name", name,
				"replicas", *deployment.Spec.Replicas,
				"readyReplicas", deployment.Status.ReadyReplicas)
			return true, nil
		}

		log.V(1).Info("Deployment not ready yet",
			"namespace", namespace,
			"name", name,
			"replicas", *deployment.Spec.Replicas,
			"updatedReplicas", deployment.Status.UpdatedReplicas,
			"readyReplicas", deployment.Status.ReadyReplicas,
			"availableReplicas", deployment.Status.AvailableReplicas)

		return false, nil
	})
}

// WaitForStatefulSetReady waits for a StatefulSet to have all replicas ready
// It returns an error if the timeout is exceeded or if there's an error fetching the StatefulSet
func (w *RolloutWaiter) WaitForStatefulSetReady(ctx context.Context, namespace, name string) error {
	log := logf.FromContext(ctx)
	log.Info("Waiting for StatefulSet to be ready", "namespace", namespace, "name", name)

	return wait.PollUntilContextTimeout(ctx, w.PollInterval, w.Timeout, true, func(ctx context.Context) (bool, error) {
		sts := &appsv1.StatefulSet{}
		if err := w.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sts); err != nil {
			return false, err
		}

		// Check if the statefulset is ready
		// A statefulset is ready when:
		// 1. UpdatedReplicas == Replicas (all replicas are updated to the latest revision)
		// 2. ReadyReplicas == Replicas (all replicas are ready)
		// 3. CurrentRevision == UpdateRevision (rollout is complete)
		if sts.Status.UpdatedReplicas == *sts.Spec.Replicas &&
			sts.Status.ReadyReplicas == *sts.Spec.Replicas {
			log.Info("StatefulSet is ready",
				"namespace", namespace,
				"name", name,
				"replicas", *sts.Spec.Replicas,
				"readyReplicas", sts.Status.ReadyReplicas)
			return true, nil
		}

		log.V(1).Info("StatefulSet not ready yet",
			"namespace", namespace,
			"name", name,
			"replicas", *sts.Spec.Replicas,
			"updatedReplicas", sts.Status.UpdatedReplicas,
			"readyReplicas", sts.Status.ReadyReplicas,
			"currentRevision", sts.Status.CurrentRevision,
			"updateRevision", sts.Status.UpdateRevision)

		return false, nil
	})
}

// IsDeploymentReady checks if a Deployment has all replicas ready (non-blocking)
func (w *RolloutWaiter) IsDeploymentReady(ctx context.Context, namespace, name string) (bool, error) {
	deployment := &appsv1.Deployment{}
	if err := w.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, deployment); err != nil {
		return false, err
	}

	return deployment.Status.UpdatedReplicas == *deployment.Spec.Replicas &&
		deployment.Status.ReadyReplicas == *deployment.Spec.Replicas &&
		deployment.Status.AvailableReplicas == *deployment.Spec.Replicas, nil
}

// IsStatefulSetReady checks if a StatefulSet has all replicas ready (non-blocking)
func (w *RolloutWaiter) IsStatefulSetReady(ctx context.Context, namespace, name string) (bool, error) {
	sts := &appsv1.StatefulSet{}
	if err := w.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sts); err != nil {
		return false, err
	}

	return sts.Status.UpdatedReplicas == *sts.Spec.Replicas &&
		sts.Status.ReadyReplicas == *sts.Spec.Replicas, nil
}

// RolloutResult contains the result of a rollout wait operation
type RolloutResult struct {
	// Ready indicates if the rollout completed successfully
	Ready bool
	// TimedOut indicates if the timeout was exceeded
	TimedOut bool
	// Error contains any error that occurred during the wait
	Error error
}

// WaitForDeploymentReadyWithResult waits for a Deployment and returns detailed result
func (w *RolloutWaiter) WaitForDeploymentReadyWithResult(ctx context.Context, namespace, name string) RolloutResult {
	err := w.WaitForDeploymentReady(ctx, namespace, name)
	if err == nil {
		return RolloutResult{Ready: true}
	}

	if ctx.Err() == context.DeadlineExceeded {
		return RolloutResult{TimedOut: true, Error: fmt.Errorf("timeout waiting for deployment %s/%s to be ready", namespace, name)}
	}

	return RolloutResult{Error: err}
}

// WaitForStatefulSetReadyWithResult waits for a StatefulSet and returns detailed result
func (w *RolloutWaiter) WaitForStatefulSetReadyWithResult(ctx context.Context, namespace, name string) RolloutResult {
	err := w.WaitForStatefulSetReady(ctx, namespace, name)
	if err == nil {
		return RolloutResult{Ready: true}
	}

	if ctx.Err() == context.DeadlineExceeded {
		return RolloutResult{TimedOut: true, Error: fmt.Errorf("timeout waiting for statefulset %s/%s to be ready", namespace, name)}
	}

	return RolloutResult{Error: err}
}

// RolloutType represents the type of workload being rolled out
type RolloutType string

const (
	RolloutTypeStatefulSet RolloutType = "StatefulSet"
	RolloutTypeDeployment  RolloutType = "Deployment"
)

// PendingRollout represents a rollout that is in progress
type PendingRollout struct {
	// Component name (e.g., "indexer", "manager-master", "dashboard")
	Component string `json:"component"`

	// Namespace of the workload
	Namespace string `json:"namespace"`

	// Name of the workload (StatefulSet or Deployment name)
	Name string `json:"name"`

	// Type of the workload
	Type RolloutType `json:"type"`

	// StartTime when the rollout was initiated
	StartTime time.Time `json:"startTime"`

	// Reason for the rollout (e.g., "certificate-renewal")
	Reason string `json:"reason,omitempty"`
}

// RolloutStatusInfo provides detailed status information about a rollout
type RolloutStatusInfo struct {
	// Ready indicates the rollout is complete
	Ready bool

	// InProgress indicates the rollout is still happening
	InProgress bool

	// CurrentReplicas is the number of current replicas
	CurrentReplicas int32

	// ReadyReplicas is the number of ready replicas
	ReadyReplicas int32

	// DesiredReplicas is the desired number of replicas
	DesiredReplicas int32

	// UpdatedReplicas is the number of replicas with the new spec
	UpdatedReplicas int32

	// Message provides additional context
	Message string

	// Error if any occurred
	Error error

	// Duration since rollout started
	Duration time.Duration
}

// CheckStatefulSetRolloutStatus checks the current status of a StatefulSet rollout without blocking
func (w *RolloutWaiter) CheckStatefulSetRolloutStatus(ctx context.Context, rollout PendingRollout) RolloutStatusInfo {
	sts := &appsv1.StatefulSet{}
	if err := w.Get(ctx, types.NamespacedName{Name: rollout.Name, Namespace: rollout.Namespace}, sts); err != nil {
		return RolloutStatusInfo{
			Error:   err,
			Message: fmt.Sprintf("failed to get StatefulSet: %v", err),
		}
	}

	desiredReplicas := int32(1)
	if sts.Spec.Replicas != nil {
		desiredReplicas = *sts.Spec.Replicas
	}

	ready := sts.Status.UpdatedReplicas == desiredReplicas &&
		sts.Status.ReadyReplicas == desiredReplicas

	return RolloutStatusInfo{
		Ready:           ready,
		InProgress:      !ready,
		CurrentReplicas: sts.Status.Replicas,
		ReadyReplicas:   sts.Status.ReadyReplicas,
		DesiredReplicas: desiredReplicas,
		UpdatedReplicas: sts.Status.UpdatedReplicas,
		Duration:        time.Since(rollout.StartTime),
		Message: fmt.Sprintf("StatefulSet %s/%s: %d/%d ready, %d updated",
			rollout.Namespace, rollout.Name,
			sts.Status.ReadyReplicas, desiredReplicas,
			sts.Status.UpdatedReplicas),
	}
}

// CheckDeploymentRolloutStatus checks the current status of a Deployment rollout without blocking
func (w *RolloutWaiter) CheckDeploymentRolloutStatus(ctx context.Context, rollout PendingRollout) RolloutStatusInfo {
	deployment := &appsv1.Deployment{}
	if err := w.Get(ctx, types.NamespacedName{Name: rollout.Name, Namespace: rollout.Namespace}, deployment); err != nil {
		return RolloutStatusInfo{
			Error:   err,
			Message: fmt.Sprintf("failed to get Deployment: %v", err),
		}
	}

	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *deployment.Spec.Replicas
	}

	ready := deployment.Status.UpdatedReplicas == desiredReplicas &&
		deployment.Status.ReadyReplicas == desiredReplicas &&
		deployment.Status.AvailableReplicas == desiredReplicas

	return RolloutStatusInfo{
		Ready:           ready,
		InProgress:      !ready,
		CurrentReplicas: deployment.Status.Replicas,
		ReadyReplicas:   deployment.Status.ReadyReplicas,
		DesiredReplicas: desiredReplicas,
		UpdatedReplicas: deployment.Status.UpdatedReplicas,
		Duration:        time.Since(rollout.StartTime),
		Message: fmt.Sprintf("Deployment %s/%s: %d/%d ready, %d updated, %d available",
			rollout.Namespace, rollout.Name,
			deployment.Status.ReadyReplicas, desiredReplicas,
			deployment.Status.UpdatedReplicas, deployment.Status.AvailableReplicas),
	}
}

// CheckRolloutStatus checks the status of a pending rollout based on its type
func (w *RolloutWaiter) CheckRolloutStatus(ctx context.Context, rollout PendingRollout) RolloutStatusInfo {
	switch rollout.Type {
	case RolloutTypeStatefulSet:
		return w.CheckStatefulSetRolloutStatus(ctx, rollout)
	case RolloutTypeDeployment:
		return w.CheckDeploymentRolloutStatus(ctx, rollout)
	default:
		return RolloutStatusInfo{
			Error:   fmt.Errorf("unknown rollout type: %s", rollout.Type),
			Message: "Unknown rollout type",
		}
	}
}

// CheckAllRollouts checks the status of multiple pending rollouts
// Returns a map of component -> status, and a bool indicating if all are ready
func (w *RolloutWaiter) CheckAllRollouts(ctx context.Context, rollouts []PendingRollout) (map[string]RolloutStatusInfo, bool) {
	log := logf.FromContext(ctx)
	statuses := make(map[string]RolloutStatusInfo)
	allReady := true

	for _, rollout := range rollouts {
		status := w.CheckRolloutStatus(ctx, rollout)
		statuses[rollout.Component] = status

		if !status.Ready {
			allReady = false
			log.V(1).Info("Rollout not ready",
				"component", rollout.Component,
				"namespace", rollout.Namespace,
				"name", rollout.Name,
				"status", status.Message,
				"duration", status.Duration)
		} else {
			log.Info("Rollout complete",
				"component", rollout.Component,
				"namespace", rollout.Namespace,
				"name", rollout.Name,
				"duration", status.Duration)
		}
	}

	return statuses, allReady
}

// NewPendingRollout creates a new PendingRollout entry
func NewPendingRollout(component, namespace, name string, rolloutType RolloutType, reason string) PendingRollout {
	return PendingRollout{
		Component: component,
		Namespace: namespace,
		Name:      name,
		Type:      rolloutType,
		StartTime: time.Now(),
		Reason:    reason,
	}
}
