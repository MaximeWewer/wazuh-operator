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
	"sort"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RollingRestartOrchestrator manages quorum-safe rolling restarts of StatefulSets.
// It is stateless: called once per reconcile loop per StatefulSet, it inspects
// the current state and takes at most one action (deleting a single outdated pod).
type RollingRestartOrchestrator struct {
	client client.Client
}

// NewOrchestrator creates a new RollingRestartOrchestrator.
func NewOrchestrator(c client.Client) *RollingRestartOrchestrator {
	return &RollingRestartOrchestrator{client: c}
}

// OrchestrateRestart performs one step of a rolling restart for the given StatefulSet.
//
// Algorithm (one pod per call):
//  1. Compare UpdateRevision vs CurrentRevision — if equal, no restart needed.
//  2. List pods and compare each pod's controller-revision-hash label to UpdateRevision.
//  3. If all pods are on target revision → Complete.
//  4. If any pod is not ready → InProgress (wait for replacement to become ready).
//  5. Call healthChecker.IsHealthyForRestart() → if unhealthy, InProgress (wait).
//  6. Delete ONE outdated pod (highest ordinal first when deleteHighestFirst=true).
//  7. Return InProgress with CurrentPod set.
func (o *RollingRestartOrchestrator) OrchestrateRestart(
	ctx context.Context,
	sts *appsv1.StatefulSet,
	healthChecker HealthChecker,
	deleteHighestFirst bool,
) (*RestartResult, error) {
	log := logf.FromContext(ctx).WithValues("statefulset", sts.Name, "namespace", sts.Namespace)

	targetRevision := sts.Status.UpdateRevision
	currentRevision := sts.Status.CurrentRevision

	// Step 1: If revisions match, no restart is needed
	if targetRevision == currentRevision {
		return &RestartResult{
			Phase:       RestartPhaseIdle,
			TotalPods:   sts.Status.Replicas,
			UpdatedPods: sts.Status.Replicas,
			Message:     "all pods are on current revision",
		}, nil
	}

	// List pods belonging to this StatefulSet
	podList := &corev1.PodList{}
	if err := o.client.List(ctx, podList,
		client.InNamespace(sts.Namespace),
		client.MatchingLabels(sts.Spec.Selector.MatchLabels),
	); err != nil {
		return nil, fmt.Errorf("failed to list pods for StatefulSet %s: %w", sts.Name, err)
	}

	// Filter pods by owner reference to ensure we only consider pods owned by this StatefulSet.
	// This is important when multiple StatefulSets share the same label selector (e.g. manager-master
	// and manager-worker both use "wazuh-manager" app label).
	stsUID := sts.UID
	var ownedPods []corev1.Pod
	for _, pod := range podList.Items {
		for _, ownerRef := range pod.OwnerReferences {
			if ownerRef.UID == stsUID {
				ownedPods = append(ownedPods, pod)
				break
			}
		}
	}

	// Step 2: Classify pods as updated or outdated
	var updatedPods, outdatedPods []corev1.Pod
	for _, pod := range ownedPods {
		revision := pod.Labels["controller-revision-hash"]
		if revision == targetRevision {
			updatedPods = append(updatedPods, pod)
		} else {
			outdatedPods = append(outdatedPods, pod)
		}
	}

	totalPods := int32(len(ownedPods))
	updatedCount := int32(len(updatedPods))

	// Step 3: All pods on target revision → Complete
	if len(outdatedPods) == 0 {
		log.Info("Rolling restart complete", "totalPods", totalPods)
		return &RestartResult{
			Phase:       RestartPhaseComplete,
			TotalPods:   totalPods,
			UpdatedPods: updatedCount,
			Message:     "all pods updated to target revision",
		}, nil
	}

	// Step 4: Check if any pod is not ready (wait for in-flight replacement)
	for _, pod := range ownedPods {
		if !isPodReady(&pod) {
			log.V(1).Info("Waiting for pod to become ready",
				"pod", pod.Name,
				"phase", pod.Status.Phase)
			return &RestartResult{
				Phase:       RestartPhaseInProgress,
				TotalPods:   totalPods,
				UpdatedPods: updatedCount,
				CurrentPod:  pod.Name,
				Message:     fmt.Sprintf("waiting for pod %s to become ready", pod.Name),
			}, nil
		}
	}

	// Step 5: Health check before deleting next pod
	healthy, msg, err := healthChecker.IsHealthyForRestart(ctx)
	if err != nil {
		return nil, fmt.Errorf("health check failed for StatefulSet %s: %w", sts.Name, err)
	}
	if !healthy {
		log.V(1).Info("Cluster not healthy for restart, waiting", "reason", msg)
		return &RestartResult{
			Phase:       RestartPhaseInProgress,
			TotalPods:   totalPods,
			UpdatedPods: updatedCount,
			Message:     fmt.Sprintf("waiting for cluster health: %s", msg),
		}, nil
	}

	// Step 6: Sort outdated pods by ordinal and delete one
	sort.Slice(outdatedPods, func(i, j int) bool {
		oi := extractOrdinal(outdatedPods[i].Name)
		oj := extractOrdinal(outdatedPods[j].Name)
		if deleteHighestFirst {
			return oi > oj // descending: highest ordinal first
		}
		return oi < oj // ascending: lowest ordinal first
	})

	podToDelete := outdatedPods[0]
	log.Info("Deleting outdated pod for rolling restart",
		"pod", podToDelete.Name,
		"currentRevision", podToDelete.Labels["controller-revision-hash"],
		"targetRevision", targetRevision,
		"remaining", len(outdatedPods)-1)

	if err := o.client.Delete(ctx, &podToDelete); err != nil {
		return nil, fmt.Errorf("failed to delete pod %s: %w", podToDelete.Name, err)
	}

	// Step 7: Return InProgress
	return &RestartResult{
		Phase:       RestartPhaseInProgress,
		TotalPods:   totalPods,
		UpdatedPods: updatedCount,
		CurrentPod:  podToDelete.Name,
		Message:     fmt.Sprintf("deleted pod %s (%d/%d updated)", podToDelete.Name, updatedCount, totalPods),
	}, nil
}

// isPodReady checks if a pod has the Ready condition set to True.
func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// extractOrdinal parses the StatefulSet ordinal from a pod name.
// StatefulSet pods are named <sts-name>-<ordinal>.
func extractOrdinal(podName string) int {
	parts := strings.Split(podName, "-")
	if len(parts) == 0 {
		return 0
	}
	ordinal, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return ordinal
}
