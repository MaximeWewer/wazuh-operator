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
// The operator only drives the restart of StatefulSets using the OnDelete update
// strategy. With RollingUpdate the StatefulSet controller already replaces the pods itself;
// deleting pods on top of it races with it (a deleted pod whose ordinal is below
// status.currentReplicas is recreated on the OLD revision, so it restarts twice). There the
// orchestrator only reports progress and unsticks pods left on an intermediate revision
// (step 4b), which the StatefulSet controller never does on its own.
//
// Algorithm (one pod per call):
//  1. Compare UpdateRevision vs CurrentRevision - if equal, no restart needed.
//  2. List pods and compare each pod's controller-revision-hash label to UpdateRevision.
//  3. If all pods are on target revision → Complete.
//  4. If a pod is terminating → InProgress (wait). If an outdated pod is not ready →
//     delete it now (it serves nothing; waiting would deadlock recovery from a bad
//     revision). If an updated pod is not ready → InProgress (wait for it).
//  5. RollingUpdate → InProgress (the StatefulSet controller replaces the ready pods).
//  6. Call healthChecker.IsHealthyForRestart() → if unhealthy, InProgress (wait).
//  7. Delete ONE outdated pod (highest ordinal first when deleteHighestFirst=true).
//  8. Return InProgress with CurrentPod set.
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

	// Step 4a: Wait while a deletion is still in flight, so a terminating pod is never
	// deleted twice nor counted as a candidate.
	for _, pod := range ownedPods {
		if pod.DeletionTimestamp != nil {
			return &RestartResult{
				Phase:       RestartPhaseInProgress,
				TotalPods:   totalPods,
				UpdatedPods: updatedCount,
				CurrentPod:  pod.Name,
				Message:     fmt.Sprintf("waiting for pod %s to terminate", pod.Name),
			}, nil
		}
	}

	// Step 4b: Replace an outdated pod that is not ready right away. It serves nothing, so
	// deleting it costs no availability, and it is how the cluster recovers when a bad
	// revision (e.g. an invalid rule) crash-looped a pod and a fixed revision followed:
	// waiting for it to become ready first would deadlock forever. The health check is
	// skipped for the same reason - it would count this very pod as unhealthy.
	managed := sts.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType
	sortByOrdinal(outdatedPods, deleteHighestFirst)
	for _, pod := range outdatedPods {
		if isPodReady(&pod) {
			continue
		}
		// Under RollingUpdate, a pod on the current revision is recreated on that same
		// revision, so deleting it fixes nothing; only an intermediate revision is stuck.
		if !managed && pod.Labels["controller-revision-hash"] == currentRevision {
			continue
		}
		log.Info("Deleting outdated pod that is not ready",
			"pod", pod.Name,
			"currentRevision", pod.Labels["controller-revision-hash"],
			"targetRevision", targetRevision)
		if err := o.client.Delete(ctx, &pod); err != nil {
			return nil, fmt.Errorf("failed to delete pod %s: %w", pod.Name, err)
		}
		return &RestartResult{
			Phase:       RestartPhaseInProgress,
			TotalPods:   totalPods,
			UpdatedPods: updatedCount,
			CurrentPod:  pod.Name,
			Message:     fmt.Sprintf("deleted not-ready outdated pod %s (%d/%d updated)", pod.Name, updatedCount, totalPods),
		}, nil
	}

	// Step 4c: Wait for an updated pod that is not ready yet (in-flight replacement, or a
	// new revision that does not come up - never spread it to the remaining pods).
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

	// Step 5: RollingUpdate - the StatefulSet controller replaces the remaining pods.
	if !managed {
		return &RestartResult{
			Phase:       RestartPhaseInProgress,
			TotalPods:   totalPods,
			UpdatedPods: updatedCount,
			Message:     fmt.Sprintf("StatefulSet rolling update in progress (%d/%d updated)", updatedCount, totalPods),
		}, nil
	}

	// Step 6: Health check before deleting next pod
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

	// Step 7: Delete one outdated pod (already sorted by ordinal in step 4b)
	podToDelete := outdatedPods[0]
	log.Info("Deleting outdated pod for rolling restart",
		"pod", podToDelete.Name,
		"currentRevision", podToDelete.Labels["controller-revision-hash"],
		"targetRevision", targetRevision,
		"remaining", len(outdatedPods)-1)

	if err := o.client.Delete(ctx, &podToDelete); err != nil {
		return nil, fmt.Errorf("failed to delete pod %s: %w", podToDelete.Name, err)
	}

	// Step 8: Return InProgress
	return &RestartResult{
		Phase:       RestartPhaseInProgress,
		TotalPods:   totalPods,
		UpdatedPods: updatedCount,
		CurrentPod:  podToDelete.Name,
		Message:     fmt.Sprintf("deleted pod %s (%d/%d updated)", podToDelete.Name, updatedCount, totalPods),
	}, nil
}

// sortByOrdinal sorts pods by StatefulSet ordinal, highest first when highestFirst is set.
func sortByOrdinal(pods []corev1.Pod, highestFirst bool) {
	sort.Slice(pods, func(i, j int) bool {
		oi := extractOrdinal(pods[i].Name)
		oj := extractOrdinal(pods[j].Name)
		if highestFirst {
			return oi > oj // descending: highest ordinal first
		}
		return oi < oj // ascending: lowest ordinal first
	})
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
