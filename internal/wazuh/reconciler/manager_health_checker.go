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

package reconciler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ManagerWorkerHealthChecker verifies that all pods matching the given labels
// are ready before allowing a pod restart. This ensures no two worker pods
// are down simultaneously during a rolling restart.
type ManagerWorkerHealthChecker struct {
	k8sClient      client.Client
	namespace      string
	selectorLabels map[string]string
}

// NewManagerWorkerHealthChecker creates a new ManagerWorkerHealthChecker.
func NewManagerWorkerHealthChecker(k8sClient client.Client, namespace string, selectorLabels map[string]string) *ManagerWorkerHealthChecker {
	return &ManagerWorkerHealthChecker{
		k8sClient:      k8sClient,
		namespace:      namespace,
		selectorLabels: selectorLabels,
	}
}

// IsHealthyForRestart checks if all pods matching the selector are ready.
// Returns unhealthy if any pod is not in Ready condition.
func (c *ManagerWorkerHealthChecker) IsHealthyForRestart(ctx context.Context) (bool, string, error) {
	podList := &corev1.PodList{}
	if err := c.k8sClient.List(ctx, podList,
		client.InNamespace(c.namespace),
		client.MatchingLabels(c.selectorLabels),
	); err != nil {
		return false, "", fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range podList.Items {
		ready := false
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady {
				ready = cond.Status == corev1.ConditionTrue
				break
			}
		}
		if !ready {
			return false, fmt.Sprintf("pod %s is not ready", pod.Name), nil
		}
	}

	return true, fmt.Sprintf("all %d pods are ready", len(podList.Items)), nil
}
