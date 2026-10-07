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

package utils //nolint:revive // utils is a common package name

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// MigrateStatefulSetSelector moves an existing StatefulSet to the selector of desired
// without stopping its pods. spec.selector is immutable, so the StatefulSet has to be
// recreated; a plain (foreground) delete would take every pod down at once. Instead:
//
//  1. the StatefulSet is deleted with the Orphan propagation policy - its pods keep running;
//  2. its pods (<name>-<ordinal>) are relabeled with the desired pod template labels, so
//     they match the new selector;
//  3. its ControllerRevisions, which would otherwise be left behind, are deleted.
//
// The caller's next reconcile finds the StatefulSet gone and recreates it from desired:
// the new StatefulSet adopts the relabeled pods (same names, same PVCs) and replaces them
// through its usual update strategy since they run an older revision.
//
// It returns true while the migration is in progress (the caller must stop reconciling
// this StatefulSet and requeue) and false when the selectors already match. Every step is
// idempotent, so an interrupted migration resumes on the next call.
func MigrateStatefulSetSelector(ctx context.Context, c client.Client, recorder record.EventRecorder, desired, existing *appsv1.StatefulSet) (bool, error) {
	if desired.Spec.Selector == nil || existing.Spec.Selector == nil ||
		equality.Semantic.DeepEqual(existing.Spec.Selector, desired.Spec.Selector) {
		return false, nil
	}

	logger := log.FromContext(ctx).WithValues("statefulset", existing.Name, "namespace", existing.Namespace)
	oldSelector := existing.Spec.Selector.MatchLabels

	if existing.DeletionTimestamp == nil {
		logger.Info("Migrating StatefulSet to a new selector (orphan delete, pods keep running)",
			"oldSelector", oldSelector, "newSelector", desired.Spec.Selector.MatchLabels)
		if recorder != nil {
			recorder.Eventf(existing, corev1.EventTypeNormal, "SelectorMigration",
				"Recreating StatefulSet %s with a new label selector; pods keep running", existing.Name)
		}
		orphan := metav1.DeletePropagationOrphan
		uid := existing.UID
		if err := c.Delete(ctx, existing, &client.DeleteOptions{
			PropagationPolicy: &orphan,
			Preconditions:     &metav1.Preconditions{UID: &uid},
		}); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("failed to delete statefulset %s for selector migration: %w", existing.Name, err)
		}
	}

	pods := &corev1.PodList{}
	if err := c.List(ctx, pods, client.InNamespace(existing.Namespace), client.MatchingLabels(oldSelector)); err != nil {
		return false, fmt.Errorf("failed to list pods of statefulset %s: %w", existing.Name, err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !isStatefulSetPodName(existing.Name, pod.Name) {
			continue
		}
		before := pod.DeepCopy()
		if pod.Labels == nil {
			pod.Labels = map[string]string{}
		}
		for k, v := range desired.Spec.Template.Labels {
			pod.Labels[k] = v
		}
		if err := c.Patch(ctx, pod, client.MergeFrom(before)); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("failed to relabel pod %s for selector migration: %w", pod.Name, err)
		}
		logger.Info("Relabeled pod for the new StatefulSet selector", "pod", pod.Name)
	}

	revisions := &appsv1.ControllerRevisionList{}
	if err := c.List(ctx, revisions, client.InNamespace(existing.Namespace), client.MatchingLabels(oldSelector)); err != nil {
		return false, fmt.Errorf("failed to list controller revisions of statefulset %s: %w", existing.Name, err)
	}
	for i := range revisions.Items {
		rev := &revisions.Items[i]
		if !strings.HasPrefix(rev.Name, existing.Name+"-") {
			continue
		}
		if err := c.Delete(ctx, rev); err != nil && !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("failed to delete controller revision %s: %w", rev.Name, err)
		}
	}

	return true, nil
}

// isStatefulSetPodName reports whether podName is <stsName>-<ordinal>.
func isStatefulSetPodName(stsName, podName string) bool {
	ordinal, ok := strings.CutPrefix(podName, stsName+"-")
	if !ok || ordinal == "" {
		return false
	}
	_, err := strconv.Atoi(ordinal)
	return err == nil
}
