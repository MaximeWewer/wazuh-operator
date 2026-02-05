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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IsStatefulSetImmutableError returns true if the error indicates an immutable StatefulSet field update.
func IsStatefulSetImmutableError(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) {
		msg := err.Error()
		return strings.Contains(msg, "updates to statefulset spec") ||
			strings.Contains(msg, "immutable")
	}
	return false
}

// IsDeploymentImmutableError returns true if the error indicates an immutable Deployment field update.
func IsDeploymentImmutableError(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) {
		msg := err.Error()
		return strings.Contains(msg, "field is immutable") ||
			strings.Contains(msg, "immutable")
	}
	return false
}

// RecreateStatefulSetOnError deletes and recreates a StatefulSet if the error is immutable-field related.
// Returns (true, nil) when a recreate is performed successfully.
func RecreateStatefulSetOnError(ctx context.Context, c client.Client, desired *appsv1.StatefulSet, existing *appsv1.StatefulSet, err error) (bool, error) {
	if !IsStatefulSetImmutableError(err) {
		return false, err
	}

	logger := log.FromContext(ctx)
	logger.Info("Recreating StatefulSet due to immutable field update error", "name", desired.Name, "namespace", desired.Namespace)

	propagation := metav1.DeletePropagationBackground
	if delErr := c.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &propagation}); delErr != nil && !apierrors.IsNotFound(delErr) {
		return true, delErr
	}

	desired.SetResourceVersion("")
	if createErr := c.Create(ctx, desired); createErr != nil {
		return true, createErr
	}
	return true, nil
}

// RecreateDeploymentOnError deletes and recreates a Deployment if the error is immutable-field related.
// Returns (true, nil) when a recreate is performed successfully.
func RecreateDeploymentOnError(ctx context.Context, c client.Client, desired *appsv1.Deployment, existing *appsv1.Deployment, err error) (bool, error) {
	if !IsDeploymentImmutableError(err) {
		return false, err
	}

	logger := log.FromContext(ctx)
	logger.Info("Recreating Deployment due to immutable field update error", "name", desired.Name, "namespace", desired.Namespace)

	propagation := metav1.DeletePropagationBackground
	if delErr := c.Delete(ctx, existing, &client.DeleteOptions{PropagationPolicy: &propagation}); delErr != nil && !apierrors.IsNotFound(delErr) {
		return true, delErr
	}

	desired.SetResourceVersion("")
	if createErr := c.Create(ctx, desired); createErr != nil {
		return true, createErr
	}
	return true, nil
}
