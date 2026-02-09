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

// Package serviceaccount provides shared ServiceAccount reconciliation for all components
package serviceaccount

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// ResolveServiceAccountName returns the SA name to set on PodSpec.
// If cfg is nil, returns "" (use namespace default).
// If cfg.Name is set, returns it. Otherwise auto-generates "{clusterName}-{component}".
func ResolveServiceAccountName(cfg *wazuhv1.ServiceAccountConfig, clusterName, component string) string {
	if cfg == nil {
		return ""
	}
	if cfg.Name != "" {
		return cfg.Name
	}
	if cfg.Create {
		return fmt.Sprintf("%s-%s", clusterName, component)
	}
	return ""
}

// ReconcileServiceAccount creates or updates a ServiceAccount if Create=true.
// Returns the SA name to set on PodSpec (empty string means use namespace default).
func ReconcileServiceAccount(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	owner metav1.Object,
	cfg *wazuhv1.ServiceAccountConfig,
	clusterName, namespace, component string,
) (string, error) {
	log := logf.FromContext(ctx)

	saName := ResolveServiceAccountName(cfg, clusterName, component)
	if saName == "" {
		return "", nil
	}

	// If Create is false, just return the name (user manages the SA)
	if cfg == nil || !cfg.Create {
		return saName, nil
	}

	// Build the desired ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: namespace,
		},
	}

	// Set annotations
	if len(cfg.Annotations) > 0 {
		sa.Annotations = make(map[string]string, len(cfg.Annotations))
		for k, v := range cfg.Annotations {
			sa.Annotations[k] = v
		}
	}

	// Set labels
	if len(cfg.Labels) > 0 {
		sa.Labels = make(map[string]string, len(cfg.Labels))
		for k, v := range cfg.Labels {
			sa.Labels[k] = v
		}
	}

	// Set owner reference for garbage collection
	if runtimeObj, ok := owner.(client.Object); ok {
		if err := controllerutil.SetControllerReference(runtimeObj, sa, scheme); err != nil {
			return "", fmt.Errorf("failed to set controller reference on ServiceAccount %s: %w", saName, err)
		}
	}

	// Create or update
	found := &corev1.ServiceAccount{}
	err := c.Get(ctx, types.NamespacedName{Name: saName, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating ServiceAccount", "name", saName, "component", component)
		if err := c.Create(ctx, sa); err != nil {
			return "", fmt.Errorf("failed to create ServiceAccount %s: %w", saName, err)
		}
		return saName, nil
	} else if err != nil {
		return "", fmt.Errorf("failed to get ServiceAccount %s: %w", saName, err)
	}

	// Update if annotations or labels changed
	needsUpdate := false
	if !mapsEqual(found.Annotations, sa.Annotations) {
		found.Annotations = sa.Annotations
		needsUpdate = true
	}
	if !mapsEqual(found.Labels, sa.Labels) {
		found.Labels = sa.Labels
		needsUpdate = true
	}

	if needsUpdate {
		log.Info("Updating ServiceAccount", "name", saName, "component", component)
		if err := c.Update(ctx, found); err != nil {
			return "", fmt.Errorf("failed to update ServiceAccount %s: %w", saName, err)
		}
	}

	return saName, nil
}

// mapsEqual compares two string maps for equality
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
