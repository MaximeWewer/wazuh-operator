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

package finalizers

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// CleanupFunc is a function that performs cleanup before resource deletion.
// It should return an error if cleanup fails and the finalizer should not be removed.
type CleanupFunc func(ctx context.Context) error

// Manager provides helper methods for managing finalizers on Kubernetes objects
type Manager struct {
	client    client.Client
	finalizer string
}

// NewManager creates a new finalizer manager for a specific finalizer
func NewManager(c client.Client, finalizer string) *Manager {
	return &Manager{
		client:    c,
		finalizer: finalizer,
	}
}

// NewManagerForKind creates a new finalizer manager using the registry
func NewManagerForKind(c client.Client, kind string) *Manager {
	return &Manager{
		client:    c,
		finalizer: GetFinalizer(kind),
	}
}

// Contains returns true if the object has this finalizer
func (m *Manager) Contains(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, m.finalizer)
}

// Add adds the finalizer to the object if not present and updates the object
func (m *Manager) Add(ctx context.Context, obj client.Object) error {
	if controllerutil.ContainsFinalizer(obj, m.finalizer) {
		return nil
	}

	controllerutil.AddFinalizer(obj, m.finalizer)
	return m.client.Update(ctx, obj)
}

// Remove removes the finalizer from the object and updates the object
func (m *Manager) Remove(ctx context.Context, obj client.Object) error {
	if !controllerutil.ContainsFinalizer(obj, m.finalizer) {
		return nil
	}

	controllerutil.RemoveFinalizer(obj, m.finalizer)
	return m.client.Update(ctx, obj)
}

// EnsureFinalizerAndCleanup handles the complete finalizer lifecycle:
// - If object is not being deleted and doesn't have finalizer: adds finalizer
// - If object is being deleted and has finalizer: runs cleanup and removes finalizer
// Returns true if the object is being deleted
func (m *Manager) EnsureFinalizerAndCleanup(ctx context.Context, obj client.Object, cleanup CleanupFunc) (bool, error) {
	// Object is not being deleted
	if obj.GetDeletionTimestamp().IsZero() {
		// Add finalizer if not present
		if !controllerutil.ContainsFinalizer(obj, m.finalizer) {
			controllerutil.AddFinalizer(obj, m.finalizer)
			if err := m.client.Update(ctx, obj); err != nil {
				return false, fmt.Errorf("failed to add finalizer: %w", err)
			}
		}
		return false, nil
	}

	// Object is being deleted
	if controllerutil.ContainsFinalizer(obj, m.finalizer) {
		// Run cleanup function if provided
		if cleanup != nil {
			if err := cleanup(ctx); err != nil {
				return true, fmt.Errorf("cleanup failed: %w", err)
			}
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(obj, m.finalizer)
		if err := m.client.Update(ctx, obj); err != nil {
			return true, fmt.Errorf("failed to remove finalizer: %w", err)
		}
	}

	return true, nil
}

// IsBeingDeleted returns true if the object has a deletion timestamp
func IsBeingDeleted(obj client.Object) bool {
	return !obj.GetDeletionTimestamp().IsZero()
}

// HasFinalizer checks if the object has a specific finalizer
func HasFinalizer(obj client.Object, finalizer string) bool {
	return controllerutil.ContainsFinalizer(obj, finalizer)
}

// AddFinalizer adds a finalizer to the object (in-memory, does not update API)
func AddFinalizer(obj client.Object, finalizer string) bool {
	if controllerutil.ContainsFinalizer(obj, finalizer) {
		return false
	}
	controllerutil.AddFinalizer(obj, finalizer)
	return true
}

// RemoveFinalizer removes a finalizer from the object (in-memory, does not update API)
func RemoveFinalizer(obj client.Object, finalizer string) bool {
	if !controllerutil.ContainsFinalizer(obj, finalizer) {
		return false
	}
	controllerutil.RemoveFinalizer(obj, finalizer)
	return true
}

// HandleDeletion is a convenience function that handles the deletion pattern:
// - Checks if object is being deleted
// - If yes and has finalizer, runs cleanup and removes finalizer
// Returns (isDeleting bool, err error)
func HandleDeletion(ctx context.Context, c client.Client, obj client.Object, finalizer string, cleanup CleanupFunc) (bool, error) {
	mgr := NewManager(c, finalizer)
	return mgr.EnsureFinalizerAndCleanup(ctx, obj, cleanup)
}
