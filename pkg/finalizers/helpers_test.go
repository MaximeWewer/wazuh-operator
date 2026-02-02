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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetFinalizer(t *testing.T) {
	tests := []struct {
		kind     string
		expected string
	}{
		{"WazuhCluster", WazuhCluster},
		{"OpenSearchUser", OpenSearchUser},
		{"OpenSearchRole", OpenSearchRole},
		{"UnknownKind", Domain + "/UnknownKind"},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := GetFinalizer(tt.kind)
			if got != tt.expected {
				t.Errorf("GetFinalizer(%s) = %s, want %s", tt.kind, got, tt.expected)
			}
		})
	}
}

func TestRequiresExternalCleanup(t *testing.T) {
	tests := []struct {
		kind     string
		expected bool
	}{
		{"WazuhCluster", false},
		{"OpenSearchUser", true},
		{"OpenSearchRole", true},
		{"WazuhRule", true},
		{"UnknownKind", false},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := RequiresExternalCleanup(tt.kind)
			if got != tt.expected {
				t.Errorf("RequiresExternalCleanup(%s) = %v, want %v", tt.kind, got, tt.expected)
			}
		})
	}
}

func TestHasFinalizer(t *testing.T) {
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{WazuhCluster},
		},
	}

	if !HasFinalizer(obj, WazuhCluster) {
		t.Error("HasFinalizer should return true for existing finalizer")
	}

	if HasFinalizer(obj, OpenSearchUser) {
		t.Error("HasFinalizer should return false for non-existing finalizer")
	}
}

func TestAddFinalizer(t *testing.T) {
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// First add should return true
	if !AddFinalizer(obj, WazuhCluster) {
		t.Error("AddFinalizer should return true when adding new finalizer")
	}

	if !HasFinalizer(obj, WazuhCluster) {
		t.Error("Finalizer should be present after add")
	}

	// Second add should return false (already exists)
	if AddFinalizer(obj, WazuhCluster) {
		t.Error("AddFinalizer should return false when finalizer already exists")
	}
}

func TestRemoveFinalizer(t *testing.T) {
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "default",
			Finalizers: []string{WazuhCluster, OpenSearchUser},
		},
	}

	// Remove existing finalizer
	if !RemoveFinalizer(obj, WazuhCluster) {
		t.Error("RemoveFinalizer should return true when removing existing finalizer")
	}

	if HasFinalizer(obj, WazuhCluster) {
		t.Error("Finalizer should not be present after remove")
	}

	// Other finalizer should still be present
	if !HasFinalizer(obj, OpenSearchUser) {
		t.Error("Other finalizers should not be affected")
	}

	// Remove non-existing finalizer
	if RemoveFinalizer(obj, WazuhCluster) {
		t.Error("RemoveFinalizer should return false when finalizer doesn't exist")
	}
}

func TestIsBeingDeleted(t *testing.T) {
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	if IsBeingDeleted(obj) {
		t.Error("Object without deletion timestamp should not be marked as being deleted")
	}

	now := metav1.Now()
	obj.DeletionTimestamp = &now

	if !IsBeingDeleted(obj) {
		t.Error("Object with deletion timestamp should be marked as being deleted")
	}
}

func TestRegistryCompleteness(t *testing.T) {
	// Verify that all expected CRDs are in the registry
	expectedKinds := []string{
		"WazuhCluster",
		"WazuhManager",
		"WazuhWorker",
		"WazuhRule",
		"WazuhDecoder",
		"OpenSearchUser",
		"OpenSearchRole",
		"OpenSearchRoleMapping",
		"OpenSearchActionGroup",
		"OpenSearchTenant",
		"OpenSearchIndex",
		"OpenSearchIndexTemplate",
		"OpenSearchComponentTemplate",
		"OpenSearchISMPolicy",
		"OpenSearchSnapshotPolicy",
		"OpenSearchSnapshotRepository",
	}

	for _, kind := range expectedKinds {
		if _, ok := Registry[kind]; !ok {
			t.Errorf("Registry should contain %s", kind)
		}
	}
}

func TestFinalizerNaming(t *testing.T) {
	// All finalizers should start with the domain
	for kind, info := range Registry {
		if len(info.Name) <= len(Domain)+1 {
			t.Errorf("Finalizer for %s is too short: %s", kind, info.Name)
		}
		if info.Name[:len(Domain)] != Domain {
			t.Errorf("Finalizer for %s should start with %s, got %s", kind, Domain, info.Name)
		}
	}
}
