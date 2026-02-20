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
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestNewRestoreReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewRestoreReconciler(client, scheme)

	if r == nil {
		t.Fatal("NewRestoreReconciler() returned nil")
	}
	if r.Client == nil {
		t.Error("NewRestoreReconciler() Client is nil")
	}
	if r.Scheme == nil {
		t.Error("NewRestoreReconciler() Scheme is nil")
	}
	if r.ClientFactory != nil {
		t.Error("NewRestoreReconciler() ClientFactory should be nil initially")
	}
}

func TestRestoreReconciler_WithClientFactory(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewRestoreReconciler(client, scheme)

	// WithClientFactory should return the same reconciler for chaining
	result := r.WithClientFactory(nil)
	if result != r {
		t.Error("WithClientFactory() should return the same reconciler instance")
	}
}
