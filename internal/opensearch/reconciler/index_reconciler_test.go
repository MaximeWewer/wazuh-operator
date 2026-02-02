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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestIndexReconciler_buildIndexSettings(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	r := NewIndexReconciler(client, scheme, recorder)

	// Helper to create int32 pointer
	int32Ptr := func(i int32) *int32 { return &i }

	tests := []struct {
		name            string
		index           *wazuhv1.OpenSearchIndex
		wantSettings    bool
		wantShards      bool
		wantReplicas    bool
		wantShardsVal   int32
		wantReplicasVal int32
	}{
		{
			name: "nil settings returns empty map",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: nil,
				},
			},
			wantSettings: false,
		},
		{
			name: "empty settings returns empty map",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: &wazuhv1.IndexSettings{},
				},
			},
			wantSettings: false,
		},
		{
			name: "only shards specified",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: &wazuhv1.IndexSettings{
						NumberOfShards: int32Ptr(3),
					},
				},
			},
			wantSettings:  true,
			wantShards:    true,
			wantShardsVal: 3,
		},
		{
			name: "only replicas specified",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: &wazuhv1.IndexSettings{
						NumberOfReplicas: int32Ptr(2),
					},
				},
			},
			wantSettings:    true,
			wantReplicas:    true,
			wantReplicasVal: 2,
		},
		{
			name: "both shards and replicas specified",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: &wazuhv1.IndexSettings{
						NumberOfShards:   int32Ptr(5),
						NumberOfReplicas: int32Ptr(1),
					},
				},
			},
			wantSettings:    true,
			wantShards:      true,
			wantReplicas:    true,
			wantShardsVal:   5,
			wantReplicasVal: 1,
		},
		{
			name: "zero replicas is valid",
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchIndexSpec{
					Settings: &wazuhv1.IndexSettings{
						NumberOfReplicas: int32Ptr(0),
					},
				},
			},
			wantSettings:    true,
			wantReplicas:    true,
			wantReplicasVal: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildIndexSettings(tt.index)

			if tt.wantSettings {
				settings, ok := got["settings"]
				if !ok {
					t.Error("Expected settings key in result, but not found")
					return
				}

				indexSettings, ok := settings.(map[string]any)["index"].(map[string]any)
				if !ok {
					t.Error("Expected settings.index to be a map")
					return
				}

				if tt.wantShards {
					shards, ok := indexSettings["number_of_shards"]
					if !ok {
						t.Error("Expected number_of_shards in settings")
					} else if shards != tt.wantShardsVal {
						t.Errorf("number_of_shards = %v, want %v", shards, tt.wantShardsVal)
					}
				}

				if tt.wantReplicas {
					replicas, ok := indexSettings["number_of_replicas"]
					if !ok {
						t.Error("Expected number_of_replicas in settings")
					} else if replicas != tt.wantReplicasVal {
						t.Errorf("number_of_replicas = %v, want %v", replicas, tt.wantReplicasVal)
					}
				}
			} else {
				if _, ok := got["settings"]; ok {
					t.Error("Expected no settings key, but found one")
				}
			}
		})
	}
}

func TestIndexReconciler_recordEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name         string
		recorder     record.EventRecorder
		index        *wazuhv1.OpenSearchIndex
		eventType    string
		reason       string
		message      string
		expectEvents int
	}{
		{
			name:     "records event when recorder is available",
			recorder: record.NewFakeRecorder(10),
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Created",
			message:      "Index created",
			expectEvents: 1,
		},
		{
			name:     "records warning event",
			recorder: record.NewFakeRecorder(10),
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeWarning,
			reason:       "CreateFailed",
			message:      "Failed to create index",
			expectEvents: 1,
		},
		{
			name:     "no panic when recorder is nil",
			recorder: nil,
			index: &wazuhv1.OpenSearchIndex{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-index",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Created",
			message:      "Index created",
			expectEvents: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			r := NewIndexReconciler(client, scheme, tt.recorder)

			// Should not panic
			r.recordEvent(tt.index, tt.eventType, tt.reason, tt.message)

			// Verify event was recorded if recorder was provided
			if fakeRecorder, ok := tt.recorder.(*record.FakeRecorder); ok && tt.expectEvents > 0 {
				select {
				case event := <-fakeRecorder.Events:
					if event == "" {
						t.Error("Expected event to be recorded, but got empty event")
					}
				default:
					t.Error("Expected event to be recorded, but none was")
				}
			}
		})
	}
}
