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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestSnapshotPolicyReconciler_buildSnapshotPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewSnapshotPolicyReconciler(client, scheme)

	// Helper to create int32 pointer
	int32Ptr := func(i int32) *int32 { return &i }

	tests := []struct {
		name          string
		policy        *wazuhv1.OpenSearchSnapshotPolicy
		wantDesc      string
		wantEnabled   bool
		wantRepo      string
		wantIndices   string
		wantCron      string
		wantTimezone  string
		wantTimeLimit string
		wantDeletion  bool
	}{
		{
			name: "minimal policy with creation schedule",
			policy: &wazuhv1.OpenSearchSnapshotPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotPolicySpec{
					Description: "Daily snapshots",
					Repository: wazuhv1.SnapshotRepository{
						Name: "my-repo",
					},
					Creation: wazuhv1.SnapshotCreation{
						Schedule: wazuhv1.CronSchedule{
							Expression: "0 0 * * *",
							Timezone:   "UTC",
						},
					},
				},
			},
			wantDesc:     "Daily snapshots",
			wantEnabled:  true,
			wantRepo:     "my-repo",
			wantCron:     "0 0 * * *",
			wantTimezone: "UTC",
			wantDeletion: false,
		},
		{
			name: "policy with indices and time limit",
			policy: &wazuhv1.OpenSearchSnapshotPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "indices-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotPolicySpec{
					Repository: wazuhv1.SnapshotRepository{
						Name: "s3-repo",
					},
					SnapshotConfig: &wazuhv1.SnapshotConfig{
						Indices: []string{"logs-*", "metrics-*"},
					},
					Creation: wazuhv1.SnapshotCreation{
						Schedule: wazuhv1.CronSchedule{
							Expression: "0 */6 * * *",
							Timezone:   "America/New_York",
						},
						TimeLimit: "1h",
					},
				},
			},
			wantEnabled:   true,
			wantRepo:      "s3-repo",
			wantIndices:   "logs-*,metrics-*",
			wantCron:      "0 */6 * * *",
			wantTimezone:  "America/New_York",
			wantTimeLimit: "1h",
			wantDeletion:  false,
		},
		{
			name: "policy with deletion schedule and conditions",
			policy: &wazuhv1.OpenSearchSnapshotPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "retention-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotPolicySpec{
					Description: "Policy with retention",
					Repository: wazuhv1.SnapshotRepository{
						Name: "fs-repo",
					},
					Creation: wazuhv1.SnapshotCreation{
						Schedule: wazuhv1.CronSchedule{
							Expression: "0 0 * * *",
						},
					},
					Deletion: &wazuhv1.SnapshotDeletion{
						Schedule: &wazuhv1.CronSchedule{
							Expression: "0 1 * * *",
							Timezone:   "Europe/Paris",
						},
						Condition: &wazuhv1.DeletionCondition{
							MaxAge:   "30d",
							MaxCount: int32Ptr(100),
							MinCount: int32Ptr(5),
						},
					},
				},
			},
			wantDesc:     "Policy with retention",
			wantEnabled:  true,
			wantRepo:     "fs-repo",
			wantCron:     "0 0 * * *",
			wantDeletion: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildSnapshotPolicy(tt.policy)

			if got.Description != tt.wantDesc {
				t.Errorf("buildSnapshotPolicy() Description = %v, want %v", got.Description, tt.wantDesc)
			}
			if got.Enabled != tt.wantEnabled {
				t.Errorf("buildSnapshotPolicy() Enabled = %v, want %v", got.Enabled, tt.wantEnabled)
			}
			if got.SnapshotConfig == nil {
				t.Fatal("Expected SnapshotConfig to be set")
			}
			if got.SnapshotConfig.Repository != tt.wantRepo {
				t.Errorf("buildSnapshotPolicy() Repository = %v, want %v", got.SnapshotConfig.Repository, tt.wantRepo)
			}
			if tt.wantIndices != "" && got.SnapshotConfig.Indices != tt.wantIndices {
				t.Errorf("buildSnapshotPolicy() Indices = %v, want %v", got.SnapshotConfig.Indices, tt.wantIndices)
			}
			if got.Creation == nil {
				t.Fatal("Expected Creation to be set")
			}
			if got.Creation.Schedule == nil || got.Creation.Schedule.Cron == nil {
				t.Fatal("Expected Creation.Schedule.Cron to be set")
			}
			if got.Creation.Schedule.Cron.Expression != tt.wantCron {
				t.Errorf("buildSnapshotPolicy() Cron Expression = %v, want %v", got.Creation.Schedule.Cron.Expression, tt.wantCron)
			}
			if tt.wantTimezone != "" && got.Creation.Schedule.Cron.Timezone != tt.wantTimezone {
				t.Errorf("buildSnapshotPolicy() Cron Timezone = %v, want %v", got.Creation.Schedule.Cron.Timezone, tt.wantTimezone)
			}
			if tt.wantTimeLimit != "" && got.Creation.TimeLimit != tt.wantTimeLimit {
				t.Errorf("buildSnapshotPolicy() TimeLimit = %v, want %v", got.Creation.TimeLimit, tt.wantTimeLimit)
			}
			if tt.wantDeletion && got.Deletion == nil {
				t.Error("Expected Deletion to be set")
			}
			if !tt.wantDeletion && got.Deletion != nil {
				t.Error("Expected Deletion to be nil")
			}
		})
	}
}

func TestSnapshotPolicyReconciler_buildSnapshotPolicy_DeletionDetails(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewSnapshotPolicyReconciler(client, scheme)

	int32Ptr := func(i int32) *int32 { return &i }

	policy := &wazuhv1.OpenSearchSnapshotPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deletion-details",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchSnapshotPolicySpec{
			Repository: wazuhv1.SnapshotRepository{Name: "repo"},
			Creation: wazuhv1.SnapshotCreation{
				Schedule: wazuhv1.CronSchedule{Expression: "0 0 * * *"},
			},
			Deletion: &wazuhv1.SnapshotDeletion{
				Schedule: &wazuhv1.CronSchedule{
					Expression: "0 2 * * *",
					Timezone:   "UTC",
				},
				Condition: &wazuhv1.DeletionCondition{
					MaxAge:   "30d",
					MaxCount: int32Ptr(50),
					MinCount: int32Ptr(3),
				},
			},
		},
	}

	got := r.buildSnapshotPolicy(policy)

	if got.Deletion == nil {
		t.Fatal("Expected Deletion to be set")
	}
	if got.Deletion.Schedule == nil || got.Deletion.Schedule.Cron == nil {
		t.Fatal("Expected Deletion.Schedule.Cron to be set")
	}
	if got.Deletion.Schedule.Cron.Expression != "0 2 * * *" {
		t.Errorf("Deletion cron = %v, want '0 2 * * *'", got.Deletion.Schedule.Cron.Expression)
	}
	if got.Deletion.Schedule.Cron.Timezone != "UTC" {
		t.Errorf("Deletion timezone = %v, want 'UTC'", got.Deletion.Schedule.Cron.Timezone)
	}
	if got.Deletion.Condition == nil {
		t.Fatal("Expected Deletion.Condition to be set")
	}
	if got.Deletion.Condition.MaxAge != "30d" {
		t.Errorf("Deletion MaxAge = %v, want '30d'", got.Deletion.Condition.MaxAge)
	}
	if got.Deletion.Condition.MaxCount != 50 {
		t.Errorf("Deletion MaxCount = %v, want 50", got.Deletion.Condition.MaxCount)
	}
	if got.Deletion.Condition.MinCount != 3 {
		t.Errorf("Deletion MinCount = %v, want 3", got.Deletion.Condition.MinCount)
	}
}

func TestSnapshotPolicyReconciler_buildSnapshotPolicy_DeletionWithoutSchedule(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewSnapshotPolicyReconciler(client, scheme)

	policy := &wazuhv1.OpenSearchSnapshotPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-deletion-schedule",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchSnapshotPolicySpec{
			Repository: wazuhv1.SnapshotRepository{Name: "repo"},
			Creation: wazuhv1.SnapshotCreation{
				Schedule: wazuhv1.CronSchedule{Expression: "0 0 * * *"},
			},
			Deletion: &wazuhv1.SnapshotDeletion{
				Condition: &wazuhv1.DeletionCondition{
					MaxAge: "7d",
				},
			},
		},
	}

	got := r.buildSnapshotPolicy(policy)

	if got.Deletion == nil {
		t.Fatal("Expected Deletion to be set")
	}
	if got.Deletion.Schedule != nil {
		t.Error("Expected Deletion.Schedule to be nil when not specified")
	}
	if got.Deletion.Condition == nil {
		t.Fatal("Expected Deletion.Condition to be set")
	}
	if got.Deletion.Condition.MaxAge != "7d" {
		t.Errorf("Deletion MaxAge = %v, want '7d'", got.Deletion.Condition.MaxAge)
	}
}
