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

func TestPolicyReconciler_buildISMPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewPolicyReconciler(client, scheme)

	tests := []struct {
		name             string
		policy           *wazuhv1.OpenSearchISMPolicy
		wantDesc         string
		wantDefaultState string
		wantStatesLen    int
		wantTemplateLen  int
	}{
		{
			name: "minimal policy with description and default state",
			policy: &wazuhv1.OpenSearchISMPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchISMPolicySpec{
					Description:  "Test ISM policy",
					DefaultState: "hot",
				},
			},
			wantDesc:         "Test ISM policy",
			wantDefaultState: "hot",
			wantStatesLen:    0,
			wantTemplateLen:  0,
		},
		{
			name: "policy with states and actions",
			policy: &wazuhv1.OpenSearchISMPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "lifecycle-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchISMPolicySpec{
					Description:  "Lifecycle policy",
					DefaultState: "hot",
					States: []wazuhv1.ISMState{
						{
							Name: "hot",
							Actions: []wazuhv1.ISMAction{
								{
									Config: &runtime.RawExtension{
										Raw: []byte(`{"rollover":{"min_index_age":"1d"}}`),
									},
								},
							},
						},
						{
							Name: "warm",
						},
					},
				},
			},
			wantDesc:         "Lifecycle policy",
			wantDefaultState: "hot",
			wantStatesLen:    2,
			wantTemplateLen:  0,
		},
		{
			name: "policy with transitions and conditions",
			policy: &wazuhv1.OpenSearchISMPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchISMPolicySpec{
					DefaultState: "hot",
					States: []wazuhv1.ISMState{
						{
							Name: "hot",
							Transitions: []wazuhv1.ISMTransition{
								{
									StateName: "warm",
									Conditions: &wazuhv1.ISMTransitionConditions{
										MinIndexAge: "7d",
									},
								},
							},
						},
						{
							Name: "warm",
							Transitions: []wazuhv1.ISMTransition{
								{
									StateName: "delete",
									Conditions: &wazuhv1.ISMTransitionConditions{
										MinDocCount: 1000000,
										MinSize:     "50gb",
									},
								},
							},
						},
						{
							Name: "delete",
						},
					},
				},
			},
			wantDefaultState: "hot",
			wantStatesLen:    3,
		},
		{
			name: "policy with ISM template patterns",
			policy: &wazuhv1.OpenSearchISMPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "template-policy",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchISMPolicySpec{
					Description:  "Policy with templates",
					DefaultState: "hot",
					ISMTemplate: []wazuhv1.ISMTemplateConfig{
						{
							IndexPatterns: []string{"logs-*"},
							Priority:      100,
						},
						{
							IndexPatterns: []string{"metrics-*", "traces-*"},
							Priority:      50,
						},
					},
				},
			},
			wantDesc:         "Policy with templates",
			wantDefaultState: "hot",
			wantTemplateLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.buildISMPolicy(tt.policy)
			if got.Policy.Description != tt.wantDesc {
				t.Errorf("buildISMPolicy() Description = %v, want %v", got.Policy.Description, tt.wantDesc)
			}
			if got.Policy.DefaultState != tt.wantDefaultState {
				t.Errorf("buildISMPolicy() DefaultState = %v, want %v", got.Policy.DefaultState, tt.wantDefaultState)
			}
			if len(got.Policy.States) != tt.wantStatesLen {
				t.Errorf("buildISMPolicy() States length = %v, want %v", len(got.Policy.States), tt.wantStatesLen)
			}
			if len(got.Policy.ISMTemplate) != tt.wantTemplateLen {
				t.Errorf("buildISMPolicy() ISMTemplate length = %v, want %v", len(got.Policy.ISMTemplate), tt.wantTemplateLen)
			}
		})
	}
}

func TestPolicyReconciler_buildISMPolicy_StateDetails(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewPolicyReconciler(client, scheme)

	policy := &wazuhv1.OpenSearchISMPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "detailed-policy",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchISMPolicySpec{
			DefaultState: "hot",
			States: []wazuhv1.ISMState{
				{
					Name: "hot",
					Actions: []wazuhv1.ISMAction{
						{
							Config: &runtime.RawExtension{
								Raw: []byte(`{"rollover":{"min_index_age":"1d"}}`),
							},
						},
					},
					Transitions: []wazuhv1.ISMTransition{
						{
							StateName: "warm",
							Conditions: &wazuhv1.ISMTransitionConditions{
								MinIndexAge: "7d",
							},
						},
					},
				},
			},
			ISMTemplate: []wazuhv1.ISMTemplateConfig{
				{
					IndexPatterns: []string{"logs-*"},
					Priority:      100,
				},
			},
		},
	}

	got := r.buildISMPolicy(policy)

	// Verify state name
	if got.Policy.States[0].Name != "hot" {
		t.Errorf("Expected state name 'hot', got %s", got.Policy.States[0].Name)
	}

	// Verify action has raw config
	if got.Policy.States[0].Actions[0].RawConfig == nil {
		t.Error("Expected action to have RawConfig set")
	}

	// Verify transition
	transition := got.Policy.States[0].Transitions[0]
	if transition.StateName != "warm" {
		t.Errorf("Expected transition state 'warm', got %s", transition.StateName)
	}
	if transition.Conditions == nil {
		t.Fatal("Expected transition conditions to be set")
	}
	if transition.Conditions.MinIndexAge != "7d" {
		t.Errorf("Expected MinIndexAge '7d', got %s", transition.Conditions.MinIndexAge)
	}

	// Verify ISM template
	if got.Policy.ISMTemplate[0].Priority != 100 {
		t.Errorf("Expected ISMTemplate priority 100, got %d", got.Policy.ISMTemplate[0].Priority)
	}
	if len(got.Policy.ISMTemplate[0].IndexPatterns) != 1 || got.Policy.ISMTemplate[0].IndexPatterns[0] != "logs-*" {
		t.Errorf("Expected ISMTemplate index pattern 'logs-*', got %v", got.Policy.ISMTemplate[0].IndexPatterns)
	}
}

func TestPolicyReconciler_buildISMPolicy_NilConditions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewPolicyReconciler(client, scheme)

	policy := &wazuhv1.OpenSearchISMPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-conditions-policy",
			Namespace: "default",
		},
		Spec: wazuhv1.OpenSearchISMPolicySpec{
			DefaultState: "hot",
			States: []wazuhv1.ISMState{
				{
					Name: "hot",
					Actions: []wazuhv1.ISMAction{
						{
							Config: nil,
						},
					},
					Transitions: []wazuhv1.ISMTransition{
						{
							StateName:  "warm",
							Conditions: nil,
						},
					},
				},
			},
		},
	}

	got := r.buildISMPolicy(policy)

	// Verify nil action config doesn't crash
	if got.Policy.States[0].Actions[0].RawConfig != nil {
		t.Error("Expected nil RawConfig for nil action config")
	}

	// Verify nil conditions
	if got.Policy.States[0].Transitions[0].Conditions != nil {
		t.Error("Expected nil conditions for transition with nil conditions")
	}
}
