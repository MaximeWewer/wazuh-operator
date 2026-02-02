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

package validation

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestValidateXML(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "valid group XML",
			content: `<group name="sshd,authentication_failed">
				<rule id="100001" level="5">
					<description>Test rule</description>
				</rule>
			</group>`,
			wantErr: false,
		},
		{
			name: "valid multiple rules",
			content: `<group name="custom">
				<rule id="100001" level="5">
					<description>First rule</description>
				</rule>
				<rule id="100002" level="10">
					<description>Second rule</description>
				</rule>
			</group>`,
			wantErr: false,
		},
		{
			name:    "empty content",
			content: "",
			wantErr: true,
		},
		{
			name:    "invalid XML - unclosed tag",
			content: "<group name='test'><rule id='100001'>",
			wantErr: true,
		},
		{
			name:    "invalid XML - malformed",
			content: "this is not xml at all",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateXML(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateXML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractRuleIDs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []int
	}{
		{
			name: "single rule",
			content: `<group name="test">
				<rule id="100001" level="5">
					<description>Test</description>
				</rule>
			</group>`,
			want: []int{100001},
		},
		{
			name: "multiple rules",
			content: `<group name="test">
				<rule id="100001" level="5">
					<description>First</description>
				</rule>
				<rule id="100002" level="10">
					<description>Second</description>
				</rule>
				<rule id="100003" level="15">
					<description>Third</description>
				</rule>
			</group>`,
			want: []int{100001, 100002, 100003},
		},
		{
			name:    "no rules",
			content: `<group name="empty"></group>`,
			want:    []int{},
		},
		{
			name: "single quotes",
			content: `<group name='test'>
				<rule id='100001' level='5'>
					<description>Test</description>
				</rule>
			</group>`,
			want: []int{100001},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRuleIDs(tt.content)
			if len(got) != len(tt.want) {
				t.Errorf("ExtractRuleIDs() = %v, want %v", got, tt.want)
				return
			}
			for i, id := range got {
				if id != tt.want[i] {
					t.Errorf("ExtractRuleIDs()[%d] = %v, want %v", i, id, tt.want[i])
				}
			}
		})
	}
}

func TestRuleValidator_validateRuleIDs(t *testing.T) {
	v := &RuleValidator{}

	tests := []struct {
		name       string
		content    string
		specRuleID int32
		wantErrors int
	}{
		{
			name: "valid custom rule IDs",
			content: `<group name="test">
				<rule id="100001" level="5">
					<description>Test</description>
				</rule>
			</group>`,
			specRuleID: 0,
			wantErrors: 0,
		},
		{
			name: "rule ID too low",
			content: `<group name="test">
				<rule id="99999" level="5">
					<description>Test</description>
				</rule>
			</group>`,
			specRuleID: 0,
			wantErrors: 1,
		},
		{
			name: "rule ID too high",
			content: `<group name="test">
				<rule id="1000000" level="5">
					<description>Test</description>
				</rule>
			</group>`,
			specRuleID: 0,
			wantErrors: 1,
		},
		{
			name: "spec ruleID too low",
			content: `<group name="test">
				<rule id="100001" level="5">
					<description>Test</description>
				</rule>
			</group>`,
			specRuleID: 50000,
			wantErrors: 1,
		},
		{
			name: "multiple invalid IDs",
			content: `<group name="test">
				<rule id="1" level="5">
					<description>First</description>
				</rule>
				<rule id="9999999" level="5">
					<description>Second</description>
				</rule>
			</group>`,
			specRuleID: 0,
			wantErrors: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := v.validateRuleIDs(tt.content, tt.specRuleID)
			if len(errors) != tt.wantErrors {
				t.Errorf("validateRuleIDs() got %d errors, want %d: %v", len(errors), tt.wantErrors, errors)
			}
		})
	}
}

func TestRuleValidator_validateRuleName(t *testing.T) {
	v := &RuleValidator{}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid simple name",
			input:   "ssh_bruteforce",
			wantErr: false,
		},
		{
			name:    "valid name with hyphen",
			input:   "ssh-brute-force",
			wantErr: false,
		},
		{
			name:    "valid alphanumeric",
			input:   "rule123test",
			wantErr: false,
		},
		{
			name:    "empty name",
			input:   "",
			wantErr: true,
		},
		{
			name:    "name with spaces",
			input:   "ssh brute force",
			wantErr: true,
		},
		{
			name:    "name with special chars",
			input:   "ssh@bruteforce!",
			wantErr: true,
		},
		{
			name:    "name too long",
			input:   "this_is_a_very_long_rule_name_that_exceeds_the_maximum_allowed_length_limit",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateRuleName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRuleName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRuleValidator_Validate(t *testing.T) {
	v := NewRuleValidator(nil) // nil client for basic validation

	tests := []struct {
		name      string
		rule      *wazuhv1.WazuhRule
		wantValid bool
	}{
		{
			name: "valid rule",
			rule: &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rule",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					RuleName: "ssh_bruteforce",
					Rules: `<group name="sshd">
						<rule id="100001" level="10">
							<description>SSH brute force detected</description>
						</rule>
					</group>`,
				},
			},
			wantValid: true,
		},
		{
			name: "invalid XML",
			rule: &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rule",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					RuleName: "test_rule",
					Rules:    "not valid xml",
				},
			},
			wantValid: false,
		},
		{
			name: "invalid rule ID",
			rule: &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rule",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					RuleName: "test_rule",
					Rules: `<group name="test">
						<rule id="99" level="5">
							<description>Invalid ID</description>
						</rule>
					</group>`,
				},
			},
			wantValid: false,
		},
		{
			name: "invalid rule name",
			rule: &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rule",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name: "test-cluster",
					},
					RuleName: "invalid name with spaces",
					Rules: `<group name="test">
						<rule id="100001" level="5">
							<description>Test</description>
						</rule>
					</group>`,
				},
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(context.Background(), tt.rule)
			if result.Valid != tt.wantValid {
				t.Errorf("Validate() valid = %v, want %v, errors: %v", result.Valid, tt.wantValid, result.Errors)
			}
		})
	}
}

func TestFormatValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		errors []string
		want   string
	}{
		{
			name:   "empty errors",
			errors: []string{},
			want:   "",
		},
		{
			name:   "single error",
			errors: []string{"error 1"},
			want:   "error 1",
		},
		{
			name:   "multiple errors",
			errors: []string{"error 1", "error 2", "error 3"},
			want:   "error 1; error 2; error 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatValidationErrors(tt.errors)
			if got != tt.want {
				t.Errorf("FormatValidationErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}
