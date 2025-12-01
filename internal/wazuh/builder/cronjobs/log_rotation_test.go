/*
Copyright 2025.

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

package cronjobs

import (
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestNewLogRotationCronJobBuilder(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")

	if builder.clusterName != "test-cluster" {
		t.Errorf("expected clusterName to be 'test-cluster', got %s", builder.clusterName)
	}
	if builder.namespace != "test-ns" {
		t.Errorf("expected namespace to be 'test-ns', got %s", builder.namespace)
	}
	if builder.schedule != constants.DefaultLogRotationSchedule {
		t.Errorf("expected schedule to be default, got %s", builder.schedule)
	}
	if builder.retentionDays != constants.DefaultLogRotationRetentionDays {
		t.Errorf("expected retentionDays to be default, got %d", builder.retentionDays)
	}
}

func TestLogRotationCronJobBuilder_WithMethods(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")

	// Test WithSchedule
	builder.WithSchedule("0 0 * * *")
	if builder.schedule != "0 0 * * *" {
		t.Errorf("expected schedule '0 0 * * *', got %s", builder.schedule)
	}

	// Test WithRetentionDays
	builder.WithRetentionDays(14)
	if builder.retentionDays != 14 {
		t.Errorf("expected retentionDays 14, got %d", builder.retentionDays)
	}

	// Test WithMaxFileSizeMB
	builder.WithMaxFileSizeMB(100)
	if builder.maxFileSizeMB != 100 {
		t.Errorf("expected maxFileSizeMB 100, got %d", builder.maxFileSizeMB)
	}

	// Test WithCombinationMode
	builder.WithCombinationMode("and")
	if builder.combinationMode != "and" {
		t.Errorf("expected combinationMode 'and', got %s", builder.combinationMode)
	}

	// Test invalid combination mode is ignored
	builder.WithCombinationMode("invalid")
	if builder.combinationMode != "and" {
		t.Errorf("expected combinationMode to remain 'and', got %s", builder.combinationMode)
	}

	// Test WithPaths
	customPaths := []string{"/custom/path/"}
	builder.WithPaths(customPaths)
	if len(builder.paths) != 1 || builder.paths[0] != "/custom/path/" {
		t.Errorf("expected custom paths, got %v", builder.paths)
	}

	// Test WithImage
	builder.WithImage("custom-image:v1")
	if builder.image != "custom-image:v1" {
		t.Errorf("expected image 'custom-image:v1', got %s", builder.image)
	}
}

func TestLogRotationCronJobBuilder_BuildFindCommand(t *testing.T) {
	tests := []struct {
		name           string
		retentionDays  int32
		maxFileSizeMB  int32
		combinationMode string
		paths          []string
		wantContains   []string
		wantNotContains []string
	}{
		{
			name:          "age only",
			retentionDays: 7,
			maxFileSizeMB: 0,
			paths:         []string{"/var/ossec/logs/alerts/"},
			wantContains:  []string{"find /var/ossec/logs/alerts/ -type f -mtime +7 -delete"},
			wantNotContains: []string{"-size"},
		},
		{
			name:           "age and size with OR",
			retentionDays:  7,
			maxFileSizeMB:  100,
			combinationMode: "or",
			paths:          []string{"/var/ossec/logs/alerts/"},
			wantContains:   []string{"-mtime +7 -o -size +100M"},
		},
		{
			name:           "age and size with AND",
			retentionDays:  14,
			maxFileSizeMB:  500,
			combinationMode: "and",
			paths:          []string{"/var/ossec/logs/alerts/"},
			wantContains:   []string{"-mtime +14 -size +500M -delete"},
			wantNotContains: []string{"-o"},
		},
		{
			name:          "multiple paths",
			retentionDays: 7,
			maxFileSizeMB: 0,
			paths:         []string{"/path1/", "/path2/"},
			wantContains:  []string{"find /path1/", "find /path2/", "; "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewLogRotationCronJobBuilder("test", "test-ns")
			builder.WithRetentionDays(tt.retentionDays)
			builder.WithMaxFileSizeMB(tt.maxFileSizeMB)
			builder.WithCombinationMode(tt.combinationMode)
			builder.WithPaths(tt.paths)

			cmd := builder.buildFindCommand()

			for _, want := range tt.wantContains {
				if !strings.Contains(cmd, want) {
					t.Errorf("expected command to contain %q, got: %s", want, cmd)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(cmd, notWant) {
					t.Errorf("expected command NOT to contain %q, got: %s", notWant, cmd)
				}
			}
		})
	}
}

func TestLogRotationCronJobBuilder_Build(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")
	builder.WithSchedule("0 0 * * 0")
	builder.WithRetentionDays(14)

	cronJob := builder.Build()

	// Check metadata
	if cronJob.Name != "test-cluster-log-rotation" {
		t.Errorf("expected name 'test-cluster-log-rotation', got %s", cronJob.Name)
	}
	if cronJob.Namespace != "test-ns" {
		t.Errorf("expected namespace 'test-ns', got %s", cronJob.Namespace)
	}

	// Check spec
	if cronJob.Spec.Schedule != "0 0 * * 0" {
		t.Errorf("expected schedule '0 0 * * 0', got %s", cronJob.Spec.Schedule)
	}
	if cronJob.Spec.ConcurrencyPolicy != batchv1.ForbidConcurrent {
		t.Errorf("expected ForbidConcurrent policy")
	}

	// Check labels
	if cronJob.Labels["app.kubernetes.io/component"] != "log-rotation" {
		t.Errorf("expected component label 'log-rotation'")
	}
	if cronJob.Labels["app.kubernetes.io/instance"] != "test-cluster" {
		t.Errorf("expected instance label 'test-cluster'")
	}

	// Check service account
	if cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName != "test-cluster-log-rotation" {
		t.Errorf("expected service account name 'test-cluster-log-rotation'")
	}
}

func TestLogRotationCronJobBuilder_BuildServiceAccount(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")
	sa := builder.BuildServiceAccount()

	if sa.Name != "test-cluster-log-rotation" {
		t.Errorf("expected name 'test-cluster-log-rotation', got %s", sa.Name)
	}
	if sa.Namespace != "test-ns" {
		t.Errorf("expected namespace 'test-ns', got %s", sa.Namespace)
	}
}

func TestLogRotationCronJobBuilder_BuildRole(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")
	role := builder.BuildRole()

	if role.Name != "test-cluster-log-rotation" {
		t.Errorf("expected name 'test-cluster-log-rotation', got %s", role.Name)
	}

	// Check rules
	if len(role.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(role.Rules))
	}

	// Rule 0: pods get/list
	if role.Rules[0].Resources[0] != "pods" {
		t.Errorf("expected rule 0 resource 'pods'")
	}

	// Rule 1: pods/exec create
	if role.Rules[1].Resources[0] != "pods/exec" {
		t.Errorf("expected rule 1 resource 'pods/exec'")
	}
}

func TestLogRotationCronJobBuilder_BuildRoleBinding(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")
	rb := builder.BuildRoleBinding()

	if rb.Name != "test-cluster-log-rotation" {
		t.Errorf("expected name 'test-cluster-log-rotation', got %s", rb.Name)
	}
	if rb.RoleRef.Name != "test-cluster-log-rotation" {
		t.Errorf("expected roleRef name 'test-cluster-log-rotation'")
	}
	if rb.Subjects[0].Name != "test-cluster-log-rotation" {
		t.Errorf("expected subject name 'test-cluster-log-rotation'")
	}
}

func TestLogRotationCronJobBuilder_GetResourceNames(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("my-cluster", "my-ns")
	cronJobName, saName, roleName, roleBindingName := builder.GetResourceNames()

	expected := "my-cluster-log-rotation"
	if cronJobName != expected {
		t.Errorf("expected cronJobName %s, got %s", expected, cronJobName)
	}
	if saName != expected {
		t.Errorf("expected saName %s, got %s", expected, saName)
	}
	if roleName != expected {
		t.Errorf("expected roleName %s, got %s", expected, roleName)
	}
	if roleBindingName != expected {
		t.Errorf("expected roleBindingName %s, got %s", expected, roleBindingName)
	}
}

func TestLogRotationCronJobBuilder_BuildScript(t *testing.T) {
	builder := NewLogRotationCronJobBuilder("test-cluster", "test-ns")
	builder.WithRetentionDays(7)
	builder.WithMaxFileSizeMB(100)

	script := builder.buildScript()

	// Check script contains key elements
	expectedContains := []string{
		"Starting log rotation for cluster test-cluster",
		"kubectl get pods -n test-ns",
		"app.kubernetes.io/component=wazuh-manager",
		"app.kubernetes.io/instance=test-cluster",
		"kubectl exec -n test-ns",
		"find",
	}

	for _, expected := range expectedContains {
		if !strings.Contains(script, expected) {
			t.Errorf("expected script to contain %q", expected)
		}
	}
}
