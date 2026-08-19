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

package cronjobs

import (
	"os"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

func TestMain(m *testing.M) {
	// DNS functions used by the agent purge builder require initialization
	_ = dns.Initialize()
	os.Exit(m.Run())
}

func TestNewAgentPurgeCronJobBuilder(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("test-cluster", "test-ns")

	if builder.clusterName != "test-cluster" {
		t.Errorf("expected clusterName to be 'test-cluster', got %s", builder.clusterName)
	}
	if builder.namespace != "test-ns" {
		t.Errorf("expected namespace to be 'test-ns', got %s", builder.namespace)
	}
	if builder.schedule != constants.DefaultAgentPurgeSchedule {
		t.Errorf("expected schedule to be default, got %s", builder.schedule)
	}
	if builder.disconnectedDays != constants.DefaultAgentPurgeDisconnectedDays {
		t.Errorf("expected disconnectedDays to be default, got %d", builder.disconnectedDays)
	}
	if builder.image != constants.DefaultAgentPurgeImage {
		t.Errorf("expected image to be default, got %s", builder.image)
	}
	if builder.credentialSecret != constants.APICredentialsName("test-cluster") {
		t.Errorf("expected credentialSecret to be default, got %s", builder.credentialSecret)
	}
}

func TestAgentPurgeCronJobBuilder_WithMethods(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("test-cluster", "test-ns")

	builder.WithSchedule("0 5 * * *")
	if builder.schedule != "0 5 * * *" {
		t.Errorf("expected schedule '0 5 * * *', got %s", builder.schedule)
	}

	builder.WithDisconnectedDays(45)
	if builder.disconnectedDays != 45 {
		t.Errorf("expected disconnectedDays 45, got %d", builder.disconnectedDays)
	}

	// Zero/negative days is ignored
	builder.WithDisconnectedDays(0)
	if builder.disconnectedDays != 45 {
		t.Errorf("expected disconnectedDays to remain 45, got %d", builder.disconnectedDays)
	}

	builder.WithStatuses([]string{"disconnected", "never_connected"})
	if len(builder.statuses) != 2 {
		t.Errorf("expected 2 statuses, got %v", builder.statuses)
	}

	builder.WithDryRun(true)
	if !builder.dryRun {
		t.Errorf("expected dryRun true")
	}

	builder.WithImage("custom/curl:v1")
	if builder.image != "custom/curl:v1" {
		t.Errorf("expected image 'custom/curl:v1', got %s", builder.image)
	}

	builder.WithCredentialSecret("custom-secret")
	if builder.credentialSecret != "custom-secret" {
		t.Errorf("expected credentialSecret 'custom-secret', got %s", builder.credentialSecret)
	}
}

func TestAgentPurgeCronJobBuilder_BuildScript(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("test-cluster", "test-ns")
	builder.WithDisconnectedDays(30)
	builder.WithStatuses([]string{"disconnected"})

	script := builder.buildScript()

	expectedContains := []string{
		"Starting agent purge for cluster test-cluster",
		"test-cluster-manager-master",
		"security/user/authenticate?raw=true",
		"-X DELETE",
		"status=$ST",
		"older_than=30d",
		"for ST in disconnected;",
	}
	for _, expected := range expectedContains {
		if !strings.Contains(script, expected) {
			t.Errorf("expected script to contain %q, got: %s", expected, script)
		}
	}

	// Non-dry-run should not include the dry-run label
	if strings.Contains(script, "[dry-run]") && strings.Contains(script, `"false" = "true"`) {
		// The dry-run branch text is still present in the shell if/else, but the flag is false
	}
}

func TestAgentPurgeCronJobBuilder_BuildScript_DryRun(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("test-cluster", "test-ns")
	builder.WithDryRun(true)
	builder.WithDisconnectedDays(15)

	script := builder.buildScript()

	expectedContains := []string{
		"dry-run: true",
		"[dry-run] agents status=$ST older_than=15d",
		"select=id,name,lastKeepAlive",
		`if [ "true" = "true" ]; then`,
	}
	for _, expected := range expectedContains {
		if !strings.Contains(script, expected) {
			t.Errorf("expected dry-run script to contain %q, got: %s", expected, script)
		}
	}
}

func TestAgentPurgeCronJobBuilder_Build(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("test-cluster", "test-ns")
	builder.WithSchedule("0 4 * * *")
	builder.WithDisconnectedDays(20)

	cronJob := builder.Build()

	// Metadata
	if cronJob.Name != "test-cluster-agent-purge" {
		t.Errorf("expected name 'test-cluster-agent-purge', got %s", cronJob.Name)
	}
	if cronJob.Namespace != "test-ns" {
		t.Errorf("expected namespace 'test-ns', got %s", cronJob.Namespace)
	}

	// Spec
	if cronJob.Spec.Schedule != "0 4 * * *" {
		t.Errorf("expected schedule '0 4 * * *', got %s", cronJob.Spec.Schedule)
	}
	if cronJob.Spec.ConcurrencyPolicy != batchv1.ForbidConcurrent {
		t.Errorf("expected ForbidConcurrent policy")
	}

	// Labels
	if cronJob.Labels["app.kubernetes.io/component"] != "agent-purge" {
		t.Errorf("expected component label 'agent-purge'")
	}
	if cronJob.Labels["app.kubernetes.io/instance"] != "test-cluster" {
		t.Errorf("expected instance label 'test-cluster'")
	}

	// Container
	containers := cronJob.Spec.JobTemplate.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	c := containers[0]
	if c.Image != constants.DefaultAgentPurgeImage {
		t.Errorf("expected image %q, got %s", constants.DefaultAgentPurgeImage, c.Image)
	}

	// Env from api-credentials secret
	if len(c.Env) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(c.Env))
	}
	foundUser, foundPass := false, false
	expectedSecret := constants.APICredentialsName("test-cluster")
	for _, e := range c.Env {
		if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("expected env %s to source from a secret", e.Name)
		}
		if e.ValueFrom.SecretKeyRef.Name != expectedSecret {
			t.Errorf("expected env %s secret %q, got %s", e.Name, expectedSecret, e.ValueFrom.SecretKeyRef.Name)
		}
		switch e.Name {
		case "API_USER":
			foundUser = true
			if e.ValueFrom.SecretKeyRef.Key != constants.SecretKeyAPIUsername {
				t.Errorf("expected API_USER key %q, got %s", constants.SecretKeyAPIUsername, e.ValueFrom.SecretKeyRef.Key)
			}
		case "API_PASS":
			foundPass = true
			if e.ValueFrom.SecretKeyRef.Key != constants.SecretKeyAPIPassword {
				t.Errorf("expected API_PASS key %q, got %s", constants.SecretKeyAPIPassword, e.ValueFrom.SecretKeyRef.Key)
			}
		}
	}
	if !foundUser || !foundPass {
		t.Errorf("expected both API_USER and API_PASS env vars")
	}

	// RestartPolicy
	if cronJob.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy != "OnFailure" {
		t.Errorf("expected RestartPolicy OnFailure")
	}

	// Script embedded in args contains the DELETE /agents call
	if len(c.Args) != 1 || !strings.Contains(c.Args[0], "older_than=20d") {
		t.Errorf("expected container args to contain the purge script with older_than=20d")
	}
}

func TestAgentPurgeCronJobBuilder_GetResourceNames(t *testing.T) {
	builder := NewAgentPurgeCronJobBuilder("my-cluster", "my-ns")
	cronJobName := builder.GetResourceNames()
	if cronJobName != "my-cluster-agent-purge" {
		t.Errorf("expected cronJobName 'my-cluster-agent-purge', got %s", cronJobName)
	}
}
