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

// Package cronjobs provides Kubernetes CronJob builders for Wazuh components
package cronjobs

import (
	"fmt"
	"maps"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// AgentPurgeCronJobBuilder builds CronJob resources that periodically delete
// stale Wazuh agents via the Manager REST API. Unlike log rotation it does not
// exec into pods; it curls the manager master service directly, so it needs no
// pods/exec RBAC.
type AgentPurgeCronJobBuilder struct {
	clusterName      string
	namespace        string
	schedule         string
	disconnectedDays int32
	statuses         []string
	dryRun           bool
	image            string
	credentialSecret string
	labels           map[string]string
	version          string
}

// NewAgentPurgeCronJobBuilder creates a new AgentPurgeCronJobBuilder with defaults
func NewAgentPurgeCronJobBuilder(clusterName, namespace string) *AgentPurgeCronJobBuilder {
	return &AgentPurgeCronJobBuilder{
		clusterName:      clusterName,
		namespace:        namespace,
		schedule:         constants.DefaultAgentPurgeSchedule,
		disconnectedDays: constants.DefaultAgentPurgeDisconnectedDays,
		statuses:         constants.DefaultAgentPurgeStatuses,
		dryRun:           false,
		image:            constants.DefaultAgentPurgeImage,
		credentialSecret: constants.APICredentialsName(clusterName),
		labels:           make(map[string]string),
		version:          constants.DefaultWazuhVersion,
	}
}

// WithSchedule sets the cron schedule
func (b *AgentPurgeCronJobBuilder) WithSchedule(schedule string) *AgentPurgeCronJobBuilder {
	if schedule != "" {
		b.schedule = schedule
	}
	return b
}

// WithDisconnectedDays sets the older_than age (in days) for purged agents
func (b *AgentPurgeCronJobBuilder) WithDisconnectedDays(days int32) *AgentPurgeCronJobBuilder {
	if days > 0 {
		b.disconnectedDays = days
	}
	return b
}

// WithStatuses sets the agent states to purge
func (b *AgentPurgeCronJobBuilder) WithStatuses(statuses []string) *AgentPurgeCronJobBuilder {
	if len(statuses) > 0 {
		b.statuses = statuses
	}
	return b
}

// WithDryRun toggles dry-run mode (list what would be deleted, delete nothing)
func (b *AgentPurgeCronJobBuilder) WithDryRun(dryRun bool) *AgentPurgeCronJobBuilder {
	b.dryRun = dryRun
	return b
}

// WithImage sets the curl-capable image
func (b *AgentPurgeCronJobBuilder) WithImage(image string) *AgentPurgeCronJobBuilder {
	if image != "" {
		b.image = image
	}
	return b
}

// WithCredentialSecret sets the API-credentials secret name
func (b *AgentPurgeCronJobBuilder) WithCredentialSecret(name string) *AgentPurgeCronJobBuilder {
	if name != "" {
		b.credentialSecret = name
	}
	return b
}

// WithVersion sets the Wazuh version for labels
func (b *AgentPurgeCronJobBuilder) WithVersion(version string) *AgentPurgeCronJobBuilder {
	if version != "" {
		b.version = version
	}
	return b
}

// WithLabels adds custom labels
func (b *AgentPurgeCronJobBuilder) WithLabels(labels map[string]string) *AgentPurgeCronJobBuilder {
	maps.Copy(b.labels, labels)
	return b
}

// buildLabels creates the standard labels for agent purge resources
func (b *AgentPurgeCronJobBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "agent-purge", b.version)
	labels["app.kubernetes.io/component"] = "agent-purge"
	maps.Copy(labels, b.labels)
	return labels
}

// resourceName returns the name for agent purge resources
func (b *AgentPurgeCronJobBuilder) resourceName() string {
	return fmt.Sprintf("%s-agent-purge", b.clusterName)
}

// masterServiceFQDN returns the FQDN of the manager master service
func (b *AgentPurgeCronJobBuilder) masterServiceFQDN() string {
	return dns.ServiceFQDN(b.clusterName+"-manager-master", b.namespace)
}

// buildScript builds the complete shell script for the CronJob.
// It authenticates against the Manager API, then either lists (dry-run) or
// deletes stale agents for each configured status. Self-signed TLS => curl -sk.
// Note: agent id 000 (the manager) is never matched by the status/older_than
// filters, so agents_list=all is safe.
func (b *AgentPurgeCronJobBuilder) buildScript() string {
	fqdn := b.masterServiceFQDN()
	statuses := strings.Join(b.statuses, " ")
	dryRun := "false"
	if b.dryRun {
		dryRun = "true"
	}

	script := fmt.Sprintf(`#!/bin/sh
set -eu

BASE="https://%s:%d"
echo "Starting agent purge for cluster %s"
echo "Statuses: %s"
echo "older_than: %dd"
echo "dry-run: %s"

TOKEN=$(curl -sk -u "$API_USER:$API_PASS" -X POST "$BASE/security/user/authenticate?raw=true")
if [ -z "$TOKEN" ]; then
    echo "Failed to authenticate against Wazuh Manager API"
    exit 1
fi

for ST in %s; do
    if [ "%s" = "true" ]; then
        echo "[dry-run] agents status=$ST older_than=%dd:"
        curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/agents?agents_list=all&status=$ST&older_than=%dd&select=id,name,lastKeepAlive&limit=500"
    else
        echo "deleting agents status=$ST older_than=%dd"
        curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/agents?agents_list=all&status=$ST&older_than=%dd"
    fi
    echo ""
done

echo "Agent purge completed"
`,
		fqdn,
		constants.PortManagerAPI,
		b.clusterName,
		statuses,
		b.disconnectedDays,
		dryRun,
		statuses,
		dryRun,
		b.disconnectedDays,
		b.disconnectedDays,
		b.disconnectedDays,
		b.disconnectedDays,
	)

	return script
}

// Build creates the CronJob resource
func (b *AgentPurgeCronJobBuilder) Build() *batchv1.CronJob {
	labels := b.buildLabels()
	name := b.resourceName()

	// Build the script
	script := b.buildScript()

	// Backoff limit
	backoffLimit := int32(3)

	// Success/Failure history limits
	successfulJobsHistoryLimit := int32(3)
	failedJobsHistoryLimit := int32(1)

	// TTL to clean up finished jobs
	ttlSecondsAfterFinished := int32(3600)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: b.namespace,
			Labels:    labels,
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   b.schedule,
			SuccessfulJobsHistoryLimit: &successfulJobsHistoryLimit,
			FailedJobsHistoryLimit:     &failedJobsHistoryLimit,
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: batchv1.JobSpec{
					BackoffLimit:            &backoffLimit,
					TTLSecondsAfterFinished: &ttlSecondsAfterFinished,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: labels,
						},
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:  "agent-purge",
									Image: b.image,
									Command: []string{
										"/bin/sh",
										"-c",
									},
									Args: []string{script},
									Env: []corev1.EnvVar{
										{
											Name: "API_USER",
											ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: b.credentialSecret,
													},
													Key: constants.SecretKeyAPIUsername,
												},
											},
										},
										{
											Name: "API_PASS",
											ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: b.credentialSecret,
													},
													Key: constants.SecretKeyAPIPassword,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// GetResourceNames returns the CronJob name for agent purge
func (b *AgentPurgeCronJobBuilder) GetResourceNames() (cronJobName string) {
	return b.resourceName()
}
