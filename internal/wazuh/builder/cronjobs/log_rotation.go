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

// Package cronjobs provides Kubernetes CronJob builders for Wazuh components
package cronjobs

import (
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// LogRotationCronJobBuilder builds CronJob resources for log rotation
type LogRotationCronJobBuilder struct {
	clusterName     string
	namespace       string
	schedule        string
	retentionDays   int32
	maxFileSizeMB   int32
	combinationMode string
	paths           []string
	image           string
	labels          map[string]string
	version         string
}

// NewLogRotationCronJobBuilder creates a new LogRotationCronJobBuilder with defaults
func NewLogRotationCronJobBuilder(clusterName, namespace string) *LogRotationCronJobBuilder {
	return &LogRotationCronJobBuilder{
		clusterName:     clusterName,
		namespace:       namespace,
		schedule:        constants.DefaultLogRotationSchedule,
		retentionDays:   constants.DefaultLogRotationRetentionDays,
		maxFileSizeMB:   0, // Disabled by default
		combinationMode: constants.DefaultLogRotationCombinationMode,
		paths:           constants.DefaultLogRotationPaths,
		image:           constants.DefaultLogRotationImage,
		labels:          make(map[string]string),
		version:         constants.DefaultWazuhVersion,
	}
}

// WithSchedule sets the cron schedule
func (b *LogRotationCronJobBuilder) WithSchedule(schedule string) *LogRotationCronJobBuilder {
	if schedule != "" {
		b.schedule = schedule
	}
	return b
}

// WithRetentionDays sets the retention days
func (b *LogRotationCronJobBuilder) WithRetentionDays(days int32) *LogRotationCronJobBuilder {
	if days > 0 {
		b.retentionDays = days
	}
	return b
}

// WithMaxFileSizeMB sets the max file size in MB
func (b *LogRotationCronJobBuilder) WithMaxFileSizeMB(sizeMB int32) *LogRotationCronJobBuilder {
	b.maxFileSizeMB = sizeMB
	return b
}

// WithCombinationMode sets the combination mode (or/and)
func (b *LogRotationCronJobBuilder) WithCombinationMode(mode string) *LogRotationCronJobBuilder {
	if mode == "or" || mode == "and" {
		b.combinationMode = mode
	}
	return b
}

// WithPaths sets the paths to clean
func (b *LogRotationCronJobBuilder) WithPaths(paths []string) *LogRotationCronJobBuilder {
	if len(paths) > 0 {
		b.paths = paths
	}
	return b
}

// WithImage sets the kubectl image
func (b *LogRotationCronJobBuilder) WithImage(image string) *LogRotationCronJobBuilder {
	if image != "" {
		b.image = image
	}
	return b
}

// WithVersion sets the Wazuh version for labels
func (b *LogRotationCronJobBuilder) WithVersion(version string) *LogRotationCronJobBuilder {
	if version != "" {
		b.version = version
	}
	return b
}

// WithLabels adds custom labels
func (b *LogRotationCronJobBuilder) WithLabels(labels map[string]string) *LogRotationCronJobBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// buildLabels creates the standard labels for log rotation resources
func (b *LogRotationCronJobBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "log-rotation", b.version)
	labels["app.kubernetes.io/component"] = "log-rotation"
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// resourceName returns the name for log rotation resources
func (b *LogRotationCronJobBuilder) resourceName() string {
	return fmt.Sprintf("%s-log-rotation", b.clusterName)
}

// buildFindCommand builds the find command for log rotation
func (b *LogRotationCronJobBuilder) buildFindCommand() string {
	var commands []string

	for _, path := range b.paths {
		var findCmd string

		// Ensure path ends with /
		cleanPath := strings.TrimSuffix(path, "/") + "/"

		if b.maxFileSizeMB > 0 {
			// Both age and size filters
			if b.combinationMode == "and" {
				// AND logic: delete only if old AND large
				findCmd = fmt.Sprintf("find %s -type f -mtime +%d -size +%dM -delete 2>/dev/null || true",
					cleanPath, b.retentionDays, b.maxFileSizeMB)
			} else {
				// OR logic: delete if old OR large
				findCmd = fmt.Sprintf("find %s -type f \\( -mtime +%d -o -size +%dM \\) -delete 2>/dev/null || true",
					cleanPath, b.retentionDays, b.maxFileSizeMB)
			}
		} else {
			// Age-based only
			findCmd = fmt.Sprintf("find %s -type f -mtime +%d -delete 2>/dev/null || true",
				cleanPath, b.retentionDays)
		}

		commands = append(commands, findCmd)
	}

	return strings.Join(commands, "; ")
}

// buildScript builds the complete shell script for the CronJob
func (b *LogRotationCronJobBuilder) buildScript() string {
	findCommand := b.buildFindCommand()

	script := fmt.Sprintf(`#!/bin/sh
set -e

echo "Starting log rotation for cluster %s"
echo "Schedule: %s"
echo "Retention: %d days"
echo "Max file size: %d MB"
echo "Combination mode: %s"
echo "Paths: %s"

# Get all Wazuh Manager pods
MANAGER_PODS=$(kubectl get pods -n %s -l app.kubernetes.io/component=wazuh-manager,app.kubernetes.io/instance=%s -o jsonpath='{.items[*].metadata.name}')

if [ -z "$MANAGER_PODS" ]; then
    echo "No Wazuh Manager pods found"
    exit 0
fi

for POD in $MANAGER_PODS; do
    echo "Cleaning logs on pod: $POD"
    kubectl exec -n %s $POD -c wazuh-manager -- sh -c '%s' || echo "Warning: Failed to clean logs on $POD"
done

echo "Log rotation completed"
`,
		b.clusterName,
		b.schedule,
		b.retentionDays,
		b.maxFileSizeMB,
		b.combinationMode,
		strings.Join(b.paths, ", "),
		b.namespace,
		b.clusterName,
		b.namespace,
		findCommand,
	)

	return script
}

// Build creates the CronJob resource
func (b *LogRotationCronJobBuilder) Build() *batchv1.CronJob {
	labels := b.buildLabels()
	name := b.resourceName()
	saName := b.serviceAccountName()

	// Build the script
	script := b.buildScript()

	// Backoff limit
	backoffLimit := int32(3)

	// Success/Failure history limits
	successfulJobsHistoryLimit := int32(3)
	failedJobsHistoryLimit := int32(1)

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
					BackoffLimit: &backoffLimit,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: labels,
						},
						Spec: corev1.PodSpec{
							ServiceAccountName: saName,
							RestartPolicy:      corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:  "log-rotation",
									Image: b.image,
									Command: []string{
										"/bin/sh",
										"-c",
									},
									Args: []string{script},
								},
							},
						},
					},
				},
			},
		},
	}
}

// serviceAccountName returns the ServiceAccount name
func (b *LogRotationCronJobBuilder) serviceAccountName() string {
	return b.resourceName()
}

// roleName returns the Role name
func (b *LogRotationCronJobBuilder) roleName() string {
	return b.resourceName()
}

// roleBindingName returns the RoleBinding name
func (b *LogRotationCronJobBuilder) roleBindingName() string {
	return b.resourceName()
}

// BuildServiceAccount creates the ServiceAccount for log rotation
func (b *LogRotationCronJobBuilder) BuildServiceAccount() *corev1.ServiceAccount {
	labels := b.buildLabels()

	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.serviceAccountName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
	}
}

// BuildRole creates the Role for log rotation (pods, pods/exec permissions)
func (b *LogRotationCronJobBuilder) BuildRole() *rbacv1.Role {
	labels := b.buildLabels()

	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.roleName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// BuildRoleBinding creates the RoleBinding for log rotation
func (b *LogRotationCronJobBuilder) BuildRoleBinding() *rbacv1.RoleBinding {
	labels := b.buildLabels()

	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.roleBindingName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     b.roleName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      b.serviceAccountName(),
				Namespace: b.namespace,
			},
		},
	}
}

// GetResourceNames returns all resource names for log rotation
func (b *LogRotationCronJobBuilder) GetResourceNames() (cronJobName, saName, roleName, roleBindingName string) {
	return b.resourceName(), b.serviceAccountName(), b.roleName(), b.roleBindingName()
}
