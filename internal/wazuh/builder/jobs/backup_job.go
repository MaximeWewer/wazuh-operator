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

// Package jobs provides Kubernetes Job and CronJob builders for Wazuh backup operations
package jobs

import (
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// BackupJobBuilder builds Job/CronJob resources for Wazuh Manager backups
type BackupJobBuilder struct {
	backup         *wazuhv1alpha1.WazuhBackup
	clusterName    string
	namespace      string
	managerPodName string
	labels         map[string]string
}

// NewBackupJobBuilder creates a new BackupJobBuilder
func NewBackupJobBuilder(backup *wazuhv1alpha1.WazuhBackup) *BackupJobBuilder {
	return &BackupJobBuilder{
		backup:      backup,
		clusterName: backup.Spec.ClusterRef.Name,
		namespace:   backup.Namespace,
		labels:      make(map[string]string),
	}
}

// WithManagerPodName sets the manager pod to backup from
func (b *BackupJobBuilder) WithManagerPodName(podName string) *BackupJobBuilder {
	b.managerPodName = podName
	return b
}

// WithLabels adds custom labels
func (b *BackupJobBuilder) WithLabels(labels map[string]string) *BackupJobBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// buildLabels creates the standard labels for backup resources
func (b *BackupJobBuilder) buildLabels() map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/name":       "wazuh-backup",
		"app.kubernetes.io/instance":   b.backup.Name,
		"app.kubernetes.io/component":  "backup",
		"app.kubernetes.io/managed-by": "wazuh-operator",
		"wazuh.com/backup":             b.backup.Name,
		"wazuh.com/cluster":            b.clusterName,
	}
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// resourceName returns the base name for backup resources
func (b *BackupJobBuilder) resourceName() string {
	return fmt.Sprintf("%s-backup", b.backup.Name)
}

// serviceAccountName returns the ServiceAccount name
func (b *BackupJobBuilder) serviceAccountName() string {
	return b.resourceName()
}

// buildBackupPaths returns the list of paths to backup based on components
func (b *BackupJobBuilder) buildBackupPaths() []string {
	var paths []string

	components := b.backup.Spec.Components

	if components.AgentKeys {
		paths = append(paths, constants.WazuhBackupPathAgentKeys)
	}
	if components.FIMDatabase {
		paths = append(paths, constants.WazuhBackupPathFIMDatabase)
	}
	if components.AgentDatabase {
		paths = append(paths, constants.WazuhBackupPathAgentDatabase)
	}
	if components.Integrations {
		paths = append(paths, constants.WazuhBackupPathIntegrations)
	}
	if components.AlertLogs {
		paths = append(paths, constants.WazuhBackupPathAlertLogs)
	}

	// Add custom paths
	paths = append(paths, components.CustomPaths...)

	return paths
}

// buildBackupScript builds the shell script for the backup job
func (b *BackupJobBuilder) buildBackupScript() string {
	paths := b.buildBackupPaths()
	storage := b.backup.Spec.Storage

	// Build tar include arguments
	var tarPaths []string
	for _, path := range paths {
		// Strip /var/ossec/ prefix for tar relative paths
		relPath := strings.TrimPrefix(path, "/var/ossec/")
		tarPaths = append(tarPaths, relPath)
	}

	// Build S3 endpoint options
	var s3EndpointOpts string
	if storage.Endpoint != "" {
		s3EndpointOpts = fmt.Sprintf("--endpoint-url %s", storage.Endpoint)
	}
	if storage.ForcePathStyle {
		s3EndpointOpts += " --no-verify-ssl"
	}

	// Build prefix with template substitution
	prefix := storage.Prefix
	if prefix == "" {
		prefix = "{{ .ClusterName }}/{{ .Namespace }}"
	}

	script := fmt.Sprintf(`#!/bin/sh
set -e

echo "========================================"
echo "Wazuh Backup Job"
echo "Cluster: %s"
echo "Namespace: %s"
echo "Backup Name: %s"
echo "Started at: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
echo "========================================"

# Variables
BACKUP_NAME="%s"
CLUSTER_NAME="%s"
NAMESPACE="%s"
TIMESTAMP=$(date -u +%%Y%%m%%d-%%H%%M%%S)
ARCHIVE_NAME="${BACKUP_NAME}-${TIMESTAMP}.tar.gz"
TEMP_DIR="/tmp/backup"
S3_BUCKET="%s"
S3_PREFIX="%s"
S3_REGION="%s"

# Resolve prefix template
S3_PREFIX=$(echo "$S3_PREFIX" | sed "s/{{ .ClusterName }}/${CLUSTER_NAME}/g" | sed "s/{{ .Namespace }}/${NAMESPACE}/g" | sed "s/{{ .Date }}/${TIMESTAMP}/g")

echo "Backup paths: %s"
echo "S3 bucket: ${S3_BUCKET}"
echo "S3 prefix: ${S3_PREFIX}"

# Create temp directory
mkdir -p ${TEMP_DIR}

# Get manager pod name (master or first manager)
MANAGER_POD=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/component=wazuh-manager,app.kubernetes.io/instance=${CLUSTER_NAME} -o jsonpath='{.items[0].metadata.name}')

if [ -z "$MANAGER_POD" ]; then
    echo "ERROR: No Wazuh Manager pod found"
    exit 1
fi

echo "Using manager pod: ${MANAGER_POD}"

# Create backup archive on the manager pod
echo "Creating backup archive on manager pod..."
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- sh -c "cd /var/ossec && tar -czf /tmp/${ARCHIVE_NAME} %s 2>/dev/null || true"

# Copy backup from pod to local temp
echo "Copying backup archive from pod..."
kubectl cp ${NAMESPACE}/${MANAGER_POD}:/tmp/${ARCHIVE_NAME} ${TEMP_DIR}/${ARCHIVE_NAME} -c wazuh-manager

# Get backup size
BACKUP_SIZE=$(ls -lh ${TEMP_DIR}/${ARCHIVE_NAME} | awk '{print $5}')
echo "Backup size: ${BACKUP_SIZE}"

# Upload to S3
echo "Uploading to S3..."
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}

aws s3 cp ${TEMP_DIR}/${ARCHIVE_NAME} s3://${S3_BUCKET}/${S3_PREFIX}/${ARCHIVE_NAME} %s --region ${S3_REGION}

# Verify upload
echo "Verifying upload..."
aws s3 ls s3://${S3_BUCKET}/${S3_PREFIX}/${ARCHIVE_NAME} %s --region ${S3_REGION}

# Cleanup temp archive on manager pod
echo "Cleaning up temporary files..."
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- rm -f /tmp/${ARCHIVE_NAME} || true

# Cleanup local temp
rm -rf ${TEMP_DIR}

echo "========================================"
echo "Backup completed successfully!"
echo "Location: s3://${S3_BUCKET}/${S3_PREFIX}/${ARCHIVE_NAME}"
echo "Size: ${BACKUP_SIZE}"
echo "Finished at: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
echo "========================================"
`,
		b.clusterName,
		b.namespace,
		b.backup.Name,
		b.backup.Name,
		b.clusterName,
		b.namespace,
		storage.Bucket,
		prefix,
		storage.Region,
		strings.Join(paths, ", "),
		strings.Join(tarPaths, " "),
		s3EndpointOpts,
		s3EndpointOpts,
	)

	return script
}

// getImage returns the backup container image
func (b *BackupJobBuilder) getImage() string {
	if b.backup.Spec.Image != nil && b.backup.Spec.Image.Repository != "" {
		repo := b.backup.Spec.Image.Repository
		tag := b.backup.Spec.Image.Tag
		if tag == "" {
			tag = "latest"
		}
		return fmt.Sprintf("%s:%s", repo, tag)
	}
	return constants.DefaultBackupImage
}

// getImagePullPolicy returns the image pull policy
func (b *BackupJobBuilder) getImagePullPolicy() corev1.PullPolicy {
	if b.backup.Spec.Image != nil && b.backup.Spec.Image.PullPolicy != "" {
		return b.backup.Spec.Image.PullPolicy
	}
	return corev1.PullIfNotPresent
}

// getResources returns resource requirements for the backup container
func (b *BackupJobBuilder) getResources() corev1.ResourceRequirements {
	if b.backup.Spec.Resources != nil {
		return *b.backup.Spec.Resources
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

// buildEnvVars returns environment variables for S3 credentials
func (b *BackupJobBuilder) buildEnvVars() []corev1.EnvVar {
	creds := b.backup.Spec.Storage.CredentialsSecret
	accessKeyKey := creds.AccessKeyKey
	secretKeyKey := creds.SecretKeyKey

	if accessKeyKey == "" {
		accessKeyKey = "accessKeyId"
	}
	if secretKeyKey == "" {
		secretKeyKey = "secretAccessKey"
	}

	return []corev1.EnvVar{
		{
			Name: "AWS_ACCESS_KEY_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: creds.Name,
					},
					Key: accessKeyKey,
				},
			},
		},
		{
			Name: "AWS_SECRET_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: creds.Name,
					},
					Key: secretKeyKey,
				},
			},
		},
	}
}

// BuildJob creates a one-shot Job for immediate backup
func (b *BackupJobBuilder) BuildJob() *batchv1.Job {
	labels := b.buildLabels()
	script := b.buildBackupScript()

	backoffLimit := int32(2)
	ttlSeconds := int32(86400) // 24 hours

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.resourceName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttlSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: b.serviceAccountName(),
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						{
							Name:            "backup",
							Image:           b.getImage(),
							ImagePullPolicy: b.getImagePullPolicy(),
							Command:         []string{"/bin/sh", "-c"},
							Args:            []string{script},
							Env:             b.buildEnvVars(),
							Resources:       b.getResources(),
						},
					},
				},
			},
		},
	}
}

// BuildCronJob creates a scheduled CronJob for periodic backups
func (b *BackupJobBuilder) BuildCronJob() *batchv1.CronJob {
	labels := b.buildLabels()
	script := b.buildBackupScript()

	backoffLimit := int32(2)
	successfulJobsHistoryLimit := int32(3)
	failedJobsHistoryLimit := int32(1)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.resourceName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
		Spec: batchv1.CronJobSpec{
			Schedule:                   b.backup.Spec.Schedule,
			Suspend:                    &b.backup.Spec.Suspend,
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
							ServiceAccountName: b.serviceAccountName(),
							RestartPolicy:      corev1.RestartPolicyOnFailure,
							Containers: []corev1.Container{
								{
									Name:            "backup",
									Image:           b.getImage(),
									ImagePullPolicy: b.getImagePullPolicy(),
									Command:         []string{"/bin/sh", "-c"},
									Args:            []string{script},
									Env:             b.buildEnvVars(),
									Resources:       b.getResources(),
								},
							},
						},
					},
				},
			},
		},
	}
}

// BuildServiceAccount creates the ServiceAccount for backup jobs
func (b *BackupJobBuilder) BuildServiceAccount() *corev1.ServiceAccount {
	labels := b.buildLabels()

	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.serviceAccountName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
	}
}

// BuildRole creates the Role for backup jobs (pods, pods/exec, pods/cp permissions)
func (b *BackupJobBuilder) BuildRole() *rbacv1.Role {
	labels := b.buildLabels()

	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.resourceName(),
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

// BuildRoleBinding creates the RoleBinding for backup jobs
func (b *BackupJobBuilder) BuildRoleBinding() *rbacv1.RoleBinding {
	labels := b.buildLabels()

	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.resourceName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     b.resourceName(),
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

// GetResourceNames returns all resource names for the backup
func (b *BackupJobBuilder) GetResourceNames() (jobOrCronJobName, saName, roleName, roleBindingName string) {
	name := b.resourceName()
	return name, b.serviceAccountName(), name, name
}
