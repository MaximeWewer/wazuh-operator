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

// RestoreJobBuilder builds Job resources for Wazuh Manager restore operations
type RestoreJobBuilder struct {
	restore     *wazuhv1alpha1.WazuhRestore
	clusterName string
	namespace   string
	labels      map[string]string
}

// NewRestoreJobBuilder creates a new RestoreJobBuilder
func NewRestoreJobBuilder(restore *wazuhv1alpha1.WazuhRestore) *RestoreJobBuilder {
	return &RestoreJobBuilder{
		restore:     restore,
		clusterName: restore.Spec.ClusterRef.Name,
		namespace:   restore.Namespace,
		labels:      make(map[string]string),
	}
}

// WithLabels adds custom labels
func (b *RestoreJobBuilder) WithLabels(labels map[string]string) *RestoreJobBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// buildLabels creates the standard labels for restore resources
func (b *RestoreJobBuilder) buildLabels() map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/name":       "wazuh-restore",
		"app.kubernetes.io/instance":   b.restore.Name,
		"app.kubernetes.io/component":  "restore",
		"app.kubernetes.io/managed-by": "wazuh-operator",
		"wazuh.com/restore":            b.restore.Name,
		"wazuh.com/cluster":            b.clusterName,
	}
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// resourceName returns the base name for restore resources
func (b *RestoreJobBuilder) resourceName() string {
	return fmt.Sprintf("%s-restore", b.restore.Name)
}

// serviceAccountName returns the ServiceAccount name
func (b *RestoreJobBuilder) serviceAccountName() string {
	return b.resourceName()
}

// buildRestorePaths returns the list of paths to restore based on components
func (b *RestoreJobBuilder) buildRestorePaths() []string {
	var paths []string

	// Default to all components if not specified
	components := b.restore.Spec.Components
	if components == nil {
		components = &wazuhv1alpha1.RestoreComponents{
			AgentKeys:     true,
			FIMDatabase:   true,
			AgentDatabase: true,
		}
	}

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

	paths = append(paths, components.CustomPaths...)

	return paths
}

// getS3Source returns the S3 source configuration
func (b *RestoreJobBuilder) getS3Source() *wazuhv1alpha1.S3RestoreSource {
	return b.restore.Spec.Source.S3
}

// buildRestoreScript builds the shell script for the restore job
func (b *RestoreJobBuilder) buildRestoreScript() string {
	s3 := b.getS3Source()
	if s3 == nil {
		return "echo 'ERROR: No S3 source configured'; exit 1"
	}

	paths := b.buildRestorePaths()

	// Build S3 endpoint options
	var s3EndpointOpts string
	if s3.Endpoint != "" {
		s3EndpointOpts = fmt.Sprintf("--endpoint-url %s", s3.Endpoint)
	}
	if s3.ForcePathStyle {
		s3EndpointOpts += " --no-verify-ssl"
	}

	// Build tar extract paths for filtering
	var tarPaths []string
	for _, path := range paths {
		relPath := strings.TrimPrefix(path, "/var/ossec/")
		tarPaths = append(tarPaths, relPath)
	}

	preRestoreBackup := "false"
	if b.restore.Spec.PreRestoreBackup {
		preRestoreBackup = "true"
	}

	stopManager := "false"
	if b.restore.Spec.StopManager {
		stopManager = "true"
	}

	restartAfterRestore := "false"
	if b.restore.Spec.RestartAfterRestore {
		restartAfterRestore = "true"
	}

	script := fmt.Sprintf(`#!/bin/sh
set -e

echo "========================================"
echo "Wazuh Restore Job"
echo "Cluster: %s"
echo "Namespace: %s"
echo "Restore Name: %s"
echo "Started at: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
echo "========================================"

# Variables
RESTORE_NAME="%s"
CLUSTER_NAME="%s"
NAMESPACE="%s"
S3_BUCKET="%s"
S3_KEY="%s"
S3_REGION="%s"
PRE_RESTORE_BACKUP="%s"
STOP_MANAGER="%s"
RESTART_AFTER_RESTORE="%s"
TEMP_DIR="/tmp/restore"

echo "Source: s3://${S3_BUCKET}/${S3_KEY}"
echo "Restore paths: %s"
echo "Pre-restore backup: ${PRE_RESTORE_BACKUP}"
echo "Stop manager: ${STOP_MANAGER}"
echo "Restart after: ${RESTART_AFTER_RESTORE}"

# Get manager pod name (master or first manager)
MANAGER_POD=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/component=wazuh-manager,app.kubernetes.io/instance=${CLUSTER_NAME} -o jsonpath='{.items[0].metadata.name}')

if [ -z "$MANAGER_POD" ]; then
    echo "ERROR: No Wazuh Manager pod found"
    exit 1
fi

echo "Using manager pod: ${MANAGER_POD}"

# Create temp directory
mkdir -p ${TEMP_DIR}

# Download backup archive from S3
echo "Downloading backup from S3..."
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}

ARCHIVE_NAME=$(basename ${S3_KEY})
aws s3 cp s3://${S3_BUCKET}/${S3_KEY} ${TEMP_DIR}/${ARCHIVE_NAME} %s --region ${S3_REGION}

echo "Downloaded: ${ARCHIVE_NAME}"
ls -lh ${TEMP_DIR}/${ARCHIVE_NAME}

# Stop manager if requested
if [ "${STOP_MANAGER}" = "true" ]; then
    echo "Stopping Wazuh Manager service..."
    kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- /var/ossec/bin/wazuh-control stop || echo "Warning: Could not stop wazuh-control"
    sleep 5
fi

# Create pre-restore backup if requested
if [ "${PRE_RESTORE_BACKUP}" = "true" ]; then
    echo "Creating pre-restore backup..."
    PRE_RESTORE_ARCHIVE="pre-restore-$(date -u +%%Y%%m%%d-%%H%%M%%S).tar.gz"
    kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- sh -c "cd /var/ossec && tar -czf /tmp/${PRE_RESTORE_ARCHIVE} %s 2>/dev/null || true"

    # Upload pre-restore backup
    PRE_RESTORE_KEY=$(dirname ${S3_KEY})/pre-restore/${PRE_RESTORE_ARCHIVE}
    kubectl cp ${NAMESPACE}/${MANAGER_POD}:/tmp/${PRE_RESTORE_ARCHIVE} ${TEMP_DIR}/${PRE_RESTORE_ARCHIVE} -c wazuh-manager
    aws s3 cp ${TEMP_DIR}/${PRE_RESTORE_ARCHIVE} s3://${S3_BUCKET}/${PRE_RESTORE_KEY} %s --region ${S3_REGION}

    echo "Pre-restore backup saved to: s3://${S3_BUCKET}/${PRE_RESTORE_KEY}"
    kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- rm -f /tmp/${PRE_RESTORE_ARCHIVE} || true
fi

# Copy archive to manager pod
echo "Copying backup archive to manager pod..."
kubectl cp ${TEMP_DIR}/${ARCHIVE_NAME} ${NAMESPACE}/${MANAGER_POD}:/tmp/${ARCHIVE_NAME} -c wazuh-manager

# Extract backup archive
echo "Extracting backup archive..."
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- sh -c "cd /var/ossec && tar -xzf /tmp/${ARCHIVE_NAME} %s 2>/dev/null || true"

# Fix permissions
echo "Fixing permissions..."
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- chown -R wazuh:wazuh /var/ossec/etc/ 2>/dev/null || true
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- chown -R wazuh:wazuh /var/ossec/queue/ 2>/dev/null || true

# Cleanup
echo "Cleaning up temporary files..."
kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- rm -f /tmp/${ARCHIVE_NAME} || true
rm -rf ${TEMP_DIR}

# Restart manager if requested
if [ "${RESTART_AFTER_RESTORE}" = "true" ]; then
    echo "Starting Wazuh Manager service..."
    kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- /var/ossec/bin/wazuh-control start || echo "Warning: Could not start wazuh-control"
    sleep 5

    # Check if service is running
    kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -c wazuh-manager -- /var/ossec/bin/wazuh-control status || echo "Warning: Service status check failed"
fi

echo "========================================"
echo "Restore completed successfully!"
echo "Source: s3://${S3_BUCKET}/${S3_KEY}"
echo "Restored to: ${MANAGER_POD}"
echo "Finished at: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"
echo "========================================"
`,
		b.clusterName,
		b.namespace,
		b.restore.Name,
		b.restore.Name,
		b.clusterName,
		b.namespace,
		s3.Bucket,
		s3.Key,
		s3.Region,
		preRestoreBackup,
		stopManager,
		restartAfterRestore,
		strings.Join(paths, ", "),
		s3EndpointOpts,
		strings.Join(tarPaths, " "),
		s3EndpointOpts,
		strings.Join(tarPaths, " "),
	)

	return script
}

// getImage returns the restore container image
func (b *RestoreJobBuilder) getImage() string {
	if b.restore.Spec.Image != nil && b.restore.Spec.Image.Repository != "" {
		repo := b.restore.Spec.Image.Repository
		tag := b.restore.Spec.Image.Tag
		if tag == "" {
			tag = "latest"
		}
		return fmt.Sprintf("%s:%s", repo, tag)
	}
	return constants.DefaultBackupImage
}

// getImagePullPolicy returns the image pull policy
func (b *RestoreJobBuilder) getImagePullPolicy() corev1.PullPolicy {
	if b.restore.Spec.Image != nil && b.restore.Spec.Image.PullPolicy != "" {
		return b.restore.Spec.Image.PullPolicy
	}
	return corev1.PullIfNotPresent
}

// getResources returns resource requirements for the restore container
func (b *RestoreJobBuilder) getResources() corev1.ResourceRequirements {
	if b.restore.Spec.Resources != nil {
		return *b.restore.Spec.Resources
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
func (b *RestoreJobBuilder) buildEnvVars() []corev1.EnvVar {
	s3 := b.getS3Source()
	if s3 == nil {
		return nil
	}

	creds := s3.CredentialsSecret
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

// BuildJob creates the restore Job
func (b *RestoreJobBuilder) BuildJob() *batchv1.Job {
	labels := b.buildLabels()
	script := b.buildRestoreScript()

	backoffLimit := int32(1) // Restore should not retry automatically
	ttlSeconds := int32(86400)

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
					RestartPolicy:      corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:            "restore",
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

// BuildServiceAccount creates the ServiceAccount for restore jobs
func (b *RestoreJobBuilder) BuildServiceAccount() *corev1.ServiceAccount {
	labels := b.buildLabels()

	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.serviceAccountName(),
			Namespace: b.namespace,
			Labels:    labels,
		},
	}
}

// BuildRole creates the Role for restore jobs
func (b *RestoreJobBuilder) BuildRole() *rbacv1.Role {
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

// BuildRoleBinding creates the RoleBinding for restore jobs
func (b *RestoreJobBuilder) BuildRoleBinding() *rbacv1.RoleBinding {
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

// GetResourceNames returns all resource names for the restore
func (b *RestoreJobBuilder) GetResourceNames() (jobName, saName, roleName, roleBindingName string) {
	name := b.resourceName()
	return name, b.serviceAccountName(), name, name
}
