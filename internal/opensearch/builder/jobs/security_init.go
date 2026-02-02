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

// Package jobs provides Kubernetes Job builders for OpenSearch operations
package jobs

import (
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// SecurityInitJobBuilder builds a Job that initializes/updates OpenSearch security configuration
type SecurityInitJobBuilder struct {
	clusterName     string
	namespace       string
	indexerService  string
	adminSecretName string
	credSecretName  string
	ownerReferences []metav1.OwnerReference
	configHash      string
}

// NewSecurityInitJobBuilder creates a new SecurityInitJobBuilder
func NewSecurityInitJobBuilder(clusterName, namespace string) *SecurityInitJobBuilder {
	return &SecurityInitJobBuilder{
		clusterName:     clusterName,
		namespace:       namespace,
		indexerService:  fmt.Sprintf("%s-indexer", clusterName),
		adminSecretName: fmt.Sprintf("%s-admin-certs", clusterName),
		credSecretName:  fmt.Sprintf("%s-indexer-credentials", clusterName),
	}
}

// WithOwnerReference sets the owner reference for garbage collection
func (b *SecurityInitJobBuilder) WithOwnerReference(ownerRef metav1.OwnerReference) *SecurityInitJobBuilder {
	b.ownerReferences = append(b.ownerReferences, ownerRef)
	return b
}

// WithConfigHash sets a config hash to trigger job recreation on config changes
func (b *SecurityInitJobBuilder) WithConfigHash(hash string) *SecurityInitJobBuilder {
	b.configHash = hash
	return b
}

// WithCredentialsSecret sets the credentials secret name
func (b *SecurityInitJobBuilder) WithCredentialsSecret(secretName string) *SecurityInitJobBuilder {
	if secretName != "" {
		b.credSecretName = secretName
	}
	return b
}

// Build creates the security initialization Job
func (b *SecurityInitJobBuilder) Build() *batchv1.Job {
	jobName := fmt.Sprintf("%s-security-init", b.clusterName)

	// Use hash in job name to trigger recreation on config changes
	if b.configHash != "" {
		// Use first 8 chars of hash for job name suffix
		hashSuffix := b.configHash
		if len(hashSuffix) > 8 {
			hashSuffix = hashSuffix[:8]
		}
		jobName = fmt.Sprintf("%s-security-init-%s", b.clusterName, hashSuffix)
	}

	labels := map[string]string{
		constants.LabelName:      "security-init",
		constants.LabelInstance:  b.clusterName,
		constants.LabelComponent: "security",
		constants.LabelPartOf:    constants.AppName,
		constants.LabelManagedBy: constants.OperatorName,
	}

	backoffLimit := int32(3)
	ttlSeconds := int32(300) // Clean up completed jobs after 5 minutes

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:            jobName,
			Namespace:       b.namespace,
			Labels:          labels,
			OwnerReferences: b.ownerReferences,
			Annotations: map[string]string{
				constants.AnnotationConfigHash: b.configHash,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttlSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						b.buildSecurityInitContainer(),
					},
					Volumes: b.buildVolumes(),
				},
			},
		},
	}
}

// buildSecurityInitContainer builds the container that updates security configuration
func (b *SecurityInitJobBuilder) buildSecurityInitContainer() corev1.Container {
	indexerURL := fmt.Sprintf("https://%s:9200", dns.ServiceFQDN(b.indexerService, b.namespace))

	// Script that updates internal users via REST API
	// Uses admin certificate authentication with proper TLS verification
	script := fmt.Sprintf(`#!/bin/sh
set -e

echo "Waiting for OpenSearch to be ready..."
INDEXER_URL="%s"
MAX_RETRIES=60
RETRY_INTERVAL=5

# Read password from mounted secret for fallback auth
ADMIN_PASSWORD=$(cat /credentials/admin-password)
if [ -z "$ADMIN_PASSWORD" ]; then
    echo "ERROR: admin-password not found in credentials secret"
    exit 1
fi

# Try cert-based auth first, then fall back to password auth
do_curl() {
    # First try with certificate authentication (mTLS)
    RESULT=$(curl -sk --cert /certs/tls.crt --key /certs/tls.key --cacert /certs/ca.crt "$@" 2>&1)
    if [ $? -eq 0 ] && echo "$RESULT" | grep -qv "Unauthorized"; then
        echo "$RESULT"
        return 0
    fi

    # Fall back to password authentication
    RESULT=$(curl -sk -u "admin:${ADMIN_PASSWORD}" "$@" 2>&1)
    echo "$RESULT"
    return $?
}

# Wait for OpenSearch to be available
for i in $(seq 1 $MAX_RETRIES); do
    if do_curl "${INDEXER_URL}/_cluster/health" > /dev/null 2>&1; then
        echo "OpenSearch is available"
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        echo "ERROR: OpenSearch not available after $MAX_RETRIES attempts"
        exit 1
    fi
    echo "Waiting for OpenSearch... ($i/$MAX_RETRIES)"
    sleep $RETRY_INTERVAL
done

echo "Updating admin user..."
RESPONSE=$(do_curl -X PUT \
    -H "Content-Type: application/json" \
    "${INDEXER_URL}/_plugins/_security/api/internalusers/admin" \
    -d "{\"password\":\"${ADMIN_PASSWORD}\",\"backend_roles\":[\"admin\"],\"description\":\"Admin user\"}")

if echo "$RESPONSE" | grep -q '"status":"OK"'; then
    echo "Admin user updated successfully"
elif echo "$RESPONSE" | grep -q '"status":"CREATED"'; then
    echo "Admin user created successfully"
else
    echo "Response: $RESPONSE"
    # Don't fail if user already exists with same config
    if ! echo "$RESPONSE" | grep -q "already exists"; then
        echo "WARNING: Unexpected response when updating admin user"
    fi
fi

echo "Updating kibanaserver user..."
RESPONSE=$(do_curl -X PUT \
    -H "Content-Type: application/json" \
    "${INDEXER_URL}/_plugins/_security/api/internalusers/kibanaserver" \
    -d "{\"password\":\"${ADMIN_PASSWORD}\",\"description\":\"Kibana server user\"}")

if echo "$RESPONSE" | grep -q '"status":"OK"'; then
    echo "Kibanaserver user updated successfully"
elif echo "$RESPONSE" | grep -q '"status":"CREATED"'; then
    echo "Kibanaserver user created successfully"
else
    echo "Response: $RESPONSE"
    if ! echo "$RESPONSE" | grep -q "already exists"; then
        echo "WARNING: Unexpected response when updating kibanaserver user"
    fi
fi

echo "Security initialization complete"
`, indexerURL)

	return corev1.Container{
		Name:  "security-init",
		Image: "curlimages/curl:latest",
		Command: []string{
			"/bin/sh",
			"-c",
			script,
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "admin-certs",
				MountPath: "/certs",
				ReadOnly:  true,
			},
			{
				Name:      "credentials",
				MountPath: "/credentials",
				ReadOnly:  true,
			},
		},
	}
}

// buildVolumes builds the volumes for the job
func (b *SecurityInitJobBuilder) buildVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "admin-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: b.adminSecretName,
				},
			},
		},
		{
			Name: "credentials",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: b.credSecretName,
				},
			},
		},
	}
}

// GetJobName returns the job name for a given cluster and config hash
func GetJobName(clusterName, configHash string) string {
	if configHash != "" {
		hashSuffix := configHash
		if len(hashSuffix) > 8 {
			hashSuffix = hashSuffix[:8]
		}
		return fmt.Sprintf("%s-security-init-%s", clusterName, hashSuffix)
	}
	return fmt.Sprintf("%s-security-init", clusterName)
}
