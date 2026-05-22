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

package security

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// SecurityAdminExecutor executes securityadmin.sh on indexer pods to apply security configuration
type SecurityAdminExecutor struct {
	k8sClient  client.Client
	restConfig *rest.Config
	clientset  kubernetes.Interface
}

// NewSecurityAdminExecutor creates a new SecurityAdminExecutor
func NewSecurityAdminExecutor(k8sClient client.Client, restConfig *rest.Config, clientset kubernetes.Interface) *SecurityAdminExecutor {
	return &SecurityAdminExecutor{
		k8sClient:  k8sClient,
		restConfig: restConfig,
		clientset:  clientset,
	}
}

// ApplySecurityConfig runs securityadmin.sh on the first indexer pod to push the
// authentication configuration (config.yml) into the .opendistro_security index.
//
// securityConfigYML must be the freshly rendered config.yml content. It is pushed
// inline (written to a temp file in the pod) rather than read from the mounted
// config.yml: that file is mounted from a Secret via subPath, and subPath Secret
// mounts are NOT refreshed by Kubernetes after pod creation. A long-running indexer
// pod therefore still sees the original config.yml, so applying the mounted file
// would silently push stale auth domains. ApplyInternalUsers pushes inline for the
// same reason.
func (e *SecurityAdminExecutor) ApplySecurityConfig(ctx context.Context, clusterName, namespace, securityConfigYML string) error {
	log := logf.FromContext(ctx).WithValues("cluster", clusterName, "namespace", namespace)

	if securityConfigYML == "" {
		return fmt.Errorf("empty security config content for cluster %s/%s", namespace, clusterName)
	}

	// Target the first indexer pod
	podName := fmt.Sprintf("%s-indexer-0", clusterName)

	// Verify pod exists and is running
	pod := &corev1.Pod{}
	if err := e.k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, pod); err != nil {
		return fmt.Errorf("failed to get indexer pod %s: %w", podName, err)
	}

	if pod.Status.Phase != corev1.PodRunning {
		return fmt.Errorf("indexer pod %s is not running (phase: %s)", podName, pod.Status.Phase)
	}

	// Build the securityadmin.sh command (pushes the rendered config inline)
	cmd := buildInlineSecurityConfigCommand(securityConfigYML)

	log.Info("Executing securityadmin.sh", "pod", podName)

	// Execute the command
	stdout, stderr, err := e.execInPod(ctx, namespace, podName, cmd)
	if err != nil {
		log.Error(err, "securityadmin.sh execution failed",
			"stdout", stdout,
			"stderr", stderr)
		return fmt.Errorf("securityadmin.sh failed: %w (stderr: %s)", err, stderr)
	}

	log.Info("securityadmin.sh executed successfully",
		"pod", podName,
		"stdout", stdout)

	return nil
}

// ApplyInternalUsers runs securityadmin.sh on the first indexer pod to push internal_users.yml
// into the OpenSearch security index. This is used to recover from credential mismatches
// when PVCs survive CR deletion but credential secrets are regenerated.
func (e *SecurityAdminExecutor) ApplyInternalUsers(ctx context.Context, clusterName, namespace, wazuhVersion, expectedInternalUsers string) error {
	log := logf.FromContext(ctx).WithValues("cluster", clusterName, "namespace", namespace)

	// Target the first indexer pod
	podName := fmt.Sprintf("%s-indexer-0", clusterName)

	// Verify pod exists and is running
	pod := &corev1.Pod{}
	if err := e.k8sClient.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, pod); err != nil {
		return fmt.Errorf("failed to get indexer pod %s: %w", podName, err)
	}

	if pod.Status.Phase != corev1.PodRunning {
		return fmt.Errorf("indexer pod %s is not running (phase: %s)", podName, pod.Status.Phase)
	}

	// Build the securityadmin.sh command targeting internal_users.yml.
	// Prefer pushing inline content from the Secret to avoid stale subPath mounts.
	var cmd []string
	if expectedInternalUsers != "" {
		cmd = buildInlineInternalUsersCommand(wazuhVersion, expectedInternalUsers)
	} else {
		cmd = buildInternalUsersCommand(wazuhVersion)
	}

	log.Info("Executing securityadmin.sh to push internal_users.yml", "pod", podName)

	// Execute the command
	stdout, stderr, err := e.execInPod(ctx, namespace, podName, cmd)
	if err != nil {
		log.Error(err, "securityadmin.sh internal_users push failed",
			"stdout", stdout,
			"stderr", stderr)
		return fmt.Errorf("securityadmin.sh failed: %w (stderr: %s)", err, stderr)
	}

	log.Info("securityadmin.sh internal_users push succeeded",
		"pod", podName,
		"stdout", stdout)

	return nil
}

// buildInlineSecurityConfigCommand writes the rendered config.yml to a temp file in the
// pod, then applies it with "securityadmin.sh -t config". Pushing inline (rather than the
// mounted config.yml) avoids stale Secret subPath mounts.
//
// Two details that previously broke the on-disk variant of this call:
//   - securityadmin.sh requires "-t config" alongside "-f"; without the type it refuses
//     the single-file upload.
//   - "-cacert" must point at a CA that signed the node's REST cert. The admin certs
//     directory always ships its own ca.crt (same root CA as the node certs) and lives at
//     a fixed, version-independent path, keeping -cacert/-cert/-key consistent.
//
// Uses bash -c with OPENSEARCH_JAVA_HOME since the container may not have 'which'.
func buildInlineSecurityConfigCommand(securityConfigYML string) []string {
	encoded := base64.StdEncoding.EncodeToString([]byte(securityConfigYML))
	return []string{
		"bash", "-c",
		fmt.Sprintf("echo '%s' | base64 -d > /tmp/config.yml; "+
			"OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk "+
			"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh "+
			"-f /tmp/config.yml "+
			"-t config "+
			"-icl -nhnv "+
			"-cacert %s/ca.crt "+
			"-cert %s/tls.crt "+
			"-key %s/tls.key",
			encoded,
			constants.PathIndexerAdminCerts, constants.PathIndexerAdminCerts, constants.PathIndexerAdminCerts),
	}
}

// buildInternalUsersCommand constructs the securityadmin.sh command for pushing internal_users.yml
// Uses bash -c with OPENSEARCH_JAVA_HOME since the container may not have 'which'
func buildInternalUsersCommand(wazuhVersion string) []string {
	preferredConfigDir := constants.IndexerSecurityConfigDir(wazuhVersion)
	fallbackConfigDir := constants.PathIndexerLegacySecurityConfig
	if preferredConfigDir == constants.PathIndexerLegacySecurityConfig {
		fallbackConfigDir = constants.PathIndexerSecurityConfig
	}

	preferredInternalUsers := preferredConfigDir + "/internal_users.yml"
	fallbackInternalUsers := fallbackConfigDir + "/internal_users.yml"
	certsDir := constants.IndexerCertsDir(wazuhVersion)

	return []string{
		"bash", "-c",
		fmt.Sprintf("INTERNAL_USERS_FILE=%s; "+
			"if [ ! -f \"$INTERNAL_USERS_FILE\" ] && [ -f %s ]; then INTERNAL_USERS_FILE=%s; fi; "+
			"if [ ! -f \"$INTERNAL_USERS_FILE\" ]; then "+
			"echo \"ERR: internal_users.yml not found at %s or %s\"; "+
			"exit 1; "+
			"fi; "+
			"OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk "+
			"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh "+
			"-f \"$INTERNAL_USERS_FILE\" "+
			"-t internalusers "+
			"-icl -nhnv "+
			"-cacert %s/ca.crt "+
			"-cert %s/tls.crt "+
			"-key %s/tls.key",
			preferredInternalUsers, fallbackInternalUsers, fallbackInternalUsers,
			preferredInternalUsers, fallbackInternalUsers,
			certsDir, constants.PathIndexerAdminCerts, constants.PathIndexerAdminCerts),
	}
}

// buildInlineInternalUsersCommand pushes internal_users content directly to a temp file in the pod,
// then applies it with securityadmin.sh. This avoids stale Secret subPath mounts.
func buildInlineInternalUsersCommand(wazuhVersion, internalUsers string) []string {
	encoded := base64.StdEncoding.EncodeToString([]byte(internalUsers))
	certsDir := constants.IndexerCertsDir(wazuhVersion)
	return []string{
		"bash", "-c",
		fmt.Sprintf("echo '%s' | base64 -d > /tmp/internal_users.yml; "+
			"OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk "+
			"/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh "+
			"-f /tmp/internal_users.yml "+
			"-t internalusers "+
			"-icl -nhnv "+
			"-cacert %s/ca.crt "+
			"-cert %s/tls.crt "+
			"-key %s/tls.key",
			encoded,
			certsDir, constants.PathIndexerAdminCerts, constants.PathIndexerAdminCerts),
	}
}

// execInPod executes a command in a pod and returns stdout, stderr, and error
func (e *SecurityAdminExecutor) execInPod(ctx context.Context, namespace, podName string, cmd []string) (string, string, error) {
	req := e.clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "opensearch",
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(e.restConfig, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("failed to create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	return stdout.String(), stderr.String(), err
}
