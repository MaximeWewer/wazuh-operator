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

// ApplySecurityConfig runs securityadmin.sh on the first indexer pod to push security config to OpenSearch
func (e *SecurityAdminExecutor) ApplySecurityConfig(ctx context.Context, clusterName, namespace string) error {
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

	// Build the securityadmin.sh command
	cmd := []string{
		"/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh",
		"-f", "/usr/share/wazuh-indexer/opensearch-security/config.yml",
		"-icl", "-nhnv",
		"-cacert", constants.PathIndexerCerts + "/ca.crt",
		"-cert", constants.PathIndexerAdminCerts + "/tls.crt",
		"-key", constants.PathIndexerAdminCerts + "/tls.key",
	}

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
