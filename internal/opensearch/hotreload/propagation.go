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

package hotreload

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// waitForCertificatePropagation waits for kubelet to sync the new certificates to the pods.
// It does this by exec'ing into each pod and comparing the hash of the mounted certificate
// with the expected hash from the Secret. This is more reliable than trying TLS connections,
// because the TLS approach fails when the pod still has OLD certificates.
//
// The flow is:
// 1. Get the expected certificate hash from the indexer-certs Secret
// 2. Exec into pod and read the mounted certificate file
// 3. Compare hashes - when they match, kubelet has synced
// 4. Return success when all pods have synced
func (h *HotReloader) waitForCertificatePropagation(ctx context.Context, podURL string, caCert, adminCert, adminKey []byte, timeout time.Duration) error {
	log := logf.FromContext(ctx)

	// Extract pod info from the URL (https://wazuh-test-indexer-0.wazuh-test-indexer-headless.wazuh.svc:9200)
	// Format: https://<podname>.<headless-service>.<namespace>.svc:<port>
	podInfo := strings.TrimPrefix(podURL, "https://")
	parts := strings.Split(podInfo, ".")
	if len(parts) < 3 {
		return fmt.Errorf("invalid pod URL format: %s", podURL)
	}
	podName := parts[0]
	namespace := parts[2] // Third part is namespace

	// Extract cluster name from pod name (e.g., "wazuh-test-indexer-0" -> "wazuh-test")
	// Pod name format: <cluster>-indexer-<ordinal>
	clusterName := strings.TrimSuffix(podName, "-0")
	clusterName = strings.TrimSuffix(clusterName, "-indexer")
	// Handle cases like "wazuh-test-indexer-1" -> "wazuh-test"
	if idx := strings.LastIndex(podName, "-indexer-"); idx > 0 {
		clusterName = podName[:idx]
	}

	// Check if we have the required config for exec
	if h.RESTConfig == nil || h.Clientset == nil {
		log.Info("REST config not available, falling back to TLS-based propagation check")
		return h.waitForCertificatePropagationViaTLS(ctx, podURL, caCert, adminCert, adminKey, timeout)
	}

	// Get expected hash from the indexer node certificate secret (not admin cert)
	expectedCert, err := h.getIndexerNodeCertificate(ctx, namespace, clusterName)
	if err != nil {
		log.Info("Failed to get indexer certificate from secret, falling back to TLS check",
			"error", err.Error())
		return h.waitForCertificatePropagationViaTLS(ctx, podURL, caCert, adminCert, adminKey, timeout)
	}
	expectedHash := utils.HashString(string(expectedCert))

	log.Info("Waiting for kubelet to sync certificates to pod",
		"pod", podName,
		"namespace", namespace,
		"clusterName", clusterName,
		"timeout", timeout,
		"expectedHash", expectedHash[:16]+"...")

	deadline := time.Now().Add(timeout)
	pollInterval := 5 * time.Second

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for certificate sync after %v - kubelet may be slow or certificates not mounted", timeout)
		}

		// Exec into the pod and read the certificate file
		certContent, err := h.execReadCertificate(ctx, namespace, podName, constants.PathIndexerCerts)
		if err != nil {
			log.V(1).Info("Failed to read certificate from pod, retrying",
				"pod", podName,
				"error", err.Error())
		} else {
			// Calculate hash of the mounted certificate
			mountedHash := utils.HashString(certContent)
			if mountedHash == expectedHash {
				log.Info("Certificate sync verified - kubelet has propagated new certificates",
					"pod", podName,
					"hash", mountedHash[:16]+"...")
				return nil
			}
			log.V(1).Info("Certificate hash mismatch - kubelet sync pending",
				"pod", podName,
				"expectedHash", expectedHash[:16]+"...",
				"mountedHash", mountedHash[:16]+"...")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
			// Continue polling
		}
	}
}

// getIndexerNodeCertificate retrieves the indexer node certificate from the Secret
func (h *HotReloader) getIndexerNodeCertificate(ctx context.Context, namespace, clusterName string) ([]byte, error) {
	secretName := constants.IndexerCertsName(clusterName)
	secret := &corev1.Secret{}
	err := h.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get indexer cert secret %s: %w", secretName, err)
	}

	certData, ok := secret.Data[constants.SecretKeyTLSCert]
	if !ok {
		return nil, fmt.Errorf("tls.crt not found in secret %s", secretName)
	}

	return certData, nil
}

// execReadCertificate execs into a pod and reads the certificate file content
func (h *HotReloader) execReadCertificate(ctx context.Context, namespace, podName, certPath string) (string, error) {
	// Read the tls.crt file from the certificate directory
	certFile := path.Join(certPath, constants.SecretKeyTLSCert)

	cmd := []string{"cat", certFile}

	req := h.Clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "opensearch", // Main container in indexer pods
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(h.RESTConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", fmt.Errorf("exec failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// waitForCertificatePropagationViaTLS is the fallback method when exec is not available.
// It tries to establish a TLS connection with the new certificates.
// Note: This method is less reliable because it tries to connect with NEW client certs
// while the pod may still have OLD server certs.
func (h *HotReloader) waitForCertificatePropagationViaTLS(ctx context.Context, podURL string, caCert, adminCert, adminKey []byte, timeout time.Duration) error {
	log := logf.FromContext(ctx)
	deadline := time.Now().Add(timeout)
	backoff := 5 * time.Second

	log.Info("Waiting for certificate propagation via TLS (fallback mode)",
		"podURL", podURL,
		"timeout", timeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for certificate propagation after %v", timeout)
		}

		client, err := api.NewClient(api.ClientConfig{
			BaseURL:    podURL,
			CACert:     caCert,
			ClientCert: adminCert,
			ClientKey:  adminKey,
			Insecure:   false,
		})
		if err != nil {
			log.V(1).Info("Failed to create client, certs may not be propagated yet",
				"error", err.Error(),
				"backoff", backoff)
		} else {
			if client.IsSecurityHealthy(ctx) {
				log.Info("Certificate propagation complete - TLS connection successful",
					"podURL", podURL)
				return nil
			}
			log.V(1).Info("TLS connection failed, certificates not yet propagated",
				"backoff", backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// VerifyPodCertSync verifies that certificates have been synced to all pods for a given cert type
// certType can be: "node", "admin", "filebeat", "dashboard"
func (h *HotReloader) VerifyPodCertSync(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
) (*PodSyncVerificationResult, error) {
	log := logf.FromContext(ctx)
	result := &PodSyncVerificationResult{
		PodResults: make([]PodSyncResult, 0),
	}

	// Get expected certificate hash from the secret
	expectedHash, err := h.getExpectedCertHash(ctx, cluster, certType)
	if err != nil {
		result.Error = fmt.Errorf("failed to get expected certificate hash: %w", err)
		return result, result.Error
	}

	log.V(1).Info("Certificate sync verification starting",
		"operation", "verify-cert-sync",
		"cluster", cluster.Name,
		"namespace", cluster.Namespace,
		"certType", certType,
		"expectedHash", expectedHash[:16]+"...")

	// Determine which pods to check based on cert type
	podNames, err := h.getPodsForCertType(cluster, certType)
	if err != nil {
		result.Error = fmt.Errorf("failed to determine pods for cert type %s: %w", certType, err)
		return result, result.Error
	}

	result.TotalPods = len(podNames)

	// Get CA certificate for TLS verification
	caCert, err := h.getCACertificate(ctx, cluster)
	if err != nil {
		result.Error = fmt.Errorf("failed to get CA certificate: %w", err)
		return result, result.Error
	}

	// Get admin certificate for mTLS authentication
	adminCert, adminKey, err := h.getAdminCertificate(ctx, cluster)
	if err != nil {
		result.Error = fmt.Errorf("failed to get admin certificate: %w", err)
		return result, result.Error
	}

	// Determine component for metrics
	component := h.getComponentForCertType(certType)

	// Check each pod
	for _, podName := range podNames {
		podResult := h.verifyPodCertSyncStatus(ctx, cluster, podName, certType, expectedHash, caCert, adminCert, adminKey)
		result.PodResults = append(result.PodResults, podResult)

		// Record per-pod sync status metric
		var statusValue float64
		switch podResult.SyncStatus {
		case SyncStatusSynced:
			result.SyncedPods++
			statusValue = 1
		case SyncStatusPending:
			result.PendingPods++
			statusValue = 0
		case SyncStatusFailed:
			result.FailedPods++
			statusValue = -1
		}
		metrics.SetPodSyncStatus(cluster.Name, cluster.Namespace, component, podName, statusValue)
	}

	result.AllSynced = result.SyncedPods == result.TotalPods

	// If all pods are synced, clear individual pod sync metrics for this component
	if result.AllSynced {
		for _, podName := range podNames {
			metrics.ClearPodSyncStatus(cluster.Name, cluster.Namespace, component, podName)
		}
	}

	log.Info("Certificate sync verification completed",
		"operation", "verify-cert-sync",
		"cluster", cluster.Name,
		"namespace", cluster.Namespace,
		"certType", certType,
		"component", component,
		"syncedPods", result.SyncedPods,
		"pendingPods", result.PendingPods,
		"failedPods", result.FailedPods,
		"totalPods", result.TotalPods,
		"allSynced", result.AllSynced)

	return result, nil
}

// getComponentForCertType returns the component name for a given certificate type
func (h *HotReloader) getComponentForCertType(certType string) string {
	switch certType {
	case constants.CertTypeNode:
		return "indexer"
	case constants.CertTypeAdmin:
		return "admin"
	case constants.CertTypeFilebeat:
		return "manager"
	case constants.CertTypeDashboard:
		return "dashboard"
	default:
		return "unknown"
	}
}

// verifyPodCertSyncStatus checks the certificate sync status for a single pod
func (h *HotReloader) verifyPodCertSyncStatus(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	podName string,
	certType string,
	expectedHash string,
	caCert, adminCert, adminKey []byte,
) PodSyncResult {
	log := logf.FromContext(ctx)
	result := PodSyncResult{
		PodName:      podName,
		LastSyncTime: time.Now(),
		ExpectedHash: expectedHash,
	}

	// Build pod URL based on the pod name pattern
	podURL := h.buildPodURL(cluster, podName)

	// Create client for this pod
	client, err := api.NewClient(api.ClientConfig{
		BaseURL:    podURL,
		CACert:     caCert,
		ClientCert: adminCert,
		ClientKey:  adminKey,
		Insecure:   false,
	})
	if err != nil {
		log.V(1).Info("Failed to create client for pod",
			"pod", podName,
			"error", err.Error())
		result.SyncStatus = SyncStatusFailed
		result.Error = fmt.Errorf("failed to create client: %w", err)
		return result
	}

	// Try to verify the certificate by checking TLS connection
	// If we can connect with the expected certificates, the sync is complete
	if client.IsSecurityHealthy(ctx) {
		result.SyncStatus = SyncStatusSynced
		result.CertHash = expectedHash // We matched the expected cert
		log.V(1).Info("Certificate sync verified for pod",
			"pod", podName,
			"certType", certType)
	} else {
		// Connection failed - either cert not synced yet or other issue
		result.SyncStatus = SyncStatusPending
		log.V(1).Info("Certificate sync pending for pod",
			"pod", podName,
			"certType", certType)
	}

	return result
}

// getExpectedCertHash returns the hash of the expected certificate from the secret
func (h *HotReloader) getExpectedCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certType string) (string, error) {
	secretName := h.getSecretNameForCertType(cluster, certType)
	if secretName == "" {
		return "", fmt.Errorf("unknown cert type: %s", certType)
	}

	secret := &corev1.Secret{}
	err := h.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	// Get the certificate data
	certData, ok := secret.Data[constants.SecretKeyTLSCert]
	if !ok {
		return "", fmt.Errorf("tls.crt not found in secret %s", secretName)
	}

	// Compute hash of the certificate
	return utils.HashString(string(certData)), nil
}

// getSecretNameForCertType returns the secret name for a given certificate type
func (h *HotReloader) getSecretNameForCertType(cluster *wazuhv1.WazuhCluster, certType string) string {
	switch certType {
	case constants.CertTypeNode:
		return constants.IndexerCertsName(cluster.Name)
	case constants.CertTypeAdmin:
		return cluster.Name + "-admin-certs"
	case constants.CertTypeFilebeat:
		return constants.FilebeatCertsName(cluster.Name)
	case constants.CertTypeDashboard:
		return constants.DashboardCertsName(cluster.Name)
	default:
		return ""
	}
}

// getPodsForCertType returns the list of pod names that use a given certificate type
func (h *HotReloader) getPodsForCertType(cluster *wazuhv1.WazuhCluster, certType string) ([]string, error) {
	var pods []string

	switch certType {
	case constants.CertTypeNode:
		// Node certs are used by indexer pods
		replicas := int32(1)
		if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
			replicas = cluster.Spec.Indexer.Replicas
		}
		for i := int32(0); i < replicas; i++ {
			pods = append(pods, fmt.Sprintf("%s-indexer-%d", cluster.Name, i))
		}

	case constants.CertTypeAdmin:
		// Admin certs are used by the operator/jobs, not mounted in pods
		// Return empty - no pod verification needed
		return []string{}, nil

	case constants.CertTypeFilebeat:
		// Filebeat certs are used by manager pods
		pods = append(pods, fmt.Sprintf("%s-manager-master-0", cluster.Name))
		if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil && *cluster.Spec.Manager.Workers.Replicas > 0 {
			workerReplicas := *cluster.Spec.Manager.Workers.Replicas
			for i := int32(0); i < workerReplicas; i++ {
				pods = append(pods, fmt.Sprintf("%s-manager-workers-%d", cluster.Name, i))
			}
		}

	case constants.CertTypeDashboard:
		// Dashboard certs are used by dashboard deployment pods
		// Dashboard is a Deployment, so pod names have random suffixes
		// We can't easily enumerate them without listing pods
		// For now, return empty - dashboard uses different verification
		return []string{}, nil

	default:
		return nil, fmt.Errorf("unknown cert type: %s", certType)
	}

	return pods, nil
}

// buildPodURL builds the HTTPS URL for a given pod
func (h *HotReloader) buildPodURL(cluster *wazuhv1.WazuhCluster, podName string) string {
	// Determine the service type based on pod name
	// Uses dns.PodFQDN for proper cluster domain support
	if strings.Contains(podName, "-indexer-") {
		headlessService := fmt.Sprintf("%s-indexer-headless", cluster.Name)
		return fmt.Sprintf("https://%s:%d",
			dns.PodFQDN(podName, headlessService, cluster.Namespace), constants.PortIndexerREST)
	}
	if strings.Contains(podName, "-manager-") {
		headlessService := fmt.Sprintf("%s-manager-headless", cluster.Name)
		return fmt.Sprintf("https://%s:%d",
			dns.PodFQDN(podName, headlessService, cluster.Namespace), constants.PortManagerAPI)
	}
	// Default to indexer pattern
	headlessService := fmt.Sprintf("%s-indexer-headless", cluster.Name)
	return fmt.Sprintf("https://%s:%d",
		dns.PodFQDN(podName, headlessService, cluster.Namespace), constants.PortIndexerREST)
}

// WaitForPodCertSync waits for certificates to be synced to all pods
func (h *HotReloader) WaitForPodCertSync(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
	timeout time.Duration,
) (*PodSyncVerificationResult, error) {
	log := logf.FromContext(ctx)
	startTime := time.Now()
	deadline := time.Now().Add(timeout)
	component := h.getComponentForCertType(certType)

	log.Info("Certificate propagation wait starting",
		"operation", "wait-cert-sync",
		"cluster", cluster.Name,
		"namespace", cluster.Namespace,
		"certType", certType,
		"component", component,
		"timeout", timeout.String())

	// Emit propagation wait event
	if h.EventRecorder != nil {
		h.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificatePropagationWait,
			"Waiting for %s certificate propagation to pods (timeout: %v)", certType, timeout)
	}

	for {
		if time.Now().After(deadline) {
			result, _ := h.VerifyPodCertSync(ctx, cluster, certType)
			result.Error = fmt.Errorf("timeout waiting for certificate sync after %v", timeout)

			log.Error(result.Error, "Certificate propagation timeout",
				"operation", "wait-cert-sync",
				"cluster", cluster.Name,
				"certType", certType,
				"component", component,
				"syncedPods", result.SyncedPods,
				"totalPods", result.TotalPods,
				"elapsed", time.Since(startTime).String())

			// Emit timeout event
			if h.EventRecorder != nil {
				h.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, constants.EventReasonCertificatePropagationTimeout,
					"Certificate propagation timeout for %s: %d/%d pods synced", certType, result.SyncedPods, result.TotalPods)
			}

			return result, result.Error
		}

		result, err := h.VerifyPodCertSync(ctx, cluster, certType)
		if err != nil {
			log.V(1).Info("Certificate sync verification error, retrying",
				"operation", "wait-cert-sync",
				"cluster", cluster.Name,
				"certType", certType,
				"error", err.Error())
		} else if result.AllSynced {
			propagationDuration := time.Since(startTime)

			log.Info("Certificate propagation completed",
				"operation", "wait-cert-sync",
				"cluster", cluster.Name,
				"namespace", cluster.Namespace,
				"certType", certType,
				"component", component,
				"syncedPods", result.SyncedPods,
				"propagationDuration", propagationDuration.String())

			// Record propagation duration metric
			metrics.RecordCertificatePropagation(cluster.Name, cluster.Namespace, component, propagationDuration.Seconds())

			// Emit completion event
			if h.EventRecorder != nil {
				h.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificatePropagationComplete,
					"Certificate propagation completed for %s: %d pods synced in %v", certType, result.SyncedPods, propagationDuration)
			}

			return result, nil
		}

		log.V(1).Info("Certificate propagation in progress",
			"operation", "wait-cert-sync",
			"cluster", cluster.Name,
			"certType", certType,
			"syncedPods", result.SyncedPods,
			"pendingPods", result.PendingPods,
			"totalPods", result.TotalPods,
			"elapsed", time.Since(startTime).String())

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			// Continue polling
		}
	}
}
