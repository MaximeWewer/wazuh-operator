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
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// callReloadCertificatesAPIPerPod calls the OpenSearch API to reload certificates on each pod individually
// This ensures all pods in the cluster reload their certificates, not just the one hit by the service
// The certificate reload API requires admin certificate authentication (mTLS),
// not username/password authentication
func (h *HotReloader) callReloadCertificatesAPIPerPod(ctx context.Context, cluster *wazuhv1.WazuhCluster, result *HotReloadResult) {
	log := logf.FromContext(ctx)

	// Get CA certificate for TLS verification
	caCert, err := h.getCACertificate(ctx, cluster)
	if err != nil {
		result.Error = fmt.Errorf("failed to get CA certificate: %w", err)
		return
	}

	// Get admin certificate for mTLS authentication
	// The reload API requires admin cert, not username/password
	adminCert, adminKey, err := h.getAdminCertificate(ctx, cluster)
	if err != nil {
		result.Error = fmt.Errorf("failed to get admin certificate: %w", err)
		return
	}

	// Determine number of indexer replicas
	replicas := int32(1)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		replicas = cluster.Spec.Indexer.Replicas
	}
	result.TotalPods = int(replicas)
	result.PodResults = make([]PodReloadResult, 0, replicas)

	log.Info("Starting per-pod certificate hot reload",
		"cluster", cluster.Name,
		"namespace", cluster.Namespace,
		"totalPods", replicas)

	// First, wait for certificate propagation on the first pod
	// This ensures kubelet has synced the new certificates to the mounted secrets
	// before we attempt to connect with mTLS
	firstPodName := fmt.Sprintf("%s-indexer-0", cluster.Name)
	firstHeadlessService := fmt.Sprintf("%s-indexer-headless", cluster.Name)
	firstPodURL := fmt.Sprintf("https://%s:%d",
		dns.PodFQDN(firstPodName, firstHeadlessService, cluster.Namespace), constants.PortIndexerREST)

	// Use configured timeout or default
	propagationTimeout := h.PropagationTimeout
	if propagationTimeout == 0 {
		propagationTimeout = defaultKubeletSyncTimeout
	}

	log.Info("Waiting for kubelet to sync new certificates to pods",
		"timeout", propagationTimeout)

	if propagationErr := h.waitForCertificatePropagation(ctx, firstPodURL, caCert, adminCert, adminKey, propagationTimeout); propagationErr != nil {
		log.Error(propagationErr, "Certificate propagation timeout - pods may not have new certificates yet")
		result.Error = fmt.Errorf("certificate propagation failed: %w", propagationErr)
		return
	}

	log.Info("Certificates propagated successfully, proceeding with hot reload")

	// Give OpenSearch a few seconds to detect the file change and reload certificates
	// OpenSearch's file watcher typically reloads within 5-10 seconds
	log.V(1).Info("Waiting for OpenSearch to reload certificates from disk", "delay", "5s")
	select {
	case <-ctx.Done():
		result.Error = ctx.Err()
		return
	case <-time.After(5 * time.Second):
	}

	// Iterate over each pod using the headless service FQDN pattern
	var errors []string
	for i := int32(0); i < replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", cluster.Name, i)
		headlessService := fmt.Sprintf("%s-indexer-headless", cluster.Name)
		podURL := fmt.Sprintf("https://%s:%d",
			dns.PodFQDN(podName, headlessService, cluster.Namespace), constants.PortIndexerREST)

		podResult := PodReloadResult{
			PodName: podName,
			PodURL:  podURL,
		}

		// Create OpenSearch client for this specific pod
		// Use Insecure: true because the pod may still be serving with OLD certificates
		// while we need to call the reload API to make it load NEW certificates.
		// This is a chicken-and-egg situation: we can't verify OLD cert with NEW CA,
		// but we need to call the API to trigger reload. We still use mTLS for auth.
		client, clientErr := api.NewClient(api.ClientConfig{
			BaseURL:    podURL,
			CACert:     caCert, // Still provided for any CA-based operations
			ClientCert: adminCert,
			ClientKey:  adminKey,
			Insecure:   true, // Skip server cert verification during reload
		})
		if clientErr != nil {
			podResult.Error = fmt.Errorf("failed to create client: %w", clientErr)
			podResult.Attempts = 0
			result.PodResults = append(result.PodResults, podResult)
			errors = append(errors, fmt.Sprintf("%s: %v", podName, clientErr))
			continue
		}

		// Wait for security plugin to be ready after certificate reload
		// Increased timeout to account for OpenSearch certificate reload time
		if secErr := h.waitForSecurityReady(ctx, client, 60*time.Second); secErr != nil {
			log.Info("Security not ready on pod, skipping reload",
				"pod", podName,
				"error", secErr.Error())
			podResult.Error = fmt.Errorf("security not ready: %w", secErr)
			podResult.Attempts = 0
			result.PodResults = append(result.PodResults, podResult)
			errors = append(errors, fmt.Sprintf("%s: security not ready", podName))
			continue
		}

		// Call reload API with retry
		reloadErr := h.callReloadWithRetry(ctx, client, podName)
		podResult.Attempts = defaultRetryAttempts
		if reloadErr != nil {
			podResult.Error = reloadErr
			result.PodResults = append(result.PodResults, podResult)
			errors = append(errors, fmt.Sprintf("%s: %v", podName, reloadErr))
			log.Error(reloadErr, "Failed to reload certificates on pod", "pod", podName)
		} else {
			podResult.Success = true
			result.SuccessfulPods++
			result.PodResults = append(result.PodResults, podResult)
			log.Info("Successfully reloaded certificates on pod", "pod", podName)
		}
	}

	// Set overall error if any pods failed
	if len(errors) > 0 {
		result.Error = fmt.Errorf("certificate reload failed on %d/%d pods: %s",
			len(errors), replicas, strings.Join(errors, "; "))
	}

	log.Info("Completed per-pod certificate hot reload",
		"cluster", cluster.Name,
		"successfulPods", result.SuccessfulPods,
		"totalPods", result.TotalPods)
}

// waitForSecurityReady waits for the OpenSearch security plugin to be ready
func (h *HotReloader) waitForSecurityReady(ctx context.Context, client *api.Client, timeout time.Duration) error {
	log := logf.FromContext(ctx)

	deadline := time.Now().Add(timeout)
	backoff := 1 * time.Second
	var lastErr error

	for {
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("timeout waiting for security to be ready after %v: last error: %w", timeout, lastErr)
			}
			return fmt.Errorf("timeout waiting for security to be ready after %v", timeout)
		}

		health, err := client.CheckSecurityHealth(ctx)
		if err != nil {
			lastErr = err
			log.V(1).Info("Security health check failed, retrying",
				"error", err.Error(),
				"backoff", backoff)
		} else if health.Status == "UP" {
			return nil
		} else {
			log.V(1).Info("Security not ready yet, waiting...",
				"status", health.Status,
				"message", health.Message,
				"backoff", backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Increase backoff up to 5 seconds
			backoff = time.Duration(float64(backoff) * 1.5)
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
}

// callReloadWithRetry calls the certificate reload API with exponential backoff retry
func (h *HotReloader) callReloadWithRetry(ctx context.Context, client *api.Client, podName string) error {
	log := logf.FromContext(ctx)
	var lastErr error
	backoff := defaultInitialBackoff

	for attempt := 1; attempt <= defaultRetryAttempts; attempt++ {
		log.V(1).Info("Calling OpenSearch API to reload certificates",
			"pod", podName,
			"attempt", attempt,
			"maxAttempts", defaultRetryAttempts)

		if err := client.ReloadAllCertificates(ctx); err != nil {
			lastErr = err
			log.Info("Certificate reload attempt failed",
				"pod", podName,
				"attempt", attempt,
				"error", err.Error())

			if attempt < defaultRetryAttempts {
				log.V(1).Info("Retrying after backoff",
					"pod", podName,
					"backoff", backoff)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
					// Exponential backoff: 1s, 2s, 4s
					backoff *= 2
				}
			}
		} else {
			return nil // Success
		}
	}

	return fmt.Errorf("all %d retry attempts failed: %w", defaultRetryAttempts, lastErr)
}

// getCACertificate retrieves the CA certificate for TLS verification
func (h *HotReloader) getCACertificate(ctx context.Context, cluster *wazuhv1.WazuhCluster) ([]byte, error) {
	secretName := cluster.Name + "-ca"
	secret := &corev1.Secret{}
	err := h.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA secret %s: %w", secretName, err)
	}

	caCert, ok := secret.Data[constants.SecretKeyCACert]
	if !ok {
		return nil, fmt.Errorf("ca.crt not found in secret %s", secretName)
	}

	return caCert, nil
}

// getAdminCertificate retrieves the admin certificate and key for mTLS authentication
// Required for OpenSearch security API calls like certificate reload
func (h *HotReloader) getAdminCertificate(ctx context.Context, cluster *wazuhv1.WazuhCluster) (cert, key []byte, err error) {
	secretName := cluster.Name + "-admin-certs"
	secret := &corev1.Secret{}
	err = h.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get admin cert secret %s: %w", secretName, err)
	}

	cert, ok := secret.Data[constants.SecretKeyTLSCert]
	if !ok {
		return nil, nil, fmt.Errorf("tls.crt not found in secret %s", secretName)
	}

	key, ok = secret.Data[constants.SecretKeyTLSKey]
	if !ok {
		return nil, nil, fmt.Errorf("tls.key not found in secret %s", secretName)
	}

	return cert, key, nil
}
