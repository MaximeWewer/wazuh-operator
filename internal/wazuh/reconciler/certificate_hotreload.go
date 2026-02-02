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

package reconciler

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
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// defaultRetryAttempts is the default number of retry attempts for API calls
	defaultRetryAttempts = 3

	// defaultInitialBackoff is the initial backoff duration for retries
	defaultInitialBackoff = 1 * time.Second

	// defaultKubeletSyncTimeout is the timeout for waiting for kubelet to sync secrets to pods
	// Kubelet syncs secrets every 1 minute by default, plus propagation time
	// This should be at least 2 minutes to ensure new certs are available
	defaultKubeletSyncTimeout = 120 * time.Second
)

// PodReloadResult contains the result of reloading certificates on a single pod
type PodReloadResult struct {
	// PodName is the name of the pod
	PodName string
	// PodURL is the URL used to call the pod
	PodURL string
	// Success indicates if the reload was successful
	Success bool
	// Error contains any error that occurred
	Error error
	// Attempts is the number of retry attempts made
	Attempts int
}

// HotReloadResult contains the result of a hot reload operation
type HotReloadResult struct {
	// Supported indicates if hot reload is supported for this version
	Supported bool
	// RequiresAPICall indicates if API call is needed (OpenSearch 2.13-2.18)
	RequiresAPICall bool
	// APICallMade indicates if an API call was made
	APICallMade bool
	// Error contains any error that occurred
	Error error
	// PodResults contains per-pod reload results when using API reload
	PodResults []PodReloadResult
	// TotalPods is the total number of pods that were targeted
	TotalPods int
	// SuccessfulPods is the number of pods that were successfully reloaded
	SuccessfulPods int
}

// ShouldTriggerHotReload determines if hot reload should be triggered based on cluster config
func (r *CertificateReconciler) ShouldTriggerHotReload(cluster *wazuhv1.WazuhCluster) bool {
	// Check if TLS is enabled
	if cluster.Spec.TLS == nil {
		return false
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return false
	}

	// Check if hot reload is configured
	if cluster.Spec.TLS.HotReload == nil {
		// Default: hot reload is enabled
		return true
	}

	return cluster.Spec.TLS.HotReload.Enabled
}

// ShouldForceAPIReload determines if API reload should be forced
func (r *CertificateReconciler) ShouldForceAPIReload(cluster *wazuhv1.WazuhCluster) bool {
	if cluster.Spec.TLS == nil || cluster.Spec.TLS.HotReload == nil {
		return false
	}
	return cluster.Spec.TLS.HotReload.ForceAPIReload
}

// TriggerCertificateHotReload triggers the appropriate hot reload mechanism based on version
// For OpenSearch 2.13-2.18.x: Calls the reload certificates API on each pod
// For OpenSearch 2.19+: Hot reload happens automatically via file watching
func (r *CertificateReconciler) TriggerCertificateHotReload(ctx context.Context, cluster *wazuhv1.WazuhCluster) *HotReloadResult {
	log := logf.FromContext(ctx)
	result := &HotReloadResult{}

	// Check if hot reload is enabled
	if !r.ShouldTriggerHotReload(cluster) {
		log.V(1).Info("Hot reload is disabled for this cluster")
		result.Supported = false
		return result
	}

	// Get hot reload support level for this Wazuh version
	support, err := utils.GetHotReloadSupportForWazuh(cluster.Spec.Version)
	if err != nil {
		log.Error(err, "Failed to determine hot reload support for version", "version", cluster.Spec.Version)
		result.Error = err
		return result
	}

	switch support {
	case utils.HotReloadNotSupported:
		log.Info("Hot reload not supported for this Wazuh version",
			"version", cluster.Spec.Version,
			"minRequired", utils.MinWazuhVersionForHotReload.String())
		result.Supported = false
		return result

	case utils.HotReloadAutomatic:
		result.Supported = true
		result.RequiresAPICall = false
		// Check if force API reload is configured
		if r.ShouldForceAPIReload(cluster) {
			log.Info("Hot reload is automatic but forceAPIReload is enabled, calling API",
				"version", cluster.Spec.Version)
			result.RequiresAPICall = true
			r.emitHotReloadStartedEvent(cluster)
			r.callReloadCertificatesAPIPerPod(ctx, cluster, result)
			result.APICallMade = true
			r.emitHotReloadResultEvent(cluster, result)
		} else {
			log.Info("Hot reload is automatic for this version, no API call needed",
				"version", cluster.Spec.Version)
			r.emitHotReloadSkippedEvent(cluster, "automatic reload enabled for version "+cluster.Spec.Version)
		}
		return result

	case utils.HotReloadWithAPICall:
		result.Supported = true
		result.RequiresAPICall = true
		log.Info("Hot reload requires API call for this version",
			"version", cluster.Spec.Version)
		r.emitHotReloadStartedEvent(cluster)
		r.callReloadCertificatesAPIPerPod(ctx, cluster, result)
		result.APICallMade = true
		r.emitHotReloadResultEvent(cluster, result)
		return result

	default:
		result.Error = fmt.Errorf("unknown hot reload support level: %d", support)
		return result
	}
}

// callReloadCertificatesAPIPerPod calls the OpenSearch API to reload certificates on each pod individually
// This ensures all pods in the cluster reload their certificates, not just the one hit by the service
// The certificate reload API requires admin certificate authentication (mTLS),
// not username/password authentication
func (r *CertificateReconciler) callReloadCertificatesAPIPerPod(ctx context.Context, cluster *wazuhv1.WazuhCluster, result *HotReloadResult) {
	log := logf.FromContext(ctx)

	// Get CA certificate for TLS verification
	caCert, err := r.getCACertificate(ctx, cluster)
	if err != nil {
		result.Error = fmt.Errorf("failed to get CA certificate: %w", err)
		return
	}

	// Get admin certificate for mTLS authentication
	// The reload API requires admin cert, not username/password
	adminCert, adminKey, err := r.getAdminCertificate(ctx, cluster)
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
	firstPodURL := fmt.Sprintf("https://%s-indexer-0.%s-indexer-headless.%s.svc:%d",
		cluster.Name, cluster.Name, cluster.Namespace, constants.PortIndexerREST)

	// Use configured timeout or default
	propagationTimeout := r.PropagationTimeout
	if propagationTimeout == 0 {
		propagationTimeout = defaultKubeletSyncTimeout
	}

	log.Info("Waiting for kubelet to sync new certificates to pods",
		"timeout", propagationTimeout)

	if propagationErr := r.waitForCertificatePropagation(ctx, firstPodURL, caCert, adminCert, adminKey, propagationTimeout); propagationErr != nil {
		log.Error(propagationErr, "Certificate propagation timeout - pods may not have new certificates yet")
		result.Error = fmt.Errorf("certificate propagation failed: %w", propagationErr)
		return
	}

	log.Info("Certificates propagated successfully, proceeding with hot reload")

	// Iterate over each pod using the headless service FQDN pattern
	var errors []string
	for i := int32(0); i < replicas; i++ {
		podName := fmt.Sprintf("%s-indexer-%d", cluster.Name, i)
		podURL := fmt.Sprintf("https://%s-indexer-%d.%s-indexer-headless.%s.svc:%d",
			cluster.Name, i, cluster.Name, cluster.Namespace, constants.PortIndexerREST)

		podResult := PodReloadResult{
			PodName: podName,
			PodURL:  podURL,
		}

		// Create OpenSearch client for this specific pod
		client, clientErr := api.NewClient(api.ClientConfig{
			BaseURL:    podURL,
			CACert:     caCert,
			ClientCert: adminCert,
			ClientKey:  adminKey,
			Insecure:   false,
		})
		if clientErr != nil {
			podResult.Error = fmt.Errorf("failed to create client: %w", clientErr)
			podResult.Attempts = 0
			result.PodResults = append(result.PodResults, podResult)
			errors = append(errors, fmt.Sprintf("%s: %v", podName, clientErr))
			continue
		}

		// Quick security health check (should pass quickly since we already waited for propagation)
		if secErr := r.waitForSecurityReady(ctx, client, 30*time.Second); secErr != nil {
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
		reloadErr := r.callReloadWithRetry(ctx, client, podName)
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
func (r *CertificateReconciler) waitForSecurityReady(ctx context.Context, client *api.Client, timeout time.Duration) error {
	log := logf.FromContext(ctx)

	deadline := time.Now().Add(timeout)
	backoff := 1 * time.Second

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for security to be ready after %v", timeout)
		}

		if client.IsSecurityHealthy(ctx) {
			return nil
		}

		log.V(1).Info("Security not ready yet, waiting...", "backoff", backoff)
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

// waitForCertificatePropagation waits for kubelet to sync the new certificates to the pod
// by polling until we can successfully establish a TLS connection with the new certificates.
// This is necessary because kubelet syncs secrets on a 1-minute interval (by default),
// so there's a delay between updating the secret and the pod seeing the new certificates.
func (r *CertificateReconciler) waitForCertificatePropagation(ctx context.Context, podURL string, caCert, adminCert, adminKey []byte, timeout time.Duration) error {
	log := logf.FromContext(ctx)
	deadline := time.Now().Add(timeout)
	backoff := 5 * time.Second // Start with 5 seconds since kubelet sync is ~1 min

	log.Info("Waiting for certificate propagation to pod",
		"podURL", podURL,
		"timeout", timeout)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for certificate propagation after %v", timeout)
		}

		// Try to create a client and connect
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
			// Try a simple health check to verify TLS works
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
			// Use fixed 5-second intervals for kubelet sync polling
			// (exponential backoff not helpful here since we're waiting for kubelet)
		}
	}
}

// callReloadWithRetry calls the certificate reload API with exponential backoff retry
func (r *CertificateReconciler) callReloadWithRetry(ctx context.Context, client *api.Client, podName string) error {
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
func (r *CertificateReconciler) getCACertificate(ctx context.Context, cluster *wazuhv1.WazuhCluster) ([]byte, error) {
	secretName := cluster.Name + "-ca"
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
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
func (r *CertificateReconciler) getAdminCertificate(ctx context.Context, cluster *wazuhv1.WazuhCluster) (cert, key []byte, err error) {
	secretName := cluster.Name + "-admin-certs"
	secret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
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

// GetHotReloadConfigString returns the OpenSearch configuration string for hot reload
// This should be added to opensearch.yml when hot reload is enabled
func GetHotReloadConfigString(cluster *wazuhv1.WazuhCluster) string {
	// Check if hot reload is enabled
	if cluster.Spec.TLS == nil {
		return ""
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return ""
	}
	if cluster.Spec.TLS.HotReload != nil && !cluster.Spec.TLS.HotReload.Enabled {
		return ""
	}

	// Check version support
	if !utils.SupportsHotReload(cluster.Spec.Version) {
		return ""
	}

	// Return the hot reload configuration
	// This enables the security plugin to reload certificates without restart
	return "plugins.security.ssl_cert_reload_enabled: true"
}

// IsHotReloadEnabled returns true if hot reload is enabled for the cluster
func IsHotReloadEnabled(cluster *wazuhv1.WazuhCluster) bool {
	if cluster.Spec.TLS == nil {
		return false
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return false
	}
	if cluster.Spec.TLS.HotReload == nil {
		// Default: enabled if TLS is enabled
		return true
	}
	return cluster.Spec.TLS.HotReload.Enabled
}

// emitHotReloadStartedEvent emits an event when certificate hot reload starts
func (r *CertificateReconciler) emitHotReloadStartedEvent(cluster *wazuhv1.WazuhCluster) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadStarted,
			"Starting certificate hot reload for cluster %s", cluster.Name)
	}
}

// emitHotReloadResultEvent emits an event based on the hot reload result
func (r *CertificateReconciler) emitHotReloadResultEvent(cluster *wazuhv1.WazuhCluster, result *HotReloadResult) {
	if r.EventRecorder == nil {
		return
	}

	if result.Error == nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadSucceeded,
			"Certificate hot reload completed successfully: %d/%d pods reloaded", result.SuccessfulPods, result.TotalPods)
	} else {
		// Build a summary of failed pods
		var failedPods []string
		for _, pr := range result.PodResults {
			if !pr.Success {
				failedPods = append(failedPods, pr.PodName)
			}
		}
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, constants.EventReasonCertificateHotReloadFailed,
			"Certificate hot reload failed: %d/%d pods reloaded. Failed pods: %s",
			result.SuccessfulPods, result.TotalPods, strings.Join(failedPods, ", "))
	}
}

// emitHotReloadSkippedEvent emits an event when hot reload is skipped
func (r *CertificateReconciler) emitHotReloadSkippedEvent(cluster *wazuhv1.WazuhCluster, reason string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadSkipped,
			"Certificate hot reload skipped: %s", reason)
	}
}
