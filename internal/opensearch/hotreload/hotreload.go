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

// Package hotreload provides OpenSearch certificate hot reload functionality.
// It handles triggering certificate reload via the OpenSearch Security API
// and verifying certificate propagation to pods.
package hotreload

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/pkg/versions"
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

// SyncStatus represents the synchronization status of a certificate
type SyncStatus string

const (
	// SyncStatusPending indicates sync is pending
	SyncStatusPending SyncStatus = "Pending"
	// SyncStatusSynced indicates sync is complete
	SyncStatusSynced SyncStatus = "Synced"
	// SyncStatusFailed indicates sync failed
	SyncStatusFailed SyncStatus = "Failed"
	// SyncStatusUnknown indicates sync status is unknown
	SyncStatusUnknown SyncStatus = "Unknown"
)

// PodSyncResult contains the result of certificate sync verification for a single pod
type PodSyncResult struct {
	// PodName is the name of the pod
	PodName string
	// SyncStatus indicates the current sync status
	SyncStatus SyncStatus
	// LastSyncTime is when the sync was last verified
	LastSyncTime time.Time
	// CertHash is the hash of the certificate observed in the pod
	CertHash string
	// ExpectedHash is the hash of the expected certificate
	ExpectedHash string
	// Error contains any error that occurred
	Error error
}

// PodSyncVerificationResult contains the overall result of pod certificate sync verification
type PodSyncVerificationResult struct {
	// TotalPods is the total number of pods checked
	TotalPods int
	// SyncedPods is the number of pods with synced certificates
	SyncedPods int
	// PendingPods is the number of pods with pending sync
	PendingPods int
	// FailedPods is the number of pods where sync failed
	FailedPods int
	// PodResults contains per-pod sync results
	PodResults []PodSyncResult
	// AllSynced indicates if all pods are synced
	AllSynced bool
	// Error contains any overall error
	Error error
}

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

// HotReloader handles OpenSearch certificate hot reload operations
type HotReloader struct {
	client.Client
	// EventRecorder is used to emit Kubernetes events for hot reload operations
	EventRecorder record.EventRecorder
	// PropagationTimeout is the timeout for waiting for kubelet to sync certificates
	// Defaults to 120 seconds if not set. Use a shorter value for unit tests.
	PropagationTimeout time.Duration
	// RESTConfig is the Kubernetes REST client configuration (needed for pod exec)
	RESTConfig *rest.Config
	// Clientset is the Kubernetes clientset (needed for pod exec)
	Clientset kubernetes.Interface
}

// NewHotReloader creates a new HotReloader
func NewHotReloader(c client.Client) *HotReloader {
	return &HotReloader{
		Client: c,
	}
}

// WithEventRecorder sets the EventRecorder for the HotReloader
func (h *HotReloader) WithEventRecorder(recorder record.EventRecorder) *HotReloader {
	h.EventRecorder = recorder
	return h
}

// WithPropagationTimeout sets the timeout for waiting for kubelet to sync certificates
func (h *HotReloader) WithPropagationTimeout(timeout time.Duration) *HotReloader {
	h.PropagationTimeout = timeout
	return h
}

// WithRESTConfig sets the Kubernetes REST configuration for pod exec operations
func (h *HotReloader) WithRESTConfig(config *rest.Config) *HotReloader {
	h.RESTConfig = config
	if config != nil {
		clientset, err := kubernetes.NewForConfig(config)
		if err == nil {
			h.Clientset = clientset
		}
	}
	return h
}

// ShouldTriggerHotReload determines if hot reload should be triggered based on cluster config
func (h *HotReloader) ShouldTriggerHotReload(cluster *wazuhv1.WazuhCluster) bool {
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
func (h *HotReloader) ShouldForceAPIReload(cluster *wazuhv1.WazuhCluster) bool {
	if cluster.Spec.TLS == nil || cluster.Spec.TLS.HotReload == nil {
		return false
	}
	return cluster.Spec.TLS.HotReload.ForceAPIReload
}

// TriggerHotReload triggers the appropriate hot reload mechanism based on version
// For OpenSearch 2.13-2.18.x: Calls the reload certificates API on each pod
// For OpenSearch 2.19+: Hot reload happens automatically via file watching
func (h *HotReloader) TriggerHotReload(ctx context.Context, cluster *wazuhv1.WazuhCluster) *HotReloadResult {
	log := logf.FromContext(ctx)
	result := &HotReloadResult{}
	startTime := time.Now()

	// Check if hot reload is enabled
	if !h.ShouldTriggerHotReload(cluster) {
		log.V(1).Info("Certificate hot reload disabled",
			"operation", "hot-reload",
			"component", "indexer",
			"cluster", cluster.Name,
			"namespace", cluster.Namespace,
			"hotReloadEnabled", false)
		result.Supported = false
		return result
	}

	// Get hot reload support level for this Wazuh version
	support, err := versions.GetHotReloadSupportForWazuh(cluster.Spec.Version)
	if err != nil {
		log.Error(err, "Failed to determine hot reload support",
			"operation", "hot-reload",
			"component", "indexer",
			"cluster", cluster.Name,
			"version", cluster.Spec.Version)
		result.Error = err
		metrics.RecordHotReloadFailure(cluster.Name, cluster.Namespace, "indexer", "version_detection_failed")
		return result
	}

	switch support {
	case versions.HotReloadNotSupported:
		log.Info("Certificate hot reload not supported for version",
			"operation", "hot-reload",
			"component", "indexer",
			"cluster", cluster.Name,
			"version", cluster.Spec.Version,
			"minRequired", versions.MinWazuhVersionForHotReload.String(),
			"hotReloadSupported", false)
		result.Supported = false
		return result

	case versions.HotReloadAutomatic:
		result.Supported = true
		result.RequiresAPICall = false
		// Check if force API reload is configured
		if h.ShouldForceAPIReload(cluster) {
			log.Info("Certificate hot reload starting (forced API mode)",
				"operation", "hot-reload",
				"component", "indexer",
				"cluster", cluster.Name,
				"version", cluster.Spec.Version,
				"method", "api-call",
				"forceAPIReload", true)
			result.RequiresAPICall = true
			h.emitHotReloadStartedEvent(cluster)
			h.callReloadCertificatesAPIPerPod(ctx, cluster, result)
			result.APICallMade = true
			h.emitHotReloadResultEvent(cluster, result)
			h.recordHotReloadMetrics(cluster, result, "api-call", time.Since(startTime))
		} else {
			log.Info("Certificate hot reload automatic (file-watch mode)",
				"operation", "hot-reload",
				"component", "indexer",
				"cluster", cluster.Name,
				"version", cluster.Spec.Version,
				"method", "automatic-file-watch",
				"apiCallNeeded", false)
			h.emitHotReloadSkippedEvent(cluster, "automatic reload enabled for version "+cluster.Spec.Version)
			metrics.RecordHotReloadSuccess(cluster.Name, cluster.Namespace, "indexer", "automatic-file-watch", time.Since(startTime).Seconds())
		}
		return result

	case versions.HotReloadWithAPICall:
		result.Supported = true
		result.RequiresAPICall = true
		log.Info("Certificate hot reload starting (API mode)",
			"operation", "hot-reload",
			"component", "indexer",
			"cluster", cluster.Name,
			"version", cluster.Spec.Version,
			"method", "api-call")
		h.emitHotReloadStartedEvent(cluster)
		h.callReloadCertificatesAPIPerPod(ctx, cluster, result)
		result.APICallMade = true
		h.emitHotReloadResultEvent(cluster, result)
		h.recordHotReloadMetrics(cluster, result, "api-call", time.Since(startTime))
		return result

	default:
		result.Error = fmt.Errorf("unknown hot reload support level: %d", support)
		metrics.RecordHotReloadFailure(cluster.Name, cluster.Namespace, "indexer", "unknown_support_level")
		return result
	}
}

// recordHotReloadMetrics records metrics for hot reload operations
func (h *HotReloader) recordHotReloadMetrics(cluster *wazuhv1.WazuhCluster, result *HotReloadResult, method string, duration time.Duration) {
	if result.Error == nil && result.SuccessfulPods == result.TotalPods {
		metrics.RecordHotReloadSuccess(cluster.Name, cluster.Namespace, "indexer", method, duration.Seconds())
	} else {
		reason := "partial_failure"
		if result.Error != nil {
			reason = "error"
		}
		metrics.RecordHotReloadFailure(cluster.Name, cluster.Namespace, "indexer", reason)
	}
}

// ShouldUseFallback determines if fallback should be used based on hot reload result
func ShouldUseFallback(result *HotReloadResult) bool {
	if result == nil {
		return true
	}
	// Use fallback if:
	// 1. Hot reload is not supported
	// 2. Hot reload failed with an error
	// 3. Not all pods were successfully reloaded
	if !result.Supported {
		return true
	}
	if result.Error != nil {
		return true
	}
	if result.RequiresAPICall && result.SuccessfulPods < result.TotalPods {
		return true
	}
	return false
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
	if !versions.SupportsHotReload(cluster.Spec.Version) {
		return ""
	}

	// Return the hot reload configuration
	// This enables the security plugin to reload certificates without restart
	return "plugins.security.ssl_cert_reload_enabled: true"
}

// emitHotReloadStartedEvent emits an event when certificate hot reload starts
func (h *HotReloader) emitHotReloadStartedEvent(cluster *wazuhv1.WazuhCluster) {
	if h.EventRecorder != nil {
		h.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadStarted,
			"Starting certificate hot reload for cluster %s", cluster.Name)
	}
}

// emitHotReloadResultEvent emits an event based on the hot reload result
func (h *HotReloader) emitHotReloadResultEvent(cluster *wazuhv1.WazuhCluster, result *HotReloadResult) {
	if h.EventRecorder == nil {
		return
	}

	if result.Error == nil {
		h.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadSucceeded,
			"Certificate hot reload completed successfully: %d/%d pods reloaded", result.SuccessfulPods, result.TotalPods)
	} else {
		// Build a summary of failed pods
		var failedPods []string
		for _, pr := range result.PodResults {
			if !pr.Success {
				failedPods = append(failedPods, pr.PodName)
			}
		}
		h.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, constants.EventReasonCertificateHotReloadFailed,
			"Certificate hot reload failed: %d/%d pods reloaded. Failed pods: %s",
			result.SuccessfulPods, result.TotalPods, strings.Join(failedPods, ", "))
	}
}

// emitHotReloadSkippedEvent emits an event when hot reload is skipped
func (h *HotReloader) emitHotReloadSkippedEvent(cluster *wazuhv1.WazuhCluster, reason string) {
	if h.EventRecorder != nil {
		h.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, constants.EventReasonCertificateHotReloadSkipped,
			"Certificate hot reload skipped: %s", reason)
	}
}
