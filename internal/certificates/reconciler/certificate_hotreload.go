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
	"time"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/hotreload"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Type aliases - types are defined in the hotreload package
type (
	// SyncStatus represents the synchronization status of a certificate
	SyncStatus = hotreload.SyncStatus
	// PodSyncResult contains the result of certificate sync verification for a single pod
	PodSyncResult = hotreload.PodSyncResult
	// PodSyncVerificationResult contains the overall result of pod certificate sync verification
	PodSyncVerificationResult = hotreload.PodSyncVerificationResult
	// HotReloadResult contains the result of a hot reload operation
	HotReloadResult = hotreload.HotReloadResult
)

// Constant aliases for backward compatibility
const (
	SyncStatusPending = hotreload.SyncStatusPending
	SyncStatusSynced  = hotreload.SyncStatusSynced
	SyncStatusFailed  = hotreload.SyncStatusFailed
	SyncStatusUnknown = hotreload.SyncStatusUnknown
)

// HotReloadWithFallbackResult contains the result of hot reload with automatic fallback
type HotReloadWithFallbackResult struct {
	// HotReloadResult contains the hot reload operation result
	HotReloadResult *HotReloadResult
	// FallbackTriggered indicates if fallback to rolling restart was triggered
	FallbackTriggered bool
	// FallbackReason explains why fallback was triggered
	FallbackReason string
	// RollingRestartResult contains the rolling restart result if fallback was triggered
	RollingRestartResult *RollingRestartResult
	// FinalSuccess indicates if the certificate update was ultimately successful
	FinalSuccess bool
	// Strategy indicates which strategy was used ("hot-reload" or "rolling-restart")
	Strategy string
}

// ShouldTriggerHotReload determines if hot reload should be triggered based on cluster config
func (r *CertificateReconciler) ShouldTriggerHotReload(cluster *wazuhv1.WazuhCluster) bool {
	return r.HotReloader.ShouldTriggerHotReload(cluster)
}

// ShouldForceAPIReload determines if API reload should be forced
func (r *CertificateReconciler) ShouldForceAPIReload(cluster *wazuhv1.WazuhCluster) bool {
	return r.HotReloader.ShouldForceAPIReload(cluster)
}

// TriggerCertificateHotReload triggers the appropriate hot reload mechanism based on version
func (r *CertificateReconciler) TriggerCertificateHotReload(ctx context.Context, cluster *wazuhv1.WazuhCluster) *HotReloadResult {
	return r.HotReloader.TriggerHotReload(ctx, cluster)
}

// TriggerCertificateHotReloadWithFallback attempts hot reload first, and falls back to rolling restart on failure
// This provides a robust certificate update mechanism:
// 1. First attempts hot reload (if supported)
// 2. If hot reload fails or not supported, triggers rolling restart as fallback
// 3. Returns detailed result including which strategy was used
func (r *CertificateReconciler) TriggerCertificateHotReloadWithFallback(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
) *HotReloadWithFallbackResult {
	log := logf.FromContext(ctx)
	result := &HotReloadWithFallbackResult{}
	startTime := time.Now()

	log.Info("Certificate update with fallback starting",
		"operation", "certificate-update",
		"component", "indexer",
		"cluster", cluster.Name,
		"namespace", cluster.Namespace,
		"certType", certType,
		"version", cluster.Spec.Version)

	// Attempt hot reload first
	hotReloadResult := r.TriggerCertificateHotReload(ctx, cluster)
	result.HotReloadResult = hotReloadResult

	// Determine if hot reload was successful
	hotReloadSucceeded := false
	if hotReloadResult.Supported {
		if hotReloadResult.RequiresAPICall {
			// For API-based hot reload, check if all pods succeeded
			hotReloadSucceeded = hotReloadResult.Error == nil &&
				hotReloadResult.SuccessfulPods == hotReloadResult.TotalPods
		} else {
			// For automatic hot reload (OpenSearch 2.19+), consider it successful if no error
			hotReloadSucceeded = hotReloadResult.Error == nil
		}
	}

	if hotReloadSucceeded {
		log.Info("Certificate update completed via hot reload",
			"operation", "certificate-update",
			"component", "indexer",
			"cluster", cluster.Name,
			"certType", certType,
			"strategy", "hot-reload",
			"hotReloadSuccess", true,
			"fallbackTriggered", false,
			"duration", time.Since(startTime).String())
		result.FinalSuccess = true
		result.Strategy = "hot-reload"
		return result
	}

	// Hot reload failed or not supported - determine fallback reason
	if !hotReloadResult.Supported {
		result.FallbackReason = fmt.Sprintf("hot reload not supported for version %s", cluster.Spec.Version)
	} else if hotReloadResult.Error != nil {
		result.FallbackReason = fmt.Sprintf("hot reload failed: %v", hotReloadResult.Error)
	} else if hotReloadResult.SuccessfulPods < hotReloadResult.TotalPods {
		result.FallbackReason = fmt.Sprintf("hot reload partially failed: %d/%d pods succeeded",
			hotReloadResult.SuccessfulPods, hotReloadResult.TotalPods)
	} else {
		result.FallbackReason = "unknown hot reload failure"
	}

	log.Info("Certificate hot reload failed, triggering fallback",
		"operation", "certificate-update",
		"component", "indexer",
		"cluster", cluster.Name,
		"certType", certType,
		"fallbackReason", result.FallbackReason,
		"hotReloadSuccess", false,
		"fallbackTriggered", true,
		"restartMethod", "rolling-restart")

	// Record fallback metric
	metrics.RecordHotReloadFallback(cluster.Name, cluster.Namespace, "indexer", result.FallbackReason)

	// Emit fallback event
	r.emitFallbackTriggeredEvent(cluster, certType, result.FallbackReason)

	// Trigger rolling restart as fallback
	result.FallbackTriggered = true
	restartStartTime := time.Now()
	restartResult, err := r.triggerFallbackRollingRestart(ctx, cluster, certType, result.FallbackReason)
	result.RollingRestartResult = restartResult
	restartDuration := time.Since(restartStartTime)

	if err != nil {
		log.Error(err, "Certificate update fallback failed",
			"operation", "certificate-update",
			"component", "indexer",
			"cluster", cluster.Name,
			"certType", certType,
			"strategy", "rolling-restart-failed",
			"hotReloadSuccess", false,
			"fallbackSuccess", false,
			"totalDuration", time.Since(startTime).String())
		result.FinalSuccess = false
		result.Strategy = "rolling-restart-failed"
	} else if restartResult != nil && restartResult.Triggered {
		log.Info("Certificate update completed via fallback rolling restart",
			"operation", "certificate-update",
			"component", "indexer",
			"cluster", cluster.Name,
			"certType", certType,
			"strategy", "rolling-restart",
			"hotReloadSuccess", false,
			"fallbackSuccess", true,
			"restartDuration", restartDuration.String(),
			"totalDuration", time.Since(startTime).String())
		result.FinalSuccess = true
		result.Strategy = "rolling-restart"
		metrics.RecordRollingRestart(cluster.Name, cluster.Namespace, "indexer", certType, restartDuration.Seconds())
	} else {
		log.Info("Certificate update completed (restart not needed)",
			"operation", "certificate-update",
			"component", "indexer",
			"cluster", cluster.Name,
			"certType", certType,
			"strategy", "rolling-restart-skipped",
			"reason", "0 replicas or already restarting",
			"totalDuration", time.Since(startTime).String())
		result.FinalSuccess = true
		result.Strategy = "rolling-restart-skipped"
	}

	return result
}

// triggerFallbackRollingRestart triggers a rolling restart as fallback when hot reload fails
func (r *CertificateReconciler) triggerFallbackRollingRestart(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
	reason string,
) (*RollingRestartResult, error) {
	// Get the restart configuration for this cert type
	restartConfig := GetRestartConfigForCertType(certType)
	restartConfig.ClusterName = cluster.Name
	restartConfig.Namespace = cluster.Namespace

	// Only trigger indexer restart for node certs
	if certType == constants.CertTypeNode && restartConfig.TriggerIndexers {
		config := &RollingRestartConfig{
			Component:    "indexer",
			CertType:     certType,
			RestartOrder: RestartOrderSequential,
			WaitForReady: true,
			Reason:       fmt.Sprintf("hot reload fallback: %s", reason),
		}
		return TriggerStatefulSetRollingRestart(ctx, r.Client, cluster.Namespace,
			constants.IndexerName(cluster.Name), config)
	}

	// For other cert types, return nil (handled by different mechanisms)
	return nil, nil
}

// VerifyPodCertSync verifies that certificates have been synced to all pods for a given cert type
func (r *CertificateReconciler) VerifyPodCertSync(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
) (*PodSyncVerificationResult, error) {
	return r.HotReloader.VerifyPodCertSync(ctx, cluster, certType)
}

// WaitForPodCertSync waits for certificates to be synced to all pods
func (r *CertificateReconciler) WaitForPodCertSync(
	ctx context.Context,
	cluster *wazuhv1.WazuhCluster,
	certType string,
	timeout time.Duration,
) (*PodSyncVerificationResult, error) {
	return r.HotReloader.WaitForPodCertSync(ctx, cluster, certType, timeout)
}

// emitFallbackTriggeredEvent emits an event when fallback to rolling restart is triggered
func (r *CertificateReconciler) emitFallbackTriggeredEvent(cluster *wazuhv1.WazuhCluster, certType, reason string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, constants.EventReasonCertificateHotReloadFallback,
			"Hot reload failed for %s certificate, triggering rolling restart fallback: %s", certType, reason)
	}
}
