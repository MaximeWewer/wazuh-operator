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

package controllers

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	wazuhClusterFinalizer = "resources.wazuh.com/finalizer"

	// RequeueIntervalNormal is the normal requeue interval when cluster is stable
	RequeueIntervalNormal = 30 * time.Second

	// RequeueIntervalPendingRollout is the faster requeue interval when rollouts are pending
	RequeueIntervalPendingRollout = 5 * time.Second

	// RequeueIntervalTestMode is the requeue interval when test mode is enabled
	RequeueIntervalTestMode = 5 * time.Second

	// RequeueIntervalDrainInProgress is the requeue interval when a drain is in progress
	RequeueIntervalDrainInProgress = 10 * time.Second
)

// WazuhClusterReconciler reconciles a WazuhCluster object
// This is a thin controller that delegates to helper reconcilers
type WazuhClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconcilers
	ClusterReconciler     *wazuhreconciler.ClusterReconciler
	CertificateReconciler *wazuhreconciler.CertificateReconciler
	IndexerReconciler     *opensearchreconciler.IndexerReconciler
	DashboardReconciler   *opensearchreconciler.DashboardReconciler
	WorkerReconciler      *wazuhreconciler.WorkerReconciler
	MonitoringReconciler  *monitoring.MonitoringReconciler

	// Drain management
	RollbackManager *drain.RollbackManagerImpl
	RetryManager    *drain.RetryManagerImpl

	// CertTestMode enables faster reconciliation for certificate testing
	CertTestMode bool

	// UseNonBlockingRollouts enables non-blocking certificate rollouts
	UseNonBlockingRollouts bool

	// drainInProgress tracks if a drain operation is currently active
	drainInProgress bool
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop for WazuhCluster
func (r *WazuhClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the WazuhCluster instance
	cluster := &wazuhv1alpha1.WazuhCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhCluster resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhCluster")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !cluster.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cluster)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cluster, wazuhClusterFinalizer) {
		log.Info("Adding finalizer to WazuhCluster")
		controllerutil.AddFinalizer(cluster, wazuhClusterFinalizer)
		if err := r.Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to update WazuhCluster with finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Update phase if pending
	if cluster.Status.Phase == "" || cluster.Status.Phase == wazuhv1alpha1.ClusterPhasePending {
		cluster.Status.Phase = wazuhv1alpha1.ClusterPhaseCreating
		cluster.Status.Version = cluster.Spec.Version
		if err := r.Status().Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to update WazuhCluster status to Creating")
			return ctrl.Result{}, err
		}
	}

	// Check and update pending rollouts from previous reconciliation
	hasPendingRollouts := r.checkAndUpdatePendingRollouts(ctx, cluster)

	// Check if any rollback is in progress and verify completion
	if err := r.verifyRollbackComplete(ctx, cluster); err != nil {
		log.Error(err, "Failed to verify rollback completion")
	}

	// Check if any retry is due and handle it
	if retryNeeded, result := r.checkAndHandleRetry(ctx, cluster); retryNeeded {
		log.Info("Drain retry handling in progress")
		return result, nil
	}

	// Update test mode metric
	if r.CertTestMode {
		metrics.SetCertificateTestMode(cluster.Name, cluster.Namespace, true)
		log.V(1).Info("Certificate test mode is enabled")
	}

	// Delegate reconciliation to helper reconcilers
	// 1. Reconcile certificates using CertificateReconciler for full lifecycle management
	// Use ReconcileWithHashes to get certificate hashes for triggering pod restarts
	var certHashes *wazuhreconciler.CertHashResult
	if r.CertificateReconciler != nil {
		var certErr error
		certHashes, certErr = r.CertificateReconciler.ReconcileWithHashes(ctx, cluster)
		if certErr != nil {
			log.Error(certErr, "Failed to reconcile certificates with CertificateReconciler")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "CertificatesFailed", certErr.Error())
			return ctrl.Result{}, certErr
		}
	} else {
		// Fallback to ClusterReconciler for basic certificate creation
		if err := r.ClusterReconciler.ReconcileCertificates(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile certificates")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "CertificatesFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	// Track new pending rollouts
	var newPendingRollouts []utils.PendingRollout

	// 2. Check dry-run mode - evaluate feasibility without executing
	if cluster.Spec.Drain != nil && cluster.Spec.Drain.DryRun {
		result := r.evaluateDryRun(ctx, cluster)
		if result != nil {
			// Update status with dry-run result
			if cluster.Status.Drain == nil {
				cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
			}
			cluster.Status.Drain.LastDryRun = result

			// Emit event with dry-run result
			r.emitDryRunEvent(cluster, result)

			log.Info("Dry-run evaluation complete",
				"feasible", result.Feasible,
				"blockers", len(result.Blockers),
				"warnings", len(result.Warnings))
		}

		// Update status and return - don't proceed with actual drain
		return ctrl.Result{RequeueAfter: RequeueIntervalNormal}, r.updateDrainStatus(ctx, cluster)
	}

	// 3. Check for indexer scale-down and handle drain if needed
	if cluster.Spec.Indexer != nil {
		desiredReplicas := cluster.Spec.Indexer.Replicas
		if desiredReplicas == 0 {
			desiredReplicas = 3 // Default
		}

		drainResult, err := r.IndexerReconciler.CheckScaleDownDrain(ctx, cluster, desiredReplicas)
		if err != nil {
			log.Error(err, "Failed to check indexer scale-down drain")
			// Don't fail reconciliation, proceed without drain
		} else if drainResult != nil && drainResult.DrainInProgress {
			// Drain is in progress, wait for it to complete before proceeding with scale-down
			log.Info("Indexer drain in progress, waiting for completion",
				"targetPod", drainResult.TargetPod,
				"progress", drainResult.Progress)
			r.drainInProgress = true

			// Update drain status in cluster
			if cluster.Status.Drain == nil {
				cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
			}

			// Requeue to check drain progress
			return ctrl.Result{RequeueAfter: RequeueIntervalDrainInProgress}, r.updateDrainStatus(ctx, cluster)
		} else if drainResult != nil && drainResult.DrainComplete {
			// Drain is complete, proceed with normal reconciliation
			log.Info("Indexer drain complete, proceeding with scale-down")
			r.drainInProgress = false
			// Reset drain state after scale-down is applied
			defer r.IndexerReconciler.ResetDrainState(cluster)
		} else {
			r.drainInProgress = false
		}
	}

	// 3. Reconcile Indexer
	// OpenSearch supports hot reload of ALL certificates (node + CA) via plugins.security.ssl_cert_reload_enabled.
	// See PR: https://github.com/opensearch-project/security/pull/4880
	// The key requirement is that certificates must be mounted as a directory (not with subPath)
	// so that Kubernetes can update the files when Secrets change.
	// This is already configured in the indexer StatefulSet.
	//
	// For OpenSearch 2.19+ (Wazuh 4.14+): Automatic hot reload via file watching
	// For OpenSearch 2.13-2.18 (Wazuh 4.9-4.11): Requires API call after cert renewal
	//
	// The indexer needs to restart when:
	// 1. CA was renewed (hot reload doesn't work for CA changes)
	// 2. Hot reload API call failed (e.g., cert already expired before API could be called)
	indexerCertHash := ""
	if certHashes != nil {
		// Restart needed if CA was renewed (hot reload doesn't work for CA)
		// OR if hot reload failed (API couldn't connect due to expired cert)
		if certHashes.CARenewed || (certHashes.IndexerCertsRenewed && certHashes.HotReloadError != nil) {
			indexerCertHash = certHashes.IndexerCertHash
			if certHashes.CARenewed {
				log.Info("CA was renewed - indexer will restart to reload trust store")
			} else {
				log.Info("Hot reload failed - indexer will restart", "error", certHashes.HotReloadError)
			}
		}
	}
	if r.UseNonBlockingRollouts {
		result := r.IndexerReconciler.ReconcileNonBlocking(ctx, cluster, indexerCertHash)
		if result.Error != nil {
			log.Error(result.Error, "Failed to reconcile Indexer (non-blocking)")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "IndexerFailed", result.Error.Error())
			return ctrl.Result{}, result.Error
		}
		if result.PendingRollout != nil {
			newPendingRollouts = append(newPendingRollouts, *result.PendingRollout)
		}
	} else {
		if err := r.IndexerReconciler.ReconcileWithCertHash(ctx, cluster, indexerCertHash); err != nil {
			log.Error(err, "Failed to reconcile Indexer")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "IndexerFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	// 4. Check Security Initialization (after indexer is up)
	securityInitialized, err := r.IndexerReconciler.CheckSecurityInitialization(ctx, cluster)
	if err != nil {
		log.Error(err, "Failed to check security initialization")
		// Non-fatal, continue
	}

	if securityInitialized {
		// Update SecurityReady condition
		r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeSecurityReady, metav1.ConditionTrue, "SecurityInitialized", "OpenSearch security plugin is initialized")

		// Resolve default admin user
		if err := r.IndexerReconciler.ResolveAndSetDefaultAdmin(ctx, cluster); err != nil {
			log.Error(err, "Failed to resolve default admin")
			// Non-fatal, continue
		}

		// Sync security CRDs
		if err := r.IndexerReconciler.SyncSecurityCRDs(ctx, cluster); err != nil {
			log.Error(err, "Failed to sync security CRDs")
			// Non-fatal, continue
		}
	} else {
		// Security not ready yet, requeue faster
		r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeSecurityReady, metav1.ConditionFalse, "SecurityPending", "Waiting for OpenSearch security to initialize")
	}

	// 5. Check for manager worker scale-down and handle drain if needed
	if cluster.Spec.Manager != nil && r.WorkerReconciler != nil {
		desiredReplicas := cluster.Spec.Manager.Workers.GetReplicas()

		drainResult, err := r.WorkerReconciler.CheckScaleDownDrain(ctx, cluster, desiredReplicas)
		if err != nil {
			log.Error(err, "Failed to check manager worker scale-down drain")
			// Don't fail reconciliation, proceed without drain
		} else if drainResult != nil && drainResult.DrainInProgress {
			// Drain is in progress, wait for it to complete before proceeding with scale-down
			log.Info("Manager worker drain in progress, waiting for completion",
				"targetPod", drainResult.TargetPod,
				"progress", drainResult.Progress)
			r.drainInProgress = true

			// Update drain status in cluster
			if cluster.Status.Drain == nil {
				cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
			}

			// Requeue to check drain progress
			return ctrl.Result{RequeueAfter: RequeueIntervalDrainInProgress}, r.updateDrainStatus(ctx, cluster)
		} else if drainResult != nil && drainResult.DrainComplete {
			// Drain is complete, proceed with normal reconciliation
			log.Info("Manager worker drain complete, proceeding with scale-down")
			r.drainInProgress = false
			// Reset drain state after scale-down is applied
			defer r.WorkerReconciler.ResetDrainState(cluster)
		} else {
			// No drain needed or drain not configured
			if r.drainInProgress {
				r.drainInProgress = false
			}
		}
	}

	// 6. Reconcile Manager with certificate hashes for pod restart on cert renewal
	if certHashes != nil {
		if r.UseNonBlockingRollouts {
			result := r.ClusterReconciler.ReconcileManagerNonBlocking(ctx, cluster, certHashes.ManagerMasterCertHash, certHashes.ManagerWorkerCertHash)
			if result.Error != nil {
				log.Error(result.Error, "Failed to reconcile Manager (non-blocking)")
				r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", result.Error.Error())
				return ctrl.Result{}, result.Error
			}
			newPendingRollouts = append(newPendingRollouts, result.PendingRollouts...)
		} else {
			if err := r.ClusterReconciler.ReconcileManagerWithCertHashes(ctx, cluster, certHashes.ManagerMasterCertHash, certHashes.ManagerWorkerCertHash); err != nil {
				log.Error(err, "Failed to reconcile Manager with cert hashes")
				r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else {
		// Fallback to regular reconciliation without cert hashes
		if err := r.ClusterReconciler.ReconcileManager(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Manager")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	// 7. Reconcile Log Rotation CronJob (if enabled)
	if err := r.ClusterReconciler.ReconcileLogRotation(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile log rotation")
		// Non-fatal, continue - log rotation is an optional feature
	}

	// 8. Reconcile Dashboard with certificate hash for pod restart on cert renewal
	if certHashes != nil {
		if r.UseNonBlockingRollouts {
			result := r.DashboardReconciler.ReconcileNonBlocking(ctx, cluster, certHashes.DashboardCertHash)
			if result.Error != nil {
				log.Error(result.Error, "Failed to reconcile Dashboard (non-blocking)")
				r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", result.Error.Error())
				return ctrl.Result{}, result.Error
			}
			if result.PendingRollout != nil {
				newPendingRollouts = append(newPendingRollouts, *result.PendingRollout)
			}
		} else {
			if err := r.DashboardReconciler.ReconcileWithCertHash(ctx, cluster, certHashes.DashboardCertHash); err != nil {
				log.Error(err, "Failed to reconcile Dashboard with cert hash")
				r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else {
		// Fallback to regular reconciliation without cert hash
		if err := r.DashboardReconciler.Reconcile(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Dashboard")
			r.updateCondition(cluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	// 9. Reconcile Monitoring resources (ServiceMonitors) if enabled
	if r.MonitoringReconciler != nil {
		if err := r.MonitoringReconciler.Reconcile(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Monitoring resources")
			// Non-fatal, continue - monitoring CRD might not be installed
		}
	}

	// 10. Check for indexer restart and re-sync if needed
	if restarted, err := r.IndexerReconciler.DetectIndexerRestart(ctx, cluster); err != nil {
		log.Error(err, "Failed to detect indexer restart")
	} else if restarted && securityInitialized {
		log.Info("Indexer restart detected, re-syncing security CRDs")
		if err := r.IndexerReconciler.SyncSecurityCRDs(ctx, cluster); err != nil {
			log.Error(err, "Failed to re-sync security CRDs after restart")
		}
	}

	// 11. Update pending rollouts status
	if len(newPendingRollouts) > 0 {
		r.addPendingRollouts(cluster, newPendingRollouts)
		hasPendingRollouts = true
		log.Info("New certificate rollouts initiated", "count", len(newPendingRollouts))
	}

	// Update metrics for pending rollouts
	pendingCount := 0
	if cluster.Status.CertificateRollouts != nil {
		for _, rollout := range cluster.Status.CertificateRollouts.PendingRollouts {
			if !rollout.Ready {
				pendingCount++
			}
		}
	}
	metrics.SetCertificateRolloutsPending(cluster.Name, cluster.Namespace, float64(pendingCount))

	// Update status
	if err := r.updateStatus(ctx, cluster); err != nil {
		log.Error(err, "Failed to update WazuhCluster status")
		return ctrl.Result{}, err
	}

	// Determine requeue interval based on state
	requeueInterval := r.determineRequeueInterval(hasPendingRollouts)
	log.V(1).Info("Reconciliation complete", "requeueAfter", requeueInterval, "hasPendingRollouts", hasPendingRollouts)

	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

// checkAndUpdatePendingRollouts checks the status of any pending rollouts and updates the cluster status
// Returns true if there are still pending rollouts
func (r *WazuhClusterReconciler) checkAndUpdatePendingRollouts(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) bool {
	log := logf.FromContext(ctx)

	if cluster.Status.CertificateRollouts == nil || len(cluster.Status.CertificateRollouts.PendingRollouts) == 0 {
		return false
	}

	waiter := utils.NewRolloutWaiter(r.Client)
	hasPending := false
	var updatedRollouts []wazuhv1alpha1.PendingCertRollout

	for _, rollout := range cluster.Status.CertificateRollouts.PendingRollouts {
		if rollout.Ready {
			// Already completed, keep it for history (could trim old ones later)
			updatedRollouts = append(updatedRollouts, rollout)
			continue
		}

		// Convert to utils.PendingRollout for checking
		pendingRollout := utils.PendingRollout{
			Component: rollout.Component,
			Namespace: cluster.Namespace,
			Name:      rollout.WorkloadName,
			Type:      utils.RolloutType(rollout.WorkloadType),
			StartTime: rollout.StartTime.Time,
			Reason:    rollout.Reason,
		}

		status := waiter.CheckRolloutStatus(ctx, pendingRollout)

		if status.Error != nil {
			log.Error(status.Error, "Error checking rollout status", "component", rollout.Component)
			// Keep as pending
			updatedRollouts = append(updatedRollouts, rollout)
			hasPending = true
			continue
		}

		if status.Ready {
			// Rollout completed
			rollout.Ready = true
			log.Info("Certificate rollout completed",
				"component", rollout.Component,
				"duration", status.Duration,
				"reason", rollout.Reason)

			// Record metrics
			metrics.RecordCertificateRolloutWait(cluster.Name, cluster.Namespace, rollout.Component, status.Duration.Seconds())
		} else {
			hasPending = true
			log.V(1).Info("Certificate rollout still in progress",
				"component", rollout.Component,
				"status", status.Message,
				"duration", status.Duration)
		}

		updatedRollouts = append(updatedRollouts, rollout)
	}

	// Update the status with the new rollout states
	cluster.Status.CertificateRollouts.PendingRollouts = updatedRollouts
	cluster.Status.CertificateRollouts.RolloutsInProgress = hasPending

	return hasPending
}

// addPendingRollouts adds new pending rollouts to the cluster status
func (r *WazuhClusterReconciler) addPendingRollouts(cluster *wazuhv1alpha1.WazuhCluster, rollouts []utils.PendingRollout) {
	if cluster.Status.CertificateRollouts == nil {
		cluster.Status.CertificateRollouts = &wazuhv1alpha1.CertificateRolloutStatus{}
	}

	now := metav1.Now()
	cluster.Status.CertificateRollouts.LastRolloutTime = &now
	cluster.Status.CertificateRollouts.RolloutsInProgress = true

	for _, rollout := range rollouts {
		// Check if this component already has a pending rollout
		found := false
		for i, existing := range cluster.Status.CertificateRollouts.PendingRollouts {
			if existing.Component == rollout.Component && !existing.Ready {
				// Update existing rollout
				cluster.Status.CertificateRollouts.PendingRollouts[i] = wazuhv1alpha1.PendingCertRollout{
					Component:    rollout.Component,
					WorkloadName: rollout.Name,
					WorkloadType: string(rollout.Type),
					StartTime:    metav1.NewTime(rollout.StartTime),
					Reason:       rollout.Reason,
					Ready:        false,
				}
				found = true
				break
			}
		}

		if !found {
			cluster.Status.CertificateRollouts.PendingRollouts = append(
				cluster.Status.CertificateRollouts.PendingRollouts,
				wazuhv1alpha1.PendingCertRollout{
					Component:    rollout.Component,
					WorkloadName: rollout.Name,
					WorkloadType: string(rollout.Type),
					StartTime:    metav1.NewTime(rollout.StartTime),
					Reason:       rollout.Reason,
					Ready:        false,
				},
			)
		}
	}
}

// determineRequeueInterval determines the appropriate requeue interval based on cluster state
func (r *WazuhClusterReconciler) determineRequeueInterval(hasPendingRollouts bool) time.Duration {
	// Test mode always uses fast requeue
	if r.CertTestMode {
		return RequeueIntervalTestMode
	}

	// Drain in progress uses faster requeue
	if r.drainInProgress {
		return RequeueIntervalDrainInProgress
	}

	// Pending rollouts use faster requeue
	if hasPendingRollouts {
		return RequeueIntervalPendingRollout
	}

	// Normal operation
	return RequeueIntervalNormal
}

// handleDeletion handles cleanup when the WazuhCluster is deleted
func (r *WazuhClusterReconciler) handleDeletion(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(cluster, wazuhClusterFinalizer) {
		return ctrl.Result{}, nil
	}

	cluster.Status.Phase = wazuhv1alpha1.ClusterPhaseDeleting
	if err := r.Status().Update(ctx, cluster); err != nil {
		log.Error(err, "Failed to update status to Deleting")
	}

	log.Info("Performing cleanup for WazuhCluster")

	// Remove finalizer
	controllerutil.RemoveFinalizer(cluster, wazuhClusterFinalizer)
	if err := r.Update(ctx, cluster); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
	}

	log.Info("Successfully cleaned up WazuhCluster")
	return ctrl.Result{}, nil
}

// updateCondition updates a condition in the WazuhCluster status
func (r *WazuhClusterReconciler) updateCondition(cluster *wazuhv1alpha1.WazuhCluster, conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: cluster.Generation,
	}

	found := false
	for i, c := range cluster.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != status {
				cluster.Status.Conditions[i] = condition
			} else {
				condition.LastTransitionTime = c.LastTransitionTime
				cluster.Status.Conditions[i] = condition
			}
			found = true
			break
		}
	}

	if !found {
		cluster.Status.Conditions = append(cluster.Status.Conditions, condition)
	}
}

// updateStatus updates the WazuhCluster status based on component states
// Uses retry logic to handle optimistic locking conflicts
func (r *WazuhClusterReconciler) updateStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		// Re-fetch the latest cluster to avoid conflicts
		latestCluster := &wazuhv1alpha1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, latestCluster); err != nil {
			return err
		}

		allReady := true

		// Check Indexer status
		if status, err := r.IndexerReconciler.GetStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Indexer status")
		} else {
			latestCluster.Status.Indexer = status
			if status != nil && status.ReadyReplicas < status.Replicas {
				allReady = false
			}
		}

		// Check Manager status
		if status, err := r.ClusterReconciler.GetManagerStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Manager status")
		} else {
			latestCluster.Status.Manager = status
			if status != nil && status.ReadyReplicas < status.Replicas {
				allReady = false
			}
		}

		// Check Dashboard status
		if status, err := r.DashboardReconciler.GetStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Dashboard status")
		} else {
			latestCluster.Status.Dashboard = status
			if status != nil && status.ReadyReplicas < status.Replicas {
				allReady = false
			}
		}

		// Copy certificate rollout status from working cluster
		latestCluster.Status.CertificateRollouts = cluster.Status.CertificateRollouts
		latestCluster.Status.Security = cluster.Status.Security

		// Copy drain status from working cluster
		latestCluster.Status.Drain = cluster.Status.Drain

		// Update overall phase
		if allReady && latestCluster.Status.Indexer != nil && latestCluster.Status.Manager != nil && latestCluster.Status.Dashboard != nil {
			latestCluster.Status.Phase = wazuhv1alpha1.ClusterPhaseRunning
			r.updateCondition(latestCluster, wazuhv1alpha1.ConditionTypeReady, metav1.ConditionTrue, "ClusterReady", "All components are ready")
			r.updateCondition(latestCluster, wazuhv1alpha1.ConditionTypeAvailable, metav1.ConditionTrue, "ClusterAvailable", "Cluster is available")
		} else {
			latestCluster.Status.Phase = wazuhv1alpha1.ClusterPhaseCreating
			r.updateCondition(latestCluster, wazuhv1alpha1.ConditionTypeProgressing, metav1.ConditionTrue, "ComponentsStarting", "Waiting for components to be ready")
		}

		latestCluster.Status.ObservedGeneration = latestCluster.Generation
		now := metav1.Now()
		latestCluster.Status.LastUpdateTime = &now

		return r.Status().Update(ctx, latestCluster)
	})
}

// updateDrainStatus updates the drain status in the cluster
func (r *WazuhClusterReconciler) updateDrainStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		// Re-fetch the latest cluster to avoid conflicts
		latestCluster := &wazuhv1alpha1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, latestCluster); err != nil {
			return err
		}

		// Copy drain status from working cluster
		latestCluster.Status.Drain = cluster.Status.Drain

		now := metav1.Now()
		latestCluster.Status.LastUpdateTime = &now

		if err := r.Status().Update(ctx, latestCluster); err != nil {
			log.Error(err, "Failed to update drain status")
			return err
		}

		return nil
	})
}

// evaluateDryRun performs dry-run evaluation of drain feasibility
func (r *WazuhClusterReconciler) evaluateDryRun(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) *wazuhv1alpha1.DryRunResult {
	log := logf.FromContext(ctx)
	log.Info("Starting dry-run evaluation", "cluster", cluster.Name)

	result := &wazuhv1alpha1.DryRunResult{
		Feasible:    true,
		EvaluatedAt: metav1.Now(),
		Component:   "all",
	}

	// Evaluate indexer drain if configured
	if cluster.Spec.Drain != nil && cluster.Spec.Drain.Indexer != nil &&
		cluster.Spec.Drain.Indexer.Enabled != nil && *cluster.Spec.Drain.Indexer.Enabled {

		// Get target node for indexer
		var targetNode string
		if cluster.Status.Drain != nil && cluster.Status.Drain.Indexer != nil {
			targetNode = cluster.Status.Drain.Indexer.TargetPod
		}

		if targetNode == "" {
			// Try to determine from spec/status
			var desiredReplicas int32 = 3
			if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
				desiredReplicas = cluster.Spec.Indexer.Replicas
			}
			var currentReplicas int32 = 0
			if cluster.Status.Indexer != nil {
				currentReplicas = cluster.Status.Indexer.Replicas
			}
			if desiredReplicas < currentReplicas {
				targetNode = fmt.Sprintf("%s-indexer-%d", cluster.Name, currentReplicas-1)
			}
		}

		if targetNode != "" && r.IndexerReconciler != nil {
			indexerResult, err := r.IndexerReconciler.EvaluateDrainFeasibility(ctx, cluster, targetNode)
			if err != nil {
				log.Error(err, "Failed to evaluate indexer drain feasibility")
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("[indexer] Evaluation failed: %v", err))
			} else if indexerResult != nil {
				if !indexerResult.Feasible {
					result.Feasible = false
				}
				for _, blocker := range indexerResult.Blockers {
					result.Blockers = append(result.Blockers, fmt.Sprintf("[indexer] %s", blocker))
				}
				for _, warning := range indexerResult.Warnings {
					result.Warnings = append(result.Warnings, fmt.Sprintf("[indexer] %s", warning))
				}
				if indexerResult.EstimatedDuration != nil && result.EstimatedDuration == nil {
					result.EstimatedDuration = indexerResult.EstimatedDuration
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "[indexer] No scale-down detected")
		}
	}

	// Evaluate manager drain if configured
	if cluster.Spec.Drain != nil && cluster.Spec.Drain.Manager != nil &&
		cluster.Spec.Drain.Manager.Enabled != nil && *cluster.Spec.Drain.Manager.Enabled {

		// Get target node for manager
		var targetNode string
		if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil {
			targetNode = cluster.Status.Drain.Manager.TargetPod
		}

		if targetNode == "" {
			// Try to determine from spec
			var desiredReplicas int32 = 0
			if cluster.Spec.Manager != nil {
				desiredReplicas = cluster.Spec.Manager.Workers.GetReplicas()
			}
			// Check if drain status has previous replicas
			var currentReplicas int32 = 0
			if cluster.Status.Drain != nil && cluster.Status.Drain.Manager != nil &&
				cluster.Status.Drain.Manager.PreviousReplicas != nil {
				currentReplicas = *cluster.Status.Drain.Manager.PreviousReplicas
			}
			if desiredReplicas < currentReplicas {
				targetNode = fmt.Sprintf("%s-manager-worker-%d", cluster.Name, currentReplicas-1)
			}
		}

		if targetNode != "" && r.WorkerReconciler != nil {
			managerResult, err := r.WorkerReconciler.EvaluateDrainFeasibility(ctx, cluster, targetNode)
			if err != nil {
				log.Error(err, "Failed to evaluate manager drain feasibility")
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("[manager] Evaluation failed: %v", err))
			} else if managerResult != nil {
				if !managerResult.Feasible {
					result.Feasible = false
				}
				for _, blocker := range managerResult.Blockers {
					result.Blockers = append(result.Blockers, fmt.Sprintf("[manager] %s", blocker))
				}
				for _, warning := range managerResult.Warnings {
					result.Warnings = append(result.Warnings, fmt.Sprintf("[manager] %s", warning))
				}
				if managerResult.EstimatedDuration != nil {
					if result.EstimatedDuration != nil {
						// Add durations
						combined := result.EstimatedDuration.Duration + managerResult.EstimatedDuration.Duration
						result.EstimatedDuration = &metav1.Duration{Duration: combined}
					} else {
						result.EstimatedDuration = managerResult.EstimatedDuration
					}
				}
			}
		} else {
			result.Warnings = append(result.Warnings, "[manager] No scale-down detected")
		}
	}

	// Dashboard evaluation is simpler - just check PDB if it exists
	if cluster.Spec.Dashboard != nil {
		result.Warnings = append(result.Warnings, "[dashboard] PDB protection not yet implemented")
	}

	return result
}

// emitDryRunEvent emits a Kubernetes event with the dry-run result
func (r *WazuhClusterReconciler) emitDryRunEvent(cluster *wazuhv1alpha1.WazuhCluster, result *wazuhv1alpha1.DryRunResult) {
	if r.IndexerReconciler == nil || r.IndexerReconciler.Recorder == nil {
		return
	}

	recorder := r.IndexerReconciler.Recorder

	var message string
	if result.Feasible {
		message = fmt.Sprintf("Dry-run: scale-down is feasible")
		if result.EstimatedDuration != nil {
			message += fmt.Sprintf(" (estimated duration: %v)", result.EstimatedDuration.Duration)
		}
		if len(result.Warnings) > 0 {
			message += fmt.Sprintf(" with %d warning(s)", len(result.Warnings))
		}
		recorder.Event(cluster, corev1.EventTypeNormal, constants.DrainEventReasonDryRun, message)
	} else {
		message = fmt.Sprintf("Dry-run: scale-down blocked by %d issue(s)", len(result.Blockers))
		if len(result.Blockers) > 0 {
			message += fmt.Sprintf(": %s", result.Blockers[0])
		}
		recorder.Event(cluster, corev1.EventTypeWarning, constants.DrainEventReasonDryRun, message)
	}
}

// handleDrainFailure triggers rollback and schedules retry for a failed drain operation
func (r *WazuhClusterReconciler) handleDrainFailure(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, component string, failureReason string) error {
	log := logf.FromContext(ctx).WithValues("component", component)
	log.Info("Handling drain failure", "reason", failureReason)

	// Get drain status for the component
	var drainStatus *wazuhv1alpha1.ComponentDrainStatus
	if cluster.Status.Drain == nil {
		cluster.Status.Drain = &wazuhv1alpha1.DrainStatus{}
	}

	switch component {
	case constants.DrainComponentIndexer:
		if cluster.Status.Drain.Indexer == nil {
			cluster.Status.Drain.Indexer = &wazuhv1alpha1.ComponentDrainStatus{}
		}
		drainStatus = cluster.Status.Drain.Indexer
	case constants.DrainComponentManager:
		if cluster.Status.Drain.Manager == nil {
			cluster.Status.Drain.Manager = &wazuhv1alpha1.ComponentDrainStatus{}
		}
		drainStatus = cluster.Status.Drain.Manager
	default:
		return fmt.Errorf("unknown component: %s", component)
	}

	// Update status to Failed
	drainStatus.Phase = wazuhv1alpha1.DrainPhaseFailed
	drainStatus.Message = failureReason
	now := metav1.Now()
	drainStatus.LastTransitionTime = &now

	// Check if retry is allowed
	retryConfig := r.getRetryConfig(cluster)
	if r.RetryManager != nil && r.RetryManager.ShouldRetry(drainStatus, retryConfig) {
		// Trigger rollback
		if r.RollbackManager != nil {
			drainStatus.Phase = wazuhv1alpha1.DrainPhaseRollingBack
			if err := r.RollbackManager.ExecuteRollback(ctx, cluster, component); err != nil {
				log.Error(err, "Failed to execute rollback")
				drainStatus.Message = fmt.Sprintf("Rollback failed: %v", err)
				r.emitDrainEvent(cluster, component, constants.DrainEventReasonRollbackFailed, drainStatus.Message)
			} else {
				// Schedule retry
				r.RetryManager.IncrementAttempt(drainStatus, retryConfig)
				drainStatus.Message = fmt.Sprintf("Rollback complete. Retry %d/%d scheduled for %v",
					drainStatus.AttemptCount, retryConfig.MaxAttempts, drainStatus.NextRetryTime.Time)
				r.emitDrainEvent(cluster, component, constants.DrainEventReasonRollback, drainStatus.Message)
				log.Info("Rollback complete, retry scheduled",
					"attemptCount", drainStatus.AttemptCount,
					"nextRetry", drainStatus.NextRetryTime)
			}
		}
	} else {
		// Max retries reached
		drainStatus.Message = fmt.Sprintf("Drain failed: %s. Max retry attempts (%d) reached. Manual intervention required.",
			failureReason, retryConfig.MaxAttempts)
		r.emitDrainEvent(cluster, component, constants.DrainEventReasonMaxRetries, drainStatus.Message)
		log.Info("Max retry attempts reached, manual intervention required")
	}

	return r.updateDrainStatus(ctx, cluster)
}

// checkAndHandleRetry checks if a retry is due and initiates it
func (r *WazuhClusterReconciler) checkAndHandleRetry(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (bool, ctrl.Result) {
	log := logf.FromContext(ctx)

	if cluster.Status.Drain == nil {
		return false, ctrl.Result{}
	}

	// Check indexer retry
	if cluster.Status.Drain.Indexer != nil {
		drainStatus := cluster.Status.Drain.Indexer
		if drainStatus.Phase == wazuhv1alpha1.DrainPhaseFailed || drainStatus.Phase == wazuhv1alpha1.DrainPhaseRollingBack {
			if r.RetryManager != nil && r.RetryManager.IsRetryDue(drainStatus) {
				log.Info("Indexer drain retry is due", "attemptCount", drainStatus.AttemptCount)
				// Reset to pending to restart the drain
				drainStatus.Phase = wazuhv1alpha1.DrainPhasePending
				drainStatus.Message = fmt.Sprintf("Retry attempt %d starting", drainStatus.AttemptCount)
				r.emitDrainEvent(cluster, constants.DrainComponentIndexer, constants.DrainEventReasonRetry, drainStatus.Message)
				if err := r.updateDrainStatus(ctx, cluster); err != nil {
					log.Error(err, "Failed to update drain status for retry")
				}
				return true, ctrl.Result{Requeue: true}
			} else if drainStatus.NextRetryTime != nil {
				// Calculate time until next retry
				waitDuration := time.Until(drainStatus.NextRetryTime.Time)
				if waitDuration > 0 {
					log.V(1).Info("Waiting for indexer drain retry", "waitDuration", waitDuration)
					return true, ctrl.Result{RequeueAfter: waitDuration}
				}
			}
		}
	}

	// Check manager retry
	if cluster.Status.Drain.Manager != nil {
		drainStatus := cluster.Status.Drain.Manager
		if drainStatus.Phase == wazuhv1alpha1.DrainPhaseFailed || drainStatus.Phase == wazuhv1alpha1.DrainPhaseRollingBack {
			if r.RetryManager != nil && r.RetryManager.IsRetryDue(drainStatus) {
				log.Info("Manager drain retry is due", "attemptCount", drainStatus.AttemptCount)
				// Reset to pending to restart the drain
				drainStatus.Phase = wazuhv1alpha1.DrainPhasePending
				drainStatus.Message = fmt.Sprintf("Retry attempt %d starting", drainStatus.AttemptCount)
				r.emitDrainEvent(cluster, constants.DrainComponentManager, constants.DrainEventReasonRetry, drainStatus.Message)
				if err := r.updateDrainStatus(ctx, cluster); err != nil {
					log.Error(err, "Failed to update drain status for retry")
				}
				return true, ctrl.Result{Requeue: true}
			} else if drainStatus.NextRetryTime != nil {
				// Calculate time until next retry
				waitDuration := time.Until(drainStatus.NextRetryTime.Time)
				if waitDuration > 0 {
					log.V(1).Info("Waiting for manager drain retry", "waitDuration", waitDuration)
					return true, ctrl.Result{RequeueAfter: waitDuration}
				}
			}
		}
	}

	return false, ctrl.Result{}
}

// verifyRollbackComplete checks if rollback has completed for both components
func (r *WazuhClusterReconciler) verifyRollbackComplete(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	if r.RollbackManager == nil || cluster.Status.Drain == nil {
		return nil
	}

	// Check indexer rollback
	if cluster.Status.Drain.Indexer != nil && cluster.Status.Drain.Indexer.Phase == wazuhv1alpha1.DrainPhaseRollingBack {
		complete, err := r.RollbackManager.VerifyRollbackComplete(ctx, cluster, constants.DrainComponentIndexer)
		if err != nil {
			log.Error(err, "Failed to verify indexer rollback")
			return err
		}
		if complete {
			cluster.Status.Drain.Indexer.Phase = wazuhv1alpha1.DrainPhaseFailed
			cluster.Status.Drain.Indexer.Message = "Rollback complete, waiting for retry"
			log.Info("Indexer rollback verified complete")
		}
	}

	// Check manager rollback
	if cluster.Status.Drain.Manager != nil && cluster.Status.Drain.Manager.Phase == wazuhv1alpha1.DrainPhaseRollingBack {
		complete, err := r.RollbackManager.VerifyRollbackComplete(ctx, cluster, constants.DrainComponentManager)
		if err != nil {
			log.Error(err, "Failed to verify manager rollback")
			return err
		}
		if complete {
			cluster.Status.Drain.Manager.Phase = wazuhv1alpha1.DrainPhaseFailed
			cluster.Status.Drain.Manager.Message = "Rollback complete, waiting for retry"
			log.Info("Manager rollback verified complete")
		}
	}

	return nil
}

// getRetryConfig returns the retry configuration from the cluster spec or defaults
func (r *WazuhClusterReconciler) getRetryConfig(cluster *wazuhv1alpha1.WazuhCluster) *wazuhv1alpha1.DrainRetryConfig {
	if cluster.Spec.Drain != nil && cluster.Spec.Drain.Retry != nil {
		return cluster.Spec.Drain.Retry
	}
	// Return default configuration
	return &wazuhv1alpha1.DrainRetryConfig{
		MaxAttempts:       constants.DefaultDrainRetryMaxAttempts,
		InitialDelay:      &metav1.Duration{Duration: constants.DefaultDrainRetryInitialDelay},
		BackoffMultiplier: fmt.Sprintf("%.1f", constants.DefaultDrainRetryBackoffMultiplier),
		MaxDelay:          &metav1.Duration{Duration: constants.DefaultDrainRetryMaxDelay},
	}
}

// emitDrainEvent emits a Kubernetes event for drain operations
func (r *WazuhClusterReconciler) emitDrainEvent(cluster *wazuhv1alpha1.WazuhCluster, component, reason, message string) {
	if r.IndexerReconciler == nil || r.IndexerReconciler.Recorder == nil {
		return
	}

	recorder := r.IndexerReconciler.Recorder
	eventType := corev1.EventTypeNormal
	if reason == constants.DrainEventReasonFailed || reason == constants.DrainEventReasonRollbackFailed || reason == constants.DrainEventReasonMaxRetries {
		eventType = corev1.EventTypeWarning
	}
	recorder.Event(cluster, eventType, reason, fmt.Sprintf("[%s] %s", component, message))
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.WazuhCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Named("wazuhcluster").
		Complete(r)
}
