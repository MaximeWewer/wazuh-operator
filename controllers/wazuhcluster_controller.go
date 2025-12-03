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
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

const (
	wazuhClusterFinalizer = "resources.wazuh.com/finalizer"

	// RequeueIntervalNormal is the normal requeue interval when cluster is stable
	RequeueIntervalNormal = 30 * time.Second

	// RequeueIntervalPendingRollout is the faster requeue interval when rollouts are pending
	RequeueIntervalPendingRollout = 5 * time.Second

	// RequeueIntervalTestMode is the requeue interval when test mode is enabled
	RequeueIntervalTestMode = 5 * time.Second
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
	MonitoringReconciler  *monitoring.MonitoringReconciler

	// CertTestMode enables faster reconciliation for certificate testing
	CertTestMode bool

	// UseNonBlockingRollouts enables non-blocking certificate rollouts
	UseNonBlockingRollouts bool
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

	// 2. Reconcile Indexer
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

	// 3. Check Security Initialization (after indexer is up)
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

	// 5. Reconcile Manager with certificate hashes for pod restart on cert renewal
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

	// 6. Reconcile Log Rotation CronJob (if enabled)
	if err := r.ClusterReconciler.ReconcileLogRotation(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile log rotation")
		// Non-fatal, continue - log rotation is an optional feature
	}

	// 7. Reconcile Dashboard with certificate hash for pod restart on cert renewal
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

	// 8. Reconcile Monitoring resources (ServiceMonitors) if enabled
	if r.MonitoringReconciler != nil {
		if err := r.MonitoringReconciler.Reconcile(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Monitoring resources")
			// Non-fatal, continue - monitoring CRD might not be installed
		}
	}

	// 9. Check for indexer restart and re-sync if needed
	if restarted, err := r.IndexerReconciler.DetectIndexerRestart(ctx, cluster); err != nil {
		log.Error(err, "Failed to detect indexer restart")
	} else if restarted && securityInitialized {
		log.Info("Indexer restart detected, re-syncing security CRDs")
		if err := r.IndexerReconciler.SyncSecurityCRDs(ctx, cluster); err != nil {
			log.Error(err, "Failed to re-sync security CRDs after restart")
		}
	}

	// 10. Update pending rollouts status
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
