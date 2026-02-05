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

package controllers

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkingv1 "k8s.io/api/networking/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/validation"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	networkingreconciler "github.com/MaximeWewer/wazuh-operator/internal/networking/reconciler"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

const (
	wazuhClusterFinalizer = "resources.wazuh.com/finalizer"

	// RequeueIntervalNormal is the normal requeue interval when cluster is stable
	RequeueIntervalNormal = 30 * time.Second

	// RequeueIntervalPendingRollout is the faster requeue interval when rollouts are pending
	RequeueIntervalPendingRollout = 5 * time.Second

	// RequeueIntervalDrainInProgress is the requeue interval when a drain is in progress
	RequeueIntervalDrainInProgress = 10 * time.Second
)

// WazuhClusterReconciler reconciles a WazuhCluster object
// This is a thin controller that delegates to helper reconcilers
type WazuhClusterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconcilers
	ClusterReconciler     *wazuhreconciler.ClusterReconciler
	CertificateReconciler *wazuhreconciler.CertificateReconciler
	IndexerReconciler     *opensearchreconciler.IndexerReconciler
	DashboardReconciler   *opensearchreconciler.DashboardReconciler
	WorkerReconciler      *wazuhreconciler.WorkerReconciler
	MonitoringReconciler  *monitoring.MonitoringReconciler
	GatewayReconciler     *networkingreconciler.GatewayReconciler
	IngressReconciler     *networkingreconciler.IngressReconciler

	// Drain management
	RollbackManager *drain.RollbackManagerImpl
	RetryManager    *drain.RetryManagerImpl

	// UseNonBlockingRollouts enables non-blocking certificate rollouts
	UseNonBlockingRollouts bool

	// GatewayAPIEnabled indicates if Gateway API support is enabled in operator config
	GatewayAPIEnabled bool

	// Gateway API CRD availability flags - set based on runtime CRD detection
	HTTPRouteAvailable bool
	TCPRouteAvailable  bool
	UDPRouteAvailable  bool

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
// +kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop for WazuhCluster
func (r *WazuhClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhCluster.Reconcile",
		telemetry.WithAttributes(
			attribute.String("namespace", req.Namespace),
			attribute.String("name", req.Name),
		))
	defer span.End()

	// Track reconciliation metrics
	startTime := time.Now()
	var reconcileResult = "success"
	defer func() {
		duration := time.Since(startTime).Seconds()
		metrics.RecordReconciliation("WazuhCluster", req.Namespace, reconcileResult, duration)
	}()

	log := logf.FromContext(ctx)

	// Fetch the WazuhCluster instance
	cluster := &wazuhv1.WazuhCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhCluster resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhCluster")
		reconcileResult = "error"
		telemetry.RecordError(span, err)
		metrics.RecordReconciliationError("WazuhCluster", req.Namespace, "get_failed")
		return ctrl.Result{}, err
	}

	// Add cluster info to span
	span.SetAttributes(
		attribute.String("cluster.version", cluster.Spec.Version),
		attribute.String("cluster.phase", string(cluster.Status.Phase)),
	)

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
	if cluster.Status.Phase == "" || cluster.Status.Phase == wazuhv1.ClusterPhasePending {
		cluster.Status.Phase = wazuhv1.ClusterPhaseCreating
		cluster.Status.Version = cluster.Spec.Version
		if err := r.Status().Update(ctx, cluster); err != nil {
			log.Error(err, "Failed to update WazuhCluster status to Creating")
			return ctrl.Result{}, err
		}
	}

	// Validate configuration mode - reject mixed mode (inline + reference)
	if cluster.IsMixedMode() {
		err := fmt.Errorf("invalid configuration: cannot mix inline mode and reference mode. " +
			"Use either inline specs (manager/indexer/dashboard) OR references (managerRef/indexerRef/dashboardRef), not both")

		log.Error(err, "Mixed mode configuration detected")
		r.Recorder.Event(cluster, corev1.EventTypeWarning, "InvalidMode", err.Error())

		r.updateCondition(cluster, wazuhv1.ConditionTypeReady, metav1.ConditionFalse,
			"InvalidMode", err.Error())

		if statusErr := r.Status().Update(ctx, cluster); statusErr != nil {
			log.Error(statusErr, "Failed to update status for mixed mode validation")
		}

		return ctrl.Result{}, err
	}

	// Validate indexer topology configuration (simple vs advanced mode)
	if cluster.Spec.Indexer != nil {
		validationResult := validation.ValidateNodePools(cluster.Spec.Indexer)
		if !validationResult.Valid {
			for _, valErr := range validationResult.Errors {
				log.Error(fmt.Errorf("%s", valErr.Message), "NodePool validation failed", "field", valErr.Field)
			}
			// Emit event for validation failure
			r.emitDrainEvent(cluster, constants.DrainComponentIndexer, "ValidationFailed",
				fmt.Sprintf("NodePool validation failed: %s", validationResult.Errors[0].Message))

			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse,
				"NodePoolValidationFailed", validationResult.Errors[0].Message)

			// Don't proceed with reconciliation if validation fails
			return ctrl.Result{}, fmt.Errorf("nodePool validation failed: %s", validationResult.Errors[0].Message)
		}

		// Log warnings but continue
		for _, warning := range validationResult.Warnings {
			log.Info("NodePool validation warning", "warning", warning)
		}

		// Initialize Indexer status if nil
		if cluster.Status.Indexer == nil {
			cluster.Status.Indexer = &wazuhv1.ComponentStatus{}
		}

		// Update topology mode in status
		if cluster.Spec.Indexer.IsAdvancedMode() {
			if cluster.Status.Indexer.TopologyMode != constants.TopologyModeAdvanced {
				cluster.Status.Indexer.TopologyMode = constants.TopologyModeAdvanced
				log.Info("Detected advanced indexer topology mode with nodePools",
					"poolCount", len(cluster.Spec.Indexer.NodePools))
			}
		} else {
			if cluster.Status.Indexer.TopologyMode != constants.TopologyModeSimple {
				cluster.Status.Indexer.TopologyMode = constants.TopologyModeSimple
				log.V(1).Info("Using simple indexer topology mode")
			}
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

	// Resolve component references if using reference mode
	// This populates cluster.Spec inline fields from referenced CRs
	// so existing reconcilers can work transparently with both modes
	if cluster.IsReferenceMode() {
		log.Info("Reference mode detected - resolving component references")

		// Resolve WazuhManager reference
		if cluster.Spec.ManagerRef != nil {
			manager, err := r.resolveManagerRef(ctx, cluster)
			if err != nil {
				log.Error(err, "Failed to resolve WazuhManager reference")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse,
					"ManagerRefResolutionFailed", err.Error())
				return ctrl.Result{}, err
			}
			if manager != nil {
				// Populate inline spec from referenced CR
				cluster.Spec.Manager = &wazuhv1.WazuhManagerClusterSpec{
					Master:                      manager.Spec.Master,
					Workers:                     manager.Spec.Workers,
					ClusterKeySecretRef:         manager.Spec.ClusterKeySecretRef,
					APICredentials:              manager.Spec.APICredentials,
					AuthdPasswordSecretRef:      manager.Spec.AuthdPasswordSecretRef,
					Image:                       manager.Spec.Image,
					Config:                      manager.Spec.Config,
					FilebeatSSLVerificationMode: manager.Spec.FilebeatSSLVerificationMode,
				}
				log.V(1).Info("Populated inline Manager spec from reference", "managerName", manager.Name)
			}
		}

		// Resolve OpenSearchIndexer reference
		if cluster.Spec.IndexerRef != nil {
			indexer, err := r.resolveIndexerRef(ctx, cluster)
			if err != nil {
				log.Error(err, "Failed to resolve OpenSearchIndexer reference")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse,
					"IndexerRefResolutionFailed", err.Error())
				return ctrl.Result{}, err
			}
			if indexer != nil {
				// Populate inline spec from referenced CR
				cluster.Spec.Indexer = &wazuhv1.WazuhIndexerClusterSpec{
					Replicas:     indexer.Spec.Replicas,
					NodePools:    nil, // NodePools not supported in OpenSearchIndexer CRD
					Resources:    indexer.Spec.Resources,
					StorageSize:  indexer.Spec.StorageSize,
					Image:        indexer.Spec.Image,
					JavaOpts:     indexer.Spec.JavaOpts,
					ClusterName:  indexer.Spec.ClusterName,
					Credentials:  indexer.Spec.Credentials,
					Service:      indexer.Spec.Service,
					NodeSelector: indexer.Spec.NodeSelector,
					Tolerations:  indexer.Spec.Tolerations,
					Affinity:     indexer.Spec.Affinity,
				}
				log.V(1).Info("Populated inline Indexer spec from reference", "indexerName", indexer.Name)
			}
		}

		// Resolve OpenSearchDashboard reference
		if cluster.Spec.DashboardRef != nil {
			dashboard, err := r.resolveDashboardRef(ctx, cluster)
			if err != nil {
				log.Error(err, "Failed to resolve OpenSearchDashboard reference")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse,
					"DashboardRefResolutionFailed", err.Error())
				return ctrl.Result{}, err
			}
			if dashboard != nil {
				// Populate inline spec from referenced CR
				cluster.Spec.Dashboard = &wazuhv1.WazuhDashboardClusterSpec{
					Replicas:     dashboard.Spec.Replicas,
					Resources:    dashboard.Spec.Resources,
					Image:        dashboard.Spec.Image,
					EnableSSL:    dashboard.Spec.EnableSSL,
					Service:      dashboard.Spec.Service,
					NodeSelector: dashboard.Spec.NodeSelector,
					Tolerations:  dashboard.Spec.Tolerations,
					Affinity:     dashboard.Spec.Affinity,
				}
				log.V(1).Info("Populated inline Dashboard spec from reference", "dashboardName", dashboard.Name)
			}
		}

		log.Info("Component references resolved successfully", "mode", "reference")
	} else if cluster.IsInlineMode() {
		log.V(1).Info("Using inline mode", "mode", "inline")
	}

	// Validate manager HA configuration and emit warning if not HA
	if cluster.Spec.Manager != nil && !cluster.Spec.Manager.IsHA() {
		totalReplicas := cluster.Spec.Manager.GetTotalReplicas()
		log.Info("Manager cluster is not configured for high availability",
			"totalReplicas", totalReplicas,
			"minRecommended", 3)
		r.Recorder.Event(cluster, corev1.EventTypeWarning, "NotHighlyAvailable",
			fmt.Sprintf("Manager cluster has only %d node(s). Minimum 3 nodes recommended for high availability (1 master + 2 workers)", totalReplicas))
	}

	// Validate indexer HA configuration and emit warning if not HA
	if cluster.Spec.Indexer != nil && !cluster.Spec.Indexer.IsHA() {
		totalReplicas := cluster.Spec.Indexer.GetTotalReplicas()
		log.Info("Indexer cluster is not configured for high availability",
			"totalReplicas", totalReplicas,
			"minRecommended", 3)
		r.Recorder.Event(cluster, corev1.EventTypeWarning, "NotHighlyAvailable",
			fmt.Sprintf("Indexer cluster has only %d node(s). Minimum 3 nodes recommended for high availability and proper quorum", totalReplicas))
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
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "CertificatesFailed", certErr.Error())
			return ctrl.Result{}, certErr
		}
	} else {
		// Fallback to ClusterReconciler for basic certificate creation
		if err := r.ClusterReconciler.ReconcileCertificates(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile certificates")
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "CertificatesFailed", err.Error())
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
				cluster.Status.Drain = &wazuhv1.DrainStatus{}
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
				cluster.Status.Drain = &wazuhv1.DrainStatus{}
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
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "IndexerFailed", result.Error.Error())
			return ctrl.Result{}, result.Error
		}
		if result.PendingRollout != nil {
			newPendingRollouts = append(newPendingRollouts, *result.PendingRollout)
		}
	} else {
		if err := r.IndexerReconciler.ReconcileWithCertHash(ctx, cluster, indexerCertHash); err != nil {
			log.Error(err, "Failed to reconcile Indexer")
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "IndexerFailed", err.Error())
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
		r.updateCondition(cluster, wazuhv1.ConditionTypeSecurityReady, metav1.ConditionTrue, "SecurityInitialized", "OpenSearch security plugin is initialized")

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
		r.updateCondition(cluster, wazuhv1.ConditionTypeSecurityReady, metav1.ConditionFalse, "SecurityPending", "Waiting for OpenSearch security to initialize")
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
				cluster.Status.Drain = &wazuhv1.DrainStatus{}
			}

			// Requeue to check drain progress
			return ctrl.Result{RequeueAfter: RequeueIntervalDrainInProgress}, r.updateDrainStatus(ctx, cluster)
		} else if drainResult != nil && drainResult.DrainComplete {
			// Drain is complete, proceed with normal reconciliation
			log.Info("Manager worker drain complete, proceeding with scale-down")
			r.drainInProgress = false
			// Reset drain state after scale-down is applied
			defer r.WorkerReconciler.ResetDrainState(cluster)
		} else if r.drainInProgress {
			// No drain needed or drain not configured
			r.drainInProgress = false
		}
	}

	// 6. Reconcile Manager with certificate hashes for pod restart on cert renewal
	if certHashes != nil {
		if r.UseNonBlockingRollouts {
			result := r.ClusterReconciler.ReconcileManagerNonBlocking(ctx, cluster, certHashes.ManagerMasterCertHash, certHashes.ManagerWorkerCertHash)
			if result.Error != nil {
				log.Error(result.Error, "Failed to reconcile Manager (non-blocking)")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", result.Error.Error())
				return ctrl.Result{}, result.Error
			}
			newPendingRollouts = append(newPendingRollouts, result.PendingRollouts...)
		} else {
			if err := r.ClusterReconciler.ReconcileManagerWithCertHashes(ctx, cluster, certHashes.ManagerMasterCertHash, certHashes.ManagerWorkerCertHash); err != nil {
				log.Error(err, "Failed to reconcile Manager with cert hashes")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else {
		// Fallback to regular reconciliation without cert hashes
		if err := r.ClusterReconciler.ReconcileManager(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Manager")
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "ManagerFailed", err.Error())
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
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", result.Error.Error())
				return ctrl.Result{}, result.Error
			}
			if result.PendingRollout != nil {
				newPendingRollouts = append(newPendingRollouts, *result.PendingRollout)
			}
		} else {
			if err := r.DashboardReconciler.ReconcileWithCertHash(ctx, cluster, certHashes.DashboardCertHash); err != nil {
				log.Error(err, "Failed to reconcile Dashboard with cert hash")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else {
		// Fallback to regular reconciliation without cert hash
		if err := r.DashboardReconciler.Reconcile(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile Dashboard")
			r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "DashboardFailed", err.Error())
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

	// 10. Reconcile Gateway API routes (HTTPRoute, TCPRoute, UDPRoute) if enabled
	if hasGatewayAPIEnabled(cluster) {
		if !r.GatewayAPIEnabled {
			// User has configured GatewayAPI on their cluster but operator doesn't have Gateway API support enabled
			log.Info("GatewayAPI is configured on WazuhCluster but Gateway API support is DISABLED in the operator",
				"hint", "Enable Gateway API support by setting gatewayAPI.enabled=true in the Helm values or GATEWAY_API_ENABLED=true env var")
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "GatewayAPIDisabled",
				"GatewayAPI is configured but operator Gateway API support is disabled. "+
					"Enable with: helm upgrade --set gatewayAPI.enabled=true or set GATEWAY_API_ENABLED=true")
		} else if r.GatewayReconciler != nil {
			if err := r.GatewayReconciler.Reconcile(ctx, cluster); err != nil {
				log.Error(err, "Failed to reconcile Gateway API routes")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "GatewayAPIFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else if r.GatewayAPIEnabled && r.GatewayReconciler != nil {
		// Gateway API is enabled in operator but not configured on this cluster
		// Still call reconciler to clean up any orphaned routes
		if err := r.GatewayReconciler.Reconcile(ctx, cluster); err != nil {
			log.V(1).Info("Failed to reconcile Gateway API routes (non-fatal)", "error", err)
		}
	}
	log.V(1).Info("Gateway API reconciliation completed")

	// 11. Reconcile Ingress resources if any component has Ingress enabled
	if hasIngressEnabled(cluster) {
		if r.IngressReconciler != nil {
			if err := r.IngressReconciler.Reconcile(ctx, cluster); err != nil {
				log.Error(err, "Failed to reconcile Ingress resources")
				r.updateCondition(cluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionFalse, "IngressFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else if r.IngressReconciler != nil {
		// Ingress is not configured on this cluster
		// Still call reconciler to clean up any orphaned ingresses
		if err := r.IngressReconciler.Reconcile(ctx, cluster); err != nil {
			log.V(1).Info("Failed to reconcile Ingress resources (non-fatal)", "error", err)
		}
	}
	log.V(1).Info("Ingress reconciliation completed")

	// 13. Check for indexer restart and re-sync if needed
	if restarted, err := r.IndexerReconciler.DetectIndexerRestart(ctx, cluster); err != nil {
		log.Error(err, "Failed to detect indexer restart")
	} else if restarted && securityInitialized {
		log.Info("Indexer restart detected, re-syncing security CRDs")
		if err := r.IndexerReconciler.SyncSecurityCRDs(ctx, cluster); err != nil {
			log.Error(err, "Failed to re-sync security CRDs after restart")
		}
	}

	// 14. Update pending rollouts status
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
func (r *WazuhClusterReconciler) checkAndUpdatePendingRollouts(ctx context.Context, cluster *wazuhv1.WazuhCluster) bool {
	log := logf.FromContext(ctx)

	if cluster.Status.CertificateRollouts == nil || len(cluster.Status.CertificateRollouts.PendingRollouts) == 0 {
		return false
	}

	waiter := utils.NewRolloutWaiter(r.Client)
	hasPending := false
	updatedRollouts := make([]wazuhv1.PendingCertRollout, 0, len(cluster.Status.CertificateRollouts.PendingRollouts))

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

		status := waiter.CheckRolloutStatus(ctx, &pendingRollout)

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
func (r *WazuhClusterReconciler) addPendingRollouts(cluster *wazuhv1.WazuhCluster, rollouts []utils.PendingRollout) {
	if cluster.Status.CertificateRollouts == nil {
		cluster.Status.CertificateRollouts = &wazuhv1.CertificateRolloutStatus{}
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
				cluster.Status.CertificateRollouts.PendingRollouts[i] = wazuhv1.PendingCertRollout{
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
				wazuhv1.PendingCertRollout{
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
//
//nolint:unparam // ctrl.Result is always empty, requeue handled via error
func (r *WazuhClusterReconciler) handleDeletion(ctx context.Context, cluster *wazuhv1.WazuhCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(cluster, wazuhClusterFinalizer) {
		return ctrl.Result{}, nil
	}

	cluster.Status.Phase = wazuhv1.ClusterPhaseDeleting
	if err := r.Status().Update(ctx, cluster); err != nil {
		log.Error(err, "Failed to update status to Deleting")
	}

	log.Info("Performing cleanup for WazuhCluster",
		"namespace", cluster.Namespace,
		"name", cluster.Name)

	// Perform cleanup of all resources
	if err := r.cleanupResources(ctx, cluster); err != nil {
		log.Error(err, "Failed to cleanup resources")
		return ctrl.Result{}, fmt.Errorf("failed to cleanup resources: %w", err)
	}

	// Record event for successful cleanup
	r.Recorder.Event(cluster, corev1.EventTypeNormal, "Cleanup", "All resources cleaned up successfully")

	// Remove finalizer after successful cleanup
	controllerutil.RemoveFinalizer(cluster, wazuhClusterFinalizer)
	if err := r.Update(ctx, cluster); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
	}

	log.Info("Successfully cleaned up WazuhCluster")
	return ctrl.Result{}, nil
}

// cleanupResources deletes all Kubernetes resources created by the WazuhCluster CR
// This includes StatefulSets, Deployments, Services, ConfigMaps, and Secrets
// Note: PVCs are handled automatically by Kubernetes garbage collection based on reclaim policy
func (r *WazuhClusterReconciler) cleanupResources(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	namespace := cluster.Namespace
	name := cluster.Name

	// Delete StatefulSets - workloads first
	statefulSetsToDelete := []string{
		name + "-manager-master",
		name + "-manager-worker",
		name + "-indexer",
	}

	for _, stsName := range statefulSetsToDelete {
		sts := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      stsName,
				Namespace: namespace,
			},
		}
		if err := r.Delete(ctx, sts); err != nil && !errors.IsNotFound(err) {
			log.Error(err, "Failed to delete StatefulSet", "statefulset", stsName)
			return fmt.Errorf("failed to delete StatefulSet %s/%s: %w", namespace, stsName, err)
		}
		log.Info("Deleted StatefulSet", "statefulset", stsName, "namespace", namespace)
	}

	// Delete Dashboard Deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-dashboard",
			Namespace: namespace,
		},
	}
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to delete Deployment", "deployment", name+"-dashboard")
		return fmt.Errorf("failed to delete Deployment %s/%s: %w", namespace, name+"-dashboard", err)
	}
	log.Info("Deleted Deployment", "deployment", name+"-dashboard", "namespace", namespace)

	// Delete Services
	servicesToDelete := []string{
		name + "-manager-master",
		name + "-manager-master-headless",
		name + "-manager-worker",
		name + "-manager-worker-headless",
		name + "-indexer",
		name + "-indexer-headless",
		name + "-dashboard",
		name + "-agents", // Agent registration service if exists
	}

	for _, svcName := range servicesToDelete {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: namespace,
			},
		}
		if err := r.Delete(ctx, svc); err != nil && !errors.IsNotFound(err) {
			log.Error(err, "Failed to delete Service", "service", svcName)
			return fmt.Errorf("failed to delete Service %s/%s: %w", namespace, svcName, err)
		}
		log.Info("Deleted Service", "service", svcName, "namespace", namespace)
	}

	// Delete ConfigMaps
	configMapsToDelete := []string{
		name + "-manager-master-config",
		name + "-manager-worker-config",
		name + "-indexer-config",
		name + "-dashboard-config",
		name + "-filebeat-config",
	}

	for _, cmName := range configMapsToDelete {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: namespace,
			},
		}
		if err := r.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
			log.Error(err, "Failed to delete ConfigMap", "configmap", cmName)
			return fmt.Errorf("failed to delete ConfigMap %s/%s: %w", namespace, cmName, err)
		}
		log.Info("Deleted ConfigMap", "configmap", cmName, "namespace", namespace)
	}

	// Delete Secrets - TLS certificates and credentials
	secretsToDelete := []string{
		name + "-manager-master-certs",
		name + "-manager-worker-certs",
		name + "-indexer-certs",
		name + "-indexer-security",    // OpenSearch security config (internal_users.yml, roles_mapping.yml)
		name + "-indexer-credentials", // Admin credentials for indexer (FIXED: was -admin-credentials)
		name + "-dashboard-certs",
		name + "-admin-certs",     // Admin certificates for securityadmin tool
		name + "-filebeat-certs",  // Filebeat TLS certificates (FIXED: was -filebeat-credentials)
		name + "-cluster-key",     // Wazuh cluster encryption key
		name + "-api-credentials", // Wazuh API credentials
	}

	for _, secretName := range secretsToDelete {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
		}
		if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
			log.Error(err, "Failed to delete Secret", "secret", secretName)
			return fmt.Errorf("failed to delete Secret %s/%s: %w", namespace, secretName, err)
		}
		log.Info("Deleted Secret", "secret", secretName, "namespace", namespace)
	}

	// Note: PVCs are NOT explicitly deleted here
	// They are handled by Kubernetes garbage collection via owner references:
	// - PVCs with Delete reclaim policy will be automatically deleted
	// - PVCs with Retain reclaim policy will remain for manual cleanup
	log.Info("PVCs cleanup handled by Kubernetes garbage collection based on reclaim policy")

	log.Info("All resources cleaned up successfully")
	return nil
}

// updateCondition updates a condition in the WazuhCluster status
func (r *WazuhClusterReconciler) updateCondition(cluster *wazuhv1.WazuhCluster, conditionType string, status metav1.ConditionStatus, reason, message string) {
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
func (r *WazuhClusterReconciler) updateStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		// Re-fetch the latest cluster to avoid conflicts
		latestCluster := &wazuhv1.WazuhCluster{}
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
			latestCluster.Status.Phase = wazuhv1.ClusterPhaseRunning
			r.updateCondition(latestCluster, wazuhv1.ConditionTypeReady, metav1.ConditionTrue, "ClusterReady", "All components are ready")
			r.updateCondition(latestCluster, wazuhv1.ConditionTypeAvailable, metav1.ConditionTrue, "ClusterAvailable", "Cluster is available")
			// Record cluster ready metric
			metrics.SetWazuhClusterStatus(latestCluster.Name, latestCluster.Namespace, true)
			// Collect agent metrics when cluster is ready (non-blocking, best-effort)
			go r.collectWazuhAgentMetrics(ctx, latestCluster)
		} else {
			latestCluster.Status.Phase = wazuhv1.ClusterPhaseCreating
			r.updateCondition(latestCluster, wazuhv1.ConditionTypeProgressing, metav1.ConditionTrue, "ComponentsStarting", "Waiting for components to be ready")
			// Record cluster not ready metric
			metrics.SetWazuhClusterStatus(latestCluster.Name, latestCluster.Namespace, false)
		}

		// Record manager node metrics
		if latestCluster.Status.Manager != nil {
			// Count master nodes (always 1 in current design)
			metrics.SetWazuhManagerNodes(latestCluster.Name, latestCluster.Namespace, "master", "ready", 1)
			// Count worker nodes
			workerCount := int(latestCluster.Status.Manager.ReadyReplicas) - 1
			if workerCount < 0 {
				workerCount = 0
			}
			metrics.SetWazuhManagerNodes(latestCluster.Name, latestCluster.Namespace, "worker", "ready", workerCount)
		}

		latestCluster.Status.ObservedGeneration = latestCluster.Generation
		now := metav1.Now()
		latestCluster.Status.LastUpdateTime = &now

		return r.Status().Update(ctx, latestCluster)
	})
}

// collectWazuhAgentMetrics collects agent statistics from the Wazuh API
// This runs asynchronously to avoid blocking the reconciliation loop
func (r *WazuhClusterReconciler) collectWazuhAgentMetrics(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	// Get manager service URL
	managerServiceName := cluster.Name + "-manager"
	baseURL := fmt.Sprintf("https://%s:%d",
		dns.ServiceFQDN(managerServiceName, cluster.Namespace), constants.PortManagerAPI)

	// Get credentials from secret
	credSecret := &corev1.Secret{}
	secretName := fmt.Sprintf("%s-wazuh-api", cluster.Name)
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, credSecret); err != nil {
		log.V(1).Info("Cannot get Wazuh API credentials for metrics", "error", err)
		return
	}

	username := string(credSecret.Data["username"])
	password := string(credSecret.Data["password"])
	if username == "" || password == "" {
		log.V(1).Info("Wazuh API credentials incomplete, skipping agent metrics")
		return
	}

	// Create API adapter
	wazuhClient := adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Insecure: true, // Internal cluster communication
	})

	// Get agent summary
	summary, err := wazuhClient.GetAgentsSummary(ctx)
	if err != nil {
		log.V(1).Info("Failed to get agent summary for metrics", "error", err)
		return
	}

	// Record agent metrics
	metrics.SetWazuhAgentsConnected(cluster.Name, cluster.Namespace, summary.Active)
}

// updateDrainStatus updates the drain status in the cluster
func (r *WazuhClusterReconciler) updateDrainStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		// Re-fetch the latest cluster to avoid conflicts
		latestCluster := &wazuhv1.WazuhCluster{}
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
func (r *WazuhClusterReconciler) evaluateDryRun(ctx context.Context, cluster *wazuhv1.WazuhCluster) *wazuhv1.DryRunResult {
	log := logf.FromContext(ctx)
	log.Info("Starting dry-run evaluation", "cluster", cluster.Name)

	result := &wazuhv1.DryRunResult{
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
			var currentReplicas int32
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
			var desiredReplicas int32
			if cluster.Spec.Manager != nil {
				desiredReplicas = cluster.Spec.Manager.Workers.GetReplicas()
			}
			// Check if drain status has previous replicas
			var currentReplicas int32
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
func (r *WazuhClusterReconciler) emitDryRunEvent(cluster *wazuhv1.WazuhCluster, result *wazuhv1.DryRunResult) {
	if r.IndexerReconciler == nil || r.IndexerReconciler.Recorder == nil {
		return
	}

	recorder := r.IndexerReconciler.Recorder

	var message string
	if result.Feasible {
		message = "Dry-run: scale-down is feasible"
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

// checkAndHandleRetry checks if a retry is due and initiates it
func (r *WazuhClusterReconciler) checkAndHandleRetry(ctx context.Context, cluster *wazuhv1.WazuhCluster) (bool, ctrl.Result) {
	log := logf.FromContext(ctx)

	if cluster.Status.Drain == nil {
		return false, ctrl.Result{}
	}

	// Check indexer retry
	if cluster.Status.Drain.Indexer != nil {
		drainStatus := cluster.Status.Drain.Indexer
		if drainStatus.Phase == wazuhv1.DrainPhaseFailed || drainStatus.Phase == wazuhv1.DrainPhaseRollingBack {
			if r.RetryManager != nil && r.RetryManager.IsRetryDue(drainStatus) {
				log.Info("Indexer drain retry is due", "attemptCount", drainStatus.AttemptCount)
				// Reset to pending to restart the drain
				drainStatus.Phase = wazuhv1.DrainPhasePending
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
		if drainStatus.Phase == wazuhv1.DrainPhaseFailed || drainStatus.Phase == wazuhv1.DrainPhaseRollingBack {
			if r.RetryManager != nil && r.RetryManager.IsRetryDue(drainStatus) {
				log.Info("Manager drain retry is due", "attemptCount", drainStatus.AttemptCount)
				// Reset to pending to restart the drain
				drainStatus.Phase = wazuhv1.DrainPhasePending
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
func (r *WazuhClusterReconciler) verifyRollbackComplete(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	if r.RollbackManager == nil || cluster.Status.Drain == nil {
		return nil
	}

	// Check indexer rollback
	if cluster.Status.Drain.Indexer != nil && cluster.Status.Drain.Indexer.Phase == wazuhv1.DrainPhaseRollingBack {
		complete, err := r.RollbackManager.VerifyRollbackComplete(ctx, cluster, constants.DrainComponentIndexer)
		if err != nil {
			log.Error(err, "Failed to verify indexer rollback")
			return err
		}
		if complete {
			cluster.Status.Drain.Indexer.Phase = wazuhv1.DrainPhaseFailed
			cluster.Status.Drain.Indexer.Message = "Rollback complete, waiting for retry"
			log.Info("Indexer rollback verified complete")
		}
	}

	// Check manager rollback
	if cluster.Status.Drain.Manager != nil && cluster.Status.Drain.Manager.Phase == wazuhv1.DrainPhaseRollingBack {
		complete, err := r.RollbackManager.VerifyRollbackComplete(ctx, cluster, constants.DrainComponentManager)
		if err != nil {
			log.Error(err, "Failed to verify manager rollback")
			return err
		}
		if complete {
			cluster.Status.Drain.Manager.Phase = wazuhv1.DrainPhaseFailed
			cluster.Status.Drain.Manager.Message = "Rollback complete, waiting for retry"
			log.Info("Manager rollback verified complete")
		}
	}

	return nil
}

// emitDrainEvent emits a Kubernetes event for drain operations
func (r *WazuhClusterReconciler) emitDrainEvent(cluster *wazuhv1.WazuhCluster, component, reason, message string) {
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

// resolveManagerRef resolves a WazuhManager reference from a WazuhCluster
// Returns the referenced WazuhManager CR, or nil if not using reference mode
// Returns error if reference is set but CR not found or fetch fails
func (r *WazuhClusterReconciler) resolveManagerRef(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.WazuhManager, error) {
	if cluster.Spec.ManagerRef == nil {
		return nil, nil // Not using reference mode
	}

	log := logf.FromContext(ctx)

	// Determine namespace (default to cluster namespace if not specified)
	namespace := cluster.Spec.ManagerRef.Namespace
	if namespace == "" {
		namespace = cluster.Namespace
	}

	// Fetch the referenced WazuhManager CR
	manager := &wazuhv1.WazuhManager{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.ManagerRef.Name,
		Namespace: namespace,
	}, manager)

	if err != nil {
		if errors.IsNotFound(err) {
			notFoundErr := fmt.Errorf("referenced WazuhManager %s/%s not found: %w",
				namespace, cluster.Spec.ManagerRef.Name, err)
			log.Error(notFoundErr, "WazuhManager reference resolution failed")
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "ManagerRefNotFound",
				fmt.Sprintf("Referenced WazuhManager %s/%s not found", namespace, cluster.Spec.ManagerRef.Name))
			return nil, notFoundErr
		}
		fetchErr := fmt.Errorf("failed to get referenced WazuhManager %s/%s: %w",
			namespace, cluster.Spec.ManagerRef.Name, err)
		log.Error(fetchErr, "WazuhManager reference fetch failed")
		return nil, fetchErr
	}

	log.V(1).Info("Resolved WazuhManager reference",
		"managerName", manager.Name,
		"managerNamespace", manager.Namespace)

	return manager, nil
}

// resolveIndexerRef resolves an OpenSearchIndexer reference from a WazuhCluster
// Returns the referenced OpenSearchIndexer CR, or nil if not using reference mode
// Returns error if reference is set but CR not found or fetch fails
func (r *WazuhClusterReconciler) resolveIndexerRef(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.OpenSearchIndexer, error) {
	if cluster.Spec.IndexerRef == nil {
		return nil, nil // Not using reference mode
	}

	log := logf.FromContext(ctx)

	// Determine namespace (default to cluster namespace if not specified)
	namespace := cluster.Spec.IndexerRef.Namespace
	if namespace == "" {
		namespace = cluster.Namespace
	}

	// Fetch the referenced OpenSearchIndexer CR
	indexer := &wazuhv1.OpenSearchIndexer{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.IndexerRef.Name,
		Namespace: namespace,
	}, indexer)

	if err != nil {
		if errors.IsNotFound(err) {
			notFoundErr := fmt.Errorf("referenced OpenSearchIndexer %s/%s not found: %w",
				namespace, cluster.Spec.IndexerRef.Name, err)
			log.Error(notFoundErr, "OpenSearchIndexer reference resolution failed")
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "IndexerRefNotFound",
				fmt.Sprintf("Referenced OpenSearchIndexer %s/%s not found", namespace, cluster.Spec.IndexerRef.Name))
			return nil, notFoundErr
		}
		fetchErr := fmt.Errorf("failed to get referenced OpenSearchIndexer %s/%s: %w",
			namespace, cluster.Spec.IndexerRef.Name, err)
		log.Error(fetchErr, "OpenSearchIndexer reference fetch failed")
		return nil, fetchErr
	}

	log.V(1).Info("Resolved OpenSearchIndexer reference",
		"indexerName", indexer.Name,
		"indexerNamespace", indexer.Namespace)

	return indexer, nil
}

// resolveDashboardRef resolves an OpenSearchDashboard reference from a WazuhCluster
// Returns the referenced OpenSearchDashboard CR, or nil if not using reference mode
// Returns error if reference is set but CR not found or fetch fails
func (r *WazuhClusterReconciler) resolveDashboardRef(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.OpenSearchDashboard, error) {
	if cluster.Spec.DashboardRef == nil {
		return nil, nil // Not using reference mode
	}

	log := logf.FromContext(ctx)

	// Determine namespace (default to cluster namespace if not specified)
	namespace := cluster.Spec.DashboardRef.Namespace
	if namespace == "" {
		namespace = cluster.Namespace
	}

	// Fetch the referenced OpenSearchDashboard CR
	dashboard := &wazuhv1.OpenSearchDashboard{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.DashboardRef.Name,
		Namespace: namespace,
	}, dashboard)

	if err != nil {
		if errors.IsNotFound(err) {
			notFoundErr := fmt.Errorf("referenced OpenSearchDashboard %s/%s not found: %w",
				namespace, cluster.Spec.DashboardRef.Name, err)
			log.Error(notFoundErr, "OpenSearchDashboard reference resolution failed")
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "DashboardRefNotFound",
				fmt.Sprintf("Referenced OpenSearchDashboard %s/%s not found", namespace, cluster.Spec.DashboardRef.Name))
			return nil, notFoundErr
		}
		fetchErr := fmt.Errorf("failed to get referenced OpenSearchDashboard %s/%s: %w",
			namespace, cluster.Spec.DashboardRef.Name, err)
		log.Error(fetchErr, "OpenSearchDashboard reference fetch failed")
		return nil, fetchErr
	}

	log.V(1).Info("Resolved OpenSearchDashboard reference",
		"dashboardName", dashboard.Name,
		"dashboardNamespace", dashboard.Namespace)

	return dashboard, nil
}

// findClustersForManager finds all WazuhClusters that reference a specific WazuhManager
// Used by the watch handler to enqueue clusters when their referenced manager changes
func (r *WazuhClusterReconciler) findClustersForManager(ctx context.Context, obj client.Object) []ctrl.Request {
	manager, ok := obj.(*wazuhv1.WazuhManager)
	if !ok {
		return []ctrl.Request{}
	}
	log := logf.FromContext(ctx)

	// List all WazuhClusters in all namespaces
	clusterList := &wazuhv1.WazuhClusterList{}
	if err := r.List(ctx, clusterList); err != nil {
		log.Error(err, "Failed to list WazuhClusters for manager watch")
		return []ctrl.Request{}
	}

	// Find clusters that reference this manager
	requests := []ctrl.Request{}
	for _, cluster := range clusterList.Items {
		if cluster.Spec.ManagerRef != nil &&
			cluster.Spec.ManagerRef.Name == manager.Name {
			// Check namespace match
			refNamespace := cluster.Spec.ManagerRef.Namespace
			if refNamespace == "" {
				refNamespace = cluster.Namespace
			}
			if refNamespace == manager.Namespace {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      cluster.Name,
						Namespace: cluster.Namespace,
					},
				})
				log.V(1).Info("Enqueueing WazuhCluster for manager change",
					"cluster", cluster.Name,
					"manager", manager.Name)
			}
		}
	}

	return requests
}

// findClustersForIndexer finds all WazuhClusters that reference a specific OpenSearchIndexer
// Used by the watch handler to enqueue clusters when their referenced indexer changes
func (r *WazuhClusterReconciler) findClustersForIndexer(ctx context.Context, obj client.Object) []ctrl.Request {
	indexer, ok := obj.(*wazuhv1.OpenSearchIndexer)
	if !ok {
		return []ctrl.Request{}
	}
	log := logf.FromContext(ctx)

	// List all WazuhClusters in all namespaces
	clusterList := &wazuhv1.WazuhClusterList{}
	if err := r.List(ctx, clusterList); err != nil {
		log.Error(err, "Failed to list WazuhClusters for indexer watch")
		return []ctrl.Request{}
	}

	// Find clusters that reference this indexer
	requests := []ctrl.Request{}
	for _, cluster := range clusterList.Items {
		if cluster.Spec.IndexerRef != nil &&
			cluster.Spec.IndexerRef.Name == indexer.Name {
			// Check namespace match
			refNamespace := cluster.Spec.IndexerRef.Namespace
			if refNamespace == "" {
				refNamespace = cluster.Namespace
			}
			if refNamespace == indexer.Namespace {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      cluster.Name,
						Namespace: cluster.Namespace,
					},
				})
				log.V(1).Info("Enqueueing WazuhCluster for indexer change",
					"cluster", cluster.Name,
					"indexer", indexer.Name)
			}
		}
	}

	return requests
}

// findClustersForDashboard finds all WazuhClusters that reference a specific OpenSearchDashboard
// Used by the watch handler to enqueue clusters when their referenced dashboard changes
func (r *WazuhClusterReconciler) findClustersForDashboard(ctx context.Context, obj client.Object) []ctrl.Request {
	dashboard, ok := obj.(*wazuhv1.OpenSearchDashboard)
	if !ok {
		return []ctrl.Request{}
	}
	log := logf.FromContext(ctx)

	// List all WazuhClusters in all namespaces
	clusterList := &wazuhv1.WazuhClusterList{}
	if err := r.List(ctx, clusterList); err != nil {
		log.Error(err, "Failed to list WazuhClusters for dashboard watch")
		return []ctrl.Request{}
	}

	// Find clusters that reference this dashboard
	requests := []ctrl.Request{}
	for _, cluster := range clusterList.Items {
		if cluster.Spec.DashboardRef != nil &&
			cluster.Spec.DashboardRef.Name == dashboard.Name {
			// Check namespace match
			refNamespace := cluster.Spec.DashboardRef.Namespace
			if refNamespace == "" {
				refNamespace = cluster.Namespace
			}
			if refNamespace == dashboard.Namespace {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      cluster.Name,
						Namespace: cluster.Namespace,
					},
				})
				log.V(1).Info("Enqueueing WazuhCluster for dashboard change",
					"cluster", cluster.Name,
					"dashboard", dashboard.Name)
			}
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.Ingress{}).
		// Watch WazuhManager CRs - reconcile WazuhCluster when referenced manager changes
		Watches(
			&wazuhv1.WazuhManager{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForManager),
		).
		// Watch OpenSearchIndexer CRs - reconcile WazuhCluster when referenced indexer changes
		Watches(
			&wazuhv1.OpenSearchIndexer{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForIndexer),
		).
		// Watch OpenSearchDashboard CRs - reconcile WazuhCluster when referenced dashboard changes
		Watches(
			&wazuhv1.OpenSearchDashboard{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForDashboard),
		)

	// Only add Gateway API watches if enabled AND the specific CRDs are available
	// This prevents the controller from failing to start if Gateway API CRDs are not installed
	if r.GatewayAPIEnabled {
		if r.HTTPRouteAvailable {
			builder = builder.Owns(&gatewayv1.HTTPRoute{})
		}
		if r.TCPRouteAvailable {
			builder = builder.Owns(&gatewayv1alpha2.TCPRoute{})
		}
		if r.UDPRouteAvailable {
			builder = builder.Owns(&gatewayv1alpha2.UDPRoute{})
		}
	}

	return builder.
		Named("wazuhcluster").
		Complete(r)
}

// hasGatewayAPIEnabled checks if any component has GatewayAPI explicitly enabled
func hasGatewayAPIEnabled(cluster *wazuhv1.WazuhCluster) bool {
	// Check Dashboard
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.GatewayAPI != nil &&
		cluster.Spec.Dashboard.GatewayAPI.Enabled {
		return true
	}

	// Check Manager Master
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.GatewayAPI != nil &&
		cluster.Spec.Manager.Master.GatewayAPI.Enabled {
		return true
	}

	// Check Indexer
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.GatewayAPI != nil &&
		cluster.Spec.Indexer.GatewayAPI.Enabled {
		return true
	}

	return false
}

// hasIngressEnabled checks if any component has Ingress explicitly enabled
func hasIngressEnabled(cluster *wazuhv1.WazuhCluster) bool {
	// Check Dashboard
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Ingress != nil &&
		cluster.Spec.Dashboard.Ingress.Enabled {
		return true
	}

	// Check Manager Master
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Ingress != nil &&
		cluster.Spec.Manager.Master.Ingress.Enabled {
		return true
	}

	// Check Manager Workers
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Ingress != nil &&
		cluster.Spec.Manager.Workers.Ingress.Enabled {
		return true
	}

	// Check Indexer
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Ingress != nil &&
		cluster.Spec.Indexer.Ingress.Enabled {
		return true
	}

	return false
}
