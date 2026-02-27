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
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	networkingv1 "k8s.io/api/networking/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	certreconciler "github.com/MaximeWewer/wazuh-operator/internal/certificates/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/health"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	networkingreconciler "github.com/MaximeWewer/wazuh-operator/internal/networking/reconciler"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/validation"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/rolling"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"
)

const (
	wazuhClusterFinalizer = "resources.wazuh.com/finalizer"
	apiCredentialRecoveryHashAnnotation = "wazuh.com/api-credential-recovery-hash"
	authdCredentialRecoveryHashAnnotation = "wazuh.com/authd-credential-recovery-hash"

	// RequeueIntervalNormal is the normal requeue interval when cluster is stable
	RequeueIntervalNormal = 30 * time.Second

	// RequeueIntervalPendingRollout is the faster requeue interval when rollouts are pending
	RequeueIntervalPendingRollout = 5 * time.Second

	// RequeueIntervalDrainInProgress is the requeue interval when a drain is in progress
	RequeueIntervalDrainInProgress = 10 * time.Second

	// RequeueIntervalRollingRestart is the requeue interval when a rolling restart is in progress
	RequeueIntervalRollingRestart = 10 * time.Second
)

// WazuhClusterReconciler reconciles a WazuhCluster object
// This is a thin controller that delegates to helper reconcilers
type WazuhClusterReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Helper reconcilers
	ClusterReconciler       *wazuhreconciler.ClusterReconciler
	CertificateReconciler   *certreconciler.CertificateReconciler
	IndexerReconciler       *opensearchreconciler.IndexerReconciler
	DashboardReconciler     *opensearchreconciler.DashboardReconciler
	WorkerReconciler        *wazuhreconciler.WorkerReconciler
	MonitoringReconciler    *monitoring.MonitoringReconciler
	GatewayReconciler       *networkingreconciler.GatewayReconciler
	IngressReconciler       *networkingreconciler.IngressReconciler
	NetworkPolicyReconciler *networkingreconciler.NetworkPolicyReconciler

	// Drain management
	RollbackManager *drain.RollbackManagerImpl
	RetryManager    *drain.RetryManagerImpl

	// GatewayAPIEnabled indicates if Gateway API support is enabled in operator config
	GatewayAPIEnabled bool

	// Gateway API CRD availability flags - set based on runtime CRD detection
	HTTPRouteAvailable bool
	TCPRouteAvailable  bool
	UDPRouteAvailable  bool

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles
	// which can be run. Defaults to 1.
	MaxConcurrentReconciles int

	// RateLimiter overrides the default controller rate limiter.
	// When nil, controller-runtime's default is used.
	RateLimiter workqueue.TypedRateLimiter[reconcile.Request]

	// Watchdog is touched after each successful reconcile so the readiness
	// probe can detect a stuck reconcile loop.
	Watchdog *health.Watchdog

	// agentMetricsInFlight prevents concurrent agent metrics goroutines
	agentMetricsInFlight atomic.Bool
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
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
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;tcproutes;udproutes;referencegrants,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop for WazuhCluster
func (r *WazuhClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, reconcileErr error) {
	// Start tracing span
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhCluster.Reconcile",
		telemetry.WithAttributes(
			attribute.String("namespace", req.Namespace),
			attribute.String("name", req.Name),
		))
	defer span.End()

	// Track reconciliation metrics
	startTime := time.Now()
	defer func() {
		reconcileResult := "success"
		if reconcileErr != nil {
			reconcileResult = "error"
		}
		duration := time.Since(startTime).Seconds()
		metrics.RecordReconciliation("WazuhCluster", req.Namespace, reconcileResult, duration)
	}()

	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	ctx = logf.IntoContext(ctx, logging.WithTraceID(ctx))
	log := logf.FromContext(ctx)

	// Fetch the WazuhCluster instance
	cluster := &wazuhv1.WazuhCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhCluster resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhCluster")
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

	// Detect version upgrade before updating status
	if oldVersion := cluster.Status.Version; oldVersion != "" && oldVersion != cluster.Spec.Version {
		metrics.RecordVersionUpgrade(cluster.Name, cluster.Namespace, oldVersion, cluster.Spec.Version)
	}

	// Update phase if pending
	if cluster.Status.Phase == "" || cluster.Status.Phase == wazuhv1.ClusterPhasePending {
		if err := utils.RetryOnConflict(ctx, func() error {
			latest := &wazuhv1.WazuhCluster{}
			if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, latest); err != nil {
				return err
			}
			latest.Status.Phase = wazuhv1.ClusterPhaseCreating
			latest.Status.Version = cluster.Spec.Version
			if err := r.Status().Update(ctx, latest); err != nil {
				return err
			}
			cluster.Status = latest.Status
			return nil
		}); err != nil {
			log.Error(err, "Failed to update WazuhCluster status to Creating")
			return ctrl.Result{}, err
		}
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

			r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing,
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
	var certHashes *certreconciler.CertHashResult
	if r.CertificateReconciler != nil {
		var certErr error
		certHashes, certErr = r.CertificateReconciler.ReconcileWithHashes(ctx, cluster)
		if certErr != nil {
			log.Error(certErr, "Failed to reconcile certificates with CertificateReconciler")
			r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "CertificatesFailed", certErr.Error())
			return ctrl.Result{}, certErr
		}
	} else {
		// Fallback to ClusterReconciler for basic certificate creation
		if err := r.ClusterReconciler.ReconcileCertificates(ctx, cluster); err != nil {
			log.Error(err, "Failed to reconcile certificates")
			r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "CertificatesFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	// Record certificate expiry days metrics for cluster-level dashboards
	r.recordCertificateExpiryDaysMetrics(ctx, cluster)

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

			// Update drain status in cluster
			if cluster.Status.Drain == nil {
				cluster.Status.Drain = &wazuhv1.DrainStatus{}
			}

			// Requeue to check drain progress
			return ctrl.Result{RequeueAfter: RequeueIntervalDrainInProgress}, r.updateDrainStatus(ctx, cluster)
		} else if drainResult != nil && drainResult.DrainComplete {
			// Drain is complete, proceed with normal reconciliation
			log.Info("Indexer drain complete, proceeding with scale-down")
			// Reset drain state after scale-down is applied
			defer r.IndexerReconciler.ResetDrainState(cluster)
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
	indexerResult := r.IndexerReconciler.ReconcileNonBlocking(ctx, cluster, indexerCertHash)
	if indexerResult.Error != nil {
		log.Error(indexerResult.Error, "Failed to reconcile Indexer")
		r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "IndexerFailed", indexerResult.Error.Error())
		return ctrl.Result{}, indexerResult.Error
	}
	if indexerResult.PendingRollout != nil {
		newPendingRollouts = append(newPendingRollouts, *indexerResult.PendingRollout)
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

			// Update drain status in cluster
			if cluster.Status.Drain == nil {
				cluster.Status.Drain = &wazuhv1.DrainStatus{}
			}

			// Requeue to check drain progress
			return ctrl.Result{RequeueAfter: RequeueIntervalDrainInProgress}, r.updateDrainStatus(ctx, cluster)
		} else if drainResult != nil && drainResult.DrainComplete {
			// Drain is complete, proceed with normal reconciliation
			log.Info("Manager worker drain complete, proceeding with scale-down")
			// Reset drain state after scale-down is applied
			defer r.WorkerReconciler.ResetDrainState(cluster)
		}
	}

	// 6. Reconcile Manager with certificate hashes for pod restart on cert renewal
	masterCertHash, workerCertHash := "", ""
	if certHashes != nil {
		masterCertHash = certHashes.ManagerMasterCertHash
		workerCertHash = certHashes.ManagerWorkerCertHash
	}
	managerResult := r.ClusterReconciler.ReconcileManagerNonBlocking(ctx, cluster, masterCertHash, workerCertHash)
	if managerResult.Error != nil {
		log.Error(managerResult.Error, "Failed to reconcile Manager")
		r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "ManagerFailed", managerResult.Error.Error())
		return ctrl.Result{}, managerResult.Error
	}
	newPendingRollouts = append(newPendingRollouts, managerResult.PendingRollouts...)

	// 7. Reconcile Log Rotation CronJob (if enabled)
	if err := r.ClusterReconciler.ReconcileLogRotation(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile log rotation")
		// Non-fatal, continue - log rotation is an optional feature
	}

	// 8. Reconcile Dashboard with certificate hash for pod restart on cert renewal
	dashboardCertHash := ""
	if certHashes != nil {
		dashboardCertHash = certHashes.DashboardCertHash
	}
	dashboardResult := r.DashboardReconciler.ReconcileNonBlocking(ctx, cluster, dashboardCertHash)
	if dashboardResult.Error != nil {
		log.Error(dashboardResult.Error, "Failed to reconcile Dashboard")
		r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "DashboardFailed", dashboardResult.Error.Error())
		return ctrl.Result{}, dashboardResult.Error
	}
	if dashboardResult.PendingRollout != nil {
		newPendingRollouts = append(newPendingRollouts, *dashboardResult.PendingRollout)
	}

	// 8.5 Reconcile Wazuh API credentials rotation state and trigger dependent component restarts
	if err := r.reconcileAPICredentialsStatusAndRollout(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile Wazuh API credentials rotation state")
		return ctrl.Result{}, err
	}
	// 8.6 Reconcile authd password rotation state and trigger manager restarts
	if err := r.reconcileAuthdCredentialsStatusAndRollout(ctx, cluster); err != nil {
		log.Error(err, "Failed to reconcile authd credentials rotation state")
		return ctrl.Result{}, err
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
				r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "GatewayAPIFailed", err.Error())
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
				r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "IngressFailed", err.Error())
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

	// 12. Reconcile NetworkPolicy resources if any component has NetworkPolicy enabled
	if hasNetworkPolicyEnabled(cluster) {
		if r.NetworkPolicyReconciler != nil {
			if err := r.NetworkPolicyReconciler.Reconcile(ctx, cluster); err != nil {
				log.Error(err, "Failed to reconcile NetworkPolicy resources")
				r.persistCondition(ctx, cluster, wazuhv1.ConditionTypeProgressing, "NetworkPolicyFailed", err.Error())
				return ctrl.Result{}, err
			}
		}
	} else if r.NetworkPolicyReconciler != nil {
		// NetworkPolicy is not configured on this cluster
		// Still call reconciler to clean up any orphaned network policies
		if err := r.NetworkPolicyReconciler.Reconcile(ctx, cluster); err != nil {
			log.V(1).Info("Failed to reconcile NetworkPolicy resources (non-fatal)", "error", err)
		}
	}
	log.V(1).Info("NetworkPolicy reconciliation completed")

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

	// 15. Orchestrate quorum-safe rolling restarts
	hasRollingRestart := false

	indexerRestart, err := r.IndexerReconciler.OrchestrateRollingRestart(ctx, cluster)
	if err != nil {
		log.Error(err, "Failed to orchestrate indexer rolling restart")
	}
	if indexerRestart != nil && indexerRestart.Phase == rolling.RestartPhaseInProgress {
		hasRollingRestart = true
	}

	masterRestart, workerRestart, err := r.ClusterReconciler.OrchestrateManagerRollingRestart(ctx, cluster)
	if err != nil {
		log.Error(err, "Failed to orchestrate manager rolling restart")
	}
	if masterRestart != nil && masterRestart.Phase == rolling.RestartPhaseInProgress {
		hasRollingRestart = true
	}
	if workerRestart != nil && workerRestart.Phase == rolling.RestartPhaseInProgress {
		hasRollingRestart = true
	}

	// Update rolling restart status
	r.updateRollingRestartStatus(cluster, indexerRestart, masterRestart, workerRestart, hasRollingRestart)

	// Update status
	if err := r.updateStatus(ctx, cluster); err != nil {
		log.Error(err, "Failed to update WazuhCluster status")
		return ctrl.Result{}, err
	}

	// Track managed WazuhCluster resource
	metrics.SetManagedResources("WazuhCluster", cluster.Namespace, 1)

	// Determine requeue interval based on state
	requeueInterval := r.determineRequeueInterval(hasPendingRollouts, hasRollingRestart)
	log.V(1).Info("Reconciliation complete",
		"requeueAfter", requeueInterval,
		"hasPendingRollouts", hasPendingRollouts,
		"hasRollingRestart", hasRollingRestart)

	// Signal the health watchdog that the reconcile loop is alive
	if r.Watchdog != nil {
		r.Watchdog.Touch()
	}

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
			// Already completed, drop from the list
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
			if errors.IsNotFound(status.Error) {
				log.V(1).Info("Rollout workload not found yet", "component", rollout.Component, "name", rollout.WorkloadName)
				// Keep as pending; likely being recreated
				updatedRollouts = append(updatedRollouts, rollout)
				hasPending = true
				continue
			}
			log.Error(status.Error, "Error checking rollout status", "component", rollout.Component)
			// Keep as pending
			updatedRollouts = append(updatedRollouts, rollout)
			hasPending = true
			continue
		}

		if status.Ready {
			// Rollout completed — log, record metrics, and drop from list
			log.Info("Certificate rollout completed",
				"component", rollout.Component,
				"duration", status.Duration,
				"reason", rollout.Reason)
			metrics.RecordCertificateRolloutWait(cluster.Name, cluster.Namespace, rollout.Component, status.Duration.Seconds())
			continue
		}

		hasPending = true
		log.V(1).Info("Certificate rollout still in progress",
			"component", rollout.Component,
			"status", status.Message,
			"duration", status.Duration)
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

// determineRequeueInterval determines the appropriate requeue interval based on cluster state.
// Note: drain-in-progress uses early returns with RequeueIntervalDrainInProgress directly,
// so this function is only reached when no drain is active.
func (r *WazuhClusterReconciler) determineRequeueInterval(hasPendingRollouts, hasRollingRestart bool) time.Duration {
	// Pending rollouts use faster requeue
	if hasPendingRollouts {
		return RequeueIntervalPendingRollout
	}

	// Rolling restarts use moderate requeue interval
	if hasRollingRestart {
		return RequeueIntervalRollingRestart
	}

	// Normal operation
	return RequeueIntervalNormal
}

// updateRollingRestartStatus updates the cluster's rolling restart status from orchestrator results.
func (r *WazuhClusterReconciler) updateRollingRestartStatus(
	cluster *wazuhv1.WazuhCluster,
	indexerRestart *rolling.RestartResult,
	masterRestart, workerRestart *rolling.RestartResult,
	hasRollingRestart bool,
) {
	// If nothing is happening and no status exists, skip
	if !hasRollingRestart && indexerRestart == nil && masterRestart == nil && workerRestart == nil {
		// Clear status if it was previously set and everything is now idle
		if cluster.Status.RollingRestart != nil {
			cluster.Status.RollingRestart = nil
		}
		return
	}

	now := metav1.Now()
	if cluster.Status.RollingRestart == nil {
		cluster.Status.RollingRestart = &wazuhv1.RollingRestartStatus{}
	}

	// Only write status for InProgress phase. Idle and Complete are terminal —
	// writing Complete with a new LastTransitionTime every cycle causes a hot
	// reconciliation loop (status update → watch fires → new reconcile → repeat).
	if indexerRestart != nil && indexerRestart.Phase == rolling.RestartPhaseInProgress {
		if cluster.Status.RollingRestart.Indexer == nil {
			cluster.Status.RollingRestart.Indexer = &wazuhv1.ComponentRollingRestart{StartTime: &now, LastTransitionTime: &now}
		}
		if cluster.Status.RollingRestart.Indexer.Phase != string(indexerRestart.Phase) ||
			cluster.Status.RollingRestart.Indexer.UpdatedPods != indexerRestart.UpdatedPods ||
			cluster.Status.RollingRestart.Indexer.CurrentPod != indexerRestart.CurrentPod {
			cluster.Status.RollingRestart.Indexer.LastTransitionTime = &now
		}
		cluster.Status.RollingRestart.Indexer.Phase = string(indexerRestart.Phase)
		cluster.Status.RollingRestart.Indexer.TotalPods = indexerRestart.TotalPods
		cluster.Status.RollingRestart.Indexer.UpdatedPods = indexerRestart.UpdatedPods
		cluster.Status.RollingRestart.Indexer.CurrentPod = indexerRestart.CurrentPod
		cluster.Status.RollingRestart.Indexer.Message = indexerRestart.Message
	} else {
		cluster.Status.RollingRestart.Indexer = nil
	}

	if masterRestart != nil && masterRestart.Phase == rolling.RestartPhaseInProgress {
		if cluster.Status.RollingRestart.ManagerMaster == nil {
			cluster.Status.RollingRestart.ManagerMaster = &wazuhv1.ComponentRollingRestart{StartTime: &now, LastTransitionTime: &now}
		}
		if cluster.Status.RollingRestart.ManagerMaster.Phase != string(masterRestart.Phase) ||
			cluster.Status.RollingRestart.ManagerMaster.UpdatedPods != masterRestart.UpdatedPods ||
			cluster.Status.RollingRestart.ManagerMaster.CurrentPod != masterRestart.CurrentPod {
			cluster.Status.RollingRestart.ManagerMaster.LastTransitionTime = &now
		}
		cluster.Status.RollingRestart.ManagerMaster.Phase = string(masterRestart.Phase)
		cluster.Status.RollingRestart.ManagerMaster.TotalPods = masterRestart.TotalPods
		cluster.Status.RollingRestart.ManagerMaster.UpdatedPods = masterRestart.UpdatedPods
		cluster.Status.RollingRestart.ManagerMaster.CurrentPod = masterRestart.CurrentPod
		cluster.Status.RollingRestart.ManagerMaster.Message = masterRestart.Message
	} else {
		cluster.Status.RollingRestart.ManagerMaster = nil
	}

	if workerRestart != nil && workerRestart.Phase == rolling.RestartPhaseInProgress {
		if cluster.Status.RollingRestart.ManagerWorker == nil {
			cluster.Status.RollingRestart.ManagerWorker = &wazuhv1.ComponentRollingRestart{StartTime: &now, LastTransitionTime: &now}
		}
		if cluster.Status.RollingRestart.ManagerWorker.Phase != string(workerRestart.Phase) ||
			cluster.Status.RollingRestart.ManagerWorker.UpdatedPods != workerRestart.UpdatedPods ||
			cluster.Status.RollingRestart.ManagerWorker.CurrentPod != workerRestart.CurrentPod {
			cluster.Status.RollingRestart.ManagerWorker.LastTransitionTime = &now
		}
		cluster.Status.RollingRestart.ManagerWorker.Phase = string(workerRestart.Phase)
		cluster.Status.RollingRestart.ManagerWorker.TotalPods = workerRestart.TotalPods
		cluster.Status.RollingRestart.ManagerWorker.UpdatedPods = workerRestart.UpdatedPods
		cluster.Status.RollingRestart.ManagerWorker.CurrentPod = workerRestart.CurrentPod
		cluster.Status.RollingRestart.ManagerWorker.Message = workerRestart.Message
	} else {
		cluster.Status.RollingRestart.ManagerWorker = nil
	}

	cluster.Status.RollingRestart.InProgress = hasRollingRestart

	// Clear the entire status if no component has an active restart
	if cluster.Status.RollingRestart.Indexer == nil &&
		cluster.Status.RollingRestart.ManagerMaster == nil &&
		cluster.Status.RollingRestart.ManagerWorker == nil {
		cluster.Status.RollingRestart = nil
	}
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

	// Clean up cluster metrics for the deleted cluster
	metrics.DeleteClusterMetrics(cluster.Name, cluster.Namespace)
	metrics.ClearCertificateMetrics(cluster.Name, cluster.Namespace)
	metrics.ClearConfigMetrics(cluster.Name, cluster.Namespace)
	log.V(1).Info("Cleaned up cluster metrics")

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

// updateCondition updates a condition in the WazuhCluster status.
// It preserves LastTransitionTime when the status hasn't changed and skips
// the update entirely when status, reason, message and generation are identical
// to avoid triggering unnecessary status writes.
func (r *WazuhClusterReconciler) updateCondition(cluster *wazuhv1.WazuhCluster, conditionType string, status metav1.ConditionStatus, reason, message string) {
	for i, c := range cluster.Status.Conditions {
		if c.Type == conditionType {
			// Nothing changed — skip entirely to avoid a no-op status write
			if c.Status == status && c.Reason == reason && c.Message == message && c.ObservedGeneration == cluster.Generation {
				return
			}
			cluster.Status.Conditions[i].Reason = reason
			cluster.Status.Conditions[i].Message = message
			cluster.Status.Conditions[i].ObservedGeneration = cluster.Generation
			if c.Status != status {
				cluster.Status.Conditions[i].Status = status
				cluster.Status.Conditions[i].LastTransitionTime = metav1.Now()
			}
			return
		}
	}

	// Condition not found — append a new one
	cluster.Status.Conditions = append(cluster.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: cluster.Generation,
	})
}

// persistCondition updates a condition to False in memory and persists it to the API server (best-effort).
// Use this on error paths where the main updateStatus() won't be reached.
func (r *WazuhClusterReconciler) persistCondition(ctx context.Context, cluster *wazuhv1.WazuhCluster, conditionType, reason, message string) {
	r.updateCondition(cluster, conditionType, metav1.ConditionFalse, reason, message)
	if err := utils.RetryOnConflict(ctx, func() error {
		latestCluster := &wazuhv1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, latestCluster); err != nil {
			return err
		}
		r.updateCondition(latestCluster, conditionType, metav1.ConditionFalse, reason, message)
		if err := r.Status().Update(ctx, latestCluster); err != nil {
			return err
		}
		cluster.Status.Conditions = latestCluster.Status.Conditions
		return nil
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to persist status condition", "conditionType", conditionType, "reason", reason)
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

		// Track component health for overall cluster health computation
		componentHealths := make(map[string]metrics.ClusterHealthStatus)

		// Check Indexer status
		if status, err := r.IndexerReconciler.GetStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Indexer status")
			componentHealths["indexer"] = metrics.ClusterHealthUnknown
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "indexer", metrics.ClusterHealthUnknown)
		} else {
			latestCluster.Status.Indexer = status
			if status != nil {
				metrics.SetClusterReplicas(cluster.Name, cluster.Namespace, "indexer", status.ReadyReplicas, status.Replicas)
				if status.ReadyReplicas < status.Replicas {
					allReady = false
					if status.ReadyReplicas == 0 {
						componentHealths["indexer"] = metrics.ClusterHealthRed
					} else {
						componentHealths["indexer"] = metrics.ClusterHealthYellow
					}
				} else {
					componentHealths["indexer"] = metrics.ClusterHealthGreen
				}
			} else {
				componentHealths["indexer"] = metrics.ClusterHealthUnknown
			}
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "indexer", componentHealths["indexer"])
		}

		// Check Manager status
		if status, err := r.ClusterReconciler.GetManagerStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Manager status")
			componentHealths["manager"] = metrics.ClusterHealthUnknown
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "manager", metrics.ClusterHealthUnknown)
		} else {
			latestCluster.Status.Manager = status
			if status != nil {
				metrics.SetClusterReplicas(cluster.Name, cluster.Namespace, "manager", status.ReadyReplicas, status.Replicas)
				if status.ReadyReplicas < status.Replicas {
					allReady = false
					if status.ReadyReplicas == 0 {
						componentHealths["manager"] = metrics.ClusterHealthRed
					} else {
						componentHealths["manager"] = metrics.ClusterHealthYellow
					}
				} else {
					componentHealths["manager"] = metrics.ClusterHealthGreen
				}
			} else {
				componentHealths["manager"] = metrics.ClusterHealthUnknown
			}
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "manager", componentHealths["manager"])
		}

		// Check Dashboard status
		if status, err := r.DashboardReconciler.GetStatus(ctx, cluster); err != nil {
			log.Error(err, "Failed to get Dashboard status")
			componentHealths["dashboard"] = metrics.ClusterHealthUnknown
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "dashboard", metrics.ClusterHealthUnknown)
		} else {
			latestCluster.Status.Dashboard = status
			if status != nil {
				metrics.SetClusterReplicas(cluster.Name, cluster.Namespace, "dashboard", status.ReadyReplicas, status.Replicas)
				if status.ReadyReplicas < status.Replicas {
					allReady = false
					if status.ReadyReplicas == 0 {
						componentHealths["dashboard"] = metrics.ClusterHealthRed
					} else {
						componentHealths["dashboard"] = metrics.ClusterHealthYellow
					}
				} else {
					componentHealths["dashboard"] = metrics.ClusterHealthGreen
				}
			} else {
				componentHealths["dashboard"] = metrics.ClusterHealthUnknown
			}
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "dashboard", componentHealths["dashboard"])
		}

		// Worker is a sub-component of manager; report separately for visibility
		// Worker replicas are tracked via the manager StatefulSet status, but we
		// set a dedicated "worker" component health so dashboards can distinguish
		// master from worker health. The worker ready count is derived from the
		// manager status (total ready minus the 1 master node).
		if latestCluster.Status.Manager != nil {
			workerReady := latestCluster.Status.Manager.ReadyReplicas - 1
			if workerReady < 0 {
				workerReady = 0
			}
			workerDesired := latestCluster.Status.Manager.Replicas - 1
			if workerDesired < 0 {
				workerDesired = 0
			}
			metrics.SetClusterReplicas(cluster.Name, cluster.Namespace, "worker", workerReady, workerDesired)
			var workerHealth metrics.ClusterHealthStatus
			if workerDesired == 0 {
				workerHealth = metrics.ClusterHealthGreen // No workers expected
			} else if workerReady == 0 {
				workerHealth = metrics.ClusterHealthRed
			} else if workerReady < workerDesired {
				workerHealth = metrics.ClusterHealthYellow
			} else {
				workerHealth = metrics.ClusterHealthGreen
			}
			metrics.SetClusterComponentHealth(cluster.Name, cluster.Namespace, "worker", workerHealth)
		}

		// Compute and set overall cluster health from component statuses
		overallHealth := metrics.CalculateOverallHealth(componentHealths)
		metrics.SetClusterHealth(cluster.Name, cluster.Namespace, overallHealth)

		// Copy conditions from working cluster (preserves SecurityReady and other
		// conditions set during the reconciliation loop before updateStatus is called)
		latestCluster.Status.Conditions = cluster.Status.Conditions

		// Copy certificate rollout status from working cluster
		latestCluster.Status.CertificateRollouts = cluster.Status.CertificateRollouts
		latestCluster.Status.Security = cluster.Status.Security

		// Copy drain status from working cluster
		latestCluster.Status.Drain = cluster.Status.Drain

		// Copy rolling restart status from working cluster
		latestCluster.Status.RollingRestart = cluster.Status.RollingRestart

		// Update overall phase
		if allReady && latestCluster.Status.Indexer != nil && latestCluster.Status.Manager != nil && latestCluster.Status.Dashboard != nil {
			latestCluster.Status.Phase = wazuhv1.ClusterPhaseRunning
			r.updateCondition(latestCluster, wazuhv1.ConditionTypeReady, metav1.ConditionTrue, "ClusterReady", "All components are ready")
			r.updateCondition(latestCluster, wazuhv1.ConditionTypeAvailable, metav1.ConditionTrue, "ClusterAvailable", "Cluster is available")
			// Record cluster ready metric
			metrics.SetWazuhClusterStatus(latestCluster.Name, latestCluster.Namespace, true)
			// Collect agent metrics when cluster is ready (non-blocking, best-effort)
			go r.collectWazuhAgentMetrics(latestCluster)
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

		return r.Status().Update(ctx, latestCluster)
	})
}

// collectWazuhAgentMetrics collects agent statistics from the Wazuh API.
// This runs asynchronously to avoid blocking the reconciliation loop.
// Only one collection runs at a time; concurrent calls are skipped.
func (r *WazuhClusterReconciler) collectWazuhAgentMetrics(cluster *wazuhv1.WazuhCluster) {
	// Skip if a collection is already in flight
	if !r.agentMetricsInFlight.CompareAndSwap(false, true) {
		return
	}
	defer r.agentMetricsInFlight.Store(false)

	// Use a dedicated context with timeout (independent from the reconcile context)
	ctx, cancel := context.WithTimeout(context.Background(), constants.TimeoutAPIRequest)
	defer cancel()

	log := logf.FromContext(ctx).WithValues("cluster", cluster.Name)

	// Get manager service URL
	managerServiceName := cluster.Name + "-manager"
	baseURL := fmt.Sprintf("https://%s:%d",
		dns.ServiceFQDN(managerServiceName, cluster.Namespace), constants.PortManagerAPI)

	// Get credentials from secret
	credSecret := &corev1.Secret{}
	secretName := constants.APICredentialsName(cluster.Name)
	usernameKey := constants.SecretKeyAPIUsername
	passwordKey := constants.SecretKeyAPIPassword
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil {
		if customSecret := cluster.Spec.Manager.APICredentials.GetSecretName(); customSecret != "" {
			secretName = customSecret
		}
		if cluster.Spec.Manager.APICredentials.UsernameKey != "" {
			usernameKey = cluster.Spec.Manager.APICredentials.UsernameKey
		} else if secretName != constants.APICredentialsName(cluster.Name) {
			usernameKey = "username"
		}
		if cluster.Spec.Manager.APICredentials.PasswordKey != "" {
			passwordKey = cluster.Spec.Manager.APICredentials.PasswordKey
		} else if secretName != constants.APICredentialsName(cluster.Name) {
			passwordKey = "password"
		}
	}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, credSecret); err != nil {
		log.V(1).Info("Cannot get Wazuh API credentials for metrics", "error", err)
		return
	}

	username := string(credSecret.Data[usernameKey])
	password := string(credSecret.Data[passwordKey])
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

func (r *WazuhClusterReconciler) resolveAPICredentialsRef(cluster *wazuhv1.WazuhCluster) (secretName, usernameKey, passwordKey string) {
	secretName = constants.APICredentialsName(cluster.Name)
	usernameKey = constants.SecretKeyAPIUsername
	passwordKey = constants.SecretKeyAPIPassword

	if cluster.Spec.Manager == nil || cluster.Spec.Manager.APICredentials == nil {
		return
	}

	ref := cluster.Spec.Manager.APICredentials
	if customSecret := ref.GetSecretName(); customSecret != "" {
		secretName = customSecret
		usernameKey = "username"
		passwordKey = "password"
	}
	if ref.UsernameKey != "" {
		usernameKey = ref.UsernameKey
	}
	if ref.PasswordKey != "" {
		passwordKey = ref.PasswordKey
	}
	return
}

func (r *WazuhClusterReconciler) computeAPICredentialsHash(ctx context.Context, cluster *wazuhv1.WazuhCluster) (string, error) {
	secretName, usernameKey, passwordKey := r.resolveAPICredentialsRef(cluster)
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
		return "", err
	}

	username := string(secret.Data[usernameKey])
	password := string(secret.Data[passwordKey])
	if username == "" && password == "" {
		return "", nil
	}

	return utils.HashStrings(username, password), nil
}

func (r *WazuhClusterReconciler) reconcileAPICredentialsStatusAndRollout(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	if cluster.Spec.Manager == nil {
		return nil
	}

	newHash, err := r.computeAPICredentialsHash(ctx, cluster)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Wazuh API credentials secret not found yet, skipping API credentials rollout check")
			return nil
		}
		return fmt.Errorf("failed to compute Wazuh API credentials hash: %w", err)
	}
	if newHash == "" {
		return nil
	}

	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}
	oldHash := cluster.Status.Security.APICredentialsHash
	if oldHash == newHash {
		return nil
	}

	// First reconciliation with a known hash: persist state without forcing restart.
	if oldHash == "" {
		cluster.Status.Security.APICredentialsHash = newHash
		log.V(1).Info("Initialized API credentials hash in cluster status")
		return nil
	}

	reason := "wazuh api credentials changed"
	if err := r.triggerStatefulSetRestartWithHash(
		ctx,
		cluster.Namespace,
		constants.ManagerMasterName(cluster.Name),
		"manager-master",
		reason,
		apiCredentialRecoveryHashAnnotation,
		newHash,
	); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to restart manager master after API credentials change: %w", err)
	}

	if err := r.triggerStatefulSetRestartWithHash(
		ctx,
		cluster.Namespace,
		constants.ManagerWorkerName(cluster.Name),
		"manager-workers",
		reason,
		apiCredentialRecoveryHashAnnotation,
		newHash,
	); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to restart manager workers after API credentials change: %w", err)
	}

	if err := r.triggerDeploymentRestartWithHash(
		ctx,
		cluster.Namespace,
		constants.DashboardName(cluster.Name),
		"dashboard",
		reason,
		apiCredentialRecoveryHashAnnotation,
		newHash,
	); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to restart dashboard after API credentials change: %w", err)
	}

	cluster.Status.Security.APICredentialsHash = newHash
	log.Info("Triggered dependent restarts after API credentials change")
	return nil
}

func (r *WazuhClusterReconciler) resolveAuthdCredentialsRef(cluster *wazuhv1.WazuhCluster) (secretName, passwordKey string, enabledOnMasterOnly bool, configured bool) {
	enabledOnMasterOnly = true
	if cluster.Spec.Manager == nil {
		return "", "", enabledOnMasterOnly, false
	}

	var (
		disabled    bool
		usePassword bool
	)

	if cluster.Spec.Manager.Config != nil && cluster.Spec.Manager.Config.Auth != nil {
		auth := cluster.Spec.Manager.Config.Auth
		if auth.Disabled != nil {
			disabled = *auth.Disabled
		}
		if auth.UsePassword != nil {
			usePassword = *auth.UsePassword
		}
		if auth.EnabledOnMasterOnly != nil {
			enabledOnMasterOnly = *auth.EnabledOnMasterOnly
		}
		if auth.PasswordSecretRef != nil {
			secretName = auth.PasswordSecretRef.Name
			passwordKey = auth.PasswordSecretRef.Key
		}
	}

	// Backward compatibility: legacy top-level authdPasswordSecretRef.
	if secretName == "" && cluster.Spec.Manager.AuthdPasswordSecretRef != nil {
		secretName = cluster.Spec.Manager.AuthdPasswordSecretRef.Name
		passwordKey = cluster.Spec.Manager.AuthdPasswordSecretRef.Key
		usePassword = true
	}

	if passwordKey == "" {
		passwordKey = defaultAuthdSecretKey(secretName)
	}

	if disabled || !usePassword || secretName == "" {
		return "", "", enabledOnMasterOnly, false
	}

	return secretName, passwordKey, enabledOnMasterOnly, true
}

func (r *WazuhClusterReconciler) computeAuthdCredentialsHash(ctx context.Context, cluster *wazuhv1.WazuhCluster) (hash string, enabledOnMasterOnly bool, configured bool, err error) {
	secretName, passwordKey, enabledOnMasterOnly, configured := r.resolveAuthdCredentialsRef(cluster)
	if !configured {
		return "", enabledOnMasterOnly, false, nil
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
		return "", enabledOnMasterOnly, true, err
	}

	password := string(secret.Data[passwordKey])
	if password == "" {
		// Fallback between common key conventions.
		altKey := "password"
		if passwordKey == "password" {
			altKey = "authd.pass"
		}
		password = string(secret.Data[altKey])
	}
	if password == "" {
		return "", enabledOnMasterOnly, true, nil
	}

	return utils.HashStrings(password), enabledOnMasterOnly, true, nil
}

func (r *WazuhClusterReconciler) reconcileAuthdCredentialsStatusAndRollout(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	if cluster.Spec.Manager == nil {
		return nil
	}

	newHash, enabledOnMasterOnly, configured, err := r.computeAuthdCredentialsHash(ctx, cluster)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("authd password secret not found yet, skipping authd credentials rollout check")
			return nil
		}
		return fmt.Errorf("failed to compute authd credentials hash: %w", err)
	}

	if cluster.Status.Security == nil {
		cluster.Status.Security = &wazuhv1.SecurityStatus{}
	}
	oldHash := cluster.Status.Security.AuthdCredentialsHash

	// Not configured for authd password or empty password.
	if !configured || newHash == "" {
		if oldHash != "" {
			cluster.Status.Security.AuthdCredentialsHash = ""
		}
		return nil
	}

	if oldHash == newHash {
		return nil
	}

	// First observed hash: persist state without restart.
	if oldHash == "" {
		cluster.Status.Security.AuthdCredentialsHash = newHash
		log.V(1).Info("Initialized authd credentials hash in cluster status")
		return nil
	}

	reason := "wazuh authd password changed"
	if err := r.triggerStatefulSetRestartWithHash(
		ctx,
		cluster.Namespace,
		constants.ManagerMasterName(cluster.Name),
		"manager-master",
		reason,
		authdCredentialRecoveryHashAnnotation,
		newHash,
	); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to restart manager master after authd password change: %w", err)
	}

	if !enabledOnMasterOnly {
		if err := r.triggerStatefulSetRestartWithHash(
			ctx,
			cluster.Namespace,
			constants.ManagerWorkerName(cluster.Name),
			"manager-workers",
			reason,
			authdCredentialRecoveryHashAnnotation,
			newHash,
		); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to restart manager workers after authd password change: %w", err)
		}
	}

	cluster.Status.Security.AuthdCredentialsHash = newHash
	log.Info("Triggered manager restart(s) after authd credentials change", "enabledOnMasterOnly", enabledOnMasterOnly)
	return nil
}

func defaultAuthdSecretKey(secretName string) string {
	if strings.HasSuffix(secretName, "-authd-pass") {
		return "authd.pass"
	}
	return "password"
}

func (r *WazuhClusterReconciler) triggerStatefulSetRestartWithHash(
	ctx context.Context,
	namespace, name, component, reason, hashAnnotationKey, hash string,
) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sts); err != nil {
			return err
		}

		if sts.Spec.Replicas != nil && *sts.Spec.Replicas == 0 {
			log.V(1).Info("Skipping restart - statefulset has 0 replicas", "statefulset", name, "component", component)
			return nil
		}

		if sts.Spec.Template.Annotations == nil {
			sts.Spec.Template.Annotations = make(map[string]string)
		}

		if sts.Spec.Template.Annotations[hashAnnotationKey] == hash {
			log.V(1).Info("Restart already requested for current hash", "statefulset", name, "component", component, "annotation", hashAnnotationKey)
			return nil
		}

		sts.Spec.Template.Annotations[constants.AnnotationRestartedAt] = time.Now().Format(time.RFC3339)
		sts.Spec.Template.Annotations[constants.AnnotationRollingRestartTriggered] = "true"
		sts.Spec.Template.Annotations[hashAnnotationKey] = hash

		if err := r.Update(ctx, sts); err != nil {
			return err
		}

		log.Info("Triggered rolling restart for statefulset",
			"statefulset", name,
			"component", component,
			"reason", reason,
			"annotation", hashAnnotationKey)
		return nil
	})
}

func (r *WazuhClusterReconciler) triggerDeploymentRestartWithHash(
	ctx context.Context,
	namespace, name, component, reason, hashAnnotationKey, hash string,
) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, deployment); err != nil {
			return err
		}

		if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 0 {
			log.V(1).Info("Skipping restart - deployment has 0 replicas", "deployment", name, "component", component)
			return nil
		}

		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = make(map[string]string)
		}

		if deployment.Spec.Template.Annotations[hashAnnotationKey] == hash {
			log.V(1).Info("Restart already requested for current hash", "deployment", name, "component", component, "annotation", hashAnnotationKey)
			return nil
		}

		deployment.Spec.Template.Annotations[constants.AnnotationRestartedAt] = time.Now().Format(time.RFC3339)
		deployment.Spec.Template.Annotations[constants.AnnotationRollingRestartTriggered] = "true"
		deployment.Spec.Template.Annotations[hashAnnotationKey] = hash

		if err := r.Update(ctx, deployment); err != nil {
			return err
		}

		log.Info("Triggered rolling restart for deployment",
			"deployment", name,
			"component", component,
			"reason", reason,
			"annotation", hashAnnotationKey)
		return nil
	})
}

// recordCertificateExpiryDaysMetrics reads certificate secrets and records
// days-until-expiry and expiry-timestamp metrics via the cluster_metrics gauges.
// This is best-effort: failures are logged at debug level and do not block reconciliation.
func (r *WazuhClusterReconciler) recordCertificateExpiryDaysMetrics(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	type certInfo struct {
		certType   string
		secretName string
		certKey    string
	}

	certs := []certInfo{
		{"ca", cluster.Name + "-ca", constants.SecretKeyCACert},
		{"indexer", constants.IndexerCertsName(cluster.Name), constants.SecretKeyNodeCert},
		{"dashboard", constants.DashboardCertsName(cluster.Name), constants.SecretKeyNodeCert},
		{"manager-master", constants.ManagerMasterCertsName(cluster.Name), constants.SecretKeyNodeCert},
		{"manager-worker", constants.ManagerWorkerCertsName(cluster.Name), constants.SecretKeyNodeCert},
		{"admin", constants.AdminCertsName(cluster.Name), constants.SecretKeyAdminCert},
		{"filebeat", constants.FilebeatCertsName(cluster.Name), constants.SecretKeyNodeCert},
	}

	now := time.Now()
	for _, ci := range certs {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: ci.secretName, Namespace: cluster.Namespace}, secret); err != nil {
			log.V(2).Info("Cannot read certificate secret for expiry metrics", "secret", ci.secretName, "error", err)
			continue
		}
		certPEM, ok := secret.Data[ci.certKey]
		if !ok {
			continue
		}
		expiry, err := certificates.GetCertificateExpiry(certPEM)
		if err != nil {
			log.V(2).Info("Failed to parse certificate expiry", "secret", ci.secretName, "error", err)
			continue
		}
		daysUntilExpiry := expiry.Sub(now).Hours() / 24
		metrics.SetCertificateExpiryDays(cluster.Name, cluster.Namespace, ci.certType, ci.secretName, daysUntilExpiry, float64(expiry.Unix()))
	}
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

		// Skip if drain status is unchanged
		if apiequality.Semantic.DeepEqual(latestCluster.Status.Drain, cluster.Status.Drain) {
			return nil
		}

		// Copy drain status from working cluster
		latestCluster.Status.Drain = cluster.Status.Drain

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

// findClustersForRule finds all WazuhClusters that a WazuhRule references via clusterRef
// Used by the watch handler to enqueue clusters when rules change
func (r *WazuhClusterReconciler) findClustersForRule(ctx context.Context, obj client.Object) []ctrl.Request {
	rule, ok := obj.(*wazuhv1.WazuhRule)
	if !ok {
		return []ctrl.Request{}
	}

	// Determine the namespace of the target cluster
	namespace := rule.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = rule.Namespace
	}

	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      rule.Spec.ClusterRef.Name,
				Namespace: namespace,
			},
		},
	}
}

// findClustersForDecoder finds all WazuhClusters that a WazuhDecoder references via clusterRef
// Used by the watch handler to enqueue clusters when decoders change
func (r *WazuhClusterReconciler) findClustersForDecoder(ctx context.Context, obj client.Object) []ctrl.Request {
	decoder, ok := obj.(*wazuhv1.WazuhDecoder)
	if !ok {
		return []ctrl.Request{}
	}

	// Determine the namespace of the target cluster
	namespace := decoder.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = decoder.Namespace
	}

	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      decoder.Spec.ClusterRef.Name,
				Namespace: namespace,
			},
		},
	}
}

// findClustersForAgentGroup finds all WazuhClusters that a WazuhAgentGroup references via clusterRef
// Used by the watch handler to enqueue clusters when agent group files change
func (r *WazuhClusterReconciler) findClustersForAgentGroup(ctx context.Context, obj client.Object) []ctrl.Request {
	group, ok := obj.(*wazuhv1.WazuhAgentGroup)
	if !ok {
		return []ctrl.Request{}
	}

	// Only trigger cluster reconcile when files are present (otherwise no volume changes needed)
	if len(group.Spec.Files) == 0 {
		return []ctrl.Request{}
	}

	// Determine the namespace of the target cluster
	namespace := group.Spec.ClusterRef.Namespace
	if namespace == "" {
		namespace = group.Namespace
	}

	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      group.Spec.ClusterRef.Name,
				Namespace: namespace,
			},
		},
	}
}

// findClustersForSecret finds WazuhClusters impacted by changes in watched secrets.
// This complements Owns(Secret), which only catches secrets with owner references.
func (r *WazuhClusterReconciler) findClustersForSecret(ctx context.Context, obj client.Object) []ctrl.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return []ctrl.Request{}
	}
	log := logf.FromContext(ctx)

	clusterList := &wazuhv1.WazuhClusterList{}
	if err := r.List(ctx, clusterList, client.InNamespace(secret.Namespace)); err != nil {
		log.Error(err, "Failed to list WazuhClusters for secret watch")
		return []ctrl.Request{}
	}

	requests := []ctrl.Request{}
	for _, cluster := range clusterList.Items {
		expectedCredentials := constants.IndexerCredentialsName(cluster.Name)
		expectedSecurity := constants.IndexerSecurityName(cluster.Name)
		expectedAPICredentials := constants.APICredentialsName(cluster.Name)
		expectedAuthdCredentials := fmt.Sprintf("%s-authd-pass", cluster.Name)
		customAPICredentials := expectedAPICredentials
		if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil {
			if ref := cluster.Spec.Manager.APICredentials.GetSecretName(); ref != "" {
				customAPICredentials = ref
			}
		}
		if cluster.Spec.Manager != nil {
			if cluster.Spec.Manager.Config != nil &&
				cluster.Spec.Manager.Config.Auth != nil &&
				cluster.Spec.Manager.Config.Auth.PasswordSecretRef != nil &&
				cluster.Spec.Manager.Config.Auth.PasswordSecretRef.Name != "" {
				expectedAuthdCredentials = cluster.Spec.Manager.Config.Auth.PasswordSecretRef.Name
			} else if cluster.Spec.Manager.AuthdPasswordSecretRef != nil && cluster.Spec.Manager.AuthdPasswordSecretRef.Name != "" {
				expectedAuthdCredentials = cluster.Spec.Manager.AuthdPasswordSecretRef.Name
			}
		}

		if secret.Name != expectedCredentials &&
			secret.Name != expectedSecurity &&
			secret.Name != expectedAPICredentials &&
			secret.Name != customAPICredentials &&
			secret.Name != expectedAuthdCredentials {
			continue
		}

		requests = append(requests, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		})
		log.V(1).Info("Enqueueing WazuhCluster for secret change",
			"cluster", cluster.Name,
			"secret", secret.Name)
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Wire the event recorder into sub-reconcilers
	if r.ClusterReconciler != nil {
		r.ClusterReconciler.Recorder = r.Recorder
	}
	if r.IndexerReconciler != nil {
		r.IndexerReconciler.Recorder = r.Recorder
	}
	if r.DashboardReconciler != nil {
		r.DashboardReconciler.Recorder = r.Recorder
	}
	if r.WorkerReconciler != nil {
		r.WorkerReconciler.Recorder = r.Recorder
	}

	// Use GenerationChangedPredicate on the primary resource to skip reconciles
	// triggered by status-only updates. Owned resources keep default predicates
	// so we still react to their status changes.
	secretWatchPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		// Accept all Secret events here and filter in findClustersForSecret.
		// This is required to catch custom apiCredentials secret names.
		return obj != nil
	})

	ctrlBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1.WazuhCluster{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		// Watch key indexer secrets even when not owned by WazuhCluster (e.g., Helm-managed).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForSecret),
			builder.WithPredicates(secretWatchPredicate),
		).
		Owns(&networkingv1.Ingress{}).
		// Watch WazuhRule CRs - reconcile WazuhCluster when rules spec changes
		Watches(
			&wazuhv1.WazuhRule{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForRule),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// Watch WazuhDecoder CRs - reconcile WazuhCluster when decoders spec changes
		Watches(
			&wazuhv1.WazuhDecoder{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForDecoder),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// Watch WazuhAgentGroup CRs - reconcile WazuhCluster when agent group spec changes
		Watches(
			&wazuhv1.WazuhAgentGroup{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersForAgentGroup),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		)

	// Only add Gateway API watches if enabled AND the specific CRDs are available
	// This prevents the controller from failing to start if Gateway API CRDs are not installed
	if r.GatewayAPIEnabled {
		if r.HTTPRouteAvailable {
			ctrlBuilder = ctrlBuilder.Owns(&gatewayv1.HTTPRoute{})
		}
		if r.TCPRouteAvailable {
			ctrlBuilder = ctrlBuilder.Owns(&gatewayv1alpha2.TCPRoute{})
		}
		if r.UDPRouteAvailable {
			ctrlBuilder = ctrlBuilder.Owns(&gatewayv1alpha2.UDPRoute{})
		}
	}

	// Configure controller options
	maxConcurrent := r.MaxConcurrentReconciles
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	opts := controller.Options{
		MaxConcurrentReconciles: maxConcurrent,
	}
	if r.RateLimiter != nil {
		opts.RateLimiter = r.RateLimiter
	}

	return ctrlBuilder.
		WithOptions(opts).
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

// hasNetworkPolicyEnabled checks if any component has NetworkPolicy explicitly enabled
func hasNetworkPolicyEnabled(cluster *wazuhv1.WazuhCluster) bool {
	// Check Indexer
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.NetworkPolicy != nil &&
		cluster.Spec.Indexer.NetworkPolicy.Enabled {
		return true
	}

	// Check Manager
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.NetworkPolicy != nil &&
		cluster.Spec.Manager.NetworkPolicy.Enabled {
		return true
	}

	// Check Dashboard
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.NetworkPolicy != nil &&
		cluster.Spec.Dashboard.NetworkPolicy.Enabled {
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
