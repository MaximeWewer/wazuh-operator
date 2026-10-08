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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/dashboards"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DefaultDashboardObjectResync is the default period between two imports of an unchanged
// source (spec.resyncInterval).
const DefaultDashboardObjectResync = 10 * time.Minute

// DashboardObjectsAPI is the subset of the Dashboards saved objects API the reconciler uses.
type DashboardObjectsAPI interface {
	Import(ctx context.Context, tenant string, ndjson []byte) (int, error)
	Delete(ctx context.Context, tenant string, obj dashboards.ObjectRef) error
}

// DashboardObjectReconciler imports OpenSearch Dashboards saved objects from an NDJSON
// export. The source is the truth: every sync re-imports it with overwrite, so changes
// made in the Dashboards UI to managed objects are reverted, and objects removed from the
// source are pruned.
type DashboardObjectReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory

	// NewAPI builds the Dashboards API client of a target cluster. Defaults to a client
	// built from ClientFactory; tests replace it.
	NewAPI func(ctx context.Context, ref wazuhv1.WazuhClusterRef) (DashboardObjectsAPI, error)
}

// NewDashboardObjectReconciler creates a new DashboardObjectReconciler
func NewDashboardObjectReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *DashboardObjectReconciler {
	r := &DashboardObjectReconciler{Client: c, Scheme: scheme, Recorder: recorder}
	r.NewAPI = r.defaultAPI
	return r
}

// WithClientFactory sets the OpenSearch client factory
func (r *DashboardObjectReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *DashboardObjectReconciler {
	r.ClientFactory = factory
	return r
}

func (r *DashboardObjectReconciler) defaultAPI(ctx context.Context, ref wazuhv1.WazuhClusterRef) (DashboardObjectsAPI, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("waiting for OpenSearch client factory")
	}
	info, err := r.ClientFactory.GetDashboardConnectionInfoForRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	return dashboards.NewClient(info, constants.TimeoutOpenSearchRequest)
}

// ResyncInterval returns the effective resync period of obj.
func ResyncInterval(obj *wazuhv1.OpenSearchDashboardObject) time.Duration {
	if obj.Spec.ResyncInterval != nil && obj.Spec.ResyncInterval.Duration > 0 {
		return obj.Spec.ResyncInterval.Duration
	}
	return DefaultDashboardObjectResync
}

// Reconcile imports the saved objects on every target cluster and prunes the ones removed
// from the source. It returns the delay before the next sync.
func (r *DashboardObjectReconciler) Reconcile(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject) (requeueAfter time.Duration, reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "DashboardObjectReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", obj.Name),
			attribute.String("resource.namespace", obj.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()
	log := logf.FromContext(ctx)

	if !obj.DeletionTimestamp.IsZero() {
		return 0, r.handleDeletion(ctx, obj)
	}
	if !controllerutil.ContainsFinalizer(obj, constants.DashboardObjectFinalizer) {
		controllerutil.AddFinalizer(obj, constants.DashboardObjectFinalizer)
		if err := r.Update(ctx, obj); err != nil {
			return 0, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	content, err := r.resolveSource(ctx, obj)
	if err != nil {
		// Waits for the ConfigMap watch or a spec change; no point retrying blindly.
		return 0, r.setFailed(ctx, obj, "SourceUnavailable", err.Error())
	}
	desired, err := dashboards.ParseNDJSON(content)
	if err != nil {
		return 0, r.setFailed(ctx, obj, "InvalidSource", fmt.Sprintf("invalid NDJSON export: %v", err))
	}

	tenant := obj.Spec.Tenant
	removed := r.objectsToRemove(obj, desired)
	statuses, anyFailed, anyPending, firstErr := r.syncClusters(ctx, obj, tenant, content, removed)

	allReady := !anyFailed && !anyPending
	obj.Status.ClusterStatuses = statuses
	obj.Status.ObjectCount = len(desired)
	if allReady {
		obj.Status.Objects = toStatusRefs(desired)
		obj.Status.Tenant = tenant
		obj.Status.LastAppliedHash = sourceHash(content, tenant)
		now := metav1.Now()
		obj.Status.LastSyncTime = &now
	} else {
		// Keep tracking the objects still to prune so the next sync retries them.
		obj.Status.Objects = toStatusRefs(unionRefs(desired, removed))
	}

	phase, msg := wazuhv1.OpenSearchResourcePhaseReady,
		fmt.Sprintf("%d saved object(s) synced on all target clusters", len(desired))
	switch {
	case anyFailed:
		phase, msg = wazuhv1.OpenSearchResourcePhaseFailed, "One or more target clusters failed to sync"
		r.recordEvent(obj, corev1.EventTypeWarning, "SyncFailed", firstErr.Error())
	case anyPending:
		phase, msg = wazuhv1.OpenSearchResourcePhasePending, "Waiting on one or more target clusters"
	}
	wasReady := obj.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady && obj.Status.ObservedGeneration == obj.Generation
	if err := r.updateStatus(ctx, obj, phase, msg, conditionReason(phase)); err != nil {
		return 0, fmt.Errorf("failed to update status: %w", err)
	}
	if allReady && !wasReady {
		r.recordEvent(obj, corev1.EventTypeNormal, "Synced", msg)
	}
	if firstErr != nil {
		return 0, firstErr
	}
	log.V(1).Info("Dashboard objects synced", "name", obj.Name, "objects", len(desired), "pruned", len(removed))
	return ResyncInterval(obj), nil
}

// syncClusters imports content and deletes removed on every target cluster.
func (r *DashboardObjectReconciler) syncClusters(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject, tenant string, content []byte, removed []dashboards.ObjectRef) (statuses []wazuhv1.OpenSearchClusterStatus, anyFailed, anyPending bool, firstErr error) {
	log := logf.FromContext(ctx)
	existing := make(map[string]wazuhv1.OpenSearchClusterStatus, len(obj.Status.ClusterStatuses))
	for _, s := range obj.Status.ClusterStatuses {
		existing[s.Namespace+"/"+s.Name] = s
	}
	removeTenant := obj.Status.Tenant
	hash := sourceHash(content, tenant)

	for _, ref := range obj.Spec.ClusterRefs {
		st := existing[ref.Namespace+"/"+ref.Name]
		st.Name, st.Namespace = ref.Name, ref.Namespace

		api, err := r.NewAPI(ctx, ref)
		if err != nil {
			st.Phase, st.Message = wazuhv1.OpenSearchResourcePhasePending, fmt.Sprintf("Dashboard not reachable: %v", err)
			anyPending = true
			if firstErr == nil {
				firstErr = err
			}
			statuses = append(statuses, st)
			continue
		}

		count, err := api.Import(ctx, tenant, content)
		if err == nil {
			var pruneErrs []string
			for _, o := range removed {
				if derr := api.Delete(ctx, removeTenant, o); derr != nil {
					pruneErrs = append(pruneErrs, derr.Error())
				} else {
					log.Info("Pruned saved object removed from the source", "object", o.String(),
						"cluster", ref.Name, "clusterNamespace", ref.Namespace)
				}
			}
			if len(pruneErrs) > 0 {
				err = fmt.Errorf("prune failed: %s", strings.Join(pruneErrs, "; "))
			}
		}
		if err != nil {
			st.Phase, st.Message = wazuhv1.OpenSearchResourcePhaseFailed, err.Error()
			anyFailed = true
			if firstErr == nil {
				firstErr = fmt.Errorf("%s/%s: %w", ref.Namespace, ref.Name, err)
			}
			statuses = append(statuses, st)
			continue
		}

		now := metav1.Now()
		st.Phase, st.Message = wazuhv1.OpenSearchResourcePhaseReady, fmt.Sprintf("%d saved object(s) imported", count)
		st.LastSyncTime = &now
		st.LastAppliedHash = hash
		statuses = append(statuses, st)
	}

	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].Namespace != statuses[j].Namespace {
			return statuses[i].Namespace < statuses[j].Namespace
		}
		return statuses[i].Name < statuses[j].Name
	})
	return statuses, anyFailed, anyPending, firstErr
}

// objectsToRemove returns the previously managed objects to delete: all of them when the
// tenant changed (they live in the old tenant), else those no longer in the source when
// pruning is enabled.
func (r *DashboardObjectReconciler) objectsToRemove(obj *wazuhv1.OpenSearchDashboardObject, desired []dashboards.ObjectRef) []dashboards.ObjectRef {
	previous := fromStatusRefs(obj.Status.Objects)
	if len(previous) == 0 {
		return nil
	}
	if obj.Status.Tenant != obj.Spec.Tenant {
		return previous
	}
	if !ptr.Deref(obj.Spec.Prune, true) {
		return nil
	}
	keep := make(map[dashboards.ObjectRef]bool, len(desired))
	for _, o := range desired {
		keep[o] = true
	}
	var removed []dashboards.ObjectRef
	for _, o := range previous {
		if !keep[o] {
			removed = append(removed, o)
		}
	}
	return removed
}

// resolveSource returns the NDJSON export from the inline field or the ConfigMap.
func (r *DashboardObjectReconciler) resolveSource(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject) ([]byte, error) {
	src := obj.Spec.Source
	if src.ConfigMapRef == nil {
		if strings.TrimSpace(src.NDJSON) == "" {
			return nil, fmt.Errorf("source.ndjson is empty")
		}
		return []byte(src.NDJSON), nil
	}
	key := src.ConfigMapRef.Key
	if key == "" {
		key = "export.ndjson"
	}
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: src.ConfigMapRef.Name, Namespace: obj.Namespace}, cm); err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s: %w", src.ConfigMapRef.Name, err)
	}
	if v, ok := cm.Data[key]; ok {
		return []byte(v), nil
	}
	if v, ok := cm.BinaryData[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("key %q not found in ConfigMap %s", key, src.ConfigMapRef.Name)
}

// handleDeletion deletes every managed object from every target cluster, then removes
// the finalizer. A cluster that no longer exists is skipped.
func (r *DashboardObjectReconciler) handleDeletion(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject) error {
	if !controllerutil.ContainsFinalizer(obj, constants.DashboardObjectFinalizer) {
		return nil
	}
	log := logf.FromContext(ctx)
	objects := fromStatusRefs(obj.Status.Objects)
	var cleanupErrs []string
	for _, ref := range obj.Spec.ClusterRefs {
		if len(objects) == 0 {
			break
		}
		api, err := r.NewAPI(ctx, ref)
		if err != nil {
			if errors.IsNotFound(err) || strings.Contains(err.Error(), "has no dashboard") {
				log.Info("Cluster or dashboard gone, skipping saved objects cleanup",
					"cluster", ref.Name, "clusterNamespace", ref.Namespace)
				continue
			}
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: connect: %v", ref.Namespace, ref.Name, err))
			continue
		}
		for _, o := range objects {
			if err := api.Delete(ctx, obj.Status.Tenant, o); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: %v", ref.Namespace, ref.Name, err))
			}
		}
	}
	if len(cleanupErrs) > 0 {
		r.recordEvent(obj, corev1.EventTypeWarning, "DeleteFailed", strings.Join(cleanupErrs, "; "))
		// Keep the finalizer: never leak the saved objects when the dashboard is unavailable.
		return fmt.Errorf("saved objects cleanup incomplete, will retry: %s", strings.Join(cleanupErrs, "; "))
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchDashboardObject{}
		if err := r.Get(ctx, types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}, latest); err != nil {
			return client.IgnoreNotFound(err)
		}
		controllerutil.RemoveFinalizer(latest, constants.DashboardObjectFinalizer)
		return r.Update(ctx, latest)
	})
}

func (r *DashboardObjectReconciler) setFailed(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject, reason, msg string) error {
	r.recordEvent(obj, corev1.EventTypeWarning, reason, msg)
	return r.updateStatus(ctx, obj, wazuhv1.OpenSearchResourcePhaseFailed, msg, reason)
}

// updateStatus writes the status with retry on conflict.
func (r *DashboardObjectReconciler) updateStatus(ctx context.Context, obj *wazuhv1.OpenSearchDashboardObject, phase wazuhv1.OpenSearchResourcePhase, message, reason string) error {
	obj.Status.Phase = phase
	obj.Status.Message = message
	obj.Status.ObservedGeneration = obj.Generation
	condStatus := metav1.ConditionFalse
	if phase == wazuhv1.OpenSearchResourcePhaseReady {
		condStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: obj.Generation,
	})
	metrics.SetResourceSyncStatus("OpenSearchDashboardObject", obj.Namespace, obj.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desired := obj.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchDashboardObject{}
		if err := r.Get(ctx, types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desired
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		obj.Status = latest.Status
		return nil
	})
}

func (r *DashboardObjectReconciler) recordEvent(obj *wazuhv1.OpenSearchDashboardObject, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, eventType, reason, message)
	}
}

func conditionReason(phase wazuhv1.OpenSearchResourcePhase) string {
	switch phase {
	case wazuhv1.OpenSearchResourcePhaseReady:
		return "Synced"
	case wazuhv1.OpenSearchResourcePhaseFailed:
		return "SyncFailed"
	default:
		return "Pending"
	}
}

func sourceHash(content []byte, tenant string) string {
	sum := sha256.Sum256(append([]byte(tenant+"\n"), content...))
	return hex.EncodeToString(sum[:])[:16]
}

func toStatusRefs(objs []dashboards.ObjectRef) []wazuhv1.DashboardObjectStatusRef {
	out := make([]wazuhv1.DashboardObjectStatusRef, 0, len(objs))
	for _, o := range objs {
		out = append(out, wazuhv1.DashboardObjectStatusRef{Type: o.Type, ID: o.ID})
	}
	return out
}

func fromStatusRefs(refs []wazuhv1.DashboardObjectStatusRef) []dashboards.ObjectRef {
	out := make([]dashboards.ObjectRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, dashboards.ObjectRef{Type: r.Type, ID: r.ID})
	}
	return out
}

func unionRefs(a, b []dashboards.ObjectRef) []dashboards.ObjectRef {
	seen := make(map[dashboards.ObjectRef]bool, len(a)+len(b))
	out := make([]dashboards.ObjectRef, 0, len(a)+len(b))
	for _, list := range [][]dashboards.ObjectRef{a, b} {
		for _, o := range list {
			if !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	return out
}
