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
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

const (
	// WazuhUserFinalizer is the finalizer for WazuhUser resources.
	WazuhUserFinalizer = "wazuhuser.resources.wazuh.com/finalizer"

	// WazuhUserConditionTypeReady is the Ready condition type.
	WazuhUserConditionTypeReady = "Ready"
	// WazuhUserConditionTypeSynced is the Synced condition type.
	WazuhUserConditionTypeSynced = "Synced"
)

// WazuhAPIUserReconciler reconciles WazuhUser resources against the Wazuh
// Manager API on each target cluster.
type WazuhAPIUserReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewWazuhAPIUserReconciler creates a new WazuhAPIUserReconciler.
func NewWazuhAPIUserReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *WazuhAPIUserReconciler {
	return &WazuhAPIUserReconciler{Client: c, Scheme: scheme, Recorder: recorder}
}

// Reconcile reconciles a WazuhUser across all target clusters.
func (r *WazuhAPIUserReconciler) Reconcile(ctx context.Context, user *wazuhv1.WazuhUser) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "WazuhAPIUserReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", user.Name),
			attribute.String("resource.namespace", user.Namespace),
			attribute.Int("resource.clusterRefs", len(user.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)
	username := user.ResolveUsername()

	if user.Status.Phase == "" {
		user.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	password, perr := r.getPassword(ctx, user)
	if perr != nil {
		user.Status.Phase = wazuhv1.WazuhRBACPhaseFailed
		user.Status.Message = fmt.Sprintf("failed to resolve password: %v", perr)
		r.setCondition(user, WazuhUserConditionTypeReady, metav1.ConditionFalse, "PasswordUnavailable", user.Status.Message)
		r.event(user, corev1.EventTypeWarning, "PasswordUnavailable", user.Status.Message)
		if uerr := r.updateStatus(ctx, user); uerr != nil {
			return uerr
		}
		return perr
	}

	existingByKey := make(map[string]wazuhv1.WazuhRBACClusterStatus, len(user.Status.ClusterStatuses))
	for _, s := range user.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.WazuhRBACClusterStatus, 0, len(user.Spec.ClusterRefs))
	anyAPIUnavailable := false
	anyFailed := false
	allReady := true

	for _, ref := range user.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		clusterErr := r.reconcileForCluster(ctx, user, username, password, ref, &st)
		if clusterErr != nil {
			if IsAPIUnavailable(clusterErr) {
				anyAPIUnavailable = true
			} else {
				anyFailed = true
			}
			log.Error(clusterErr, "Failed to reconcile WazuhUser on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.WazuhRBACPhaseReady {
			allReady = false
		}
		newStatuses = append(newStatuses, st)
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	user.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		user.Status.Phase = wazuhv1.WazuhRBACPhaseFailed
		r.setCondition(user, WazuhUserConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to sync")
		user.Status.Message = "One or more target clusters failed to sync"
	case anyAPIUnavailable:
		user.Status.Phase = wazuhv1.WazuhRBACPhasePending
		r.setCondition(user, WazuhUserConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			"One or more Wazuh APIs are unavailable")
		user.Status.Message = "Waiting for Wazuh API availability on one or more clusters"
	case allReady:
		user.Status.Phase = wazuhv1.WazuhRBACPhaseReady
		r.setCondition(user, WazuhUserConditionTypeSynced, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("User %s synced on all target clusters", username))
		r.setCondition(user, WazuhUserConditionTypeReady, metav1.ConditionTrue, "Ready",
			fmt.Sprintf("User %s is ready on all target clusters", username))
		user.Status.Message = ""
	default:
		user.Status.Phase = wazuhv1.WazuhRBACPhasePending
	}

	user.Status.ObservedGeneration = user.Generation

	if err := r.updateStatus(ctx, user); err != nil {
		return fmt.Errorf("failed to update WazuhUser status: %w", err)
	}

	metrics.RecordReconciliation("WazuhUser", user.Namespace, "success", 0)

	if anyAPIUnavailable && !anyFailed {
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("one or more wazuh APIs unavailable")}
	}
	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to sync")
	}
	log.Info("WazuhUser reconciliation completed", "name", user.Name, "user", username)
	return nil
}

// reconcileForCluster ensures the user exists, has run_as set and is linked to
// the requested roles on one cluster.
func (r *WazuhAPIUserReconciler) reconcileForCluster(
	ctx context.Context,
	user *wazuhv1.WazuhUser,
	username, password string,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.WazuhRBACClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.WazuhRBACPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterNN)
			r.event(user, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			return nil
		}
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	apiClient, err := buildWazuhAPIClient(ctx, r.Client, cluster)
	if err != nil {
		st.Phase = wazuhv1.WazuhRBACPhasePending
		st.Message = fmt.Sprintf("Wazuh API unavailable: %v", err)
		return &WazuhAPIUnavailableError{Err: err}
	}
	if !apiClient.IsHealthy(ctx) {
		st.Phase = wazuhv1.WazuhRBACPhasePending
		st.Message = "Wazuh API is not healthy"
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("wazuh API health check failed")}
	}

	specHash := computeUserSpecHash(user, username, password)
	if specHash == st.LastAppliedHash && st.UserID != 0 && st.Phase == wazuhv1.WazuhRBACPhaseReady {
		return nil // already synced
	}

	userID, err := apiClient.EnsureUser(ctx, username, password)
	if err != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("user %s: %v", username, err)
		r.event(user, corev1.EventTypeWarning, "UserFailed", st.Message)
		return err
	}
	if userID < adapters.ReservedRBACIDThreshold {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("username %q collides with a reserved Wazuh user", username)
		r.event(user, corev1.EventTypeWarning, "ReservedCollision", st.Message)
		return fmt.Errorf("user %s collides with reserved object (id %d)", username, userID)
	}
	st.UserID = userID

	if err := apiClient.SetUserRunAs(ctx, userID, user.Spec.AllowRunAs); err != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("set run_as: %v", err)
		r.event(user, corev1.EventTypeWarning, "RunAsFailed", st.Message)
		return err
	}

	// Resolve role names to IDs.
	prevRoleIDs := st.AssignedRoleIDs
	newRoleIDs := make(map[string]int, len(user.Spec.Roles))
	for _, roleName := range user.Spec.Roles {
		id, err := apiClient.GetRoleByName(ctx, roleName)
		if err != nil {
			st.Phase = wazuhv1.WazuhRBACPhaseFailed
			st.Message = fmt.Sprintf("resolve role %s: %v", roleName, err)
			r.event(user, corev1.EventTypeWarning, "RoleResolveFailed", st.Message)
			return err
		}
		if id == 0 {
			st.Phase = wazuhv1.WazuhRBACPhaseFailed
			st.Message = fmt.Sprintf("role %q not found on cluster (waiting for WazuhRole)", roleName)
			r.event(user, corev1.EventTypeWarning, "RoleNotFound", st.Message)
			return fmt.Errorf("role %s not found on cluster %s/%s", roleName, ref.Namespace, ref.Name)
		}
		newRoleIDs[roleName] = id
	}

	if err := apiClient.LinkUserRoles(ctx, userID, mapValues(newRoleIDs)); err != nil {
		st.Phase = wazuhv1.WazuhRBACPhaseFailed
		st.Message = fmt.Sprintf("link roles: %v", err)
		r.event(user, corev1.EventTypeWarning, "LinkFailed", st.Message)
		return err
	}
	st.AssignedRoleIDs = newRoleIDs

	// Unlink roles removed from spec (best-effort).
	for name, id := range prevRoleIDs {
		if _, keep := newRoleIDs[name]; !keep {
			if err := apiClient.UnlinkUserRoles(ctx, userID, []int{id}); err != nil {
				log.Error(err, "Failed to unlink removed role", "role", name, "id", id)
			}
		}
	}

	wasReady := st.Phase == wazuhv1.WazuhRBACPhaseReady
	st.Phase = wazuhv1.WazuhRBACPhaseReady
	st.Message = ""
	st.LastAppliedHash = specHash
	if !wasReady {
		now := metav1.Now()
		st.LastSyncTime = &now
		r.event(user, corev1.EventTypeNormal, "Synced",
			fmt.Sprintf("User %s synced on %s/%s", username, ref.Namespace, ref.Name))
	}
	return nil
}

// Delete removes the user from the Wazuh API on every target cluster.
func (r *WazuhAPIUserReconciler) Delete(ctx context.Context, user *wazuhv1.WazuhUser) error {
	log := logf.FromContext(ctx)

	byKey := make(map[string]wazuhv1.WazuhRBACClusterStatus, len(user.Status.ClusterStatuses))
	for _, s := range user.Status.ClusterStatuses {
		byKey[clusterKey(s.Name, s.Namespace)] = s
	}

	var cleanupErrs []string
	for _, ref := range user.Spec.ClusterRefs {
		st := byKey[clusterKey(ref.Name, ref.Namespace)]
		if st.UserID < adapters.ReservedRBACIDThreshold {
			continue
		}
		cluster := &wazuhv1.WazuhCluster{}
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, cluster); err != nil {
			if errors.IsNotFound(err) {
				// The cluster itself is gone, so the user went with it: nothing to delete.
				log.Info("Cluster not found during delete, skipping API cleanup", "cluster", ref.Name)
				continue
			}
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: get cluster: %v", ref.Namespace, ref.Name, err))
			continue
		}
		apiClient, err := buildWazuhAPIClient(ctx, r.Client, cluster)
		if err != nil {
			// API temporarily unavailable: retry rather than leak the user.
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: build API client: %v", ref.Namespace, ref.Name, err))
			continue
		}
		if err := apiClient.UnlinkUserRoles(ctx, st.UserID, mapValues(st.AssignedRoleIDs)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: unlink user roles: %v", ref.Namespace, ref.Name, err))
		}
		if err := apiClient.DeleteUsers(ctx, st.UserID); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s/%s: delete user: %v", ref.Namespace, ref.Name, err))
		}
	}

	if len(cleanupErrs) > 0 {
		// Keep the finalizer and retry: the user must actually be removed from Wazuh, not
		// silently leaked when the API is unavailable or the delete fails.
		return fmt.Errorf("user %q cleanup incomplete, will retry: %s", user.ResolveUsername(), strings.Join(cleanupErrs, "; "))
	}

	r.event(user, corev1.EventTypeNormal, "Deleted",
		fmt.Sprintf("User %s cleaned up on all target clusters", user.ResolveUsername()))
	return nil
}

// getPassword resolves the user password from the referenced Secret.
func (r *WazuhAPIUserReconciler) getPassword(ctx context.Context, user *wazuhv1.WazuhUser) (string, error) {
	if user.Spec.PasswordSecret == nil {
		return "", fmt.Errorf("passwordSecret not specified")
	}
	secretName := user.Spec.PasswordSecret.GetSecretName()
	if secretName == "" {
		return "", fmt.Errorf("passwordSecret has no secret name")
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: user.Namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get password secret: %w", err)
	}
	key := user.Spec.PasswordSecret.PasswordKey
	if key == "" {
		key = "password"
	}
	password, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, secretName)
	}
	return string(password), nil
}

func (r *WazuhAPIUserReconciler) setCondition(user *wazuhv1.WazuhUser, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&user.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: user.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *WazuhAPIUserReconciler) event(user *wazuhv1.WazuhUser, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(user, eventType, reason, message)
	}
}

func (r *WazuhAPIUserReconciler) updateStatus(ctx context.Context, user *wazuhv1.WazuhUser) error {
	desiredStatus := user.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhUser{}
		if err := r.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		user.Status = latest.Status
		return nil
	})
}

// computeUserSpecHash hashes the user spec (incl. password) for drift detection.
func computeUserSpecHash(user *wazuhv1.WazuhUser, username, password string) string {
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(password))
	h.Write([]byte(strconv.FormatBool(user.Spec.AllowRunAs)))
	roles := append([]string(nil), user.Spec.Roles...)
	sort.Strings(roles)
	for _, role := range roles {
		h.Write([]byte(role))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
