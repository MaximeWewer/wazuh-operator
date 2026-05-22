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

	"go.opentelemetry.io/otel/attribute"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	retry "k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// UserReconciler handles reconciliation of OpenSearch users
type UserReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory *security.OpenSearchClientFactory
}

// NewUserReconciler creates a new UserReconciler
func NewUserReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *UserReconciler {
	return &UserReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// WithClientFactory sets the OpenSearch client factory for dynamic client resolution
func (r *UserReconciler) WithClientFactory(factory *security.OpenSearchClientFactory) *UserReconciler {
	r.ClientFactory = factory
	return r
}

// Reconcile reconciles an OpenSearch user
func (r *UserReconciler) Reconcile(ctx context.Context, user *wazuhv1.OpenSearchUser) (reconcileErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "UserReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", user.Name),
			attribute.String("resource.namespace", user.Namespace),
		))
	defer span.End()
	defer func() {
		if reconcileErr != nil {
			telemetry.RecordError(span, reconcileErr)
		}
	}()

	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(user, constants.UserFinalizer) {
		controllerutil.AddFinalizer(user, constants.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !user.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, user)
	}

	// Get password from secret
	password, err := r.getPassword(ctx, user)
	if err != nil {
		r.recordEvent(user, corev1.EventTypeWarning, "PasswordError", fmt.Sprintf("Failed to get password: %v", err))
		return fmt.Errorf("failed to get password: %w", err)
	}

	username := user.Name
	osUser := adapters.SecurityUser{
		Password:                password,
		BackendRoles:            user.Spec.BackendRoles,
		Attributes:              user.Spec.Attributes,
		Description:             user.Spec.Description,
		OpendistroSecurityRoles: user.Spec.OpenSearchRoles,
	}
	specHash, _ := patch.ComputeSpecHash(user.Spec)

	newStatuses := make([]wazuhv1.OpenSearchClusterStatus, 0, len(user.Spec.ClusterRefs))
	anyFailed := false
	anyPending := false
	allReady := len(user.Spec.ClusterRefs) > 0
	var firstErr error
	existingByKey := make(map[string]wazuhv1.OpenSearchClusterStatus, len(user.Status.ClusterStatuses))
	for _, s := range user.Status.ClusterStatuses {
		existingByKey[s.Namespace+"/"+s.Name] = s
	}

	for _, ref := range user.Spec.ClusterRefs {
		st := existingByKey[ref.Namespace+"/"+ref.Name]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		osClient, err := r.getOpenSearchClientForRef(ctx, ref)
		if err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhasePending
			st.Message = fmt.Sprintf("Failed to connect: %v", err)
			anyPending = true
			allReady = false
			if firstErr == nil {
				firstErr = err
			}
			r.recordEvent(user, corev1.EventTypeWarning, "ConnectionError",
				fmt.Sprintf("Failed to connect to OpenSearch %s/%s: %v", ref.Namespace, ref.Name, err))
			newStatuses = append(newStatuses, st)
			continue
		}
		if err := osClient.CreateUser(ctx, username, osUser); err != nil {
			st.Phase = wazuhv1.OpenSearchResourcePhaseFailed
			st.Message = err.Error()
			anyFailed = true
			allReady = false
			if firstErr == nil {
				firstErr = err
			}
			r.recordEvent(user, corev1.EventTypeWarning, "SyncFailed",
				fmt.Sprintf("Failed to sync user to %s/%s: %v", ref.Namespace, ref.Name, err))
			newStatuses = append(newStatuses, st)
			continue
		}
		wasClusterReady := st.Phase == wazuhv1.OpenSearchResourcePhaseReady
		st.Phase = wazuhv1.OpenSearchResourcePhaseReady
		st.Message = ""
		st.LastAppliedHash = specHash
		if !wasClusterReady {
			now := metav1.Now()
			st.LastSyncTime = &now
		}
		newStatuses = append(newStatuses, st)
	}
	user.Status.ClusterStatuses = newStatuses

	if specHash != "" && user.Status.LastAppliedHash != "" && user.Status.LastAppliedHash != specHash {
		user.Status.DriftDetected = true
		now := metav1.Now()
		user.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchUser", user.Namespace)
		log.Info("Drift detected on OpenSearchUser", "name", user.Name)
	} else {
		user.Status.DriftDetected = false
	}
	if specHash != "" {
		user.Status.LastAppliedHash = specHash
	}

	wasReady := user.Status.Phase == wazuhv1.OpenSearchResourcePhaseReady &&
		user.Status.ObservedGeneration == user.Generation

	var phase wazuhv1.OpenSearchResourcePhase
	var msg string
	switch {
	case anyFailed:
		phase = wazuhv1.OpenSearchResourcePhaseFailed
		msg = "One or more target clusters failed to sync"
	case anyPending:
		phase = wazuhv1.OpenSearchResourcePhasePending
		msg = "Waiting on one or more target clusters"
	case allReady:
		phase = wazuhv1.OpenSearchResourcePhaseReady
		msg = "User reconciled on all target clusters"
	default:
		phase = wazuhv1.OpenSearchResourcePhasePending
		msg = ""
	}
	if err := r.updateStatus(ctx, user, phase, msg, phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	if phase == wazuhv1.OpenSearchResourcePhaseReady && !wasReady {
		r.recordEvent(user, corev1.EventTypeNormal, "Synced", "User synced on all target clusters")
	}

	if firstErr != nil {
		return firstErr
	}
	log.Info("User reconciliation completed", "name", user.Name)
	return nil
}

// getOpenSearchClientForRef builds an HTTP adapter for the given cluster ref.
func (r *UserReconciler) getOpenSearchClientForRef(ctx context.Context, ref wazuhv1.WazuhClusterRef) (*adapters.OpenSearchHTTPAdapter, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("client factory not configured")
	}
	baseURL, username, password, caCert, err := r.ClientFactory.GetConnectionInfoForRef(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}
	return adapters.NewOpenSearchHTTPAdapter(adapters.OpenSearchConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	})
}

// recordEvent emits an event if the recorder is available
func (r *UserReconciler) recordEvent(user *wazuhv1.OpenSearchUser, eventType, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(user, eventType, reason, message)
	}
}

// getPassword retrieves the password from the referenced secret
func (r *UserReconciler) getPassword(ctx context.Context, user *wazuhv1.OpenSearchUser) (string, error) {
	// Check if hash is provided directly
	if user.Spec.Hash != "" {
		return user.Spec.Hash, nil
	}

	// Otherwise get from secret
	if user.Spec.PasswordSecret == nil {
		return "", fmt.Errorf("password secret reference not specified and no hash provided")
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      user.Spec.PasswordSecret.SecretName,
		Namespace: user.Namespace,
	}, secret); err != nil {
		return "", fmt.Errorf("failed to get password secret: %w", err)
	}

	// Use PasswordKey from CredentialsSecretRef (default to "password")
	key := user.Spec.PasswordSecret.PasswordKey
	if key == "" {
		key = "password"
	}

	password, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret", key)
	}

	return string(password), nil
}

// getOpenSearchClient (legacy) returns a client for the first cluster ref.
// Used by Delete which currently iterates manually.
func (r *UserReconciler) getOpenSearchClient(ctx context.Context, user *wazuhv1.OpenSearchUser) (*adapters.OpenSearchHTTPAdapter, error) {
	if len(user.Spec.ClusterRefs) == 0 {
		return nil, fmt.Errorf("no cluster references configured")
	}
	return r.getOpenSearchClientForRef(ctx, user.Spec.ClusterRefs[0])
}

// updateStatus updates the user status with retry on conflict.
// Skips the write when phase, message and generation are unchanged.
func (r *UserReconciler) updateStatus(ctx context.Context, user *wazuhv1.OpenSearchUser, phase wazuhv1.OpenSearchResourcePhase, message string, updateTimestamp ...bool) error {
	shouldUpdateTS := len(updateTimestamp) == 0 || updateTimestamp[0]

	// Skip entirely when nothing changed
	if user.Status.Phase == phase && user.Status.Message == message &&
		user.Status.ObservedGeneration == user.Generation && !shouldUpdateTS {
		return nil
	}

	user.Status.Phase = phase
	user.Status.Message = message
	user.Status.ObservedGeneration = user.Generation
	if shouldUpdateTS {
		now := metav1.Now()
		user.Status.LastSyncTime = &now
	}

	metrics.SetResourceSyncStatus("OpenSearchUser", user.Namespace, user.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	desiredStatus := user.Status
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchUser{}
		if err := r.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, latest); err != nil {
			return err
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		user.Status = latest.Status
		return nil
	})
}

// handleDeletion handles user cleanup on deletion
func (r *UserReconciler) handleDeletion(ctx context.Context, user *wazuhv1.OpenSearchUser) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, user); err != nil {
		log.Error(err, "Failed to delete user from OpenSearch, proceeding with finalizer removal")
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &wazuhv1.OpenSearchUser{}
		if err := r.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, latest); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(latest, constants.UserFinalizer)
		return r.Client.Update(ctx, latest)
	})
}

// Delete handles cleanup when a user is deleted
func (r *UserReconciler) Delete(ctx context.Context, user *wazuhv1.OpenSearchUser) error {
	log := logf.FromContext(ctx)
	username := user.Name

	for _, ref := range user.Spec.ClusterRefs {
		osClient, err := r.getOpenSearchClientForRef(ctx, ref)
		if err != nil {
			r.recordEvent(user, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to connect to %s/%s for deletion: %v", ref.Namespace, ref.Name, err))
			continue
		}
		if err := osClient.DeleteUser(ctx, username); err != nil {
			r.recordEvent(user, corev1.EventTypeWarning, "DeleteFailed",
				fmt.Sprintf("Failed to delete user from %s/%s: %v", ref.Namespace, ref.Name, err))
			continue
		}
		log.Info("Deleted OpenSearch user", "username", username, "cluster", ref.Name, "clusterNamespace", ref.Namespace)
	}
	r.recordEvent(user, corev1.EventTypeNormal, "Deleted", "User deletion processed on all target clusters")
	return nil
}
