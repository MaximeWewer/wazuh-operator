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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
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
func (r *UserReconciler) Reconcile(ctx context.Context, user *wazuhv1.OpenSearchUser) error {
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

	osClient, err := r.getOpenSearchClient(ctx, user)
	if err != nil {
		r.recordEvent(user, corev1.EventTypeWarning, "ConnectionError", fmt.Sprintf("Failed to connect to OpenSearch: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Create or update user - use CR name as username
	username := user.Name
	osUser := adapters.SecurityUser{
		Password:                password,
		BackendRoles:            user.Spec.BackendRoles,
		Attributes:              user.Spec.Attributes,
		Description:             user.Spec.Description,
		OpendistroSecurityRoles: user.Spec.OpenSearchRoles,
	}

	if err := osClient.CreateUser(ctx, username, osUser); err != nil {
		r.recordEvent(user, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Failed to sync user to OpenSearch: %v", err))
		return fmt.Errorf("failed to create/update user: %w", err)
	}

	r.recordEvent(user, corev1.EventTypeNormal, "Synced", "User successfully synchronized to OpenSearch")

	// Compute spec hash for drift detection
	specHash, hashErr := patch.ComputeSpecHash(user.Spec)
	if hashErr == nil && user.Status.LastAppliedHash != "" && user.Status.LastAppliedHash != specHash {
		user.Status.DriftDetected = true
		now := metav1.Now()
		user.Status.LastDriftTime = &now
		metrics.RecordDriftDetection("OpenSearchUser", user.Namespace)
		log.Info("Drift detected on OpenSearchUser", "name", user.Name)
	} else {
		user.Status.DriftDetected = false
	}
	if hashErr == nil {
		user.Status.LastAppliedHash = specHash
	}

	// Update status
	if err := r.updateStatus(ctx, user, wazuhv1.OpenSearchResourcePhaseReady, "User reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("User reconciliation completed", "name", user.Name)
	return nil
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

// getOpenSearchClient gets an OpenSearch HTTP adapter using dynamic client resolution
func (r *UserReconciler) getOpenSearchClient(ctx context.Context, user *wazuhv1.OpenSearchUser) (*adapters.OpenSearchHTTPAdapter, error) {
	if r.ClientFactory == nil {
		return nil, fmt.Errorf("client factory not configured")
	}

	baseURL, username, password, caCert, err := r.ClientFactory.GetConnectionInfo(ctx, user.Spec.ClusterRef, user.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection info: %w", err)
	}

	config := adapters.OpenSearchConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the user status
func (r *UserReconciler) updateStatus(ctx context.Context, user *wazuhv1.OpenSearchUser, phase wazuhv1.OpenSearchResourcePhase, message string) error {
	user.Status.Phase = phase
	user.Status.Message = message
	now := metav1.Now()
	user.Status.LastSyncTime = &now

	metrics.SetResourceSyncStatus("OpenSearchUser", user.Namespace, user.Name, phase == wazuhv1.OpenSearchResourcePhaseReady)

	return r.Status().Update(ctx, user)
}

// handleDeletion handles user cleanup on deletion
func (r *UserReconciler) handleDeletion(ctx context.Context, user *wazuhv1.OpenSearchUser) error {
	log := logf.FromContext(ctx)

	if err := r.Delete(ctx, user); err != nil {
		log.Error(err, "Failed to delete user from OpenSearch, proceeding with finalizer removal")
	}

	controllerutil.RemoveFinalizer(user, constants.UserFinalizer)
	return r.Update(ctx, user)
}

// Delete handles cleanup when a user is deleted
func (r *UserReconciler) Delete(ctx context.Context, user *wazuhv1.OpenSearchUser) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, user)
	if err != nil {
		r.recordEvent(user, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to connect to OpenSearch for deletion: %v", err))
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Use CR name as username
	username := user.Name
	if err := osClient.DeleteUser(ctx, username); err != nil {
		r.recordEvent(user, corev1.EventTypeWarning, "DeleteFailed", fmt.Sprintf("Failed to delete user from OpenSearch: %v", err))
		return fmt.Errorf("failed to delete user: %w", err)
	}

	r.recordEvent(user, corev1.EventTypeNormal, "Deleted", "User deleted from OpenSearch")
	log.Info("Deleted OpenSearch user", "username", username)
	return nil
}
