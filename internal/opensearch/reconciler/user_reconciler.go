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

package reconciler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// UserReconciler handles reconciliation of OpenSearch users
type UserReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	OpenSearchAddr string
	OpenSearchUser string
	OpenSearchPass string
}

// NewUserReconciler creates a new UserReconciler
func NewUserReconciler(c client.Client, scheme *runtime.Scheme) *UserReconciler {
	return &UserReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles an OpenSearch user
func (r *UserReconciler) Reconcile(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser) error {
	log := logf.FromContext(ctx)

	// Get password from secret
	password, err := r.getPassword(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}

	osClient, err := r.getOpenSearchClient(ctx, user.Namespace)
	if err != nil {
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
		return fmt.Errorf("failed to create/update user: %w", err)
	}

	// Update status
	if err := r.updateStatus(ctx, user, "Ready", "User reconciled successfully"); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("User reconciliation completed", "name", user.Name)
	return nil
}

// getPassword retrieves the password from the referenced secret
func (r *UserReconciler) getPassword(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser) (string, error) {
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

// getOpenSearchClient gets an OpenSearch HTTP adapter
func (r *UserReconciler) getOpenSearchClient(ctx context.Context, namespace string) (*adapters.OpenSearchHTTPAdapter, error) {
	config := adapters.OpenSearchConfig{
		BaseURL:  r.OpenSearchAddr,
		Username: r.OpenSearchUser,
		Password: r.OpenSearchPass,
		Insecure: true,
	}

	return adapters.NewOpenSearchHTTPAdapter(config)
}

// updateStatus updates the user status
func (r *UserReconciler) updateStatus(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser, phase, message string) error {
	user.Status.Phase = phase
	user.Status.Message = message
	now := metav1.Now()
	user.Status.LastSyncTime = &now

	return r.Status().Update(ctx, user)
}

// Delete handles cleanup when a user is deleted
func (r *UserReconciler) Delete(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser) error {
	log := logf.FromContext(ctx)

	osClient, err := r.getOpenSearchClient(ctx, user.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get OpenSearch client: %w", err)
	}

	// Use CR name as username
	username := user.Name
	if err := osClient.DeleteUser(ctx, username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	log.Info("Deleted OpenSearch user", "username", username)
	return nil
}
