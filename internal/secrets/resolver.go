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

package secrets

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// Resolver resolves secrets from various sources (native K8s Secrets, ExternalSecrets)
type Resolver struct {
	client client.Client
}

// NewResolver creates a new secret resolver
func NewResolver(c client.Client) *Resolver {
	return &Resolver{client: c}
}

// ResolveSecretSourceRef resolves a SecretSourceRef to secret data
// For ExternalSecrets, it reads the K8s Secret that ESO creates
func (r *Resolver) ResolveSecretSourceRef(ctx context.Context, ref *wazuhv1.SecretSourceRef, defaultNamespace string) (*corev1.Secret, error) {
	if ref == nil {
		return nil, fmt.Errorf("secret reference is nil")
	}

	secretName := ref.GetSecretName()
	if secretName == "" {
		return nil, fmt.Errorf("secret name is empty")
	}

	namespace := ref.GetSecretNamespace(defaultNamespace)

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}

	return secret, nil
}

// ResolveSecretKey resolves a specific key from a SecretSourceRef
func (r *Resolver) ResolveSecretKey(ctx context.Context, ref *wazuhv1.SecretSourceRef, key, defaultNamespace string) (string, error) {
	secret, err := r.ResolveSecretSourceRef(ctx, ref, defaultNamespace)
	if err != nil {
		return "", err
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, secret.Namespace, secret.Name)
	}

	return string(value), nil
}

// ResolveSecretReference resolves a native SecretReference
func (r *Resolver) ResolveSecretReference(ctx context.Context, ref *wazuhv1.SecretReference, defaultNamespace string) (*corev1.Secret, error) {
	if ref == nil {
		return nil, fmt.Errorf("secret reference is nil")
	}

	namespace := defaultNamespace
	if ref.Namespace != "" {
		namespace = ref.Namespace
	}

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      ref.Name,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	return secret, nil
}

// ResolveSecretKeyRef resolves a SecretKeyRef to a string value
func (r *Resolver) ResolveSecretKeyRef(ctx context.Context, ref *wazuhv1.SecretKeyRef, defaultNamespace string) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("secret key reference is nil")
	}

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      ref.Name,
		Namespace: defaultNamespace,
	}, secret)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", defaultNamespace, ref.Name, err)
	}

	key := ref.Key
	if key == "" {
		key = "password"
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, defaultNamespace, ref.Name)
	}

	return string(value), nil
}

// ResolveCredentials resolves credentials from a CredentialsSecretRef
func (r *Resolver) ResolveCredentials(ctx context.Context, ref *wazuhv1.CredentialsSecretRef, defaultNamespace string) (username, password string, err error) {
	if ref == nil {
		return "", "", fmt.Errorf("credentials reference is nil")
	}

	// Try ExternalSecret first if specified
	if ref.ExternalSecretRef != nil {
		return r.resolveCredentialsFromExternalSecret(ctx, ref, defaultNamespace)
	}

	// Fall back to native secret
	if ref.SecretName != "" {
		return r.resolveCredentialsFromNativeSecret(ctx, ref, defaultNamespace)
	}

	return "", "", fmt.Errorf("no secret reference specified")
}

// resolveCredentialsFromNativeSecret resolves credentials from a native K8s Secret
func (r *Resolver) resolveCredentialsFromNativeSecret(ctx context.Context, ref *wazuhv1.CredentialsSecretRef, defaultNamespace string) (string, string, error) {
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      ref.SecretName,
		Namespace: defaultNamespace,
	}, secret)
	if err != nil {
		return "", "", fmt.Errorf("failed to get credentials secret %s/%s: %w", defaultNamespace, ref.SecretName, err)
	}

	usernameKey := "username"
	if ref.UsernameKey != "" {
		usernameKey = ref.UsernameKey
	}

	passwordKey := "password"
	if ref.PasswordKey != "" {
		passwordKey = ref.PasswordKey
	}

	username, ok := secret.Data[usernameKey]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in secret %s/%s", usernameKey, defaultNamespace, ref.SecretName)
	}

	password, ok := secret.Data[passwordKey]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in secret %s/%s", passwordKey, defaultNamespace, ref.SecretName)
	}

	return string(username), string(password), nil
}

// resolveCredentialsFromExternalSecret resolves credentials from an ExternalSecret
func (r *Resolver) resolveCredentialsFromExternalSecret(ctx context.Context, ref *wazuhv1.CredentialsSecretRef, defaultNamespace string) (string, string, error) {
	// ExternalSecret creates a K8s Secret with the same name
	secretName := ref.ExternalSecretRef.Name
	namespace := defaultNamespace
	if ref.ExternalSecretRef.Namespace != "" {
		namespace = ref.ExternalSecretRef.Namespace
	}

	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return "", "", fmt.Errorf("failed to get secret from ExternalSecret %s/%s: %w", namespace, secretName, err)
	}

	usernameKey := "username"
	if ref.UsernameKey != "" {
		usernameKey = ref.UsernameKey
	}

	passwordKey := "password"
	if ref.PasswordKey != "" {
		passwordKey = ref.PasswordKey
	}

	username, ok := secret.Data[usernameKey]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in secret from ExternalSecret %s/%s", usernameKey, namespace, secretName)
	}

	password, ok := secret.Data[passwordKey]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in secret from ExternalSecret %s/%s", passwordKey, namespace, secretName)
	}

	return string(username), string(password), nil
}

// WaitForExternalSecret checks if an ExternalSecret has synced successfully
// This is useful to ensure the K8s Secret exists before trying to use it
func (r *Resolver) WaitForExternalSecret(ctx context.Context, name, namespace string) error {
	// Just check if the target secret exists
	// The ExternalSecret controller will have created it
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return fmt.Errorf("secret from ExternalSecret %s/%s not ready: %w", namespace, name, err)
	}
	return nil
}
