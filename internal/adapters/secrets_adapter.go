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

package adapters

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// SecretsAdapter provides secret management functionality
type SecretsAdapter struct {
	client client.Client
}

// NewSecretsAdapter creates a new SecretsAdapter
func NewSecretsAdapter(c client.Client) *SecretsAdapter {
	return &SecretsAdapter{
		client: c,
	}
}

// GetSecret retrieves a secret
func (a *SecretsAdapter) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// SecretExists checks if a secret exists
func (a *SecretsAdapter) SecretExists(ctx context.Context, namespace, name string) (bool, error) {
	secret := &corev1.Secret{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateSecret creates a new secret
func (a *SecretsAdapter) CreateSecret(ctx context.Context, secret *corev1.Secret) error {
	return a.client.Create(ctx, secret)
}

// UpdateSecret updates an existing secret
func (a *SecretsAdapter) UpdateSecret(ctx context.Context, secret *corev1.Secret) error {
	return a.client.Update(ctx, secret)
}

// DeleteSecret deletes a secret
func (a *SecretsAdapter) DeleteSecret(ctx context.Context, namespace, name string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
	return a.client.Delete(ctx, secret)
}

// GetSecretData retrieves specific data from a secret
func (a *SecretsAdapter) GetSecretData(ctx context.Context, namespace, name, key string) ([]byte, error) {
	secret, err := a.GetSecret(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("key %s not found in secret %s/%s", key, namespace, name)
	}

	return data, nil
}

// GetSecretString retrieves a string value from a secret
func (a *SecretsAdapter) GetSecretString(ctx context.Context, namespace, name, key string) (string, error) {
	data, err := a.GetSecretData(ctx, namespace, name, key)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// CreateOrUpdateSecret creates or updates a secret
func (a *SecretsAdapter) CreateOrUpdateSecret(ctx context.Context, secret *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := a.client.Get(ctx, client.ObjectKeyFromObject(secret), existing)
	if errors.IsNotFound(err) {
		return a.client.Create(ctx, secret)
	}
	if err != nil {
		return err
	}

	// Update the existing secret
	existing.Data = secret.Data
	existing.StringData = secret.StringData
	return a.client.Update(ctx, existing)
}

// EnsureCredentialsSecret ensures a credentials secret exists with username/password
func (a *SecretsAdapter) EnsureCredentialsSecret(ctx context.Context, namespace, name, username string, passwordLength int) (*corev1.Secret, error) {
	secret, err := a.GetSecret(ctx, namespace, name)
	if err == nil {
		return secret, nil
	}

	if !errors.IsNotFound(err) {
		return nil, err
	}

	// Generate password
	password, err := GenerateRandomPassword(passwordLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	// Create new secret
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				constants.LabelManagedBy: "wazuh-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyAdminUsername: []byte(username),
			constants.SecretKeyAdminPassword: []byte(password),
		},
	}

	if err := a.client.Create(ctx, newSecret); err != nil {
		return nil, err
	}

	return newSecret, nil
}

// EnsureClusterKeySecret ensures a cluster key secret exists
func (a *SecretsAdapter) EnsureClusterKeySecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret, err := a.GetSecret(ctx, namespace, name)
	if err == nil {
		return secret, nil
	}

	if !errors.IsNotFound(err) {
		return nil, err
	}

	// Generate cluster key
	clusterKey, err := GenerateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster key: %w", err)
	}

	// Create new secret
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				constants.LabelManagedBy: "wazuh-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyClusterKey: []byte(clusterKey),
		},
	}

	if err := a.client.Create(ctx, newSecret); err != nil {
		return nil, err
	}

	return newSecret, nil
}

// GetCertificateExpiry gets the expiry time from a certificate secret annotation
func (a *SecretsAdapter) GetCertificateExpiry(ctx context.Context, namespace, name string) (time.Time, error) {
	secret, err := a.GetSecret(ctx, namespace, name)
	if err != nil {
		return time.Time{}, err
	}

	expiryStr, ok := secret.Annotations[constants.AnnotationCertificateExpiry]
	if !ok {
		return time.Time{}, fmt.Errorf("certificate expiry annotation not found")
	}

	return time.Parse(time.RFC3339, expiryStr)
}

// SetCertificateExpiry sets the expiry time on a certificate secret
func (a *SecretsAdapter) SetCertificateExpiry(ctx context.Context, secret *corev1.Secret, expiry time.Time) error {
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[constants.AnnotationCertificateExpiry] = expiry.Format(time.RFC3339)
	return a.client.Update(ctx, secret)
}

// NeedsCertificateRenewal checks if a certificate needs renewal
func (a *SecretsAdapter) NeedsCertificateRenewal(ctx context.Context, namespace, name string, renewBefore time.Duration) (bool, error) {
	expiry, err := a.GetCertificateExpiry(ctx, namespace, name)
	if err != nil {
		return false, err
	}

	renewalTime := expiry.Add(-renewBefore)
	return time.Now().After(renewalTime), nil
}

// GenerateRandomPassword generates a random password
func GenerateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
