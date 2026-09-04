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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// generateTestCert generates a self-signed test certificate with the given validity
func generateTestCert(t *testing.T, validity time.Duration) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(validity),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestReconcileCustomCerts_BasicFlow(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	caCert := generateTestCert(t, 365*24*time.Hour) // 1 year validity

	// User-provided CA secret
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ca-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": caCert,
		},
	}

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: new(true),
				CustomCerts: &wazuhv1.CustomCertsConfig{
					CASecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-ca-secret"},
						Key:                  "ca.crt",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster, caSecret).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	result, err := reconciler.reconcileCustomCerts(context.Background(), cluster)
	if err != nil {
		t.Fatalf("reconcileCustomCerts failed: %v", err)
	}

	// Verify CA secret was created
	caInternalSecret := &corev1.Secret{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-ca",
		Namespace: "default",
	}, caInternalSecret)
	if err != nil {
		t.Fatalf("Expected CA secret to be created: %v", err)
	}

	if _, ok := caInternalSecret.Data[constants.SecretKeyCACert]; !ok {
		t.Errorf("CA secret missing key %s", constants.SecretKeyCACert)
	}

	if result == nil {
		t.Error("Expected non-nil CertHashResult")
	}
}

func TestReconcileCustomCerts_WithNodeCerts(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	caCert := generateTestCert(t, 365*24*time.Hour)
	nodeCert := generateTestCert(t, 365*24*time.Hour)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ca",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": caCert,
		},
	}

	nodeSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-node-certs",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"node.crt": nodeCert,
			"node.key": []byte("fake-key"),
		},
	}

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: new(true),
				CustomCerts: &wazuhv1.CustomCertsConfig{
					CASecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-ca"},
						Key:                  "ca.crt",
					},
					NodeSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-node-certs"},
						Key:                  "node.crt",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster, caSecret, nodeSecret).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	_, err := reconciler.reconcileCustomCerts(context.Background(), cluster)
	if err != nil {
		t.Fatalf("reconcileCustomCerts failed: %v", err)
	}

	// Verify all component cert secrets were created
	componentSecrets := []string{
		constants.IndexerCertsName("test-cluster"),
		constants.ManagerMasterCertsName("test-cluster"),
		constants.ManagerWorkerCertsName("test-cluster"),
		constants.DashboardCertsName("test-cluster"),
	}

	for _, name := range componentSecrets {
		secret := &corev1.Secret{}
		err := client.Get(context.Background(), types.NamespacedName{
			Name:      name,
			Namespace: "default",
		}, secret)
		if err != nil {
			t.Errorf("Expected secret %s to be created: %v", name, err)
			continue
		}
		if _, ok := secret.Data[constants.SecretKeyRootCA]; !ok {
			t.Errorf("Secret %s missing root CA key", name)
		}
		if _, ok := secret.Data["node.crt"]; !ok {
			t.Errorf("Secret %s missing node.crt", name)
		}
	}
}

func TestReconcileCustomCerts_MissingCASecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			TLS: &wazuhv1.TLSConfig{
				Enabled: new(true),
				CustomCerts: &wazuhv1.CustomCertsConfig{
					CASecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "nonexistent"},
						Key:                  "ca.crt",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	_, err := reconciler.reconcileCustomCerts(context.Background(), cluster)
	if err == nil {
		t.Fatal("Expected error for missing CA secret")
	}
}

func TestWarnIfCertExpiringSoon(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Generate a cert expiring in 10 days (within the 30-day warning threshold)
	expiringCert := generateTestCert(t, 10*24*time.Hour)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	reconciler.warnIfCertExpiringSoon(context.Background(), cluster, expiringCert, "test")

	// Check that a warning event was emitted
	select {
	case event := <-recorder.Events:
		if event == "" {
			t.Error("Expected non-empty warning event")
		}
	default:
		t.Error("Expected a warning event to be emitted for expiring cert")
	}
}

func TestWarnIfCertNotExpiringSoon(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Generate a cert expiring in 1 year (well beyond the 30-day threshold)
	longLivedCert := generateTestCert(t, 365*24*time.Hour)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	recorder := record.NewFakeRecorder(20)

	reconciler := NewCertificateReconciler(client, scheme).
		WithEventRecorder(recorder)

	reconciler.warnIfCertExpiringSoon(context.Background(), cluster, longLivedCert, "test")

	// No warning should be emitted
	select {
	case event := <-recorder.Events:
		t.Errorf("Did not expect warning event for long-lived cert, got: %s", event)
	default:
		// Expected: no event
	}
}

func TestReadSecretFromRef_MissingKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"other-key": []byte("data"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	reconciler := NewCertificateReconciler(client, scheme)

	ref := &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
		Key:                  "missing-key",
	}

	_, err := reconciler.readSecretFromRef(context.Background(), "default", ref)
	if err == nil {
		t.Fatal("Expected error for missing key in secret")
	}
}
