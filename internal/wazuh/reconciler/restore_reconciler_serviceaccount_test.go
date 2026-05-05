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
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/jobs"
)

func TestRestoreReconciler_ReconcileRBAC_ServiceAccountCreateTrue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	restore := &wazuhv1.WazuhRestore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "restore-job",
			Namespace: "wazuh",
		},
		Spec: wazuhv1.WazuhRestoreSpec{
			ClusterRef: wazuhv1.WazuhClusterRef{Name: "wazuh-cluster", Namespace: "wazuh"},
			Source: wazuhv1.RestoreSource{
				S3: &wazuhv1.S3RestoreSource{
					Bucket: "bucket",
					Key:    "path/to/backup.tar.gz",
				},
			},
			ServiceAccount: &wazuhv1.ServiceAccountConfig{
				Create: true,
				Name:   "custom-restore-sa",
				Annotations: map[string]string{
					"iam.gke.io/gcp-service-account": "restore@project.iam.gserviceaccount.com",
				},
			},
		},
	}

	builder := jobs.NewRestoreJobBuilder(restore)
	r := &WazuhRestoreReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme: scheme,
	}

	if err := r.reconcileRBAC(context.Background(), restore, builder); err != nil {
		t.Fatalf("reconcileRBAC() error = %v", err)
	}

	sa := &corev1.ServiceAccount{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "custom-restore-sa", Namespace: "wazuh"}, sa); err != nil {
		t.Fatalf("expected ServiceAccount to be created, got error: %v", err)
	}
	if got := sa.Annotations["iam.gke.io/gcp-service-account"]; got != "restore@project.iam.gserviceaccount.com" {
		t.Fatalf("expected ServiceAccount annotation to be set, got %q", got)
	}
}

func TestRestoreReconciler_ReconcileRBAC_ServiceAccountCreateFalse(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	restore := &wazuhv1.WazuhRestore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "restore-job",
			Namespace: "wazuh",
		},
		Spec: wazuhv1.WazuhRestoreSpec{
			ClusterRef: wazuhv1.WazuhClusterRef{Name: "wazuh-cluster", Namespace: "wazuh"},
			Source: wazuhv1.RestoreSource{
				S3: &wazuhv1.S3RestoreSource{
					Bucket: "bucket",
					Key:    "path/to/backup.tar.gz",
				},
			},
			ServiceAccount: &wazuhv1.ServiceAccountConfig{
				Create: false,
				Name:   "existing-restore-sa",
			},
		},
	}

	builder := jobs.NewRestoreJobBuilder(restore)
	r := &WazuhRestoreReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme: scheme,
	}

	if err := r.reconcileRBAC(context.Background(), restore, builder); err != nil {
		t.Fatalf("reconcileRBAC() error = %v", err)
	}

	sa := &corev1.ServiceAccount{}
	err := r.Get(context.Background(), types.NamespacedName{Name: "existing-restore-sa", Namespace: "wazuh"}, sa)
	if err == nil || !errors.IsNotFound(err) {
		t.Fatalf("expected ServiceAccount to not be created, got err=%v", err)
	}
}
