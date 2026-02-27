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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/config"
)

func TestResolveManagerConfig_PropagatesGlobalConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.2",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Config: &wazuhv1.WazuhConfigSpec{
					Global: &wazuhv1.OSSECGlobalSpec{
						LogAll:     ptr.To(true),
						LogAllJSON: ptr.To(true),
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg, _, authdPassword, err := reconciler.resolveManagerConfig(context.Background(), cluster)
	if err != nil {
		t.Fatalf("resolveManagerConfig failed: %v", err)
	}

	ossecConf, err := config.BuildMasterConfigWithConfig(
		cluster.Name,
		cluster.Namespace,
		cluster.Name+"-manager-master",
		"",
		"",
		globalCfg,
		alertsCfg,
		loggingCfg,
		remoteCfg,
		authCfg,
		authdPassword,
	)
	if err != nil {
		t.Fatalf("BuildMasterConfigWithConfig failed: %v", err)
	}

	if !strings.Contains(ossecConf, "<logall>yes</logall>") {
		t.Fatalf("expected logall to be enabled in ossec.conf, got: %s", ossecConf)
	}
	if !strings.Contains(ossecConf, "<logall_json>yes</logall_json>") {
		t.Fatalf("expected logall_json to be enabled in ossec.conf, got: %s", ossecConf)
	}
}

func TestResolveManagerConfig_BackwardCompat_NilManager(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.2",
			Manager: nil,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg, _, authdPassword, err := reconciler.resolveManagerConfig(context.Background(), cluster)
	if err != nil {
		t.Fatalf("resolveManagerConfig failed: %v", err)
	}
	if globalCfg == nil || alertsCfg == nil || loggingCfg == nil || remoteCfg == nil || authCfg == nil {
		t.Fatalf("expected default configs when manager is nil")
	}
	if authdPassword != "" {
		t.Fatalf("expected empty authd password when manager is nil")
	}
}

func TestResolveManagerConfig_BackwardCompat_NilManagerConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.14.2",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Config: nil,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster).
		Build()

	reconciler := NewClusterReconciler(client, scheme)

	globalCfg, alertsCfg, loggingCfg, remoteCfg, authCfg, _, authdPassword, err := reconciler.resolveManagerConfig(context.Background(), cluster)
	if err != nil {
		t.Fatalf("resolveManagerConfig failed: %v", err)
	}
	if globalCfg == nil || alertsCfg == nil || loggingCfg == nil || remoteCfg == nil || authCfg == nil {
		t.Fatalf("expected default configs when manager.config is nil")
	}
	if authdPassword != "" {
		t.Fatalf("expected empty authd password when manager.config is nil")
	}
}
