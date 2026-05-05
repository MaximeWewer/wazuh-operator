//go:build broken_multi_cluster

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestDecoderReconciler_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name          string
		decoder       *wazuhv1.WazuhDecoder
		cluster       *wazuhv1.WazuhCluster
		wantPhase     wazuhv1.DecoderPhase
		wantConfigMap bool
		wantErr       bool
	}{
		{
			name: "valid decoder creates ConfigMap",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-decoder",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "test-cluster",
						Namespace: "default",
					},
					DecoderName: "test_decoder",
					Decoders: `<decoder name="test-decoder">
  <prematch>^Test</prematch>
</decoder>`,
					TargetNodes: "all",
				},
			},
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
					},
				},
			},
			wantPhase:     wazuhv1.DecoderPhaseApplied,
			wantConfigMap: true,
			wantErr:       false,
		},
		{
			name: "invalid XML fails validation",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "invalid-decoder",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "test-cluster",
						Namespace: "default",
					},
					DecoderName: "invalid_decoder",
					Decoders:    "not valid xml",
					TargetNodes: "all",
				},
			},
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
				},
			},
			wantPhase:     wazuhv1.DecoderPhaseFailed,
			wantConfigMap: false,
			wantErr:       false, // Validation errors are handled gracefully
		},
		{
			name: "cluster not found sets pending",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "orphan-decoder",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "nonexistent-cluster",
						Namespace: "default",
					},
					DecoderName: "orphan_decoder",
					Decoders: `<decoder name="orphan-decoder">
  <prematch>^Test</prematch>
</decoder>`,
					TargetNodes: "all",
				},
			},
			cluster:       nil, // No cluster
			wantPhase:     wazuhv1.DecoderPhasePending,
			wantConfigMap: false,
			wantErr:       false,
		},
		{
			name: "invalid decoder name fails validation",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "badname-decoder",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "test-cluster",
						Namespace: "default",
					},
					DecoderName: "invalid name!", // Invalid: has space and exclamation
					Decoders: `<decoder name="test">
  <prematch>^Test</prematch>
</decoder>`,
					TargetNodes: "all",
				},
			},
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
				},
			},
			wantPhase:     wazuhv1.DecoderPhaseFailed,
			wantConfigMap: false,
			wantErr:       false,
		},
		{
			name: "decoder with master target",
			decoder: &wazuhv1.WazuhDecoder{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "master-decoder",
					Namespace:  "default",
					Generation: 1,
				},
				Spec: wazuhv1.WazuhDecoderSpec{
					ClusterRef: wazuhv1.WazuhClusterReference{
						Name:      "test-cluster",
						Namespace: "default",
					},
					DecoderName: "master_decoder",
					Decoders: `<decoder name="master-decoder">
  <prematch>^Master</prematch>
</decoder>`,
					TargetNodes: "master",
				},
			},
			cluster: &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "default",
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.0",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(2),
						},
					},
				},
			},
			wantPhase:     wazuhv1.DecoderPhaseApplied,
			wantConfigMap: true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fake client with objects
			objs := []runtime.Object{tt.decoder}
			if tt.cluster != nil {
				objs = append(objs, tt.cluster)
			}
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				WithStatusSubresource(&wazuhv1.WazuhDecoder{}).
				Build()

			reconciler := NewDecoderReconciler(client, scheme, nil)

			err := reconciler.Reconcile(context.Background(), tt.decoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check phase
			if tt.decoder.Status.Phase != tt.wantPhase {
				t.Errorf("Reconcile() phase = %v, want %v", tt.decoder.Status.Phase, tt.wantPhase)
			}

			// Check ConfigMap creation
			if tt.wantConfigMap {
				cm := &corev1.ConfigMap{}
				configMapName := tt.decoder.Name + "-decoder"
				err := client.Get(context.Background(), types.NamespacedName{
					Name:      configMapName,
					Namespace: tt.decoder.Namespace,
				}, cm)
				if err != nil {
					t.Errorf("Expected ConfigMap %s to be created, got error: %v", configMapName, err)
				}
			}

			// Check conditions are set
			if len(tt.decoder.Status.Conditions) == 0 {
				t.Error("Expected conditions to be set")
			}
		})
	}
}

func TestDecoderReconciler_ListDecodersForCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	decoder1 := &wazuhv1.WazuhDecoder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "decoder-1",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhDecoderSpec{
			ClusterRef: wazuhv1.WazuhClusterReference{
				Name: "cluster-a",
			},
			DecoderName: "decoder_1",
			Decoders:    `<decoder name="d1"><prematch>^1</prematch></decoder>`,
		},
	}

	decoder2 := &wazuhv1.WazuhDecoder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "decoder-2",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhDecoderSpec{
			ClusterRef: wazuhv1.WazuhClusterReference{
				Name: "cluster-a",
			},
			DecoderName: "decoder_2",
			Decoders:    `<decoder name="d2"><prematch>^2</prematch></decoder>`,
		},
	}

	decoder3 := &wazuhv1.WazuhDecoder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "decoder-3",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhDecoderSpec{
			ClusterRef: wazuhv1.WazuhClusterReference{
				Name: "cluster-b", // Different cluster
			},
			DecoderName: "decoder_3",
			Decoders:    `<decoder name="d3"><prematch>^3</prematch></decoder>`,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(decoder1, decoder2, decoder3).
		Build()

	reconciler := NewDecoderReconciler(client, scheme, nil)

	decoders, err := reconciler.ListDecodersForCluster(context.Background(), "cluster-a", "default")
	if err != nil {
		t.Fatalf("ListDecodersForCluster() error = %v", err)
	}

	if len(decoders) != 2 {
		t.Errorf("ListDecodersForCluster() got %d decoders, want 2", len(decoders))
	}
}

func TestDecoderReconciler_GetDecoderConfigMapsForCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	decoder1 := &wazuhv1.WazuhDecoder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "decoder-1",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhDecoderSpec{
			ClusterRef: wazuhv1.WazuhClusterReference{
				Name: "cluster-a",
			},
			DecoderName: "decoder_1",
			Decoders:    `<decoder name="d1"><prematch>^1</prematch></decoder>`,
		},
		Status: wazuhv1.WazuhDecoderStatus{
			Phase: wazuhv1.DecoderPhaseApplied,
			ConfigMapRef: &wazuhv1.ConfigMapReference{
				Name:      "decoder-1-decoder",
				Namespace: "default",
			},
		},
	}

	decoder2 := &wazuhv1.WazuhDecoder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "decoder-2",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhDecoderSpec{
			ClusterRef: wazuhv1.WazuhClusterReference{
				Name: "cluster-a",
			},
			DecoderName: "decoder_2",
			Decoders:    `<decoder name="d2"><prematch>^2</prematch></decoder>`,
		},
		Status: wazuhv1.WazuhDecoderStatus{
			Phase: wazuhv1.DecoderPhasePending, // Not applied yet
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(decoder1, decoder2).
		Build()

	reconciler := NewDecoderReconciler(client, scheme, nil)

	configMaps, hash, err := reconciler.GetDecoderConfigMapsForCluster(context.Background(), "cluster-a", "default")
	if err != nil {
		t.Fatalf("GetDecoderConfigMapsForCluster() error = %v", err)
	}

	// Only decoder1 should be included (decoder2 is pending)
	if len(configMaps) != 1 {
		t.Errorf("GetDecoderConfigMapsForCluster() got %d configMaps, want 1", len(configMaps))
	}

	if configMaps[0].ConfigMapName != "decoder-1-decoder" {
		t.Errorf("GetDecoderConfigMapsForCluster() configMap name = %s, want decoder-1-decoder", configMaps[0].ConfigMapName)
	}

	if hash == "" {
		t.Error("GetDecoderConfigMapsForCluster() hash should not be empty")
	}
}

func TestDecoderReconciler_DetermineAppliedNodes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.0",
			Manager: &wazuhv1.WazuhManagerClusterSpec{
				Workers: wazuhv1.WazuhWorkerSpec{
					Replicas: int32Ptr(3),
				},
			},
		},
	}

	tests := []struct {
		name        string
		targetNodes string
		wantCount   int
		wantMaster  bool
		wantWorkers bool
	}{
		{
			name:        "all nodes",
			targetNodes: "all",
			wantCount:   4, // 1 master + 3 workers
			wantMaster:  true,
			wantWorkers: true,
		},
		{
			name:        "master only",
			targetNodes: "master",
			wantCount:   1,
			wantMaster:  true,
			wantWorkers: false,
		},
		{
			name:        "workers only",
			targetNodes: "workers",
			wantCount:   3,
			wantMaster:  false,
			wantWorkers: true,
		},
		{
			name:        "empty defaults to all",
			targetNodes: "",
			wantCount:   4,
			wantMaster:  true,
			wantWorkers: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := &wazuhv1.WazuhDecoder{
				Spec: wazuhv1.WazuhDecoderSpec{
					TargetNodes: tt.targetNodes,
				},
			}

			reconciler := &DecoderReconciler{}
			nodes := reconciler.determineAppliedNodes(decoder, cluster)

			if len(nodes) != tt.wantCount {
				t.Errorf("determineAppliedNodes() got %d nodes, want %d", len(nodes), tt.wantCount)
			}

			hasMaster := false
			hasWorkers := false
			for _, node := range nodes {
				if node == "test-cluster-manager-master-0" {
					hasMaster = true
				}
				if len(node) > 0 && node != "test-cluster-manager-master-0" {
					hasWorkers = true
				}
			}

			if hasMaster != tt.wantMaster {
				t.Errorf("determineAppliedNodes() hasMaster = %v, want %v", hasMaster, tt.wantMaster)
			}
			if hasWorkers != tt.wantWorkers {
				t.Errorf("determineAppliedNodes() hasWorkers = %v, want %v", hasWorkers, tt.wantWorkers)
			}
		})
	}
}
