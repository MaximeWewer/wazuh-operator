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

package deployments

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestNewNodePoolStatefulSetBuilder(t *testing.T) {
	clusterName := "test-cluster"
	namespace := "test-ns"
	poolName := "masters"

	builder := NewNodePoolStatefulSetBuilder(clusterName, namespace, poolName)
	sts := builder.Build()

	// Verify naming
	expectedName := constants.IndexerNodePoolName(clusterName, poolName)
	if sts.Name != expectedName {
		t.Errorf("expected name %s, got %s", expectedName, sts.Name)
	}

	if sts.Namespace != namespace {
		t.Errorf("expected namespace %s, got %s", namespace, sts.Namespace)
	}

	// Verify headless service name
	expectedServiceName := constants.IndexerNodePoolHeadlessName(clusterName, poolName)
	if sts.Spec.ServiceName != expectedServiceName {
		t.Errorf("expected serviceName %s, got %s", expectedServiceName, sts.Spec.ServiceName)
	}

	// Verify nodePool label
	if sts.Labels[constants.LabelNodePool] != poolName {
		t.Errorf("expected nodePool label %s, got %s", poolName, sts.Labels[constants.LabelNodePool])
	}
}

func TestNodePoolStatefulSetBuilder_WithReplicas(t *testing.T) {
	tests := []struct {
		name     string
		replicas int32
	}{
		{"single replica", 1},
		{"three replicas", 3},
		{"five replicas", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
			sts := builder.WithReplicas(tt.replicas).Build()

			if *sts.Spec.Replicas != tt.replicas {
				t.Errorf("expected %d replicas, got %d", tt.replicas, *sts.Spec.Replicas)
			}
		})
	}
}

func TestNodePoolStatefulSetBuilder_WithRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
	}{
		{"cluster_manager only", []string{"cluster_manager"}},
		{"data only", []string{"data"}},
		{"multiple roles", []string{"cluster_manager", "data", "ingest"}},
		{"coordinating only (empty)", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
			sts := builder.WithRoles(tt.roles).Build()

			// Verify StatefulSet is created (roles are stored in builder, used by config)
			if sts == nil {
				t.Error("expected StatefulSet to be created")
			}
		})
	}
}

func TestNodePoolStatefulSetBuilder_WithStorageSize(t *testing.T) {
	tests := []struct {
		name        string
		storageSize string
	}{
		{"default", constants.DefaultIndexerStorageSize},
		{"50Gi", "50Gi"},
		{"100Gi", "100Gi"},
		{"1Ti", "1Ti"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
			sts := builder.WithStorageSize(tt.storageSize).Build()

			// Check VolumeClaimTemplate
			if len(sts.Spec.VolumeClaimTemplates) != 1 {
				t.Fatalf("expected 1 VolumeClaimTemplate, got %d", len(sts.Spec.VolumeClaimTemplates))
			}

			pvc := sts.Spec.VolumeClaimTemplates[0]
			storageRequest := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
			expectedStorage := resource.MustParse(tt.storageSize)

			if !storageRequest.Equal(expectedStorage) {
				t.Errorf("expected storage %s, got %s", tt.storageSize, storageRequest.String())
			}
		})
	}
}

func TestNodePoolStatefulSetBuilder_WithStorageClassName(t *testing.T) {
	tests := []struct {
		name         string
		storageClass string
	}{
		{"standard", "standard"},
		{"fast-ssd", "fast-ssd"},
		{"gp3", "gp3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
			sts := builder.WithStorageClassName(tt.storageClass).Build()

			// Check VolumeClaimTemplate
			if len(sts.Spec.VolumeClaimTemplates) != 1 {
				t.Fatalf("expected 1 VolumeClaimTemplate, got %d", len(sts.Spec.VolumeClaimTemplates))
			}

			pvc := sts.Spec.VolumeClaimTemplates[0]
			if pvc.Spec.StorageClassName == nil {
				t.Fatal("expected StorageClassName to be set")
			}

			if *pvc.Spec.StorageClassName != tt.storageClass {
				t.Errorf("expected StorageClassName %s, got %s", tt.storageClass, *pvc.Spec.StorageClassName)
			}
		})
	}
}

func TestNodePoolStatefulSetBuilder_WithResources(t *testing.T) {
	resources := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("4Gi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("4"),
			corev1.ResourceMemory: resource.MustParse("8Gi"),
		},
	}

	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.WithResources(resources).Build()

	container := sts.Spec.Template.Spec.Containers[0]

	// Check requests
	cpuRequest := container.Resources.Requests[corev1.ResourceCPU]
	if cpuRequest.String() != "2" {
		t.Errorf("expected CPU request 2, got %s", cpuRequest.String())
	}

	memRequest := container.Resources.Requests[corev1.ResourceMemory]
	if memRequest.String() != "4Gi" {
		t.Errorf("expected memory request 4Gi, got %s", memRequest.String())
	}

	// Check limits
	cpuLimit := container.Resources.Limits[corev1.ResourceCPU]
	if cpuLimit.String() != "4" {
		t.Errorf("expected CPU limit 4, got %s", cpuLimit.String())
	}

	memLimit := container.Resources.Limits[corev1.ResourceMemory]
	if memLimit.String() != "8Gi" {
		t.Errorf("expected memory limit 8Gi, got %s", memLimit.String())
	}
}

func TestNodePoolStatefulSetBuilder_WithNodeSelector(t *testing.T) {
	nodeSelector := map[string]string{
		"node-type":                   "hot",
		"topology.kubernetes.io/zone": "us-east-1a",
	}

	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.WithNodeSelector(nodeSelector).Build()

	for k, v := range nodeSelector {
		if sts.Spec.Template.Spec.NodeSelector[k] != v {
			t.Errorf("expected nodeSelector[%s]=%s, got %s", k, v, sts.Spec.Template.Spec.NodeSelector[k])
		}
	}
}

func TestNodePoolStatefulSetBuilder_WithTolerations(t *testing.T) {
	tolerations := []corev1.Toleration{
		{
			Key:      "dedicated",
			Operator: corev1.TolerationOpEqual,
			Value:    "opensearch",
			Effect:   corev1.TaintEffectNoSchedule,
		},
	}

	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.WithTolerations(tolerations).Build()

	if len(sts.Spec.Template.Spec.Tolerations) != 1 {
		t.Fatalf("expected 1 toleration, got %d", len(sts.Spec.Template.Spec.Tolerations))
	}

	if sts.Spec.Template.Spec.Tolerations[0].Key != "dedicated" {
		t.Errorf("expected toleration key 'dedicated', got %s", sts.Spec.Template.Spec.Tolerations[0].Key)
	}
}

func TestNodePoolStatefulSetBuilder_WithJavaOpts(t *testing.T) {
	javaOpts := "-Xms4g -Xmx4g"

	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.WithJavaOpts(javaOpts).Build()

	// Find OPENSEARCH_JAVA_OPTS env var
	container := sts.Spec.Template.Spec.Containers[0]
	var found bool
	for _, env := range container.Env {
		if env.Name == "OPENSEARCH_JAVA_OPTS" {
			if env.Value != javaOpts {
				t.Errorf("expected OPENSEARCH_JAVA_OPTS=%s, got %s", javaOpts, env.Value)
			}
			found = true
			break
		}
	}

	if !found {
		t.Error("OPENSEARCH_JAVA_OPTS env var not found")
	}
}

func TestNodePoolStatefulSetBuilder_Labels(t *testing.T) {
	clusterName := "my-cluster"
	poolName := "data-hot"

	builder := NewNodePoolStatefulSetBuilder(clusterName, "ns", poolName)
	sts := builder.Build()

	// Verify common labels
	if sts.Labels[constants.LabelInstance] != clusterName {
		t.Errorf("expected instance label %s, got %s", clusterName, sts.Labels[constants.LabelInstance])
	}

	if sts.Labels[constants.LabelComponent] != constants.ComponentIndexer {
		t.Errorf("expected component label %s, got %s", constants.ComponentIndexer, sts.Labels[constants.LabelComponent])
	}

	// Verify nodePool label
	if sts.Labels[constants.LabelNodePool] != poolName {
		t.Errorf("expected nodePool label %s, got %s", poolName, sts.Labels[constants.LabelNodePool])
	}

	// Verify selector includes nodePool
	if sts.Spec.Selector.MatchLabels[constants.LabelNodePool] != poolName {
		t.Errorf("expected selector nodePool label %s, got %s", poolName, sts.Spec.Selector.MatchLabels[constants.LabelNodePool])
	}
}

func TestNodePoolStatefulSetBuilder_PodAnnotations(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")

	certHash := "abc123"
	configHash := "def456"

	sts := builder.
		WithCertHash(certHash).
		WithConfigHash(configHash).
		Build()

	// Check pod annotations
	podAnnotations := sts.Spec.Template.Annotations

	if podAnnotations[constants.AnnotationCertHash] != certHash {
		t.Errorf("expected cert hash annotation %s, got %s", certHash, podAnnotations[constants.AnnotationCertHash])
	}

	if podAnnotations[constants.AnnotationConfigHash] != configHash {
		t.Errorf("expected config hash annotation %s, got %s", configHash, podAnnotations[constants.AnnotationConfigHash])
	}
}

func TestNodePoolStatefulSetBuilder_SpecHash(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")

	specHash := "spec123"

	sts := builder.WithSpecHash(specHash).Build()

	// Check StatefulSet annotations (not pod annotations)
	if sts.Annotations[constants.AnnotationSpecHash] != specHash {
		t.Errorf("expected spec hash annotation %s, got %s", specHash, sts.Annotations[constants.AnnotationSpecHash])
	}
}

func TestNodePoolStatefulSetBuilder_InitContainers(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.Build()

	// Verify init containers exist
	initContainers := sts.Spec.Template.Spec.InitContainers

	if len(initContainers) < 3 {
		t.Fatalf("expected at least 3 init containers, got %d", len(initContainers))
	}

	// Check for required init containers
	foundInitConfig := false
	foundVolumeMountHack := false
	foundVmMaxMapCount := false

	for _, c := range initContainers {
		switch c.Name {
		case "init-config":
			foundInitConfig = true
		case "volume-mount-hack":
			foundVolumeMountHack = true
		case "increase-the-vm-max-map-count":
			foundVmMaxMapCount = true
		}
	}

	if !foundInitConfig {
		t.Error("init-config init container not found")
	}
	if !foundVolumeMountHack {
		t.Error("volume-mount-hack init container not found")
	}
	if !foundVmMaxMapCount {
		t.Error("increase-the-vm-max-map-count init container not found")
	}
}

func TestNodePoolStatefulSetBuilder_Volumes(t *testing.T) {
	clusterName := "test-cluster"
	poolName := "masters"

	builder := NewNodePoolStatefulSetBuilder(clusterName, "ns", poolName)
	sts := builder.Build()

	volumes := sts.Spec.Template.Spec.Volumes

	// Check for required volumes
	volumeNames := make(map[string]bool)
	for _, v := range volumes {
		volumeNames[v.Name] = true
	}

	requiredVolumes := []string{
		constants.VolumeNameIndexerConfig,
		constants.VolumeNameIndexerCerts,
		constants.VolumeNameAdminCerts,
		constants.VolumeNameIndexerSecurity,
		constants.VolumeNameConfigProcessed,
	}

	for _, name := range requiredVolumes {
		if !volumeNames[name] {
			t.Errorf("required volume %s not found", name)
		}
	}

	// Verify ConfigMap volume references the nodePool-specific ConfigMap
	for _, v := range volumes {
		if v.Name == constants.VolumeNameIndexerConfig {
			expectedConfigMapName := constants.IndexerNodePoolConfigName(clusterName, poolName)
			if v.ConfigMap == nil {
				t.Error("expected ConfigMap volume source")
			} else if v.ConfigMap.Name != expectedConfigMapName {
				t.Errorf("expected ConfigMap name %s, got %s", expectedConfigMapName, v.ConfigMap.Name)
			}
			break
		}
	}
}

func TestNodePoolStatefulSetBuilder_Ports(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.Build()

	container := sts.Spec.Template.Spec.Containers[0]

	// Check for required ports
	portMap := make(map[string]int32)
	for _, p := range container.Ports {
		portMap[p.Name] = p.ContainerPort
	}

	expectedPorts := map[string]int32{
		constants.PortNameIndexerREST:      constants.PortIndexerREST,
		constants.PortNameIndexerTransport: constants.PortIndexerTransport,
		constants.PortNameIndexerMetrics:   constants.PortIndexerMetrics,
	}

	for name, expectedPort := range expectedPorts {
		if actualPort, ok := portMap[name]; !ok {
			t.Errorf("port %s not found", name)
		} else if actualPort != expectedPort {
			t.Errorf("expected port %s=%d, got %d", name, expectedPort, actualPort)
		}
	}
}

func TestNodePoolStatefulSetBuilder_SecurityContext(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.Build()

	secCtx := sts.Spec.Template.Spec.SecurityContext

	if secCtx == nil {
		t.Fatal("expected security context to be set")
	}

	if secCtx.FSGroup == nil || *secCtx.FSGroup != 1000 {
		t.Error("expected FSGroup to be 1000")
	}

	if secCtx.RunAsUser == nil || *secCtx.RunAsUser != 1000 {
		t.Error("expected RunAsUser to be 1000")
	}
}

func TestNodePoolStatefulSetBuilder_ParallelPodManagement(t *testing.T) {
	builder := NewNodePoolStatefulSetBuilder("cluster", "ns", "pool")
	sts := builder.Build()

	if sts.Spec.PodManagementPolicy != "Parallel" {
		t.Errorf("expected Parallel pod management policy, got %s", sts.Spec.PodManagementPolicy)
	}
}
