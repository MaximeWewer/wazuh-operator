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

// Package deployments provides Kubernetes StatefulSet builders for OpenSearch components
package deployments

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// IndexerStatefulSetBuilder builds a StatefulSet for OpenSearch Indexer
type IndexerStatefulSetBuilder struct {
	name             string
	namespace        string
	clusterName      string
	version          string
	replicas         int32
	storageSize      string
	storageClassName *string
	resources        *corev1.ResourceRequirements
	image            string
	nodeSelector     map[string]string
	tolerations      []corev1.Toleration
	affinity         *corev1.Affinity
	labels           map[string]string
	annotations      map[string]string
	podAnnotations   map[string]string
	env              []corev1.EnvVar
	envFrom          []corev1.EnvFromSource
	volumes          []corev1.Volume
	volumeMounts     []corev1.VolumeMount
	javaOpts         string
	// Monitoring configuration
	cluster *wazuhv1alpha1.WazuhCluster
}

// NewIndexerStatefulSetBuilder creates a new IndexerStatefulSetBuilder
func NewIndexerStatefulSetBuilder(clusterName, namespace string) *IndexerStatefulSetBuilder {
	name := fmt.Sprintf("%s-indexer", clusterName)
	return &IndexerStatefulSetBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion, // Use Wazuh version for wazuh-indexer image
		replicas:    constants.DefaultIndexerReplicas,
		storageSize: constants.DefaultIndexerStorageSize,
		javaOpts:    constants.DefaultIndexerJavaOpts,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch version
func (b *IndexerStatefulSetBuilder) WithVersion(version string) *IndexerStatefulSetBuilder {
	b.version = version
	return b
}

// WithReplicas sets the number of replicas
func (b *IndexerStatefulSetBuilder) WithReplicas(replicas int32) *IndexerStatefulSetBuilder {
	b.replicas = replicas
	return b
}

// WithStorageSize sets the storage size
func (b *IndexerStatefulSetBuilder) WithStorageSize(size string) *IndexerStatefulSetBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *IndexerStatefulSetBuilder) WithStorageClassName(className string) *IndexerStatefulSetBuilder {
	b.storageClassName = &className
	return b
}

// WithResources sets the resource requirements
func (b *IndexerStatefulSetBuilder) WithResources(resources *corev1.ResourceRequirements) *IndexerStatefulSetBuilder {
	b.resources = resources
	return b
}

// WithImage sets the container image
func (b *IndexerStatefulSetBuilder) WithImage(image string) *IndexerStatefulSetBuilder {
	b.image = image
	return b
}

// WithNodeSelector sets the node selector
func (b *IndexerStatefulSetBuilder) WithNodeSelector(nodeSelector map[string]string) *IndexerStatefulSetBuilder {
	b.nodeSelector = nodeSelector
	return b
}

// WithTolerations sets the tolerations
func (b *IndexerStatefulSetBuilder) WithTolerations(tolerations []corev1.Toleration) *IndexerStatefulSetBuilder {
	b.tolerations = tolerations
	return b
}

// WithAffinity sets the affinity
func (b *IndexerStatefulSetBuilder) WithAffinity(affinity *corev1.Affinity) *IndexerStatefulSetBuilder {
	b.affinity = affinity
	return b
}

// WithLabels sets custom labels
func (b *IndexerStatefulSetBuilder) WithLabels(labels map[string]string) *IndexerStatefulSetBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations sets custom annotations
func (b *IndexerStatefulSetBuilder) WithAnnotations(annotations map[string]string) *IndexerStatefulSetBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithPodAnnotations sets pod annotations
func (b *IndexerStatefulSetBuilder) WithPodAnnotations(annotations map[string]string) *IndexerStatefulSetBuilder {
	b.podAnnotations = annotations
	return b
}

// WithEnv adds environment variables
func (b *IndexerStatefulSetBuilder) WithEnv(env []corev1.EnvVar) *IndexerStatefulSetBuilder {
	b.env = env
	return b
}

// WithEnvFrom adds environment variable sources
func (b *IndexerStatefulSetBuilder) WithEnvFrom(envFrom []corev1.EnvFromSource) *IndexerStatefulSetBuilder {
	b.envFrom = envFrom
	return b
}

// WithVolumes adds volumes
func (b *IndexerStatefulSetBuilder) WithVolumes(volumes []corev1.Volume) *IndexerStatefulSetBuilder {
	b.volumes = volumes
	return b
}

// WithVolumeMounts adds volume mounts
func (b *IndexerStatefulSetBuilder) WithVolumeMounts(mounts []corev1.VolumeMount) *IndexerStatefulSetBuilder {
	b.volumeMounts = mounts
	return b
}

// WithJavaOpts sets the JVM options
func (b *IndexerStatefulSetBuilder) WithJavaOpts(opts string) *IndexerStatefulSetBuilder {
	b.javaOpts = opts
	return b
}

// WithCertHash sets the certificate hash annotation on pods
// This triggers pod restart when certificates are renewed
func (b *IndexerStatefulSetBuilder) WithCertHash(hash string) *IndexerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationCertHash] = hash
	}
	return b
}

// WithSpecHash sets the spec hash annotation on the StatefulSet
// This enables detection of CRD spec changes (version, resources, replicas, etc.)
func (b *IndexerStatefulSetBuilder) WithSpecHash(hash string) *IndexerStatefulSetBuilder {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b
}

// WithConfigHash sets the config hash annotation on pods
// This triggers pod restart when ConfigMap content changes
func (b *IndexerStatefulSetBuilder) WithConfigHash(hash string) *IndexerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationConfigHash] = hash
	}
	return b
}

// WithCluster sets the WazuhCluster reference for monitoring configuration
// This is required for adding the Prometheus exporter plugin
func (b *IndexerStatefulSetBuilder) WithCluster(cluster *wazuhv1alpha1.WazuhCluster) *IndexerStatefulSetBuilder {
	b.cluster = cluster
	return b
}

// Build creates the StatefulSet
func (b *IndexerStatefulSetBuilder) Build() *appsv1.StatefulSet {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	// Default image if not set - use Wazuh indexer image
	image := b.image
	if image == "" {
		image = fmt.Sprintf("%s:%s", constants.DefaultWazuhIndexerImage, b.version)
	}

	// Default resources if not set
	resources := b.resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultIndexerCPURequest),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultIndexerMemoryRequest),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultIndexerCPULimit),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultIndexerMemoryLimit),
			},
		}
	}

	// Build volumes
	volumes := b.buildVolumes()

	// Build volume mounts
	volumeMounts := b.buildVolumeMounts()

	// Build env vars
	env := b.buildEnvVars()

	// Security context for OpenSearch
	fsGroup := int64(1000)
	runAsUser := int64(1000)

	// Configure RollingUpdate strategy for graceful rollout
	// Partition 0 means all pods will be updated, but OrderedReady ensures one at a time
	partition := int32(0)

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &b.replicas,
			ServiceName: b.name + "-headless",
			// OrderedReady ensures pods are updated sequentially and each must be Ready before the next
			PodManagementPolicy: appsv1.OrderedReadyPodManagement,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateStatefulSetStrategy{
					Partition: &partition,
				},
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: selectorLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: b.podAnnotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector: b.nodeSelector,
					Tolerations:  b.tolerations,
					Affinity:     b.affinity,
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup:   &fsGroup,
						RunAsUser: &runAsUser,
					},
					InitContainers: b.buildInitContainers(image),
					Containers: []corev1.Container{
						{
							Name:            "opensearch",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Resources:       *resources,
							Ports: []corev1.ContainerPort{
								{Name: constants.PortNameIndexerREST, ContainerPort: constants.PortIndexerREST, Protocol: corev1.ProtocolTCP},
								{Name: constants.PortNameIndexerTransport, ContainerPort: constants.PortIndexerTransport, Protocol: corev1.ProtocolTCP},
								{Name: constants.PortNameIndexerMetrics, ContainerPort: constants.PortIndexerMetrics, Protocol: corev1.ProtocolTCP},
							},
							Env:          env,
							EnvFrom:      b.envFrom,
							VolumeMounts: volumeMounts,
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(int(constants.PortIndexerREST)),
									},
								},
								InitialDelaySeconds: 120,
								PeriodSeconds:       30,
								TimeoutSeconds:      5,
								FailureThreshold:    5,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(int(constants.PortIndexerREST)),
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       10,
								TimeoutSeconds:      5,
								FailureThreshold:    3,
							},
						},
					},
					Volumes: volumes,
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "opensearch-data",
						Labels: selectorLabels,
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{
							corev1.ReadWriteOnce,
						},
						StorageClassName: b.storageClassName,
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse(b.storageSize),
							},
						},
					},
				},
			},
		},
	}

	return sts
}

// buildLabels builds the complete label set
func (b *IndexerStatefulSetBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *IndexerStatefulSetBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, constants.ComponentIndexer)
}

// buildVolumes builds the volume list
func (b *IndexerStatefulSetBuilder) buildVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "opensearch-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-indexer-config", b.clusterName),
					},
				},
			},
		},
		{
			Name: "opensearch-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-indexer-certs", b.clusterName),
				},
			},
		},
		{
			Name: "admin-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-admin-certs", b.clusterName),
				},
			},
		},
		{
			Name: "opensearch-security",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-indexer-security", b.clusterName),
				},
			},
		},
		{
			Name: "config-processed",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	// Add custom volumes
	volumes = append(volumes, b.volumes...)

	return volumes
}

// buildVolumeMounts builds the volume mount list
func (b *IndexerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      "opensearch-data",
			MountPath: constants.PathIndexerData,
		},
		{
			Name:      "config-processed",
			MountPath: constants.PathIndexerBase + "/opensearch.yml",
			SubPath:   constants.ConfigMapKeyOpenSearchYml,
			ReadOnly:  true,
		},
		// Mount certificates as directory (without subPath) to enable hot reload
		// When secrets are mounted without subPath, Kubernetes automatically updates
		// the files when the Secret changes, enabling OpenSearch SSL hot reload
		{
			Name:      "opensearch-certs",
			MountPath: constants.PathIndexerCerts,
			ReadOnly:  true,
		},
		// Admin certificates for securityadmin tool
		{
			Name:      "admin-certs",
			MountPath: constants.PathIndexerBase + "/admin-certs",
			ReadOnly:  true,
		},
		{
			Name:      "config-processed",
			MountPath: constants.PathIndexerSecurityConfig + "/internal_users.yml",
			SubPath:   "internal_users.yml",
			ReadOnly:  true,
		},
		{
			Name:      "config-processed",
			MountPath: constants.PathIndexerSecurityConfig + "/roles_mapping.yml",
			SubPath:   "roles_mapping.yml",
			ReadOnly:  true,
		},
	}

	// Add plugins directory mount if monitoring is enabled
	// This allows the prometheus-exporter plugin to be loaded from persistent storage
	if b.cluster != nil {
		pluginsMount := monitoring.GetPluginsVolumeMountFromSpec(b.cluster)
		if pluginsMount != nil {
			mounts = append(mounts, *pluginsMount)
		}
	}

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	return mounts
}

// buildEnvVars builds the environment variables
func (b *IndexerStatefulSetBuilder) buildEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name:  "cluster.name",
			Value: b.clusterName,
		},
		{
			Name: "node.name",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name:  "discovery.seed_hosts",
			Value: b.name,
		},
		{
			Name:  "OPENSEARCH_JAVA_OPTS",
			Value: b.javaOpts,
		},
		{
			Name:  "bootstrap.memory_lock",
			Value: "false",
		},
		{
			Name:  "network.host",
			Value: "0.0.0.0",
		},
		// Required for OpenSearch 2.12+
		{
			Name: "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-indexer-credentials", b.clusterName),
					},
					Key: constants.SecretKeyAdminPassword,
				},
			},
		},
	}

	// Add initial master nodes for cluster formation
	env = append(env, corev1.EnvVar{
		Name:  "cluster.initial_master_nodes",
		Value: b.buildInitialMasterNodes(),
	})

	// Add custom env vars
	env = append(env, b.env...)

	return env
}

// buildInitialMasterNodes builds the initial master nodes list
func (b *IndexerStatefulSetBuilder) buildInitialMasterNodes() string {
	nodes := ""
	for i := int32(0); i < b.replicas; i++ {
		if i > 0 {
			nodes += ","
		}
		nodes += fmt.Sprintf("%s-%d", b.name, i)
	}
	return nodes
}

// buildInitContainers creates the init containers for the StatefulSet
func (b *IndexerStatefulSetBuilder) buildInitContainers(image string) []corev1.Container {
	initContainers := []corev1.Container{
		{
			Name:    "init-config",
			Image:   "busybox:stable",
			Command: []string{"sh", "-c"},
			Args: []string{`
set -e
echo "Substituting environment variables in opensearch.yml..."
sed -e "s|\${NODE_NAME}|$NODE_NAME|g" \
    -e "s|\${CLUSTER_NAME}|$CLUSTER_NAME|g" \
    /tmp/config-template/opensearch.yml > /tmp/config/opensearch.yml

echo "Copying security configuration files..."
cp /tmp/security-template/*.yml /tmp/config/ 2>/dev/null || true

echo "Configuration files prepared"
ls -la /tmp/config/
`},
			Env: []corev1.EnvVar{
				{
					Name: "NODE_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.name",
						},
					},
				},
				{
					Name:  "CLUSTER_NAME",
					Value: b.clusterName,
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "opensearch-config",
					MountPath: "/tmp/config-template",
					ReadOnly:  true,
				},
				{
					Name:      "opensearch-security",
					MountPath: "/tmp/security-template",
					ReadOnly:  true,
				},
				{
					Name:      "config-processed",
					MountPath: "/tmp/config",
				},
			},
		},
		{
			Name:    "volume-mount-hack",
			Image:   "busybox:stable",
			Command: []string{"sh", "-c", fmt.Sprintf("chown -R 1000:1000 %s || true", constants.PathIndexerData)},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: int64Ptr(0),
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "opensearch-data",
					MountPath: constants.PathIndexerData,
				},
			},
		},
		{
			Name:  "increase-the-vm-max-map-count",
			Image: "busybox:stable",
			Command: []string{
				"sh", "-c",
				"sysctl -w vm.max_map_count=262144 || echo 'sysctl failed - vm.max_map_count might need to be set on the host node'",
			},
			SecurityContext: &corev1.SecurityContext{
				Privileged: boolPtr(true),
			},
		},
	}

	// Add Prometheus exporter plugin installation init container if monitoring is enabled
	if b.cluster != nil {
		pluginContainer := monitoring.BuildPluginInstallInitContainerFromSpec(b.cluster)
		if pluginContainer != nil {
			initContainers = append(initContainers, *pluginContainer)
		}
	}

	return initContainers
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// int64Ptr returns a pointer to an int64
func int64Ptr(i int64) *int64 {
	return &i
}
