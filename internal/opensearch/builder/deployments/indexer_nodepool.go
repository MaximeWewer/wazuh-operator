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

// NodePoolStatefulSetBuilder builds a StatefulSet for an OpenSearch nodePool
// This is used in advanced topology mode where each nodePool has dedicated roles
type NodePoolStatefulSetBuilder struct {
	clusterName      string
	namespace        string
	poolName         string
	version          string
	replicas         int32
	roles            []string
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

// NewNodePoolStatefulSetBuilder creates a new NodePoolStatefulSetBuilder
func NewNodePoolStatefulSetBuilder(clusterName, namespace, poolName string) *NodePoolStatefulSetBuilder {
	return &NodePoolStatefulSetBuilder{
		clusterName: clusterName,
		namespace:   namespace,
		poolName:    poolName,
		version:     constants.DefaultWazuhVersion,
		replicas:    1,
		storageSize: constants.DefaultIndexerStorageSize,
		javaOpts:    constants.DefaultIndexerJavaOpts,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version (determines OpenSearch image)
func (b *NodePoolStatefulSetBuilder) WithVersion(version string) *NodePoolStatefulSetBuilder {
	b.version = version
	return b
}

// WithReplicas sets the number of replicas
func (b *NodePoolStatefulSetBuilder) WithReplicas(replicas int32) *NodePoolStatefulSetBuilder {
	b.replicas = replicas
	return b
}

// WithRoles sets the OpenSearch node roles
func (b *NodePoolStatefulSetBuilder) WithRoles(roles []string) *NodePoolStatefulSetBuilder {
	b.roles = roles
	return b
}

// WithStorageSize sets the storage size for PVCs
func (b *NodePoolStatefulSetBuilder) WithStorageSize(size string) *NodePoolStatefulSetBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *NodePoolStatefulSetBuilder) WithStorageClassName(className string) *NodePoolStatefulSetBuilder {
	b.storageClassName = &className
	return b
}

// WithResources sets the resource requirements
func (b *NodePoolStatefulSetBuilder) WithResources(resources *corev1.ResourceRequirements) *NodePoolStatefulSetBuilder {
	b.resources = resources
	return b
}

// WithImage sets the container image
func (b *NodePoolStatefulSetBuilder) WithImage(image string) *NodePoolStatefulSetBuilder {
	b.image = image
	return b
}

// WithNodeSelector sets the node selector
func (b *NodePoolStatefulSetBuilder) WithNodeSelector(nodeSelector map[string]string) *NodePoolStatefulSetBuilder {
	b.nodeSelector = nodeSelector
	return b
}

// WithTolerations sets the tolerations
func (b *NodePoolStatefulSetBuilder) WithTolerations(tolerations []corev1.Toleration) *NodePoolStatefulSetBuilder {
	b.tolerations = tolerations
	return b
}

// WithAffinity sets the affinity
func (b *NodePoolStatefulSetBuilder) WithAffinity(affinity *corev1.Affinity) *NodePoolStatefulSetBuilder {
	b.affinity = affinity
	return b
}

// WithLabels adds custom labels
func (b *NodePoolStatefulSetBuilder) WithLabels(labels map[string]string) *NodePoolStatefulSetBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations adds custom annotations
func (b *NodePoolStatefulSetBuilder) WithAnnotations(annotations map[string]string) *NodePoolStatefulSetBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithPodAnnotations sets pod annotations
func (b *NodePoolStatefulSetBuilder) WithPodAnnotations(annotations map[string]string) *NodePoolStatefulSetBuilder {
	b.podAnnotations = annotations
	return b
}

// WithEnv adds environment variables
func (b *NodePoolStatefulSetBuilder) WithEnv(env []corev1.EnvVar) *NodePoolStatefulSetBuilder {
	b.env = env
	return b
}

// WithEnvFrom adds environment variable sources
func (b *NodePoolStatefulSetBuilder) WithEnvFrom(envFrom []corev1.EnvFromSource) *NodePoolStatefulSetBuilder {
	b.envFrom = envFrom
	return b
}

// WithVolumes adds volumes
func (b *NodePoolStatefulSetBuilder) WithVolumes(volumes []corev1.Volume) *NodePoolStatefulSetBuilder {
	b.volumes = volumes
	return b
}

// WithVolumeMounts adds volume mounts
func (b *NodePoolStatefulSetBuilder) WithVolumeMounts(mounts []corev1.VolumeMount) *NodePoolStatefulSetBuilder {
	b.volumeMounts = mounts
	return b
}

// WithJavaOpts sets the JVM options
func (b *NodePoolStatefulSetBuilder) WithJavaOpts(opts string) *NodePoolStatefulSetBuilder {
	b.javaOpts = opts
	return b
}

// WithCertHash sets the certificate hash annotation on pods
func (b *NodePoolStatefulSetBuilder) WithCertHash(hash string) *NodePoolStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationCertHash] = hash
	}
	return b
}

// WithSpecHash sets the spec hash annotation on the StatefulSet
func (b *NodePoolStatefulSetBuilder) WithSpecHash(hash string) *NodePoolStatefulSetBuilder {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b
}

// WithConfigHash sets the config hash annotation on pods
func (b *NodePoolStatefulSetBuilder) WithConfigHash(hash string) *NodePoolStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationConfigHash] = hash
	}
	return b
}

// WithCluster sets the WazuhCluster reference for monitoring configuration
func (b *NodePoolStatefulSetBuilder) WithCluster(cluster *wazuhv1alpha1.WazuhCluster) *NodePoolStatefulSetBuilder {
	b.cluster = cluster
	return b
}

// Build creates the StatefulSet for this nodePool
func (b *NodePoolStatefulSetBuilder) Build() *appsv1.StatefulSet {
	name := constants.IndexerNodePoolName(b.clusterName, b.poolName)
	headlessServiceName := constants.IndexerNodePoolHeadlessName(b.clusterName, b.poolName)
	configMapName := constants.IndexerNodePoolConfigName(b.clusterName, b.poolName)

	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	// Default image if not set
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
	volumes := b.buildVolumes(configMapName)

	// Build volume mounts
	volumeMounts := b.buildVolumeMounts()

	// Build env vars
	env := b.buildEnvVars()

	// Security context for OpenSearch
	fsGroup := int64(1000)
	runAsUser := int64(1000)

	// Configure RollingUpdate strategy
	partition := int32(0)

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &b.replicas,
			ServiceName: headlessServiceName,
			// Parallel allows all pods to start simultaneously for cluster formation
			PodManagementPolicy: appsv1.ParallelPodManagement,
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
					InitContainers: b.buildInitContainers(image, configMapName),
					Containers: []corev1.Container{
						{
							Name:            constants.ContainerNameOpenSearch,
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
						Name:   constants.VolumeNameIndexerData,
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
func (b *NodePoolStatefulSetBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentIndexer, b.version)
	// Add nodePool-specific labels
	labels[constants.LabelNodePool] = b.poolName
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *NodePoolStatefulSetBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, constants.ComponentIndexer)
	// Add nodePool label to selector for pool-specific targeting
	labels[constants.LabelNodePool] = b.poolName
	return labels
}

// buildVolumes builds the volume list
func (b *NodePoolStatefulSetBuilder) buildVolumes(configMapName string) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: constants.VolumeNameIndexerConfig,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: configMapName,
					},
				},
			},
		},
		{
			Name: constants.VolumeNameIndexerCerts,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.IndexerCertsName(b.clusterName),
				},
			},
		},
		{
			Name: constants.VolumeNameAdminCerts,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.AdminCertsName(b.clusterName),
				},
			},
		},
		{
			Name: constants.VolumeNameIndexerSecurity,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.IndexerSecurityName(b.clusterName),
				},
			},
		},
		{
			Name: constants.VolumeNameConfigProcessed,
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
func (b *NodePoolStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      constants.VolumeNameIndexerData,
			MountPath: constants.PathIndexerData,
		},
		{
			Name:      constants.VolumeNameConfigProcessed,
			MountPath: constants.PathIndexerBase + "/opensearch.yml",
			SubPath:   constants.ConfigMapKeyOpenSearchYml,
			ReadOnly:  true,
		},
		// Mount certificates as directory for hot reload
		{
			Name:      constants.VolumeNameIndexerCerts,
			MountPath: constants.PathIndexerCerts,
			ReadOnly:  true,
		},
		// Admin certificates for securityadmin tool
		{
			Name:      constants.VolumeNameAdminCerts,
			MountPath: constants.PathIndexerBase + "/admin-certs",
			ReadOnly:  true,
		},
		{
			Name:      constants.VolumeNameConfigProcessed,
			MountPath: constants.PathIndexerSecurityConfig + "/internal_users.yml",
			SubPath:   constants.SecretKeyInternalUsers,
			ReadOnly:  true,
		},
		{
			Name:      constants.VolumeNameConfigProcessed,
			MountPath: constants.PathIndexerSecurityConfig + "/roles_mapping.yml",
			SubPath:   constants.SecretKeyRolesMapping,
			ReadOnly:  true,
		},
	}

	// Add plugins directory mount if monitoring is enabled
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
func (b *NodePoolStatefulSetBuilder) buildEnvVars() []corev1.EnvVar {
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
						Name: constants.IndexerCredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAdminPassword,
				},
			},
		},
	}

	// Add custom env vars
	env = append(env, b.env...)

	return env
}

// buildInitContainers creates the init containers for the StatefulSet
func (b *NodePoolStatefulSetBuilder) buildInitContainers(image, configMapName string) []corev1.Container {
	initContainers := []corev1.Container{
		{
			Name:    "init-config",
			Image:   constants.ImageBusyboxStable,
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
					Name:      constants.VolumeNameIndexerConfig,
					MountPath: "/tmp/config-template",
					ReadOnly:  true,
				},
				{
					Name:      constants.VolumeNameIndexerSecurity,
					MountPath: "/tmp/security-template",
					ReadOnly:  true,
				},
				{
					Name:      constants.VolumeNameConfigProcessed,
					MountPath: "/tmp/config",
				},
			},
		},
		{
			Name:    "volume-mount-hack",
			Image:   constants.ImageBusyboxStable,
			Command: []string{"sh", "-c", fmt.Sprintf("chown -R 1000:1000 %s || true", constants.PathIndexerData)},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: int64Ptr(0),
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      constants.VolumeNameIndexerData,
					MountPath: constants.PathIndexerData,
				},
			},
		},
		{
			Name:  "increase-the-vm-max-map-count",
			Image: constants.ImageBusyboxStable,
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
