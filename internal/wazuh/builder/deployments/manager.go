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

// Package deployments provides Kubernetes Deployment builders for Wazuh components
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

// ManagerStatefulSetBuilder builds a StatefulSet for Wazuh Manager (master or workers)
type ManagerStatefulSetBuilder struct {
	name             string
	namespace        string
	clusterName      string
	version          string
	replicas         int32
	nodeType         string // "master" or "worker"
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
	// Monitoring configuration
	cluster *wazuhv1alpha1.WazuhCluster
}

// NewManagerStatefulSetBuilder creates a new ManagerStatefulSetBuilder
func NewManagerStatefulSetBuilder(clusterName, namespace, nodeType string) *ManagerStatefulSetBuilder {
	name := fmt.Sprintf("%s-manager-%s", clusterName, nodeType)
	return &ManagerStatefulSetBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion,
		replicas:    1,
		nodeType:    nodeType,
		storageSize: constants.DefaultManagerStorageSize,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *ManagerStatefulSetBuilder) WithVersion(version string) *ManagerStatefulSetBuilder {
	b.version = version
	return b
}

// WithReplicas sets the number of replicas
func (b *ManagerStatefulSetBuilder) WithReplicas(replicas int32) *ManagerStatefulSetBuilder {
	b.replicas = replicas
	return b
}

// WithStorageSize sets the storage size
func (b *ManagerStatefulSetBuilder) WithStorageSize(size string) *ManagerStatefulSetBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *ManagerStatefulSetBuilder) WithStorageClassName(className string) *ManagerStatefulSetBuilder {
	b.storageClassName = &className
	return b
}

// WithResources sets the resource requirements
func (b *ManagerStatefulSetBuilder) WithResources(resources *corev1.ResourceRequirements) *ManagerStatefulSetBuilder {
	b.resources = resources
	return b
}

// WithImage sets the container image
func (b *ManagerStatefulSetBuilder) WithImage(image string) *ManagerStatefulSetBuilder {
	b.image = image
	return b
}

// WithNodeSelector sets the node selector
func (b *ManagerStatefulSetBuilder) WithNodeSelector(nodeSelector map[string]string) *ManagerStatefulSetBuilder {
	b.nodeSelector = nodeSelector
	return b
}

// WithTolerations sets the tolerations
func (b *ManagerStatefulSetBuilder) WithTolerations(tolerations []corev1.Toleration) *ManagerStatefulSetBuilder {
	b.tolerations = tolerations
	return b
}

// WithAffinity sets the affinity
func (b *ManagerStatefulSetBuilder) WithAffinity(affinity *corev1.Affinity) *ManagerStatefulSetBuilder {
	b.affinity = affinity
	return b
}

// WithLabels sets custom labels
func (b *ManagerStatefulSetBuilder) WithLabels(labels map[string]string) *ManagerStatefulSetBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations sets custom annotations
func (b *ManagerStatefulSetBuilder) WithAnnotations(annotations map[string]string) *ManagerStatefulSetBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithPodAnnotations sets pod annotations
func (b *ManagerStatefulSetBuilder) WithPodAnnotations(annotations map[string]string) *ManagerStatefulSetBuilder {
	b.podAnnotations = annotations
	return b
}

// WithEnv adds environment variables
func (b *ManagerStatefulSetBuilder) WithEnv(env []corev1.EnvVar) *ManagerStatefulSetBuilder {
	b.env = env
	return b
}

// WithEnvFrom adds environment variable sources
func (b *ManagerStatefulSetBuilder) WithEnvFrom(envFrom []corev1.EnvFromSource) *ManagerStatefulSetBuilder {
	b.envFrom = envFrom
	return b
}

// WithVolumes adds volumes
func (b *ManagerStatefulSetBuilder) WithVolumes(volumes []corev1.Volume) *ManagerStatefulSetBuilder {
	b.volumes = volumes
	return b
}

// WithVolumeMounts adds volume mounts
func (b *ManagerStatefulSetBuilder) WithVolumeMounts(mounts []corev1.VolumeMount) *ManagerStatefulSetBuilder {
	b.volumeMounts = mounts
	return b
}

// WithCertHash sets the certificate hash annotation on pods
// This triggers pod restart when certificates are renewed
func (b *ManagerStatefulSetBuilder) WithCertHash(hash string) *ManagerStatefulSetBuilder {
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
func (b *ManagerStatefulSetBuilder) WithSpecHash(hash string) *ManagerStatefulSetBuilder {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b
}

// WithConfigHash sets the config hash annotation on pods
// This triggers pod restart when ConfigMap content changes
func (b *ManagerStatefulSetBuilder) WithConfigHash(hash string) *ManagerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationConfigHash] = hash
	}
	return b
}

// WithCluster sets the WazuhCluster reference for monitoring configuration
// This is required for adding the Prometheus exporter sidecar to master nodes
func (b *ManagerStatefulSetBuilder) WithCluster(cluster *wazuhv1alpha1.WazuhCluster) *ManagerStatefulSetBuilder {
	b.cluster = cluster
	return b
}

// Build creates the StatefulSet
func (b *ManagerStatefulSetBuilder) Build() *appsv1.StatefulSet {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	// Default image if not set
	image := b.image
	if image == "" {
		image = fmt.Sprintf("wazuh/wazuh-manager:%s", b.version)
	}

	// Default resources if not set
	resources := b.resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("512Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1000m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		}
	}

	// Build volumes
	volumes := b.buildVolumes()

	// Build volume mounts
	volumeMounts := b.buildVolumeMounts()

	// Build env vars
	env := b.buildEnvVars()

	// Configure RollingUpdate strategy for graceful rollout
	// Partition 0 means all pods will be updated, but OrderedReady ensures one at a time
	partition := int32(0)

	// Wazuh manager requires root (uid 0) to run s6, filebeat, and other services
	runAsRoot := int64(0)

	// Build containers list
	containers := []corev1.Container{
		{
			Name:            "wazuh-manager",
			Image:           image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Resources:       *resources,
			// SecurityContext: Wazuh manager image runs multiple services via s6 supervisor
			// (wazuh-manager, filebeat, etc.) which require root privileges and SYS_CHROOT capability
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: &runAsRoot,
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"SYS_CHROOT"},
				},
			},
			Ports: []corev1.ContainerPort{
				{Name: "registration", ContainerPort: constants.PortManagerRegistration, Protocol: corev1.ProtocolTCP},
				{Name: "cluster", ContainerPort: constants.PortManagerCluster, Protocol: corev1.ProtocolTCP},
				{Name: "api", ContainerPort: constants.PortManagerAPI, Protocol: corev1.ProtocolTCP},
				{Name: "agents", ContainerPort: constants.PortManagerAgents, Protocol: corev1.ProtocolTCP},
			},
			Env:          env,
			EnvFrom:      b.envFrom,
			VolumeMounts: volumeMounts,
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(int(constants.PortManagerAPI)),
					},
				},
				InitialDelaySeconds: 90,
				PeriodSeconds:       30,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(int(constants.PortManagerAPI)),
					},
				},
				InitialDelaySeconds: 30,
				PeriodSeconds:       10,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
		},
	}

	// Add Prometheus exporter sidecar for master nodes if monitoring is enabled
	if b.nodeType == "master" && b.cluster != nil {
		exporterContainer := monitoring.BuildExporterSidecar(b.cluster)
		if exporterContainer != nil {
			containers = append(containers, *exporterContainer)
		}
	}

	// Build init containers
	initContainers := []corev1.Container{
		b.buildInitContainer(),
	}

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &b.replicas,
			ServiceName: b.name,
			// Parallel allows all pods to start simultaneously
			// This is the recommended policy for Wazuh manager as per official Wazuh Kubernetes deployment
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
					// SecurityContext at pod level - fsGroup 101 is the wazuh group in the official image
					// SeccompProfile Unconfined is needed on some environments (WSL2, certain kernels)
					// to allow Filebeat's Go runtime to create threads (pthread_create)
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup: func() *int64 { v := int64(101); return &v }(),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeUnconfined,
						},
					},
					InitContainers: initContainers,
					Containers:     containers,
					Volumes:        volumes,
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "wazuh-manager-data",
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
func (b *ManagerStatefulSetBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = b.nodeType
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *ManagerStatefulSetBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, "wazuh-manager")
}

// buildVolumes builds the volume list
func (b *ManagerStatefulSetBuilder) buildVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		// ConfigMap source (read-only)
		{
			Name: "wazuh-config-source",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-manager-%s-config", b.clusterName, b.nodeType),
					},
				},
			},
		},
		// Writable volume for ossec.conf (init container copies here)
		{
			Name: "wazuh-config-mount",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		// Writable volume for filebeat.yml (init container copies here)
		{
			Name: "filebeat-config",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "wazuh-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-manager-%s-certs", b.clusterName, b.nodeType),
					Items: []corev1.KeyToPath{
						{Key: constants.SecretKeyTLSCert, Path: "filebeat.pem"},
						{Key: constants.SecretKeyTLSKey, Path: "filebeat-key.pem"},
					},
				},
			},
		},
		// Indexer CA for filebeat SSL verification
		{
			Name: "indexer-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-indexer-certs", b.clusterName),
					Items: []corev1.KeyToPath{
						{
							Key:  constants.SecretKeyCACert,
							Path: "root-ca.pem",
						},
					},
				},
			},
		},
	}

	// Add custom volumes
	volumes = append(volumes, b.volumes...)

	return volumes
}

// buildVolumeMounts builds the volume mount list for the main container
func (b *ManagerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      "wazuh-manager-data",
			MountPath: constants.PathWazuhData,
		},
		// Mount writable ossec.conf directory (populated by init container)
		// The Wazuh entrypoint expects configs at /wazuh-config-mount/etc/
		{
			Name:      "wazuh-config-mount",
			MountPath: "/wazuh-config-mount",
		},
		// Mount writable filebeat.yml (populated by init container)
		{
			Name:      "filebeat-config",
			MountPath: "/etc/filebeat",
		},
		// Mount certificates as directory for filebeat SSL
		{
			Name:      "wazuh-certs",
			MountPath: "/etc/ssl/certs/wazuh",
			ReadOnly:  true,
		},
		{
			Name:      "indexer-certs",
			MountPath: "/etc/ssl/certs/indexer",
			ReadOnly:  true,
		},
	}

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	return mounts
}

// buildInitContainerVolumeMounts builds the volume mount list for the init container
func (b *ManagerStatefulSetBuilder) buildInitContainerVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		// Source: ConfigMap (read-only)
		{
			Name:      "wazuh-config-source",
			MountPath: "/config-source",
			ReadOnly:  true,
		},
		// Destination: writable ossec.conf directory
		{
			Name:      "wazuh-config-mount",
			MountPath: "/wazuh-config-mount",
		},
		// Destination: writable filebeat config directory
		{
			Name:      "filebeat-config",
			MountPath: "/etc/filebeat",
		},
	}
}

// buildInitContainer creates the init container that copies configs to writable volumes
func (b *ManagerStatefulSetBuilder) buildInitContainer() corev1.Container {
	return corev1.Container{
		Name:  "copy-configs",
		Image: "busybox:1.36",
		Command: []string{
			"/bin/sh",
			"-c",
			`echo "Copying configuration files to writable volumes..."
# Create directory structure for ossec.conf
mkdir -p /wazuh-config-mount/etc
# Copy ossec.conf if it exists
if [ -f /config-source/ossec.conf ]; then
    cp /config-source/ossec.conf /wazuh-config-mount/etc/ossec.conf
    chmod 644 /wazuh-config-mount/etc/ossec.conf
    echo "Copied ossec.conf"
fi
# Copy filebeat.yml if it exists
if [ -f /config-source/filebeat.yml ]; then
    cp /config-source/filebeat.yml /etc/filebeat/filebeat.yml
    chmod 644 /etc/filebeat/filebeat.yml
    echo "Copied filebeat.yml"
fi
echo "Configuration copy complete"
ls -la /wazuh-config-mount/etc/ 2>/dev/null || true
ls -la /etc/filebeat/ 2>/dev/null || true`,
		},
		VolumeMounts: b.buildInitContainerVolumeMounts(),
	}
}

// buildEnvVars builds the environment variables
// Note: Filebeat configuration (indexer URL, credentials, SSL) is now embedded directly
// in filebeat.yml via the ConfigMap, no longer passed via environment variables
func (b *ManagerStatefulSetBuilder) buildEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name:  "WAZUH_CLUSTER_NAME",
			Value: b.clusterName,
		},
		{
			Name: "WAZUH_CLUSTER_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-cluster-key", b.clusterName),
					},
					Key: constants.SecretKeyClusterKey,
				},
			},
		},
		{
			Name:  "WAZUH_NODE_TYPE",
			Value: b.nodeType,
		},
		{
			Name: "WAZUH_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name: "API_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-api-credentials", b.clusterName),
					},
					Key: constants.SecretKeyAPIUsername,
				},
			},
		},
		{
			Name: "API_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-api-credentials", b.clusterName),
					},
					Key: constants.SecretKeyAPIPassword,
				},
			},
		},
	}

	// Add master address for workers
	if b.nodeType == "worker" {
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_MASTER_ADDRESS",
			Value: fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", b.clusterName, b.namespace),
		})
	}

	// Add custom env vars
	env = append(env, b.env...)

	return env
}
