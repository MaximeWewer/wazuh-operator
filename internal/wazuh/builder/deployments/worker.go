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

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WorkerStatefulSetBuilder builds a StatefulSet for Wazuh Manager Worker nodes
type WorkerStatefulSetBuilder struct {
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
	masterAddress    string
}

// NewWorkerStatefulSetBuilder creates a new WorkerStatefulSetBuilder
func NewWorkerStatefulSetBuilder(clusterName, namespace string) *WorkerStatefulSetBuilder {
	name := fmt.Sprintf("%s-manager-worker", clusterName)
	masterAddr := fmt.Sprintf("%s-manager-master.%s.svc.cluster.local", clusterName, namespace)
	return &WorkerStatefulSetBuilder{
		name:          name,
		namespace:     namespace,
		clusterName:   clusterName,
		version:       constants.DefaultWazuhVersion,
		replicas:      constants.DefaultManagerWorkerReplicas,
		storageSize:   constants.DefaultWorkerStorageSize,
		masterAddress: masterAddr,
		labels:        make(map[string]string),
		annotations:   make(map[string]string),
	}
}

// WithVersion sets the Wazuh version
func (b *WorkerStatefulSetBuilder) WithVersion(version string) *WorkerStatefulSetBuilder {
	b.version = version
	return b
}

// WithReplicas sets the number of replicas
func (b *WorkerStatefulSetBuilder) WithReplicas(replicas int32) *WorkerStatefulSetBuilder {
	b.replicas = replicas
	return b
}

// WithStorageSize sets the storage size
func (b *WorkerStatefulSetBuilder) WithStorageSize(size string) *WorkerStatefulSetBuilder {
	b.storageSize = size
	return b
}

// WithStorageClassName sets the storage class name
func (b *WorkerStatefulSetBuilder) WithStorageClassName(className string) *WorkerStatefulSetBuilder {
	b.storageClassName = &className
	return b
}

// WithResources sets the resource requirements
func (b *WorkerStatefulSetBuilder) WithResources(resources *corev1.ResourceRequirements) *WorkerStatefulSetBuilder {
	b.resources = resources
	return b
}

// WithImage sets the container image
func (b *WorkerStatefulSetBuilder) WithImage(image string) *WorkerStatefulSetBuilder {
	b.image = image
	return b
}

// WithNodeSelector sets the node selector
func (b *WorkerStatefulSetBuilder) WithNodeSelector(nodeSelector map[string]string) *WorkerStatefulSetBuilder {
	b.nodeSelector = nodeSelector
	return b
}

// WithTolerations sets the tolerations
func (b *WorkerStatefulSetBuilder) WithTolerations(tolerations []corev1.Toleration) *WorkerStatefulSetBuilder {
	b.tolerations = tolerations
	return b
}

// WithAffinity sets the affinity
func (b *WorkerStatefulSetBuilder) WithAffinity(affinity *corev1.Affinity) *WorkerStatefulSetBuilder {
	b.affinity = affinity
	return b
}

// WithLabels sets custom labels
func (b *WorkerStatefulSetBuilder) WithLabels(labels map[string]string) *WorkerStatefulSetBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations sets custom annotations
func (b *WorkerStatefulSetBuilder) WithAnnotations(annotations map[string]string) *WorkerStatefulSetBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithPodAnnotations sets pod annotations
func (b *WorkerStatefulSetBuilder) WithPodAnnotations(annotations map[string]string) *WorkerStatefulSetBuilder {
	b.podAnnotations = annotations
	return b
}

// WithEnv adds environment variables
func (b *WorkerStatefulSetBuilder) WithEnv(env []corev1.EnvVar) *WorkerStatefulSetBuilder {
	b.env = env
	return b
}

// WithEnvFrom adds environment variable sources
func (b *WorkerStatefulSetBuilder) WithEnvFrom(envFrom []corev1.EnvFromSource) *WorkerStatefulSetBuilder {
	b.envFrom = envFrom
	return b
}

// WithVolumes adds volumes
func (b *WorkerStatefulSetBuilder) WithVolumes(volumes []corev1.Volume) *WorkerStatefulSetBuilder {
	b.volumes = volumes
	return b
}

// WithVolumeMounts adds volume mounts
func (b *WorkerStatefulSetBuilder) WithVolumeMounts(mounts []corev1.VolumeMount) *WorkerStatefulSetBuilder {
	b.volumeMounts = mounts
	return b
}

// WithMasterAddress sets the master node address
func (b *WorkerStatefulSetBuilder) WithMasterAddress(address string) *WorkerStatefulSetBuilder {
	b.masterAddress = address
	return b
}

// WithCertHash sets the certificate hash annotation on pods
// This triggers pod restart when certificates are renewed
func (b *WorkerStatefulSetBuilder) WithCertHash(hash string) *WorkerStatefulSetBuilder {
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
func (b *WorkerStatefulSetBuilder) WithSpecHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b
}

// WithConfigHash sets the config hash annotation on pods
// This triggers pod restart when ConfigMap content changes
func (b *WorkerStatefulSetBuilder) WithConfigHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationConfigHash] = hash
	}
	return b
}

// Build creates the StatefulSet
func (b *WorkerStatefulSetBuilder) Build() *appsv1.StatefulSet {
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
					Containers: []corev1.Container{
						{
							Name:            "wazuh-manager",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Resources:       *resources,
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
					},
					Volumes: volumes,
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
func (b *WorkerStatefulSetBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = "worker"
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *WorkerStatefulSetBuilder) buildSelectorLabels() map[string]string {
	labels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	labels[constants.LabelManagerNodeType] = "worker"
	return labels
}

// buildVolumes builds the volume list
func (b *WorkerStatefulSetBuilder) buildVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "wazuh-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-manager-worker-config", b.clusterName),
					},
				},
			},
		},
		{
			Name: "wazuh-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-manager-worker-certs", b.clusterName),
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
							Path: "indexer-ca.pem",
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

// buildVolumeMounts builds the volume mount list
func (b *WorkerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      "wazuh-manager-data",
			MountPath: constants.PathWazuhData,
		},
		{
			Name:      "wazuh-config",
			MountPath: "/wazuh-config-mount",
		},
		// Mount certificates individually with SubPath (allows container to modify other files)
		{
			Name:      "indexer-certs",
			MountPath: "/etc/ssl/root-ca.pem",
			SubPath:   "indexer-ca.pem",
			ReadOnly:  true,
		},
		{
			Name:      "wazuh-certs",
			MountPath: "/etc/ssl/filebeat.pem",
			SubPath:   "filebeat.pem",
			ReadOnly:  true,
		},
		{
			Name:      "wazuh-certs",
			MountPath: "/etc/ssl/filebeat.key",
			SubPath:   "filebeat-key.pem",
			ReadOnly:  true,
		},
	}

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	return mounts
}

// buildEnvVars builds the environment variables
func (b *WorkerStatefulSetBuilder) buildEnvVars() []corev1.EnvVar {
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
			Value: "worker",
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
			Name:  "WAZUH_MASTER_ADDRESS",
			Value: b.masterAddress,
		},
		// Indexer configuration for filebeat (auto-configured by container)
		{
			Name:  "INDEXER_URL",
			Value: fmt.Sprintf("https://%s-indexer.%s.svc.cluster.local:%d", b.clusterName, b.namespace, constants.PortIndexerREST),
		},
		{
			Name: "INDEXER_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-indexer-credentials", b.clusterName),
					},
					Key: constants.SecretKeyAdminUsername,
				},
			},
		},
		{
			Name: "INDEXER_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-indexer-credentials", b.clusterName),
					},
					Key: constants.SecretKeyAdminPassword,
				},
			},
		},
		// SSL configuration for filebeat
		{
			Name:  "FILEBEAT_SSL_VERIFICATION_MODE",
			Value: "full",
		},
		{
			Name:  "SSL_CERTIFICATE_AUTHORITIES",
			Value: "/etc/ssl/root-ca.pem",
		},
		{
			Name:  "SSL_CERTIFICATE",
			Value: "/etc/ssl/filebeat.pem",
		},
		{
			Name:  "SSL_KEY",
			Value: "/etc/ssl/filebeat.key",
		},
	}

	// Add custom env vars
	env = append(env, b.env...)

	return env
}
