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
	baseStatefulSetBuilder[*WorkerStatefulSetBuilder]
	masterAddress string
}

// NewWorkerStatefulSetBuilder creates a new WorkerStatefulSetBuilder
func NewWorkerStatefulSetBuilder(clusterName, namespace string) *WorkerStatefulSetBuilder {
	b := &WorkerStatefulSetBuilder{
		masterAddress: constants.ManagerMasterServiceFQDN(clusterName, namespace),
	}
	b.self = b
	b.name = constants.ManagerWorkerName(clusterName)
	b.namespace = namespace
	b.clusterName = clusterName
	b.version = constants.DefaultWazuhVersion
	b.replicas = constants.DefaultManagerWorkerReplicas
	b.storageSize = constants.DefaultWorkerStorageSize
	b.labels = make(map[string]string)
	b.annotations = make(map[string]string)
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

	// Default image pull policy if not set
	imagePullPolicy := b.imagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
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

	// Build pod-level security context with defaults, then merge user overrides
	// Defaults: FSGroup=999 (wazuh group), SeccompProfile=Unconfined (needed for Filebeat)
	// FSGroupChangePolicy=OnRootMismatch so the kubelet only recursively chowns the
	// data PVC when its root is not already the fsGroup — without this (default
	// "Always") every pod start re-chowns the whole volume, adding minutes.
	onRootMismatch := corev1.FSGroupChangeOnRootMismatch
	podSecCtx := &corev1.PodSecurityContext{
		FSGroup:             func() *int64 { v := int64(999); return &v }(),
		FSGroupChangePolicy: &onRootMismatch,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeUnconfined,
		},
	}
	if b.securityContext != nil {
		if b.securityContext.FSGroup != nil {
			podSecCtx.FSGroup = b.securityContext.FSGroup
		}
		if b.securityContext.FSGroupChangePolicy != nil {
			podSecCtx.FSGroupChangePolicy = b.securityContext.FSGroupChangePolicy
		}
		if b.securityContext.RunAsUser != nil {
			podSecCtx.RunAsUser = b.securityContext.RunAsUser
		}
		if b.securityContext.RunAsGroup != nil {
			podSecCtx.RunAsGroup = b.securityContext.RunAsGroup
		}
		if b.securityContext.RunAsNonRoot != nil {
			podSecCtx.RunAsNonRoot = b.securityContext.RunAsNonRoot
		}
		if b.securityContext.SeccompProfile != nil {
			podSecCtx.SeccompProfile = b.securityContext.SeccompProfile
		}
		if b.securityContext.SELinuxOptions != nil {
			podSecCtx.SELinuxOptions = b.securityContext.SELinuxOptions
		}
		if b.securityContext.Sysctls != nil {
			podSecCtx.Sysctls = b.securityContext.Sysctls
		}
		if b.securityContext.SupplementalGroups != nil {
			podSecCtx.SupplementalGroups = b.securityContext.SupplementalGroups
		}
	}

	// Build container-level security context with defaults, then merge user overrides
	// Defaults: RunAsUser=0 (root, required by s6), SYS_CHROOT capability
	runAsRoot := int64(0)
	containerSecCtx := &corev1.SecurityContext{
		RunAsUser: &runAsRoot,
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{"SYS_CHROOT"},
		},
	}
	if b.containerSecurityContext != nil {
		if b.containerSecurityContext.AllowPrivilegeEscalation != nil {
			containerSecCtx.AllowPrivilegeEscalation = b.containerSecurityContext.AllowPrivilegeEscalation
		}
		if b.containerSecurityContext.Capabilities != nil {
			containerSecCtx.Capabilities = b.containerSecurityContext.Capabilities
		}
		if b.containerSecurityContext.RunAsUser != nil {
			containerSecCtx.RunAsUser = b.containerSecurityContext.RunAsUser
		}
		if b.containerSecurityContext.RunAsGroup != nil {
			containerSecCtx.RunAsGroup = b.containerSecurityContext.RunAsGroup
		}
		if b.containerSecurityContext.RunAsNonRoot != nil {
			containerSecCtx.RunAsNonRoot = b.containerSecurityContext.RunAsNonRoot
		}
		if b.containerSecurityContext.ReadOnlyRootFilesystem != nil {
			containerSecCtx.ReadOnlyRootFilesystem = b.containerSecurityContext.ReadOnlyRootFilesystem
		}
		if b.containerSecurityContext.Privileged != nil {
			containerSecCtx.Privileged = b.containerSecurityContext.Privileged
		}
		if b.containerSecurityContext.SeccompProfile != nil {
			containerSecCtx.SeccompProfile = b.containerSecurityContext.SeccompProfile
		}
		if b.containerSecurityContext.SELinuxOptions != nil {
			containerSecCtx.SELinuxOptions = b.containerSecurityContext.SELinuxOptions
		}
	}

	// Build init containers
	initContainers := []corev1.Container{
		buildSeedAPIConfigInitContainer(image),
		b.buildInitContainer(),
	}

	// Insert the cdb-fetch init container (large CDB lists) after fix-permissions creates
	// /var/ossec/etc/lists and before fix-ownership chowns the written files to 999.
	if cdbFetch, ok := b.buildCDBFetchInitContainer(); ok {
		initContainers = append(initContainers, cdbFetch)
	}

	initContainers = append(initContainers, corev1.Container{
		Name:  "fix-ownership",
		Image: image,
		Command: []string{
			"/bin/bash",
			"-c",
			// Chown only writable files not already owned by 999: "-writable" skips
			// read-only mounts (e.g. the authd.pass Secret) that would otherwise fail
			// the chown on a read-only fs; "! -user 999" skips the already-correct
			// files so restarts don't re-chown the whole /var/ossec tree.
			"find /var/ossec -writable ! -user 999 -print0 | xargs -0 -r chown 999:999",
		},
		VolumeMounts: b.buildVolumeMounts(),
	})

	// Append extra init containers
	initContainers = append(initContainers, b.extraInitContainers...)

	// Build containers list
	containers := []corev1.Container{
		{
			Name:            constants.ContainerNameWazuhManager,
			Image:           image,
			ImagePullPolicy: imagePullPolicy,
			Resources:       *resources,
			SecurityContext: containerSecCtx,
			Ports: []corev1.ContainerPort{
				{Name: "registration", ContainerPort: constants.PortManagerAgentAuth, Protocol: corev1.ProtocolTCP},
				{Name: "cluster", ContainerPort: constants.PortManagerCluster, Protocol: corev1.ProtocolTCP},
				{Name: "api", ContainerPort: constants.PortManagerAPI, Protocol: corev1.ProtocolTCP},
				{Name: "agents", ContainerPort: constants.PortManagerAgentEvents, Protocol: corev1.ProtocolTCP},
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

	// Append extra sidecar containers
	containers = append(containers, b.extraContainers...)

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
			// MinReadySeconds ensures pod is stable before considered available
			// This prevents premature progression during rolling updates
			MinReadySeconds: 30,
			// Parallel allows all pods to start simultaneously during initial deployment
			PodManagementPolicy: appsv1.ParallelPodManagement,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: b.resolveUpdateStrategy(),
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
					TerminationGracePeriodSeconds: b.terminationGracePeriodSeconds,
					ServiceAccountName:            b.serviceAccountName,
					NodeSelector:                  b.nodeSelector,
					Tolerations:                   b.tolerations,
					Affinity:                      b.affinity,
					ImagePullSecrets:              b.imagePullSecrets,
					TopologySpreadConstraints:     b.topologySpreadConstraints,
					SecurityContext:               podSecCtx,
					InitContainers:                initContainers,
					Containers:                    containers,
					Volumes:                       volumes,
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   constants.VolumeNameWazuhData,
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
		// ConfigMap source (read-only)
		{
			Name: constants.VolumeNameWazuhConfigSource,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.ManagerConfigName(b.clusterName, "worker"),
					},
				},
			},
		},
		// Writable volume for ossec.conf (init container copies here)
		// Must be emptyDir so s6 always gets fresh config from ConfigMap
		{
			Name: constants.VolumeNameWazuhConfigMount,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: func() *resource.Quantity { q := resource.MustParse("10Mi"); return &q }(),
				},
			},
		},
		{
			Name: constants.VolumeNameWazuhCerts,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.ManagerWorkerCertsName(b.clusterName),
					Items: []corev1.KeyToPath{
						{Key: constants.SecretKeyTLSCert, Path: "filebeat.pem"},
						{Key: constants.SecretKeyTLSKey, Path: "filebeat-key.pem"},
					},
				},
			},
		},
		// Indexer CA for filebeat SSL verification
		{
			Name: constants.VolumeNameIndexerCerts,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: constants.IndexerCertsName(b.clusterName),
					Items: []corev1.KeyToPath{
						{
							Key:  constants.SecretKeyCACert,
							Path: constants.SecretKeyRootCA,
						},
					},
				},
			},
		},
	}

	// Add custom volumes
	volumes = append(volumes, b.volumes...)

	// Add ConfigMap-backed content volumes (rules, decoders, agent-group files,
	// integrations, CDB lists, active responses) — shared with the master builder.
	volumes = append(volumes, b.configMapVolumes()...)

	return volumes
}

// buildVolumeMounts builds the volume mount list for the main container
func (b *WorkerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := wazuhDataBaseMounts()

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	// Add ConfigMap-backed content mounts (rules, decoders, agent-group files,
	// integrations, CDB lists, active responses) — shared with the master builder.
	mounts = append(mounts, b.configMapMounts()...)

	return mounts
}

// buildEnvVars builds the environment variables
// Filebeat configuration is passed via env vars for compatibility with Wazuh s6 init scripts
// The s6 script 1-config-filebeat uses these to customize the default filebeat.yml
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
						Name: constants.ClusterKeyName(b.clusterName),
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
		{
			Name: "API_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.APICredentialsName(b.clusterName),
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
						Name: constants.APICredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAPIPassword,
				},
			},
		},
	}

	// Filebeat env vars for s6 init script (1-config-filebeat) compatibility.
	// The s6 script 0-wazuh-init overwrites /etc/filebeat/filebeat.yml with the image default,
	// then 1-config-filebeat uses sed to patch it with these env vars.
	// These env vars are identical across all Wazuh 4.x versions (4.9 through 4.14).
	env = append(env,
		corev1.EnvVar{
			Name:  "INDEXER_URL",
			Value: fmt.Sprintf("https://%s:%d", constants.IndexerServiceFQDN(b.clusterName, b.namespace), constants.PortIndexerREST),
		},
		corev1.EnvVar{
			Name: "INDEXER_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.IndexerCredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAdminUsername,
				},
			},
		},
		corev1.EnvVar{
			Name: "INDEXER_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.IndexerCredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAdminPassword,
				},
			},
		},
		corev1.EnvVar{
			Name:  "FILEBEAT_SSL_VERIFICATION_MODE",
			Value: "full",
		},
		corev1.EnvVar{
			Name:  "SSL_CERTIFICATE_AUTHORITIES",
			Value: constants.PathFilebeatCAFile,
		},
		corev1.EnvVar{
			Name:  "SSL_CERTIFICATE",
			Value: constants.PathFilebeatCertFile,
		},
		corev1.EnvVar{
			Name:  "SSL_KEY",
			Value: constants.PathFilebeatKeyFile,
		},
	)

	// Add custom env vars
	env = append(env, b.env...)

	return env
}
