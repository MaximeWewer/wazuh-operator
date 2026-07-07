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
	name                      string
	namespace                 string
	clusterName               string
	version                   string
	replicas                  int32
	storageSize               string
	storageClassName          *string
	resources                 *corev1.ResourceRequirements
	image                     string
	nodeSelector              map[string]string
	tolerations               []corev1.Toleration
	affinity                  *corev1.Affinity
	imagePullSecrets          []corev1.LocalObjectReference
	topologySpreadConstraints []corev1.TopologySpreadConstraint
	labels                    map[string]string
	annotations               map[string]string
	podAnnotations            map[string]string
	env                       []corev1.EnvVar
	envFrom                   []corev1.EnvFromSource
	volumes                   []corev1.Volume
	volumeMounts              []corev1.VolumeMount
	masterAddress             string
	// Rule ConfigMaps to mount
	ruleConfigMaps []RuleConfigMapRef
	// Decoder ConfigMaps to mount
	decoderConfigMaps []DecoderConfigMapRef
	// Agent group file ConfigMaps to mount
	agentGroupFiles []AgentGroupFileRef
	// Integration script ConfigMaps to mount
	integrationConfigMaps []IntegrationConfigMapRef
	// CDB list ConfigMaps to mount
	cdbListConfigMaps []CDBListConfigMapRef
	// Active response script ConfigMaps to mount
	activeResponseConfigMaps []ActiveResponseConfigMapRef
	// Extra init containers
	extraInitContainers []corev1.Container
	// Extra sidecar containers
	extraContainers []corev1.Container
	// Termination grace period
	terminationGracePeriodSeconds *int64
	// Service account name
	serviceAccountName string
	// Image pull policy
	imagePullPolicy corev1.PullPolicy
	// Pod-level security context override
	securityContext *corev1.PodSecurityContext
	// Container-level security context override
	containerSecurityContext *corev1.SecurityContext
	// Update strategy for the StatefulSet
	updateStrategy appsv1.StatefulSetUpdateStrategyType
}

// NewWorkerStatefulSetBuilder creates a new WorkerStatefulSetBuilder
func NewWorkerStatefulSetBuilder(clusterName, namespace string) *WorkerStatefulSetBuilder {
	name := constants.ManagerWorkerName(clusterName)
	masterAddr := constants.ManagerMasterServiceFQDN(clusterName, namespace)
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

// WithImagePullPolicy sets the image pull policy for the main container
func (b *WorkerStatefulSetBuilder) WithImagePullPolicy(policy corev1.PullPolicy) *WorkerStatefulSetBuilder {
	b.imagePullPolicy = policy
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

// WithImagePullSecrets sets the image pull secrets
func (b *WorkerStatefulSetBuilder) WithImagePullSecrets(secrets []corev1.LocalObjectReference) *WorkerStatefulSetBuilder {
	b.imagePullSecrets = secrets
	return b
}

// WithTopologySpreadConstraints sets the topology spread constraints
func (b *WorkerStatefulSetBuilder) WithTopologySpreadConstraints(constraints []corev1.TopologySpreadConstraint) *WorkerStatefulSetBuilder {
	b.topologySpreadConstraints = constraints
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

// WithRuleConfigMaps sets the rule ConfigMaps to mount
// Each rule ConfigMap contains custom Wazuh detection rules that will be mounted
// to /var/ossec/etc/rules/{filename}.xml
func (b *WorkerStatefulSetBuilder) WithRuleConfigMaps(refs []RuleConfigMapRef) *WorkerStatefulSetBuilder {
	b.ruleConfigMaps = refs
	return b
}

// WithRuleHash sets the rule hash annotation on pods
// This triggers pod restart when rule content changes
func (b *WorkerStatefulSetBuilder) WithRuleHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationRuleHash] = hash
	}
	return b
}

// WithDecoderConfigMaps sets the decoder ConfigMaps to mount
// Each decoder ConfigMap contains custom Wazuh log decoders that will be mounted
// to /var/ossec/etc/decoders/{filename}.xml
func (b *WorkerStatefulSetBuilder) WithDecoderConfigMaps(refs []DecoderConfigMapRef) *WorkerStatefulSetBuilder {
	b.decoderConfigMaps = refs
	return b
}

// WithDecoderHash sets the decoder hash annotation on pods
// This triggers pod restart when decoder content changes
func (b *WorkerStatefulSetBuilder) WithDecoderHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationDecoderHash] = hash
	}
	return b
}

// WithCDBListConfigMaps sets the CDB list ConfigMaps to mount
// Each ConfigMap contains a CDB list that will be mounted to /var/ossec/etc/lists/<filename>
func (b *WorkerStatefulSetBuilder) WithCDBListConfigMaps(refs []CDBListConfigMapRef) *WorkerStatefulSetBuilder {
	b.cdbListConfigMaps = refs
	return b
}

// WithCDBListHash sets the CDB list hash annotation on pods
// This triggers pod restart when CDB list content changes
func (b *WorkerStatefulSetBuilder) WithCDBListHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationCDBListHash] = hash
	}
	return b
}

// WithActiveResponseConfigMaps sets the active response script ConfigMaps to mount
// Each ConfigMap holds a custom active response script mounted executable to
// /var/ossec/active-response/bin/<filename>
func (b *WorkerStatefulSetBuilder) WithActiveResponseConfigMaps(refs []ActiveResponseConfigMapRef) *WorkerStatefulSetBuilder {
	b.activeResponseConfigMaps = refs
	return b
}

// WithActiveResponseHash sets the active response hash annotation on pods
// This triggers pod restart when active response scripts or configuration change
func (b *WorkerStatefulSetBuilder) WithActiveResponseHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationActiveResponseHash] = hash
	}
	return b
}

// WithIntegrationConfigMaps sets the integration script ConfigMaps to mount
// Each ConfigMap holds a custom integration script that will be mounted executable
// to /var/ossec/integrations/<filename>
func (b *WorkerStatefulSetBuilder) WithIntegrationConfigMaps(refs []IntegrationConfigMapRef) *WorkerStatefulSetBuilder {
	b.integrationConfigMaps = refs
	return b
}

// WithIntegrationHash sets the integration hash annotation on pods
// This triggers pod restart when integration scripts or configuration change
func (b *WorkerStatefulSetBuilder) WithIntegrationHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationIntegrationHash] = hash
	}
	return b
}

// WithAgentGroupFiles sets the agent group file ConfigMaps to mount
// Each ConfigMap contains files for a specific agent group that will be mounted
// to /var/ossec/etc/shared/<groupName>/<filename>
func (b *WorkerStatefulSetBuilder) WithAgentGroupFiles(refs []AgentGroupFileRef) *WorkerStatefulSetBuilder {
	b.agentGroupFiles = refs
	return b
}

// WithAgentGroupFilesHash sets the agent group files hash annotation on pods
// This triggers pod restart when agent group file content changes
func (b *WorkerStatefulSetBuilder) WithAgentGroupFilesHash(hash string) *WorkerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationAgentGroupFilesHash] = hash
	}
	return b
}

// WithExtraInitContainers sets extra init containers
func (b *WorkerStatefulSetBuilder) WithExtraInitContainers(containers []corev1.Container) *WorkerStatefulSetBuilder {
	b.extraInitContainers = containers
	return b
}

// WithExtraContainers sets extra sidecar containers
func (b *WorkerStatefulSetBuilder) WithExtraContainers(containers []corev1.Container) *WorkerStatefulSetBuilder {
	b.extraContainers = containers
	return b
}

// WithTerminationGracePeriodSeconds sets the termination grace period for pods
func (b *WorkerStatefulSetBuilder) WithTerminationGracePeriodSeconds(seconds *int64) *WorkerStatefulSetBuilder {
	b.terminationGracePeriodSeconds = seconds
	return b
}

// WithServiceAccountName sets the ServiceAccount name on the PodSpec
func (b *WorkerStatefulSetBuilder) WithServiceAccountName(name string) *WorkerStatefulSetBuilder {
	b.serviceAccountName = name
	return b
}

// WithSecurityContext sets the pod-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *WorkerStatefulSetBuilder) WithSecurityContext(sc *corev1.PodSecurityContext) *WorkerStatefulSetBuilder {
	b.securityContext = sc
	return b
}

// WithContainerSecurityContext sets the container-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *WorkerStatefulSetBuilder) WithContainerSecurityContext(sc *corev1.SecurityContext) *WorkerStatefulSetBuilder {
	b.containerSecurityContext = sc
	return b
}

// WithUpdateStrategy sets the StatefulSet update strategy type
func (b *WorkerStatefulSetBuilder) WithUpdateStrategy(strategy appsv1.StatefulSetUpdateStrategyType) *WorkerStatefulSetBuilder {
	b.updateStrategy = strategy
	return b
}

// resolveUpdateStrategy returns the configured strategy or defaults to RollingUpdate
func (b *WorkerStatefulSetBuilder) resolveUpdateStrategy() appsv1.StatefulSetUpdateStrategyType {
	if b.updateStrategy != "" {
		return b.updateStrategy
	}
	return appsv1.RollingUpdateStatefulSetStrategyType
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
		{
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
		},
	}

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

	// Add rule ConfigMap volumes
	for _, ref := range b.ruleConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("wazuh-rule-%s", ref.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.Name,
					},
				},
			},
		})
	}

	// Add decoder ConfigMap volumes
	for _, ref := range b.decoderConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("wazuh-decoder-%s", ref.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.Name,
					},
				},
			},
		})
	}

	// Add agent group file ConfigMap volumes
	for _, ref := range b.agentGroupFiles {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("agentgroup-files-%s", ref.ConfigMapName),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.ConfigMapName,
					},
				},
			},
		})
	}

	// Add integration script ConfigMap volumes. Mounted read-only via subPath into
	// /var/ossec/integrations; DefaultMode 0750 + the pod fsGroup (wazuh) yield
	// root:wazuh 0750 — exactly what Wazuh requires for a custom integration script.
	for _, ref := range b.integrationConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("wazuh-integration-%s", ref.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.Name,
					},
					DefaultMode: &integrationScriptMode,
				},
			},
		})
	}

	// Add CDB list ConfigMap volumes
	for _, ref := range b.cdbListConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("wazuh-cdblist-%s", ref.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.Name,
					},
				},
			},
		})
	}

	// Add active response script ConfigMap volumes. Mounted executable via subPath into
	// /var/ossec/active-response/bin; DefaultMode 0750 + the pod fsGroup (wazuh) yield
	// root:wazuh 0750 — exactly what Wazuh requires for a custom active response script.
	for _, ref := range b.activeResponseConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("wazuh-activeresponse-%s", ref.Name),
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ref.Name,
					},
					DefaultMode: &integrationScriptMode,
				},
			},
		})
	}

	return volumes
}

// buildVolumeMounts builds the volume mount list for the main container
func (b *WorkerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		// PVC subPath mounts - each subdirectory is persisted on the same PVC
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhAPIConfig, SubPath: constants.SubPathWazuhAPIConfig},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhConfig, SubPath: constants.SubPathWazuhEtc},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhLogs, SubPath: constants.SubPathWazuhLogs},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhQueue, SubPath: constants.SubPathWazuhQueue},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhVarMultigroups, SubPath: constants.SubPathWazuhVarMultigroups},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhIntegrations, SubPath: constants.SubPathWazuhIntegrations},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhActiveResponse, SubPath: constants.SubPathWazuhActiveResponse},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhAgentless, SubPath: constants.SubPathWazuhAgentless},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathWazuhWodles, SubPath: constants.SubPathWazuhWodles},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathFilebeatConfig, SubPath: constants.SubPathFilebeatConfig},
		{Name: constants.VolumeNameWazuhData, MountPath: constants.PathFilebeatData, SubPath: constants.SubPathFilebeatData},
		// Mount writable ossec.conf directory (populated by init container)
		// The Wazuh entrypoint expects configs at /wazuh-config-mount/etc/
		{
			Name:      constants.VolumeNameWazuhConfigMount,
			MountPath: constants.PathMountWazuhConfig,
		},
		// Mount certificates as directory for filebeat SSL
		{
			Name:      constants.VolumeNameWazuhCerts,
			MountPath: constants.PathMountSSLCertsWazuh,
			ReadOnly:  true,
		},
		{
			Name:      constants.VolumeNameIndexerCerts,
			MountPath: constants.PathMountSSLCertsIndexer,
			ReadOnly:  true,
		},
	}

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	// Add rule ConfigMap mounts at /var/ossec/etc/rules/
	for _, ref := range b.ruleConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("wazuh-rule-%s", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/rules/%s", ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	// Add decoder ConfigMap mounts at /var/ossec/etc/decoders/
	for _, ref := range b.decoderConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("wazuh-decoder-%s", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/decoders/%s", ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	// Add agent group file mounts at /var/ossec/etc/shared/<groupName>/<filename>
	for _, ref := range b.agentGroupFiles {
		for _, fileName := range ref.FileNames {
			mounts = append(mounts, corev1.VolumeMount{
				Name:      fmt.Sprintf("agentgroup-files-%s", ref.ConfigMapName),
				MountPath: fmt.Sprintf("/var/ossec/etc/shared/%s/%s", ref.GroupName, fileName),
				SubPath:   fileName,
				ReadOnly:  true,
			})
		}
	}

	// Add integration script mounts at /var/ossec/integrations/<filename>.
	// Read-only subPath mount; DefaultMode 0750 + fsGroup give root:wazuh 0750.
	for _, ref := range b.integrationConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("wazuh-integration-%s", ref.Name),
			MountPath: fmt.Sprintf("%s/%s", constants.PathWazuhIntegrations, ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	// Add CDB list mounts at /var/ossec/etc/lists/<path>. FileName may include a
	// subdirectory; the subPath is the ConfigMap key (basename). kubelet creates any
	// intermediate directory of the mount path.
	for _, ref := range b.cdbListConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("wazuh-cdblist-%s", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/lists/%s", ref.FileName),
			SubPath:   ref.Key,
			ReadOnly:  true,
		})
	}

	// Add active response script mounts at /var/ossec/active-response/bin/<filename>.
	// Read-only subPath mount; DefaultMode 0750 + fsGroup give root:wazuh 0750.
	for _, ref := range b.activeResponseConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("wazuh-activeresponse-%s", ref.Name),
			MountPath: fmt.Sprintf("%s/%s", constants.PathWazuhActiveResponse, ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	return mounts
}

// buildInitContainerVolumeMounts builds the volume mount list for the init container
func (b *WorkerStatefulSetBuilder) buildInitContainerVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		// Source: ConfigMap (read-only)
		{
			Name:      constants.VolumeNameWazuhConfigSource,
			MountPath: constants.PathMountConfigSource,
			ReadOnly:  true,
		},
		// Destination: writable ossec.conf directory (emptyDir - fresh every start)
		{
			Name:      constants.VolumeNameWazuhConfigMount,
			MountPath: constants.PathMountWazuhConfig,
		},
		// Destination: PVC-backed filebeat config
		{
			Name:      constants.VolumeNameWazuhData,
			MountPath: constants.PathFilebeatConfig,
			SubPath:   constants.SubPathFilebeatConfig,
		},
		// Destination: PVC-backed wazuh etc (includes shared/, rules/, decoders/)
		{
			Name:      constants.VolumeNameWazuhData,
			MountPath: constants.PathWazuhConfig,
			SubPath:   constants.SubPathWazuhEtc,
		},
		// Full PVC volume (no subpath) for chown -R to fix ownership of all PVC data
		{
			Name:      constants.VolumeNameWazuhData,
			MountPath: "/wazuh-data",
		},
	}

	return mounts
}

// buildInitContainer creates the init container that copies configs to writable volumes
func (b *WorkerStatefulSetBuilder) buildInitContainer() corev1.Container {
	return corev1.Container{
		Name:  constants.InitContainerNamePermissions,
		Image: constants.ImageBusyboxInit,
		Command: []string{
			"/bin/sh",
			"-c",
			`echo "Initializing PVC directories and copying configuration files..."
# Create directory structure for ossec.conf (emptyDir)
mkdir -p /wazuh-config-mount/etc
# Create required subdirectories on PVC-backed /var/ossec/etc
mkdir -p /var/ossec/etc/shared /var/ossec/etc/rules /var/ossec/etc/decoders /var/ossec/etc/lists
# Create ar.conf in shared directory (required by wazuh-analysisd)
touch /var/ossec/etc/shared/ar.conf
chown 0:999 /var/ossec/etc/shared/ar.conf
chmod 660 /var/ossec/etc/shared/ar.conf
chown 0:999 /var/ossec/etc/shared
chmod 770 /var/ossec/etc/shared
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
# Copy wazuh-template.json if it exists
if [ -f /config-source/wazuh-template.json ]; then
    cp /config-source/wazuh-template.json /etc/filebeat/wazuh-template.json
    chmod 644 /etc/filebeat/wazuh-template.json
    echo "Copied wazuh-template.json"
fi
# Copy local_internal_options.conf if it exists
if [ -f /config-source/local_internal_options.conf ]; then
    cp /config-source/local_internal_options.conf /wazuh-config-mount/etc/local_internal_options.conf
    chmod 644 /wazuh-config-mount/etc/local_internal_options.conf
    echo "Copied local_internal_options.conf"
fi
echo "Configuration copy complete"
ls -la /wazuh-config-mount/etc/ 2>/dev/null || true
ls -la /etc/filebeat/ 2>/dev/null || true
# Fix ownership of all PVC-backed data and emptyDir config
echo "Fixing ownership to wazuh (999:999)..."
chown -R 999:999 /wazuh-data
chown -R 999:999 /wazuh-config-mount
echo "Ownership fix complete"`,
		},
		VolumeMounts: b.buildInitContainerVolumeMounts(),
	}
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
