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

// Package deployments provides Kubernetes Deployment builders for Wazuh components
package deployments

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerStatefulSetBuilder builds a StatefulSet for Wazuh Manager (master or workers)
type ManagerStatefulSetBuilder struct {
	name                      string
	namespace                 string
	clusterName               string
	version                   string
	replicas                  int32
	nodeType                  string // "master" or "worker"
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
	// Monitoring configuration
	cluster *wazuhv1.WazuhCluster
	// Rule ConfigMaps to mount
	ruleConfigMaps []RuleConfigMapRef
	// Decoder ConfigMaps to mount
	decoderConfigMaps []DecoderConfigMapRef
	// Agent group file ConfigMaps to mount
	agentGroupFiles []AgentGroupFileRef
	// Integration script ConfigMaps to mount
	integrationConfigMaps []IntegrationConfigMapRef
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

// RuleConfigMapRef holds information about a rule ConfigMap to mount
type RuleConfigMapRef struct {
	Name     string // ConfigMap name
	FileName string // Filename for the rule (e.g., "my_rule.xml")
}

// DecoderConfigMapRef holds information about a decoder ConfigMap to mount
type DecoderConfigMapRef struct {
	Name     string // ConfigMap name
	FileName string // Filename for the decoder (e.g., "my_decoder.xml")
}

// AgentGroupFileRef holds information about an agent group files ConfigMap to mount
type AgentGroupFileRef struct {
	ConfigMapName string   // ConfigMap name
	GroupName     string   // Agent group name (used for mount path)
	FileNames     []string // Filenames within the ConfigMap
}

// IntegrationConfigMapRef holds information about an integration script ConfigMap to mount
type IntegrationConfigMapRef struct {
	Name     string // ConfigMap name
	FileName string // Script filename (e.g. "custom-jira")
}

// integrationScriptMode is the file mode applied to mounted integration scripts.
// Combined with the pod fsGroup (wazuh), a read-only ConfigMap subPath mount with
// this DefaultMode yields root:wazuh 0750 — exactly what Wazuh requires.
var integrationScriptMode = int32(0o750)

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

// WithImagePullPolicy sets the image pull policy for the main container
func (b *ManagerStatefulSetBuilder) WithImagePullPolicy(policy corev1.PullPolicy) *ManagerStatefulSetBuilder {
	b.imagePullPolicy = policy
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

// WithImagePullSecrets sets the image pull secrets
func (b *ManagerStatefulSetBuilder) WithImagePullSecrets(secrets []corev1.LocalObjectReference) *ManagerStatefulSetBuilder {
	b.imagePullSecrets = secrets
	return b
}

// WithTopologySpreadConstraints sets the topology spread constraints
func (b *ManagerStatefulSetBuilder) WithTopologySpreadConstraints(constraints []corev1.TopologySpreadConstraint) *ManagerStatefulSetBuilder {
	b.topologySpreadConstraints = constraints
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
func (b *ManagerStatefulSetBuilder) WithCluster(cluster *wazuhv1.WazuhCluster) *ManagerStatefulSetBuilder {
	b.cluster = cluster
	return b
}

// WithRuleConfigMaps sets the rule ConfigMaps to mount
// Each rule ConfigMap contains custom Wazuh detection rules that will be mounted
// to /var/ossec/etc/rules/{filename}.xml
func (b *ManagerStatefulSetBuilder) WithRuleConfigMaps(refs []RuleConfigMapRef) *ManagerStatefulSetBuilder {
	b.ruleConfigMaps = refs
	return b
}

// WithRuleHash sets the rule hash annotation on pods
// This triggers pod restart when rule content changes
func (b *ManagerStatefulSetBuilder) WithRuleHash(hash string) *ManagerStatefulSetBuilder {
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
func (b *ManagerStatefulSetBuilder) WithDecoderConfigMaps(refs []DecoderConfigMapRef) *ManagerStatefulSetBuilder {
	b.decoderConfigMaps = refs
	return b
}

// WithDecoderHash sets the decoder hash annotation on pods
// This triggers pod restart when decoder content changes
func (b *ManagerStatefulSetBuilder) WithDecoderHash(hash string) *ManagerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationDecoderHash] = hash
	}
	return b
}

// WithIntegrationConfigMaps sets the integration script ConfigMaps to mount
// Each ConfigMap holds a custom integration script that will be mounted executable
// to /var/ossec/integrations/<filename>
func (b *ManagerStatefulSetBuilder) WithIntegrationConfigMaps(refs []IntegrationConfigMapRef) *ManagerStatefulSetBuilder {
	b.integrationConfigMaps = refs
	return b
}

// WithIntegrationHash sets the integration hash annotation on pods
// This triggers pod restart when integration scripts or configuration change
func (b *ManagerStatefulSetBuilder) WithIntegrationHash(hash string) *ManagerStatefulSetBuilder {
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
func (b *ManagerStatefulSetBuilder) WithAgentGroupFiles(refs []AgentGroupFileRef) *ManagerStatefulSetBuilder {
	b.agentGroupFiles = refs
	return b
}

// WithAgentGroupFilesHash sets the agent group files hash annotation on pods
// This triggers pod restart when agent group file content changes
func (b *ManagerStatefulSetBuilder) WithAgentGroupFilesHash(hash string) *ManagerStatefulSetBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationAgentGroupFilesHash] = hash
	}
	return b
}

// WithExtraInitContainers sets extra init containers
func (b *ManagerStatefulSetBuilder) WithExtraInitContainers(containers []corev1.Container) *ManagerStatefulSetBuilder {
	b.extraInitContainers = containers
	return b
}

// WithExtraContainers sets extra sidecar containers
func (b *ManagerStatefulSetBuilder) WithExtraContainers(containers []corev1.Container) *ManagerStatefulSetBuilder {
	b.extraContainers = containers
	return b
}

// WithTerminationGracePeriodSeconds sets the termination grace period for pods
func (b *ManagerStatefulSetBuilder) WithTerminationGracePeriodSeconds(seconds *int64) *ManagerStatefulSetBuilder {
	b.terminationGracePeriodSeconds = seconds
	return b
}

// WithServiceAccountName sets the ServiceAccount name on the PodSpec
func (b *ManagerStatefulSetBuilder) WithServiceAccountName(name string) *ManagerStatefulSetBuilder {
	b.serviceAccountName = name
	return b
}

// WithSecurityContext sets the pod-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *ManagerStatefulSetBuilder) WithSecurityContext(sc *corev1.PodSecurityContext) *ManagerStatefulSetBuilder {
	b.securityContext = sc
	return b
}

// WithContainerSecurityContext sets the container-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *ManagerStatefulSetBuilder) WithContainerSecurityContext(sc *corev1.SecurityContext) *ManagerStatefulSetBuilder {
	b.containerSecurityContext = sc
	return b
}

// WithUpdateStrategy sets the StatefulSet update strategy type
func (b *ManagerStatefulSetBuilder) WithUpdateStrategy(strategy appsv1.StatefulSetUpdateStrategyType) *ManagerStatefulSetBuilder {
	b.updateStrategy = strategy
	return b
}

// resolveUpdateStrategy returns the configured strategy or defaults to RollingUpdate
func (b *ManagerStatefulSetBuilder) resolveUpdateStrategy() appsv1.StatefulSetUpdateStrategyType {
	if b.updateStrategy != "" {
		return b.updateStrategy
	}
	return appsv1.RollingUpdateStatefulSetStrategyType
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
	// "Always") every pod start re-chowns the whole 10Gi volume, adding minutes.
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

	// Add Prometheus exporter sidecar for master nodes if monitoring is enabled
	if b.nodeType == "master" && b.cluster != nil {
		exporterContainer := monitoring.BuildExporterSidecar(b.cluster)
		if exporterContainer != nil {
			containers = append(containers, *exporterContainer)
		}
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
	labels := constants.SelectorLabels(b.clusterName, "wazuh-manager")
	labels[constants.LabelManagerNodeType] = b.nodeType
	return labels
}

// buildVolumes builds the volume list
func (b *ManagerStatefulSetBuilder) buildVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		// ConfigMap source (read-only)
		{
			Name: constants.VolumeNameWazuhConfigSource,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.ManagerConfigName(b.clusterName, b.nodeType),
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
					SecretName: constants.ManagerCertsName(b.clusterName, b.nodeType),
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

	// Add the exporter CA volume on master nodes when API TLS verification is enabled
	if b.nodeType == "master" && b.cluster != nil {
		if caVolume := monitoring.BuildExporterCAVolume(b.cluster); caVolume != nil {
			volumes = append(volumes, *caVolume)
		}
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

	return volumes
}

// buildVolumeMounts builds the volume mount list for the main container
func (b *ManagerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
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

	return mounts
}

// buildInitContainerVolumeMounts builds the volume mount list for the init container
func (b *ManagerStatefulSetBuilder) buildInitContainerVolumeMounts() []corev1.VolumeMount {
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
		// Operator-issued cert (signed by the common CA, SAN localhost) — copied into
		// the API ssl dir below so the Wazuh API serves a CA-verifiable certificate.
		{
			Name:      constants.VolumeNameWazuhCerts,
			MountPath: "/operator-certs",
			ReadOnly:  true,
		},
	}

	return mounts
}

// buildInitContainer creates the init container that copies configs to writable volumes
func (b *ManagerStatefulSetBuilder) buildInitContainer() corev1.Container {
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
mkdir -p /var/ossec/etc/shared /var/ossec/etc/rules /var/ossec/etc/decoders
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
# Install the operator-issued Wazuh API server certificate (signed by the common CA,
# SAN includes localhost) into the PVC-backed API ssl dir, replacing the API's default
# self-signed cert. Copied (not mounted) so wazuh-apid can chown it at startup; the
# chown -R below sets ownership to wazuh. Path matches SubPathWazuhAPIConfig.
if [ -f /operator-certs/filebeat.pem ] && [ -f /operator-certs/filebeat-key.pem ]; then
    mkdir -p /wazuh-data/wazuh/api/configuration/ssl
    cp /operator-certs/filebeat.pem /wazuh-data/wazuh/api/configuration/ssl/server.crt
    cp /operator-certs/filebeat-key.pem /wazuh-data/wazuh/api/configuration/ssl/server.key
    chmod 644 /wazuh-data/wazuh/api/configuration/ssl/server.crt
    chmod 640 /wazuh-data/wazuh/api/configuration/ssl/server.key
    echo "Installed operator-managed Wazuh API server certificate"
fi
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
						Name: constants.ClusterKeyName(b.clusterName),
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

	// Add master address for workers
	if b.nodeType == "worker" {
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_MASTER_ADDRESS",
			Value: constants.ManagerMasterServiceFQDN(b.clusterName, b.namespace),
		})
	}

	// Add custom env vars
	env = append(env, b.env...)

	return env
}
