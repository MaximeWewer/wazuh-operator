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
	"maps"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ManagerStatefulSetBuilder builds a StatefulSet for Wazuh Manager (master or workers)
type ManagerStatefulSetBuilder struct {
	baseStatefulSetBuilder[*ManagerStatefulSetBuilder]
	nodeType string                // "master" or "worker"
	cluster  *wazuhv1.WazuhCluster // Monitoring configuration (Prometheus exporter sidecar)
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

// CDBListConfigMapRef holds information about a CDB list ConfigMap to mount
type CDBListConfigMapRef struct {
	Name     string // ConfigMap name
	FileName string // CDB list path relative to etc/lists (e.g. "blocked-ips" or "malicious-ioc/malicious-ip")
	Key      string // ConfigMap data key and mount subPath (basename of FileName)
}

// CDBListInitFetchRef describes a large CDB list (over the ConfigMap size limit) delivered
// by the cdb-fetch init container: it downloads URL and converts it (per Format, after
// dropping SkipLines header lines) directly into /var/ossec/etc/lists/<ListName> on the PVC.
type CDBListInitFetchRef struct {
	ListName  string // list path relative to etc/lists (may contain a subdir)
	URL       string // source URL to fetch at pod startup
	Format    string // "cdb" | "iplist" | "keylist"
	SkipLines int32  // header lines dropped before conversion
	Insecure  bool   // skip TLS certificate verification
}

// ActiveResponseConfigMapRef holds information about an active response script ConfigMap to mount
type ActiveResponseConfigMapRef struct {
	Name     string // ConfigMap name
	FileName string // Script filename (e.g. "firewall-drop.sh")
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
// this DefaultMode yields root:wazuh 0750 - exactly what Wazuh requires.
var integrationScriptMode = int32(0o750)

// NewManagerStatefulSetBuilder creates a new ManagerStatefulSetBuilder
func NewManagerStatefulSetBuilder(clusterName, namespace, nodeType string) *ManagerStatefulSetBuilder {
	b := &ManagerStatefulSetBuilder{nodeType: nodeType}
	b.self = b
	b.name = fmt.Sprintf("%s-manager-%s", clusterName, nodeType)
	b.namespace = namespace
	b.clusterName = clusterName
	b.version = constants.DefaultWazuhVersion
	b.replicas = 1
	b.storageSize = constants.DefaultManagerStorageSize
	b.labels = make(map[string]string)
	b.annotations = make(map[string]string)
	b.installAPICert = true // master serves the Wazuh API cert
	return b
}

// WithCluster sets the WazuhCluster reference for monitoring configuration
// This is required for adding the Prometheus exporter sidecar to master nodes
func (b *ManagerStatefulSetBuilder) WithCluster(cluster *wazuhv1.WazuhCluster) *ManagerStatefulSetBuilder {
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
	// data PVC when its root is not already the fsGroup - without this (default
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

	// Build init containers. The migrate-data container (present only when per-path PVCs
	// are declared) runs first so all later steps see already-migrated volumes.
	initContainers := []corev1.Container{}
	if mig, ok := b.buildMigrationInitContainer(); ok {
		initContainers = append(initContainers, mig)
	}
	initContainers = append(initContainers,
		buildSeedAPIConfigInitContainer(image),
		b.buildInitContainer(),
	)

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
				ProbeHandler:        managerAPIProbeHandler(),
				InitialDelaySeconds: 90,
				PeriodSeconds:       30,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler:        managerAPIProbeHandler(),
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
			VolumeClaimTemplates: b.buildManagerVolumeClaimTemplates(selectorLabels),
		},
	}

	return sts
}

// buildLabels builds the complete label set
func (b *ManagerStatefulSetBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, "wazuh-manager", b.version)
	labels[constants.LabelManagerNodeType] = b.nodeType
	maps.Copy(labels, b.labels)
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

	// Add ConfigMap-backed content volumes (rules, decoders, agent-group files,
	// integrations, CDB lists, active responses) - shared with the worker builder.
	volumes = append(volumes, b.configMapVolumes()...)

	return volumes
}

// buildVolumeMounts builds the volume mount list for the main container
func (b *ManagerStatefulSetBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := b.applyVolumeClaimMounts(wazuhDataBaseMounts())

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	// Add ConfigMap-backed content mounts (rules, decoders, agent-group files,
	// integrations, CDB lists, active responses) - shared with the worker builder.
	mounts = append(mounts, b.configMapMounts()...)

	return mounts
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
