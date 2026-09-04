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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// baseStatefulSetBuilder holds the configuration common to the manager (master) and
// worker StatefulSet builders and the fluent setters shared between them. The type
// parameter T is the concrete builder pointer; each setter returns b.self (the concrete
// builder) so chaining keeps the concrete type and callers can mix shared and
// builder-specific methods in a single chain.
type baseStatefulSetBuilder[T any] struct {
	self T

	name        string
	namespace   string
	clusterName string
	version     string
	replicas    int32
	storageSize string

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

	// volumeClaims declares additional per-path PVCs carved out of the default
	// wazuh-data volume (see ManagerVolumeClaimRef).
	volumeClaims []ManagerVolumeClaimRef

	// ConfigMap-backed content mounted into the manager pods.
	ruleConfigMaps           []RuleConfigMapRef
	decoderConfigMaps        []DecoderConfigMapRef
	agentGroupFiles          []AgentGroupFileRef
	integrationConfigMaps    []IntegrationConfigMapRef
	cdbListConfigMaps        []CDBListConfigMapRef
	cdbListInitFetches       []CDBListInitFetchRef
	activeResponseConfigMaps []ActiveResponseConfigMapRef

	extraInitContainers           []corev1.Container
	extraContainers               []corev1.Container
	terminationGracePeriodSeconds *int64
	serviceAccountName            string
	imagePullPolicy               corev1.PullPolicy
	securityContext               *corev1.PodSecurityContext
	containerSecurityContext      *corev1.SecurityContext
	updateStrategy                appsv1.StatefulSetUpdateStrategyType

	// installAPICert stages the operator-issued Wazuh API server certificate in the
	// fix-permissions init container (master only; workers do not serve the API cert).
	installAPICert bool
}

// setPodAnnotation lazily initializes podAnnotations and sets key=hash when hash != "".
func (b *baseStatefulSetBuilder[T]) setPodAnnotation(key, hash string) T {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[key] = hash
	}
	return b.self
}

// WithVersion sets the Wazuh version
func (b *baseStatefulSetBuilder[T]) WithVersion(version string) T {
	b.version = version
	return b.self
}

// WithReplicas sets the number of replicas
func (b *baseStatefulSetBuilder[T]) WithReplicas(replicas int32) T {
	b.replicas = replicas
	return b.self
}

// WithStorageSize sets the storage size
func (b *baseStatefulSetBuilder[T]) WithStorageSize(size string) T {
	b.storageSize = size
	return b.self
}

// WithStorageClassName sets the storage class name
func (b *baseStatefulSetBuilder[T]) WithStorageClassName(className string) T {
	b.storageClassName = &className
	return b.self
}

// ManagerVolumeClaimRef is a per-path dedicated PVC for a manager StatefulSet, carved out
// of the default wazuh-data volume. Path is an absolute directory under /var/ossec mounted
// as the whole PVC (no subPath). StorageClass nil falls back to the builder's default class.
type ManagerVolumeClaimRef struct {
	Path         string
	Size         string
	StorageClass *string
	AccessMode   corev1.PersistentVolumeAccessMode
}

// WithVolumeClaims sets the per-path dedicated PVCs.
func (b *baseStatefulSetBuilder[T]) WithVolumeClaims(vcs []ManagerVolumeClaimRef) T {
	b.volumeClaims = vcs
	return b.self
}

// managerAPIProbeHandler returns a probe handler that verifies the Wazuh Manager
// API is actually serving HTTP, not merely accepting TCP. A wedged apid (or a
// broken wazuh-db that leaves apid accepting TCP) keeps a plain TCPSocket probe
// green while the manager no longer serves; this catches that.
//
// It deliberately treats HTTP 401 (auth required) as healthy: every real API
// endpoint needs a token, so this check does NOT depend on wazuh-db and cannot
// crash-loop the pod on database corruption. That signal is surfaced through
// metrics/conditions (wazuh_api_reachable, AgentsReporting) instead.
func managerAPIProbeHandler() corev1.ProbeHandler {
	return corev1.ProbeHandler{
		Exec: &corev1.ExecAction{
			Command: []string{"sh", "-c", fmt.Sprintf(
				`code=$(curl -sk -o /dev/null -m 3 -w '%%{http_code}' https://127.0.0.1:%d/ 2>/dev/null); [ "$code" = "200" ] || [ "$code" = "401" ]`,
				constants.PortManagerAPI)},
		},
	}
}

// WithResources sets the resource requirements
func (b *baseStatefulSetBuilder[T]) WithResources(resources *corev1.ResourceRequirements) T {
	b.resources = resources
	return b.self
}

// WithImage sets the container image
func (b *baseStatefulSetBuilder[T]) WithImage(image string) T {
	b.image = image
	return b.self
}

// WithImagePullPolicy sets the image pull policy for the main container
func (b *baseStatefulSetBuilder[T]) WithImagePullPolicy(policy corev1.PullPolicy) T {
	b.imagePullPolicy = policy
	return b.self
}

// WithNodeSelector sets the node selector
func (b *baseStatefulSetBuilder[T]) WithNodeSelector(nodeSelector map[string]string) T {
	b.nodeSelector = nodeSelector
	return b.self
}

// WithTolerations sets the tolerations
func (b *baseStatefulSetBuilder[T]) WithTolerations(tolerations []corev1.Toleration) T {
	b.tolerations = tolerations
	return b.self
}

// WithAffinity sets the affinity
func (b *baseStatefulSetBuilder[T]) WithAffinity(affinity *corev1.Affinity) T {
	b.affinity = affinity
	return b.self
}

// WithImagePullSecrets sets the image pull secrets
func (b *baseStatefulSetBuilder[T]) WithImagePullSecrets(secrets []corev1.LocalObjectReference) T {
	b.imagePullSecrets = secrets
	return b.self
}

// WithTopologySpreadConstraints sets the topology spread constraints
func (b *baseStatefulSetBuilder[T]) WithTopologySpreadConstraints(constraints []corev1.TopologySpreadConstraint) T {
	b.topologySpreadConstraints = constraints
	return b.self
}

// WithLabels sets custom labels
func (b *baseStatefulSetBuilder[T]) WithLabels(labels map[string]string) T {
	maps.Copy(b.labels, labels)
	return b.self
}

// WithAnnotations sets custom annotations
func (b *baseStatefulSetBuilder[T]) WithAnnotations(annotations map[string]string) T {
	maps.Copy(b.annotations, annotations)
	return b.self
}

// WithPodAnnotations sets pod annotations
func (b *baseStatefulSetBuilder[T]) WithPodAnnotations(annotations map[string]string) T {
	b.podAnnotations = annotations
	return b.self
}

// WithEnv adds environment variables
func (b *baseStatefulSetBuilder[T]) WithEnv(env []corev1.EnvVar) T {
	b.env = env
	return b.self
}

// WithEnvFrom adds environment variable sources
func (b *baseStatefulSetBuilder[T]) WithEnvFrom(envFrom []corev1.EnvFromSource) T {
	b.envFrom = envFrom
	return b.self
}

// WithVolumes adds volumes
func (b *baseStatefulSetBuilder[T]) WithVolumes(volumes []corev1.Volume) T {
	b.volumes = volumes
	return b.self
}

// WithVolumeMounts adds volume mounts
func (b *baseStatefulSetBuilder[T]) WithVolumeMounts(mounts []corev1.VolumeMount) T {
	b.volumeMounts = mounts
	return b.self
}

// WithCertHash sets the certificate hash annotation on pods
// This triggers pod restart when certificates are renewed
func (b *baseStatefulSetBuilder[T]) WithCertHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationCertHash, hash)
}

// WithSpecHash sets the spec hash annotation on the StatefulSet
// This enables detection of CRD spec changes (version, resources, replicas, etc.)
func (b *baseStatefulSetBuilder[T]) WithSpecHash(hash string) T {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b.self
}

// WithConfigHash sets the config hash annotation on pods
// This triggers pod restart when ConfigMap content changes
func (b *baseStatefulSetBuilder[T]) WithConfigHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationConfigHash, hash)
}

// WithRuleConfigMaps sets the rule ConfigMaps to mount
// Each rule ConfigMap contains custom Wazuh detection rules mounted to
// /var/ossec/etc/rules/{filename}.xml
func (b *baseStatefulSetBuilder[T]) WithRuleConfigMaps(refs []RuleConfigMapRef) T {
	b.ruleConfigMaps = refs
	return b.self
}

// WithRuleHash sets the rule hash annotation on pods (restart on rule change)
func (b *baseStatefulSetBuilder[T]) WithRuleHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationRuleHash, hash)
}

// WithDecoderConfigMaps sets the decoder ConfigMaps to mount
// Each decoder ConfigMap contains custom Wazuh log decoders mounted to
// /var/ossec/etc/decoders/{filename}.xml
func (b *baseStatefulSetBuilder[T]) WithDecoderConfigMaps(refs []DecoderConfigMapRef) T {
	b.decoderConfigMaps = refs
	return b.self
}

// WithDecoderHash sets the decoder hash annotation on pods (restart on decoder change)
func (b *baseStatefulSetBuilder[T]) WithDecoderHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationDecoderHash, hash)
}

// WithIntegrationConfigMaps sets the integration script ConfigMaps to mount
// Each ConfigMap holds a custom integration script mounted executable to
// /var/ossec/integrations/<filename>
func (b *baseStatefulSetBuilder[T]) WithIntegrationConfigMaps(refs []IntegrationConfigMapRef) T {
	b.integrationConfigMaps = refs
	return b.self
}

// WithIntegrationHash sets the integration hash annotation on pods (restart on change)
func (b *baseStatefulSetBuilder[T]) WithIntegrationHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationIntegrationHash, hash)
}

// WithCDBListConfigMaps sets the CDB list ConfigMaps to mount
// Each ConfigMap contains a CDB list mounted to /var/ossec/etc/lists/<filename>
func (b *baseStatefulSetBuilder[T]) WithCDBListConfigMaps(refs []CDBListConfigMapRef) T {
	b.cdbListConfigMaps = refs
	return b.self
}

// WithCDBListInitFetches sets the large CDB lists delivered by the cdb-fetch init
// container. Each list is fetched from its URL and converted directly into
// /var/ossec/etc/lists/<listName> on the PVC at pod startup.
func (b *baseStatefulSetBuilder[T]) WithCDBListInitFetches(refs []CDBListInitFetchRef) T {
	b.cdbListInitFetches = refs
	return b.self
}

// WithCDBListHash sets the CDB list hash annotation on pods (restart on change)
func (b *baseStatefulSetBuilder[T]) WithCDBListHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationCDBListHash, hash)
}

// WithActiveResponseConfigMaps sets the active response script ConfigMaps to mount
// Each ConfigMap holds a custom active response script mounted executable to
// /var/ossec/active-response/bin/<filename>
func (b *baseStatefulSetBuilder[T]) WithActiveResponseConfigMaps(refs []ActiveResponseConfigMapRef) T {
	b.activeResponseConfigMaps = refs
	return b.self
}

// WithActiveResponseHash sets the active response hash annotation on pods (restart on change)
func (b *baseStatefulSetBuilder[T]) WithActiveResponseHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationActiveResponseHash, hash)
}

// WithAgentGroupFiles sets the agent group file ConfigMaps to mount
// Each ConfigMap contains files for a specific agent group mounted to
// /var/ossec/etc/shared/<groupName>/<filename>
func (b *baseStatefulSetBuilder[T]) WithAgentGroupFiles(refs []AgentGroupFileRef) T {
	b.agentGroupFiles = refs
	return b.self
}

// WithAgentGroupFilesHash sets the agent group files hash annotation on pods (restart on change)
func (b *baseStatefulSetBuilder[T]) WithAgentGroupFilesHash(hash string) T {
	return b.setPodAnnotation(constants.AnnotationAgentGroupFilesHash, hash)
}

// WithExtraInitContainers sets extra init containers
func (b *baseStatefulSetBuilder[T]) WithExtraInitContainers(containers []corev1.Container) T {
	b.extraInitContainers = containers
	return b.self
}

// WithExtraContainers sets extra sidecar containers
func (b *baseStatefulSetBuilder[T]) WithExtraContainers(containers []corev1.Container) T {
	b.extraContainers = containers
	return b.self
}

// WithTerminationGracePeriodSeconds sets the termination grace period for pods
func (b *baseStatefulSetBuilder[T]) WithTerminationGracePeriodSeconds(seconds *int64) T {
	b.terminationGracePeriodSeconds = seconds
	return b.self
}

// WithServiceAccountName sets the ServiceAccount name on the PodSpec
func (b *baseStatefulSetBuilder[T]) WithServiceAccountName(name string) T {
	b.serviceAccountName = name
	return b.self
}

// WithSecurityContext sets the pod-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *baseStatefulSetBuilder[T]) WithSecurityContext(sc *corev1.PodSecurityContext) T {
	b.securityContext = sc
	return b.self
}

// WithContainerSecurityContext sets the container-level security context override
// Non-nil fields in sc will override the corresponding defaults.
func (b *baseStatefulSetBuilder[T]) WithContainerSecurityContext(sc *corev1.SecurityContext) T {
	b.containerSecurityContext = sc
	return b.self
}

// WithUpdateStrategy sets the StatefulSet update strategy type
func (b *baseStatefulSetBuilder[T]) WithUpdateStrategy(strategy appsv1.StatefulSetUpdateStrategyType) T {
	b.updateStrategy = strategy
	return b.self
}

// resolveUpdateStrategy returns the configured strategy or defaults to RollingUpdate
func (b *baseStatefulSetBuilder[T]) resolveUpdateStrategy() appsv1.StatefulSetUpdateStrategyType {
	if b.updateStrategy != "" {
		return b.updateStrategy
	}
	return appsv1.RollingUpdateStatefulSetStrategyType
}

// configMapVolumes returns the ConfigMap-backed volumes for every kind of mounted
// content (rules, decoders, agent-group files, integration scripts, CDB lists, active
// response scripts). Shared by the master and worker builders; the order is stable so
// the rendered StatefulSet is deterministic.
func (b *baseStatefulSetBuilder[T]) configMapVolumes() []corev1.Volume {
	var volumes []corev1.Volume

	// Add rule ConfigMap volumes
	for _, ref := range b.ruleConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: boundedVolumeName("wazuh-rule", ref.Name),
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
			Name: boundedVolumeName("wazuh-decoder", ref.Name),
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
			Name: boundedVolumeName("agentgroup-files", ref.ConfigMapName),
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
	// root:wazuh 0750 - exactly what Wazuh requires for a custom integration script.
	for _, ref := range b.integrationConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: boundedVolumeName("wazuh-integration", ref.Name),
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
			Name: boundedVolumeName("wazuh-cdblist", ref.Name),
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
	// root:wazuh 0750 - exactly what Wazuh requires for a custom active response script.
	for _, ref := range b.activeResponseConfigMaps {
		volumes = append(volumes, corev1.Volume{
			Name: boundedVolumeName("wazuh-activeresponse", ref.Name),
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

// configMapMounts returns the volume mounts for every kind of ConfigMap-backed content,
// in the same order as configMapVolumes. Shared by the master and worker builders.
func (b *baseStatefulSetBuilder[T]) configMapMounts() []corev1.VolumeMount {
	var mounts []corev1.VolumeMount

	// Add rule ConfigMap mounts at /var/ossec/etc/rules/
	for _, ref := range b.ruleConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      boundedVolumeName("wazuh-rule", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/rules/%s", ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	// Add decoder ConfigMap mounts at /var/ossec/etc/decoders/
	for _, ref := range b.decoderConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      boundedVolumeName("wazuh-decoder", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/decoders/%s", ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	// Add agent group file mounts at /var/ossec/etc/shared/<groupName>/<filename>
	for _, ref := range b.agentGroupFiles {
		for _, fileName := range ref.FileNames {
			mounts = append(mounts, corev1.VolumeMount{
				Name:      boundedVolumeName("agentgroup-files", ref.ConfigMapName),
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
			Name:      boundedVolumeName("wazuh-integration", ref.Name),
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
			Name:      boundedVolumeName("wazuh-cdblist", ref.Name),
			MountPath: fmt.Sprintf("/var/ossec/etc/lists/%s", ref.FileName),
			SubPath:   ref.Key,
			ReadOnly:  true,
		})
	}

	// Add active response script mounts at /var/ossec/active-response/bin/<filename>.
	// Read-only subPath mount; DefaultMode 0750 + fsGroup give root:wazuh 0750.
	for _, ref := range b.activeResponseConfigMaps {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      boundedVolumeName("wazuh-activeresponse", ref.Name),
			MountPath: fmt.Sprintf("%s/%s", constants.PathWazuhActiveResponse, ref.FileName),
			SubPath:   ref.FileName,
			ReadOnly:  true,
		})
	}

	return mounts
}

// initScriptHead is the common busybox init-container script: it creates the PVC
// subdirectories and copies the operator-rendered config files into place. Shared by
// the master and worker builders.
const initScriptHead = `echo "Initializing PVC directories and copying configuration files..."
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
# Seed the built-in "default" agent group. /var/ossec/etc is PVC-backed, so on a fresh
# volume the default group shipped in the image is shadowed by the empty mount; without it
# wazuh-db logs "Unable to find the id of the group 'default'" and every agent stays
# permanently unassigned. Only create agent.conf when missing so existing groups (and their
# generated merged.mg) are never clobbered on restart.
mkdir -p /var/ossec/etc/shared/default
if [ ! -f /var/ossec/etc/shared/default/agent.conf ]; then
    touch /var/ossec/etc/shared/default/agent.conf
fi
chown 0:999 /var/ossec/etc/shared/default /var/ossec/etc/shared/default/agent.conf
chmod 770 /var/ossec/etc/shared/default
chmod 660 /var/ossec/etc/shared/default/agent.conf
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
ls -la /etc/filebeat/ 2>/dev/null || true`

// apiCertInstallScript installs the operator-issued Wazuh API server certificate into the
// PVC-backed API ssl dir. Master-only (workers do not stage the API cert).
const apiCertInstallScript = `# Install the operator-issued Wazuh API server certificate (signed by the common CA,
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
fi`

// initScriptTail fixes ownership of the PVC-backed data and emptyDir config.
const initScriptTail = `# Fix ownership of all PVC-backed data and emptyDir config
echo "Fixing ownership to wazuh (999:999)..."
chown -R 999:999 /wazuh-data
chown -R 999:999 /wazuh-config-mount
echo "Ownership fix complete"`

// buildInitContainer creates the busybox "fix-permissions" init container, staging the
// operator-issued API certificate on the master (installAPICert).
func (b *baseStatefulSetBuilder[T]) buildInitContainer() corev1.Container {
	certInstall := ""
	if b.installAPICert {
		certInstall = apiCertInstallScript
	}
	return buildConfigInitContainer(certInstall, b.buildInitContainerVolumeMounts())
}

// buildInitContainerVolumeMounts returns the init-container volume mounts, adding the
// operator cert dir on the master (installAPICert) so the cert install can read it.
func (b *baseStatefulSetBuilder[T]) buildInitContainerVolumeMounts() []corev1.VolumeMount {
	mounts := initBaseVolumeMounts()
	if b.installAPICert {
		mounts = append(mounts,
			// Operator-issued cert (signed by the common CA, SAN localhost) - copied into
			// the API ssl dir so the Wazuh API serves a CA-verifiable certificate.
			corev1.VolumeMount{
				Name:      constants.VolumeNameWazuhCerts,
				MountPath: "/operator-certs",
				ReadOnly:  true,
			},
		)
	}
	return mounts
}

// buildConfigInitContainer builds the busybox "fix-permissions" init container. certInstall
// is inserted between the config-copy and ownership-fix sections (empty for workers).
func buildConfigInitContainer(certInstall string, mounts []corev1.VolumeMount) corev1.Container {
	script := initScriptHead
	if certInstall != "" {
		script += "\n" + certInstall
	}
	script += "\n" + initScriptTail
	return corev1.Container{
		Name:         constants.InitContainerNamePermissions,
		Image:        constants.ImageBusyboxInit,
		Command:      []string{"/bin/sh", "-c", script},
		VolumeMounts: mounts,
	}
}

// busybox awk programs that reproduce the internal/wazuh/cdblist converters byte-for-byte
// so an init-fetched large list yields the same CDB content the operator would have baked
// into a ConfigMap. They avoid POSIX interval regex ({n}) which busybox awk lacks.
const (
	// cdbFetchAWKIPList mirrors cdblist.IPListToCDB.
	cdbFetchAWKIPList = `{ sub(/\r$/,""); if (match($0, "^[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?(/[0-9][0-9]?)?")) { tok=substr($0,RSTART,RLENGTH); s=index(tok,"/"); if(s>0){ip=substr(tok,1,s-1);mask=substr(tok,s+1)}else{ip=tok;mask=""}; if(mask!=""){keep=0; if(mask=="32")keep=4; else if(mask=="24")keep=3; else if(mask=="16")keep=2; else if(mask=="8")keep=1; if(keep==0)next; m=split(ip,o,"."); if(keep>m)next; ip=o[1]; for(i=2;i<=keep;i++)ip=ip"."o[i]; if(mask!="32")ip=ip"."} print ip":" } }`

	// cdbFetchAWKKeyList mirrors cdblist.KeyListToCDB.
	cdbFetchAWKKeyList = `{ sub(/^[ \t\r]+/,""); sub(/[ \t\r]+$/,""); if($0==""||substr($0,1,1)=="#")next; if(index($0,":")==0)$0=$0":"; print }`

	// cdbFetchAWKCDB mirrors cdblist.Normalize (the "cdb"/default format).
	cdbFetchAWKCDB = `{ sub(/^[ \t\r]+/,""); sub(/[ \t\r]+$/,""); if($0!="")print }`
)

// cdbFetchAWKProgram returns the busybox awk converter for a CDB list format.
func cdbFetchAWKProgram(format string) string {
	switch format {
	case "iplist":
		return cdbFetchAWKIPList
	case "keylist":
		return cdbFetchAWKKeyList
	default:
		return cdbFetchAWKCDB
	}
}

// shellSingleQuote wraps s in single quotes safe for POSIX sh, escaping embedded quotes.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildCDBFetchInitContainer builds the busybox "cdb-fetch" init container that downloads
// each large CDB list from its URL and converts it directly into the PVC-backed
// /var/ossec/etc/lists/<listName>. The second return value is false when there are no
// init-fetch lists (so the caller omits the container). Refs are sorted by ListName for a
// deterministic script (stable pod hash). A failed fetch leaves any existing file intact.
func (b *baseStatefulSetBuilder[T]) buildCDBFetchInitContainer() (corev1.Container, bool) {
	if len(b.cdbListInitFetches) == 0 {
		return corev1.Container{}, false
	}

	refs := make([]CDBListInitFetchRef, len(b.cdbListInitFetches))
	copy(refs, b.cdbListInitFetches)
	sort.Slice(refs, func(i, j int) bool { return refs[i].ListName < refs[j].ListName })

	var sb strings.Builder
	sb.WriteString("set -u\n")
	sb.WriteString("echo 'cdb-fetch: fetching large CDB lists...' >&2\n")
	for _, ref := range refs {
		dest := "/var/ossec/etc/lists/" + ref.ListName
		raw := dest + ".raw"
		tmp := dest + ".tmp"
		qDest := shellSingleQuote(dest)
		qRaw := shellSingleQuote(raw)
		qTmp := shellSingleQuote(tmp)
		qURL := shellSingleQuote(ref.URL)
		insecure := ""
		if ref.Insecure {
			insecure = "--no-check-certificate "
		}
		awkProg := cdbFetchAWKProgram(ref.Format)
		skip := ref.SkipLines + 1

		fmt.Fprintf(&sb, "mkdir -p \"$(dirname %s)\"\n", qDest)
		// Fetch the raw body first; only convert and publish on a successful download so a
		// failed fetch never clobbers a previously written file with empty content.
		fmt.Fprintf(&sb, "if wget -q %s-O %s %s; then\n", insecure, qRaw, qURL)
		fmt.Fprintf(&sb, "  tail -n +%d %s | awk '%s' > %s && mv %s %s\n", skip, qRaw, awkProg, qTmp, qTmp, qDest)
		fmt.Fprintf(&sb, "  rm -f %s\n", qRaw)
		fmt.Fprintf(&sb, "  printf 'cdb-fetch: wrote %%s\\n' %s >&2\n", qDest)
		sb.WriteString("else\n")
		fmt.Fprintf(&sb, "  rm -f %s\n", qRaw)
		fmt.Fprintf(&sb, "  printf 'cdb-fetch: failed to fetch %%s, keeping existing file\\n' %s >&2\n", qURL)
		sb.WriteString("fi\n")
	}

	return corev1.Container{
		Name:    constants.InitContainerNameCDBFetch,
		Image:   constants.ImageBusyboxInit,
		Command: []string{"/bin/sh", "-c", sb.String()},
		VolumeMounts: []corev1.VolumeMount{
			// PVC-backed /var/ossec/etc (writable) so the list files land under etc/lists
			// and are chowned to 999 by the following fix-ownership init container.
			{
				Name:      constants.VolumeNameWazuhData,
				MountPath: constants.PathWazuhConfig,
				SubPath:   constants.SubPathWazuhEtc,
			},
		},
	}, true
}

// wazuhDataBaseMounts returns the main-container volume mounts common to the master and
// worker: the PVC subPath mounts plus the writable ossec.conf and certificate dirs.
func wazuhDataBaseMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
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
}

// initBaseVolumeMounts returns the init-container volume mounts common to the master and
// worker. The master additionally mounts the operator cert dir (see manager buildInitContainerVolumeMounts).
func initBaseVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
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
}

// buildSeedAPIConfigInitContainer seeds the default Wazuh API configuration
// (api.yaml, the security/ RBAC directory, and ssl/) into the PVC.
//
// /var/ossec/api/configuration is a PVC subPath mount, so a fresh PVC arrives empty and
// hides the image defaults. The Wazuh entrypoint (0-wazuh-init: mount_permanent_data)
// only seeds this directory when it is empty; the fix-permissions init container then
// stages the operator API certificate into ssl/, which makes the directory non-empty and
// causes the entrypoint to SKIP its seed. The result is a missing security/ directory, so
// wazuh-apid fails to create its RBAC database with "unable to open database file".
//
// This init container runs first and restores any missing defaults from the image's
// permanent-data backup using a no-clobber copy: it seeds a fresh PVC in full AND repairs
// a cluster that a pre-fix operator left without security/ - all without ever overwriting
// existing data or the operator-managed API cert in ssl/. A final mkdir guarantees the
// RBAC directory even if the image backup is absent. Shared by the master and worker
// builders (both mount api/configuration as a PVC subPath and run wazuh-apid).
func buildSeedAPIConfigInitContainer(image string) corev1.Container {
	return corev1.Container{
		Name:  constants.InitContainerNameSeedAPIConfig,
		Image: image,
		Command: []string{
			"/bin/bash",
			"-c",
			`set -e
DEST=/wazuh-data/wazuh/api/configuration
BACKUP=/var/ossec/data_tmp/permanent/var/ossec/api/configuration
mkdir -p "$DEST"
if [ -d "$BACKUP" ]; then
  # No-clobber: copy only files missing from the PVC. Seeds a fresh PVC fully and
  # repairs a broken one (missing security/) without touching existing data or the
  # operator API cert in ssl/.
  cp -an "$BACKUP/." "$DEST/"
  echo "Ensured API configuration defaults from image backup"
else
  echo "WARNING: image backup $BACKUP not found; ensuring security/ and ssl/ exist"
  mkdir -p "$DEST/ssl"
fi
# Guarantee the RBAC directory exists (wazuh-apid creates security/rbac.db inside it).
mkdir -p "$DEST/security"
chown -R 999:999 "$DEST"`,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: constants.VolumeNameWazuhData, MountPath: "/wazuh-data"},
		},
	}
}

// boundedVolumeName builds "<prefix>-<key>" as a Kubernetes volume name, capped at the
// 63-char DNS-1123 limit. When the concatenation is too long (e.g. a long cluster name plus
// a long active-response/agent-group name) it truncates the key and appends a short hash of
// the full key so distinct keys keep distinct, stable names. The same (prefix,key) always
// yields the same name, so a Volume and its VolumeMount stay in sync.
func boundedVolumeName(prefix, key string) string {
	name := prefix + "-" + key
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(key))
	suffix := "-" + hex.EncodeToString(sum[:])[:8] // 9 chars, alphanumeric end
	budget := max(63-len(prefix)-1-len(suffix), 1)
	trimmed := key
	if len(trimmed) > budget {
		trimmed = strings.TrimRight(trimmed[:budget], "-")
	}
	return prefix + "-" + trimmed + suffix
}

// SplitVolumeName returns the deterministic VolumeClaimTemplate/volume name for a split
// path, e.g. /var/ossec/queue/db -> "wazuh-data-queue-db". Lowercase DNS-1123.
func SplitVolumeName(path string) string {
	rel := strings.ToLower(strings.TrimPrefix(path, constants.PathWazuhBase+"/"))
	var sb strings.Builder
	prevDash := false
	for _, r := range rel {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			sb.WriteByte('-')
			prevDash = true
		}
	}
	slug := strings.Trim(sb.String(), "-")
	if slug == "" {
		slug = "vol"
	}
	return constants.VolumeNameWazuhData + "-" + slug
}

// oldSubPathForPath maps a declared path to the subPath under wazuh-data where its data
// currently lives, so the migration init container knows the source. It uses the base-mount
// table (closest ancestor subPath mount), else the wazuh/<relative> convention.
func oldSubPathForPath(path string) string {
	bestMount, bestSub := "", ""
	for _, m := range wazuhDataBaseMounts() {
		if m.Name != constants.VolumeNameWazuhData || m.SubPath == "" {
			continue
		}
		if path == m.MountPath || strings.HasPrefix(path, m.MountPath+"/") {
			if len(m.MountPath) > len(bestMount) {
				bestMount, bestSub = m.MountPath, m.SubPath
			}
		}
	}
	if bestMount != "" {
		return bestSub + strings.TrimPrefix(path, bestMount) // e.g. wazuh/queue + /db
	}
	return "wazuh/" + strings.TrimPrefix(path, constants.PathWazuhBase+"/")
}

// sortedVolumeClaims returns a copy of the volume claims sorted by path for deterministic
// output (stable VCT order and script, hence stable pod-spec hash).
func sortedVolumeClaims(vcs []ManagerVolumeClaimRef) []ManagerVolumeClaimRef {
	out := make([]ManagerVolumeClaimRef, len(vcs))
	copy(out, vcs)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// buildManagerVolumeClaimTemplates returns the default wazuh-data VCT plus one VCT per
// declared split path. selectorLabels MUST be applied to every VCT so the volume-expansion
// reconciler's label selector matches all of them.
func (b *baseStatefulSetBuilder[T]) buildManagerVolumeClaimTemplates(selectorLabels map[string]string) []corev1.PersistentVolumeClaim {
	vcts := []corev1.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{Name: constants.VolumeNameWazuhData, Labels: selectorLabels},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				StorageClassName: b.storageClassName,
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(b.storageSize)},
				},
			},
		},
	}
	for _, vc := range sortedVolumeClaims(b.volumeClaims) {
		accessMode := vc.AccessMode
		if accessMode == "" {
			accessMode = corev1.ReadWriteOnce
		}
		sc := vc.StorageClass
		if sc == nil {
			sc = b.storageClassName
		}
		vcts = append(vcts, corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:        SplitVolumeName(vc.Path),
				Labels:      selectorLabels,
				Annotations: map[string]string{constants.AnnotationVolumeSubPath: oldSubPathForPath(vc.Path)},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes:      []corev1.PersistentVolumeAccessMode{accessMode},
				StorageClassName: sc,
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(vc.Size)},
				},
			},
		})
	}
	return vcts
}

// applyVolumeClaimMounts rewrites the wazuh-data subPath mounts against the declared split
// paths: an exact-match base path has its subPath mount replaced by the dedicated PVC (no
// subPath); a nested/independent path gets an appended dedicated mount. Appended mounts are
// ordered by path length ascending so a parent mount always precedes its child.
func (b *baseStatefulSetBuilder[T]) applyVolumeClaimMounts(base []corev1.VolumeMount) []corev1.VolumeMount {
	if len(b.volumeClaims) == 0 {
		return base
	}
	dedicated := make(map[string]string, len(b.volumeClaims))
	for _, vc := range b.volumeClaims {
		dedicated[vc.Path] = SplitVolumeName(vc.Path)
	}
	out := make([]corev1.VolumeMount, 0, len(base)+len(b.volumeClaims))
	replaced := make(map[string]bool)
	for _, m := range base {
		if m.Name == constants.VolumeNameWazuhData {
			if vol, ok := dedicated[m.MountPath]; ok {
				out = append(out, corev1.VolumeMount{Name: vol, MountPath: m.MountPath})
				replaced[m.MountPath] = true
				continue
			}
		}
		out = append(out, m)
	}
	var pending []ManagerVolumeClaimRef
	for _, vc := range b.volumeClaims {
		if !replaced[vc.Path] {
			pending = append(pending, vc)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return len(pending[i].Path) < len(pending[j].Path) })
	for _, vc := range pending {
		out = append(out, corev1.VolumeMount{Name: SplitVolumeName(vc.Path), MountPath: vc.Path})
	}
	return out
}

// buildMigrationInitContainer copies existing data from the old wazuh-data subdirectories
// into freshly-introduced split PVCs, exactly once (idempotent via a .migrated marker and an
// emptiness guard). The source in wazuh-data is never deleted. Returns false when no split
// volume is declared.
func (b *baseStatefulSetBuilder[T]) buildMigrationInitContainer() (corev1.Container, bool) {
	if len(b.volumeClaims) == 0 {
		return corev1.Container{}, false
	}
	mounts := []corev1.VolumeMount{{Name: constants.VolumeNameWazuhData, MountPath: "/wazuh-data"}}
	var sb strings.Builder
	sb.WriteString("set -eu\n")
	for _, vc := range sortedVolumeClaims(b.volumeClaims) {
		vol := SplitVolumeName(vc.Path)
		src := "/wazuh-data/" + oldSubPathForPath(vc.Path)
		dst := "/migrate/" + vol
		mounts = append(mounts, corev1.VolumeMount{Name: vol, MountPath: dst})
		fmt.Fprintf(&sb, `
DST=%q; SRC=%q
if [ ! -f "$DST/.migrated" ]; then
  if [ -d "$SRC" ] && [ -z "$(ls -A "$DST" 2>/dev/null)" ]; then
    echo "migrate-data: copying $SRC -> $DST"
    cp -a "$SRC/." "$DST/" 2>/dev/null || true
  fi
  chown -R 999:999 "$DST" || true
  touch "$DST/.migrated"
fi
`, dst, src)
	}
	return corev1.Container{
		Name:         constants.InitContainerNameMigrateData,
		Image:        b.image,
		Command:      []string{"/bin/sh", "-c", sb.String()},
		VolumeMounts: mounts,
	}, true
}
