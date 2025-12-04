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

// DashboardDeploymentBuilder builds a Deployment for OpenSearch Dashboard
type DashboardDeploymentBuilder struct {
	name           string
	namespace      string
	clusterName    string
	version        string
	replicas       int32
	resources      *corev1.ResourceRequirements
	image          string
	nodeSelector   map[string]string
	tolerations    []corev1.Toleration
	affinity       *corev1.Affinity
	labels         map[string]string
	annotations    map[string]string
	podAnnotations map[string]string
	env            []corev1.EnvVar
	envFrom        []corev1.EnvFromSource
	volumes        []corev1.Volume
	volumeMounts   []corev1.VolumeMount
	indexerURL     string
	wazuhPlugin    bool
}

// NewDashboardDeploymentBuilder creates a new DashboardDeploymentBuilder
func NewDashboardDeploymentBuilder(clusterName, namespace string) *DashboardDeploymentBuilder {
	name := constants.DashboardName(clusterName)
	indexerURL := fmt.Sprintf("https://%s:%d", constants.IndexerServiceFQDN(clusterName, namespace), constants.PortIndexerREST)
	return &DashboardDeploymentBuilder{
		name:        name,
		namespace:   namespace,
		clusterName: clusterName,
		version:     constants.DefaultWazuhVersion, // Use Wazuh version as default (wazuhPlugin=true by default)
		replicas:    constants.DefaultDashboardReplicas,
		indexerURL:  indexerURL,
		wazuhPlugin: true,
		labels:      make(map[string]string),
		annotations: make(map[string]string),
	}
}

// WithVersion sets the OpenSearch Dashboard version
func (b *DashboardDeploymentBuilder) WithVersion(version string) *DashboardDeploymentBuilder {
	b.version = version
	return b
}

// WithReplicas sets the number of replicas
func (b *DashboardDeploymentBuilder) WithReplicas(replicas int32) *DashboardDeploymentBuilder {
	b.replicas = replicas
	return b
}

// WithResources sets the resource requirements
func (b *DashboardDeploymentBuilder) WithResources(resources *corev1.ResourceRequirements) *DashboardDeploymentBuilder {
	b.resources = resources
	return b
}

// WithImage sets the container image
func (b *DashboardDeploymentBuilder) WithImage(image string) *DashboardDeploymentBuilder {
	b.image = image
	return b
}

// WithNodeSelector sets the node selector
func (b *DashboardDeploymentBuilder) WithNodeSelector(nodeSelector map[string]string) *DashboardDeploymentBuilder {
	b.nodeSelector = nodeSelector
	return b
}

// WithTolerations sets the tolerations
func (b *DashboardDeploymentBuilder) WithTolerations(tolerations []corev1.Toleration) *DashboardDeploymentBuilder {
	b.tolerations = tolerations
	return b
}

// WithAffinity sets the affinity
func (b *DashboardDeploymentBuilder) WithAffinity(affinity *corev1.Affinity) *DashboardDeploymentBuilder {
	b.affinity = affinity
	return b
}

// WithLabels sets custom labels
func (b *DashboardDeploymentBuilder) WithLabels(labels map[string]string) *DashboardDeploymentBuilder {
	for k, v := range labels {
		b.labels[k] = v
	}
	return b
}

// WithAnnotations sets custom annotations
func (b *DashboardDeploymentBuilder) WithAnnotations(annotations map[string]string) *DashboardDeploymentBuilder {
	for k, v := range annotations {
		b.annotations[k] = v
	}
	return b
}

// WithPodAnnotations sets pod annotations
func (b *DashboardDeploymentBuilder) WithPodAnnotations(annotations map[string]string) *DashboardDeploymentBuilder {
	b.podAnnotations = annotations
	return b
}

// WithEnv adds environment variables
func (b *DashboardDeploymentBuilder) WithEnv(env []corev1.EnvVar) *DashboardDeploymentBuilder {
	b.env = env
	return b
}

// WithEnvFrom adds environment variable sources
func (b *DashboardDeploymentBuilder) WithEnvFrom(envFrom []corev1.EnvFromSource) *DashboardDeploymentBuilder {
	b.envFrom = envFrom
	return b
}

// WithVolumes adds volumes
func (b *DashboardDeploymentBuilder) WithVolumes(volumes []corev1.Volume) *DashboardDeploymentBuilder {
	b.volumes = volumes
	return b
}

// WithVolumeMounts adds volume mounts
func (b *DashboardDeploymentBuilder) WithVolumeMounts(mounts []corev1.VolumeMount) *DashboardDeploymentBuilder {
	b.volumeMounts = mounts
	return b
}

// WithIndexerURL sets the OpenSearch indexer URL
func (b *DashboardDeploymentBuilder) WithIndexerURL(url string) *DashboardDeploymentBuilder {
	b.indexerURL = url
	return b
}

// WithWazuhPlugin enables or disables the Wazuh plugin
func (b *DashboardDeploymentBuilder) WithWazuhPlugin(enabled bool) *DashboardDeploymentBuilder {
	b.wazuhPlugin = enabled
	return b
}

// WithCertHash sets the certificate hash annotation on pods
// This triggers pod restart when certificates are renewed
func (b *DashboardDeploymentBuilder) WithCertHash(hash string) *DashboardDeploymentBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationCertHash] = hash
	}
	return b
}

// WithSpecHash sets the spec hash annotation on the Deployment
// This enables detection of CRD spec changes (version, resources, replicas, etc.)
func (b *DashboardDeploymentBuilder) WithSpecHash(hash string) *DashboardDeploymentBuilder {
	if hash != "" {
		b.annotations[constants.AnnotationSpecHash] = hash
	}
	return b
}

// WithConfigHash sets the config hash annotation on pods
// This triggers pod restart when ConfigMap content changes
func (b *DashboardDeploymentBuilder) WithConfigHash(hash string) *DashboardDeploymentBuilder {
	if hash != "" {
		if b.podAnnotations == nil {
			b.podAnnotations = make(map[string]string)
		}
		b.podAnnotations[constants.AnnotationConfigHash] = hash
	}
	return b
}

// Build creates the Deployment
func (b *DashboardDeploymentBuilder) Build() *appsv1.Deployment {
	labels := b.buildLabels()
	selectorLabels := b.buildSelectorLabels()

	// Default image if not set
	image := b.image
	if image == "" {
		if b.wazuhPlugin {
			image = fmt.Sprintf("wazuh/wazuh-dashboard:%s", b.version)
		} else {
			image = fmt.Sprintf("opensearchproject/opensearch-dashboards:%s", b.version)
		}
	}

	// Default resources if not set
	resources := b.resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultDashboardCPURequest),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultDashboardMemoryRequest),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultDashboardCPULimit),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultDashboardMemoryLimit),
			},
		}
	}

	// Build volumes
	volumes := b.buildVolumes()

	// Build volume mounts
	volumeMounts := b.buildVolumeMounts()

	// Build env vars
	env := b.buildEnvVars()

	// Configure RollingUpdate strategy with maxUnavailable=0 for graceful rollout
	// This ensures new pods are Ready before old pods are terminated (zero downtime)
	maxUnavailable := intstr.FromInt(0)
	maxSurge := intstr.FromInt(1)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.name,
			Namespace:   b.namespace,
			Labels:      labels,
			Annotations: b.annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &b.replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
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
					InitContainers: []corev1.Container{
						{
							Name:  "config-processor",
							Image: constants.ImageBusyboxStable,
							Command: []string{
								"sh",
								"-c",
								`sed "s/\${INDEXER_USERNAME}/$INDEXER_USERNAME/g; s/\${INDEXER_PASSWORD}/$INDEXER_PASSWORD/g" /config-template/opensearch_dashboards.yml > /config-processed/opensearch_dashboards.yml`,
							},
							Env: env,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      constants.VolumeNameDashboardConfig,
									MountPath: "/config-template",
									ReadOnly:  true,
								},
								{
									Name:      constants.VolumeNameDashboardConfigProcessed,
									MountPath: "/config-processed",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "dashboard",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Resources:       *resources,
							Ports: []corev1.ContainerPort{
								{Name: constants.PortNameDashboardHTTP, ContainerPort: constants.PortDashboardHTTP, Protocol: corev1.ProtocolTCP},
							},
							Env:          env,
							EnvFrom:      b.envFrom,
							VolumeMounts: volumeMounts,
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/app/login",
										Port:   intstr.FromInt(int(constants.PortDashboardHTTP)),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
								TimeoutSeconds:      5,
								FailureThreshold:    3,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/app/login",
										Port:   intstr.FromInt(int(constants.PortDashboardHTTP)),
										Scheme: corev1.URISchemeHTTPS,
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
		},
	}

	return deployment
}

// buildLabels builds the complete label set
func (b *DashboardDeploymentBuilder) buildLabels() map[string]string {
	labels := constants.CommonLabels(b.clusterName, constants.ComponentDashboard, b.version)
	for k, v := range b.labels {
		labels[k] = v
	}
	return labels
}

// buildSelectorLabels builds the selector labels
func (b *DashboardDeploymentBuilder) buildSelectorLabels() map[string]string {
	return constants.SelectorLabels(b.clusterName, constants.ComponentDashboard)
}

// buildVolumes builds the volume list
func (b *DashboardDeploymentBuilder) buildVolumes() []corev1.Volume {
	// Default mode for script to be executable
	scriptMode := int32(0755)

	volumes := []corev1.Volume{
		{
			Name: constants.VolumeNameDashboardConfig,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.DashboardConfigName(b.clusterName),
					},
				},
			},
		},
		{
			Name: constants.VolumeNameDashboardConfigProcessed,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		// Combined certs volume that mounts dashboard certs with correct filenames
		// This creates a single directory with all needed certs for the dashboard
		{
			Name: constants.VolumeNameDashboardCerts,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							Secret: &corev1.SecretProjection{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: constants.DashboardCertsName(b.clusterName),
								},
								Items: []corev1.KeyToPath{
									{Key: constants.SecretKeyTLSCert, Path: "dashboard.pem"},
									{Key: constants.SecretKeyTLSKey, Path: "dashboard-key.pem"},
								},
							},
						},
						{
							Secret: &corev1.SecretProjection{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: constants.IndexerCertsName(b.clusterName),
								},
								Items: []corev1.KeyToPath{
									{Key: constants.SecretKeyCACert, Path: constants.SecretKeyRootCA},
								},
							},
						},
					},
				},
			},
		},
		// Custom wazuh_app_config.sh script from ConfigMap
		{
			Name: constants.VolumeNameWazuhAppConfigScript,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.DashboardConfigName(b.clusterName),
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "wazuh_app_config.sh",
							Path: "wazuh_app_config.sh",
							Mode: &scriptMode,
						},
					},
				},
			},
		},
		// Wazuh plugin config (wazuh.yml)
		{
			Name: constants.VolumeNameWazuhConfig,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.DashboardConfigName(b.clusterName),
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "wazuh.yml",
							Path: "wazuh.yml",
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
func (b *DashboardDeploymentBuilder) buildVolumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      constants.VolumeNameDashboardConfigProcessed,
			MountPath: constants.PathDashboardConfig + "/" + constants.ConfigMapKeyDashboardYml,
			SubPath:   constants.ConfigMapKeyDashboardYml,
		},
		// Mount all certs as a directory (contains root-ca.pem, dashboard.pem, dashboard-key.pem)
		{
			Name:      constants.VolumeNameDashboardCerts,
			MountPath: constants.PathDashboardConfig + "/certs",
			ReadOnly:  true,
		},
		// Mount custom wazuh_app_config.sh script at /wazuh_app_config.sh (replaces default to avoid hardcoded host ID)
		// The entrypoint.sh calls /wazuh_app_config.sh directly, not /usr/share/wazuh-dashboard/config/wazuh_app_config.sh
		{
			Name:      constants.VolumeNameWazuhAppConfigScript,
			MountPath: "/wazuh_app_config.sh",
			SubPath:   "wazuh_app_config.sh",
			ReadOnly:  true,
		},
		// Mount wazuh.yml config (pre-configured by operator)
		{
			Name:      constants.VolumeNameWazuhConfig,
			MountPath: constants.PathDashboardConfig + "/wazuh.yml",
			SubPath:   "wazuh.yml",
			ReadOnly:  true,
		},
	}

	// Add custom volume mounts
	mounts = append(mounts, b.volumeMounts...)

	return mounts
}

// buildEnvVars builds the environment variables
func (b *DashboardDeploymentBuilder) buildEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name:  "OPENSEARCH_HOSTS",
			Value: b.indexerURL,
		},
		{
			Name:  "SERVER_SSL_ENABLED",
			Value: "true",
		},
		{
			Name:  "SERVER_SSL_CERTIFICATE",
			Value: constants.PathDashboardConfig + "/certs/dashboard.pem",
		},
		{
			Name:  "SERVER_SSL_KEY",
			Value: constants.PathDashboardConfig + "/certs/dashboard-key.pem",
		},
		{
			Name:  "OPENSEARCH_SSL_CERTIFICATEAUTHORITIES",
			Value: constants.PathDashboardConfig + "/certs/root-ca.pem",
		},
		// DASHBOARD_USERNAME and DASHBOARD_PASSWORD are used by entrypoint.sh to populate keystore
		// These override the opensearch_dashboards.yml config
		{
			Name: "DASHBOARD_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.IndexerCredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAdminUsername,
				},
			},
		},
		{
			Name: "DASHBOARD_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.IndexerCredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAdminPassword,
				},
			},
		},
		// INDEXER_USERNAME and INDEXER_PASSWORD are used by init container to substitute in config
		{
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
		{
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
	}

	// Add Wazuh API configuration if plugin is enabled
	// Note: URL should NOT include port (port is specified separately in wazuh.yml)
	if b.wazuhPlugin {
		// Use manager master service FQDN but without port (port specified separately in wazuh.yml)
		wazuhAPIURL := fmt.Sprintf("https://%s", constants.ManagerMasterServiceFQDN(b.clusterName, b.namespace))
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_API_URL",
			Value: wazuhAPIURL,
		})
		// API_USERNAME and API_PASSWORD are used by wazuh_app_config.sh to configure wazuh.yml
		env = append(env, corev1.EnvVar{
			Name: "API_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.APICredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAPIUsername,
				},
			},
		})
		env = append(env, corev1.EnvVar{
			Name: "API_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: constants.APICredentialsName(b.clusterName),
					},
					Key: constants.SecretKeyAPIPassword,
				},
			},
		})
	}

	// Add custom env vars
	env = append(env, b.env...)

	return env
}
