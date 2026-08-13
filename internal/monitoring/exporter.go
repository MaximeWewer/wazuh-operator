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

package monitoring

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// Re-export from centralized constants for backward compatibility
const (
	// DefaultWazuhExporterImage is the default image for the Wazuh Prometheus exporter
	DefaultWazuhExporterImage = constants.ImageWazuhExporter

	// DefaultWazuhExporterPort is the default port for the exporter
	DefaultWazuhExporterPort = constants.PortWazuhExporter
)

// DefaultWazuhAPIPort is the default Wazuh API port (derived from constants)
var DefaultWazuhAPIPort = fmt.Sprintf("%d", constants.PortManagerAPI)

const (
	// exporterCAVolumeName is the sidecar volume holding the CA used to verify the API cert
	exporterCAVolumeName = "wazuh-exporter-ca"
	// exporterCAMountPath is where that CA is mounted in the exporter sidecar
	exporterCAMountPath = "/etc/wazuh-exporter/ca"
	// exporterCAFileName is the projected CA filename (→ WAZUH_API_CA_FILE)
	exporterCAFileName = "ca.crt"
)

// WazuhExporterConfig holds configuration for the Wazuh exporter sidecar.
// Targets github.com/MaximeWewer/wazuh-prometheus-exporter (Go binary), which is
// configured entirely through WAZUH_* environment variables.
type WazuhExporterConfig struct {
	ClusterName       string
	Image             string
	Port              int32
	APIProtocol       string
	APIVerifySSL      bool
	LogLevel          string
	CacheTTL          string
	StartupGrace      string
	Resources         *corev1.ResourceRequirements
	APICredentialsRef string
	// CASecretName/CASecretKey identify the CA bundle mounted to verify the API cert
	// (only set when APIVerifySSL is true).
	CASecretName string
	CASecretKey  string
}

// NewWazuhExporterConfig creates a new WazuhExporterConfig from the cluster spec
func NewWazuhExporterConfig(cluster *wazuhv1.WazuhCluster) *WazuhExporterConfig {
	if !isWazuhExporterEnabled(cluster) {
		return nil
	}

	exporterSpec := cluster.Spec.Monitoring.WazuhExporter

	config := &WazuhExporterConfig{
		ClusterName:       cluster.Name,
		Image:             DefaultWazuhExporterImage,
		Port:              DefaultWazuhExporterPort,
		APIProtocol:       "https",
		APIVerifySSL:      exporterSpec.APIVerifySSL,
		LogLevel:          "info",
		StartupGrace:      "60s",
		APICredentialsRef: constants.APICredentialsName(cluster.Name),
	}

	// Override with spec values if provided
	if exporterSpec.Image != "" {
		config.Image = exporterSpec.Image
	}
	if exporterSpec.Port != 0 {
		config.Port = exporterSpec.Port
	}
	if exporterSpec.APIProtocol != "" {
		config.APIProtocol = exporterSpec.APIProtocol
	}
	if exporterSpec.LogLevel != "" {
		config.LogLevel = exporterSpec.LogLevel
	}
	config.CacheTTL = exporterSpec.CacheTTL
	if exporterSpec.StartupGrace != "" {
		config.StartupGrace = exporterSpec.StartupGrace
	}
	config.Resources = exporterSpec.Resources

	// When TLS verification is enabled, resolve the CA bundle to mount. Default to the
	// cluster's common CA (manager master certs secret) since the operator issues the
	// Wazuh API cert from it; a custom APICASecretRef overrides that.
	if config.APIVerifySSL {
		if ref := exporterSpec.APICASecretRef; ref != nil && ref.Name != "" {
			config.CASecretName = ref.Name
			config.CASecretKey = ref.Key
			if config.CASecretKey == "" {
				config.CASecretKey = constants.SecretKeyCACert
			}
		} else {
			config.CASecretName = constants.ManagerCertsName(cluster.Name, "master")
			config.CASecretKey = constants.SecretKeyCACert
		}
	}

	return config
}

// BuildExporterContainer creates the Wazuh Prometheus exporter sidecar container.
// The exporter is a self-contained Go binary with its own entrypoint, so no startup
// wrapper is needed: its /ready endpoint stays 503 until the first successful
// collection, which the startup probe absorbs while the Wazuh API comes up.
func (c *WazuhExporterConfig) BuildExporterContainer() corev1.Container {
	env := c.buildEnvVars()

	// Default resources for exporter
	resources := c.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultExporterCPURequest),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultExporterMemoryRequest),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultExporterCPULimit),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultExporterMemoryLimit),
			},
		}
	}

	var volumeMounts []corev1.VolumeMount
	if c.APIVerifySSL && c.CASecretName != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      exporterCAVolumeName,
			MountPath: exporterCAMountPath,
			ReadOnly:  true,
		})
	}

	return corev1.Container{
		Name:            "prometheus-exporter",
		Image:           c.Image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: []corev1.ContainerPort{
			{
				Name:          "metrics",
				ContainerPort: c.Port,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env:          env,
		Resources:    *resources,
		VolumeMounts: volumeMounts,
		// Startup probe on /health (the exporter's own HTTP server, up in ~1s and
		// independent of the Wazuh API). It deliberately does NOT probe /ready:
		// /ready stays 503 until the first Wazuh API collection succeeds (~60-120s),
		// and gating "started" on it would keep the whole manager pod NotReady for that
		// long, stalling rolling restarts. The exporter is a best-effort sidecar and
		// must not delay the manager's readiness - it scrapes once the API is up.
		StartupProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/health",
					Port:   intstr.FromInt32(c.Port),
					Scheme: corev1.URISchemeHTTP,
				},
			},
			InitialDelaySeconds: constants.ProbeStartupInitialDelaySeconds,
			PeriodSeconds:       constants.ProbeStartupPeriodSeconds,
			TimeoutSeconds:      5,
			FailureThreshold:    constants.ProbeStartupFailureThreshold,
		},
		// Liveness: the exporter is serving (independent of the Wazuh API).
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/health",
					Port:   intstr.FromInt32(c.Port),
					Scheme: corev1.URISchemeHTTP,
				},
			},
			InitialDelaySeconds: constants.ProbeLivenessInitialDelaySeconds,
			PeriodSeconds:       constants.ProbeLivenessPeriodSeconds,
			TimeoutSeconds:      constants.ProbeTimeoutSeconds,
			FailureThreshold:    constants.ProbeLivenessFailureThreshold,
		},
		// No ReadinessProbe on purpose: the exporter must not gate the manager pod's
		// Ready condition on Wazuh API reachability. With no readiness probe the
		// container is Ready as soon as it is running, so pod readiness tracks the
		// wazuh-manager container alone.
	}
}

// buildEnvVars constructs the WAZUH_* environment variables for the exporter
func (c *WazuhExporterConfig) buildEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			// The exporter is a sidecar in the manager pod, so it reaches the API
			// directly over the IPv4 loopback. NOT "localhost" (Go resolves it to
			// the IPv6 [::1], but the Wazuh API binds 0.0.0.0 = IPv4 only -> refused)
			// and NOT the service FQDN (routing through the Service would deadlock
			// at startup: the pod only joins the Service endpoints once Ready, but
			// the exporter's own readiness gates that). apiVerifySSL defaults to
			// false for this in-pod loopback hop.
			Name:  "WAZUH_API_URL",
			Value: fmt.Sprintf("%s://127.0.0.1:%d", c.APIProtocol, constants.PortManagerAPI),
		},
		{
			Name:  "WAZUH_LISTEN_ADDRESS",
			Value: fmt.Sprintf("0.0.0.0:%d", c.Port),
		},
		{
			Name: "WAZUH_API_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: c.APICredentialsRef,
					},
					Key: constants.SecretKeyAPIUsername,
				},
			},
		},
		{
			Name: "WAZUH_API_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: c.APICredentialsRef,
					},
					Key: constants.SecretKeyAPIPassword,
				},
			},
		},
		{
			// CRD APIVerifySSL=false (default) means skip verification (self-signed certs).
			Name:  "WAZUH_API_TLS_SKIP_VERIFY",
			Value: fmt.Sprintf("%t", !c.APIVerifySSL),
		},
		{
			Name:  "WAZUH_LOG_LEVEL",
			Value: strings.ToLower(c.LogLevel),
		},
	}

	if c.CacheTTL != "" {
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_CACHE_TTL",
			Value: c.CacheTTL,
		})
	}

	// Quiet-startup window so a slow-to-boot Wazuh API logs warn (not error) until
	// the first successful collection.
	if c.StartupGrace != "" {
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_STARTUP_GRACE",
			Value: c.StartupGrace,
		})
	}

	// Point the exporter at the mounted CA bundle when verifying the API cert.
	if c.APIVerifySSL && c.CASecretName != "" {
		env = append(env, corev1.EnvVar{
			Name:  "WAZUH_API_CA_FILE",
			Value: exporterCAMountPath + "/" + exporterCAFileName,
		})
	}

	return env
}

// GetMetricsPort returns the metrics port for the exporter
func (c *WazuhExporterConfig) GetMetricsPort() int32 {
	return c.Port
}

// BuildExporterSidecar is a convenience function to build the exporter sidecar container
// from a WazuhCluster spec. Returns nil if exporter is not enabled.
func BuildExporterSidecar(cluster *wazuhv1.WazuhCluster) *corev1.Container {
	config := NewWazuhExporterConfig(cluster)
	if config == nil {
		return nil
	}
	container := config.BuildExporterContainer()
	return &container
}

// BuildExporterCAVolume returns the pod volume projecting the CA used to verify the
// Wazuh API certificate, or nil when verification is disabled / no CA is resolved.
// The caller (manager pod builder) appends it to the pod volumes alongside the sidecar.
func BuildExporterCAVolume(cluster *wazuhv1.WazuhCluster) *corev1.Volume {
	config := NewWazuhExporterConfig(cluster)
	if config == nil || !config.APIVerifySSL || config.CASecretName == "" {
		return nil
	}
	return &corev1.Volume{
		Name: exporterCAVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: config.CASecretName,
				Items: []corev1.KeyToPath{
					{Key: config.CASecretKey, Path: exporterCAFileName},
				},
			},
		},
	}
}

// GetExporterMetricsPort returns the metrics port from the cluster spec
// Returns 0 if exporter is not enabled
func GetExporterMetricsPort(cluster *wazuhv1.WazuhCluster) int32 {
	if !isWazuhExporterEnabled(cluster) {
		return 0
	}
	if cluster.Spec.Monitoring.WazuhExporter.Port != 0 {
		return cluster.Spec.Monitoring.WazuhExporter.Port
	}
	return DefaultWazuhExporterPort
}
