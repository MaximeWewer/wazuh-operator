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

package monitoring

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// DefaultWazuhExporterImage is the default image for the Wazuh Prometheus exporter
	DefaultWazuhExporterImage = "kennyopennix/wazuh-exporter:latest"

	// DefaultWazuhExporterPort is the default port for the exporter
	DefaultWazuhExporterPort int32 = 9090
)

// DefaultWazuhAPIPort is the default Wazuh API port (derived from constants)
var DefaultWazuhAPIPort = fmt.Sprintf("%d", constants.PortManagerAPI)

// WazuhExporterConfig holds configuration for the Wazuh exporter sidecar
type WazuhExporterConfig struct {
	ClusterName       string
	Image             string
	Port              int32
	APIProtocol       string
	LogLevel          string
	SkipLastLogs      bool
	SkipLastAgent     bool
	SkipWazuhAPIInfo  bool
	Resources         *corev1.ResourceRequirements
	APICredentialsRef string
}

// NewWazuhExporterConfig creates a new WazuhExporterConfig from the cluster spec
func NewWazuhExporterConfig(cluster *wazuhv1alpha1.WazuhCluster) *WazuhExporterConfig {
	if !isWazuhExporterEnabled(cluster) {
		return nil
	}

	exporterSpec := cluster.Spec.Monitoring.WazuhExporter

	config := &WazuhExporterConfig{
		ClusterName:       cluster.Name,
		Image:             DefaultWazuhExporterImage,
		Port:              DefaultWazuhExporterPort,
		APIProtocol:       "https",
		LogLevel:          "INFO",
		APICredentialsRef: fmt.Sprintf("%s-api-credentials", cluster.Name),
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
	config.SkipLastLogs = exporterSpec.SkipLastLogs
	config.SkipLastAgent = exporterSpec.SkipLastRegisteredAgent
	config.SkipWazuhAPIInfo = exporterSpec.SkipWazuhAPIInfo
	config.Resources = exporterSpec.Resources

	return config
}

// BuildExporterContainer creates the Wazuh Prometheus exporter sidecar container
func (c *WazuhExporterConfig) BuildExporterContainer() corev1.Container {
	// Build environment variables
	env := c.buildEnvVars()

	// Default resources for exporter
	resources := c.Resources
	if resources == nil {
		resources = &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		}
	}

	// Build startup command that waits for Wazuh API to be available
	// This prevents the exporter from crashing before the manager is ready
	startupScript := fmt.Sprintf(`
echo "Waiting for Wazuh API to be available..."
max_attempts=60
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sk -u "$WAZUH_API_USERNAME:$WAZUH_API_PASSWORD" "https://localhost:%s/security/user/authenticate" | grep -q '"data"'; then
        echo "Wazuh API is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "Attempt $attempt/$max_attempts: Wazuh API not ready yet, waiting 5s..."
    sleep 5
done
if [ $attempt -eq $max_attempts ]; then
    echo "WARNING: Wazuh API did not become available after $max_attempts attempts, starting exporter anyway..."
fi
exec python ./main.py
`, DefaultWazuhAPIPort)

	return corev1.Container{
		Name:            "prometheus-exporter",
		Image:           c.Image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/bin/sh", "-c"},
		Args:            []string{startupScript},
		Ports: []corev1.ContainerPort{
			{
				Name:          "metrics",
				ContainerPort: c.Port,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env:       env,
		Resources: *resources,
		// Startup probe allows container to start slowly while waiting for manager
		StartupProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/metrics",
					Port:   intstr.FromInt32(c.Port),
					Scheme: corev1.URISchemeHTTP,
				},
			},
			InitialDelaySeconds: 30,
			PeriodSeconds:       10,
			TimeoutSeconds:      5,
			FailureThreshold:    30, // Allow up to 5 minutes for manager to start
		},
		// Liveness probe ensures exporter is still healthy
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/metrics",
					Port:   intstr.FromInt32(c.Port),
					Scheme: corev1.URISchemeHTTP,
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       30,
			TimeoutSeconds:      10,
			FailureThreshold:    3,
		},
	}
}

// buildEnvVars constructs the environment variables for the Wazuh exporter
func (c *WazuhExporterConfig) buildEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name:  "WAZUH_API_HOST",
			Value: "localhost",
		},
		{
			Name:  "WAZUH_API_PORT",
			Value: DefaultWazuhAPIPort,
		},
		{
			Name:  "WAZUH_API_PROTOCOL",
			Value: c.APIProtocol,
		},
		{
			Name: "WAZUH_API_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: c.APICredentialsRef,
					},
					Key: "username",
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
					Key: "password",
				},
			},
		},
		{
			Name:  "EXPORTER_PORT",
			Value: fmt.Sprintf("%d", c.Port),
		},
		{
			Name:  "EXPORTER_LOG_LEVEL",
			Value: c.LogLevel,
		},
	}

	// Add optional skip flags if enabled
	if c.SkipLastLogs {
		env = append(env, corev1.EnvVar{
			Name:  "SKIP_LAST_LOGS",
			Value: "true",
		})
	}

	if c.SkipLastAgent {
		env = append(env, corev1.EnvVar{
			Name:  "SKIP_LAST_REGISTERED_AGENT",
			Value: "true",
		})
	}

	if c.SkipWazuhAPIInfo {
		env = append(env, corev1.EnvVar{
			Name:  "SKIP_WAZUH_API_INFO",
			Value: "true",
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
func BuildExporterSidecar(cluster *wazuhv1alpha1.WazuhCluster) *corev1.Container {
	config := NewWazuhExporterConfig(cluster)
	if config == nil {
		return nil
	}
	container := config.BuildExporterContainer()
	return &container
}

// GetExporterMetricsPort returns the metrics port from the cluster spec
// Returns 0 if exporter is not enabled
func GetExporterMetricsPort(cluster *wazuhv1alpha1.WazuhCluster) int32 {
	if !isWazuhExporterEnabled(cluster) {
		return 0
	}
	if cluster.Spec.Monitoring.WazuhExporter.Port != 0 {
		return cluster.Spec.Monitoring.WazuhExporter.Port
	}
	return DefaultWazuhExporterPort
}
