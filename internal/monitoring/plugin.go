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

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// PrometheusPluginConfig holds configuration for the OpenSearch Prometheus plugin
type PrometheusPluginConfig struct {
	WazuhVersion  string
	PluginVersion string
	IndexerImage  string
}

// NewPrometheusPluginConfig creates a new PrometheusPluginConfig from the cluster spec
func NewPrometheusPluginConfig(cluster *wazuhv1alpha1.WazuhCluster) *PrometheusPluginConfig {
	if !isIndexerExporterEnabled(cluster) {
		return nil
	}

	config := &PrometheusPluginConfig{
		WazuhVersion: cluster.Spec.Version,
	}

	// Get plugin version - either from spec or auto-detect from Wazuh version
	if cluster.Spec.Monitoring.IndexerExporter.Version != "" {
		config.PluginVersion = cluster.Spec.Monitoring.IndexerExporter.Version
	} else {
		config.PluginVersion = constants.GetPrometheusExporterPluginVersionForWazuh(cluster.Spec.Version)
	}

	// Build indexer image
	config.IndexerImage = fmt.Sprintf("%s:%s", constants.DefaultWazuhIndexerImage, cluster.Spec.Version)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Image != nil && cluster.Spec.Indexer.Image.Repository != "" {
		repo := cluster.Spec.Indexer.Image.Repository
		tag := cluster.Spec.Version
		if cluster.Spec.Indexer.Image.Tag != "" {
			tag = cluster.Spec.Indexer.Image.Tag
		}
		config.IndexerImage = fmt.Sprintf("%s:%s", repo, tag)
	}

	return config
}

// BuildPluginInstallInitContainer creates an init container to install the Prometheus plugin
func (c *PrometheusPluginConfig) BuildPluginInstallInitContainer() corev1.Container {
	// Construct download URL
	downloadURL := fmt.Sprintf(
		"https://github.com/opensearch-project/opensearch-prometheus-exporter/releases/download/%s/prometheus-exporter-%s.zip",
		c.PluginVersion,
		c.PluginVersion,
	)

	// Build installation script
	installScript := fmt.Sprintf(`
set -e
# Install the OpenSearch Prometheus exporter plugin
# Wazuh Version: %s
# Plugin Version: %s

echo "Preparing plugins directory..."

# Check if plugins have already been copied to persistent volume
if [ -f "/mnt/plugins/.plugins-initialized" ]; then
    echo "Plugins already initialized in persistent volume"
    ls -la /mnt/plugins/ | head -25
    exit 0
fi

echo "Copying built-in plugins to persistent volume..."
# Copy all built-in plugins from the container image to persistent storage
cp -r /usr/share/wazuh-indexer/plugins/* /mnt/plugins/

echo "Installing Prometheus exporter plugin version %s..."
# Install the prometheus-exporter plugin to the container's plugin directory
/usr/share/wazuh-indexer/bin/opensearch-plugin install -b %s || {
    echo "ERROR: Failed to install prometheus-exporter plugin, continuing anyway..."
}

# Copy the prometheus-exporter plugin if it was installed
if [ -d "/usr/share/wazuh-indexer/plugins/prometheus-exporter" ]; then
    echo "Copying prometheus-exporter plugin to persistent volume..."
    cp -r /usr/share/wazuh-indexer/plugins/prometheus-exporter /mnt/plugins/
    echo "Plugin copied successfully"
else
    echo "WARNING: prometheus-exporter plugin not found after installation"
fi

# Mark plugins as initialized
touch /mnt/plugins/.plugins-initialized
echo "Plugins initialization completed"
ls -la /mnt/plugins/ | head -25
`, c.WazuhVersion, c.PluginVersion, c.PluginVersion, downloadURL)

	return corev1.Container{
		Name:    "install-prometheus-exporter",
		Image:   c.IndexerImage,
		Command: []string{"sh", "-c"},
		Args:    []string{installScript},
		Env: []corev1.EnvVar{
			{
				Name:  "OPENSEARCH_PATH_CONF",
				Value: "/usr/share/wazuh-indexer",
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "opensearch-data",
				MountPath: "/mnt/plugins",
				SubPath:   "plugins",
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultInitContainerCPURequest),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultInitContainerMemoryRequest),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(constants.DefaultInitContainerCPULimit),
				corev1.ResourceMemory: resource.MustParse(constants.DefaultInitContainerMemoryLimit),
			},
		},
	}
}

// GetPluginsVolumeMount returns the volume mount for the plugins directory
func (c *PrometheusPluginConfig) GetPluginsVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "opensearch-data",
		MountPath: "/usr/share/wazuh-indexer/plugins",
		SubPath:   "plugins",
	}
}

// BuildPluginInstallInitContainerFromSpec is a convenience function to build the init container
// from a WazuhCluster spec. Returns nil if exporter is not enabled.
func BuildPluginInstallInitContainerFromSpec(cluster *wazuhv1alpha1.WazuhCluster) *corev1.Container {
	config := NewPrometheusPluginConfig(cluster)
	if config == nil {
		return nil
	}
	container := config.BuildPluginInstallInitContainer()
	return &container
}

// GetPluginsVolumeMountFromSpec returns the volume mount for plugins if enabled
// Returns nil if exporter is not enabled.
func GetPluginsVolumeMountFromSpec(cluster *wazuhv1alpha1.WazuhCluster) *corev1.VolumeMount {
	config := NewPrometheusPluginConfig(cluster)
	if config == nil {
		return nil
	}
	mount := config.GetPluginsVolumeMount()
	return &mount
}
