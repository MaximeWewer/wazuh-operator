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

package plugins

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// repoPluginsMarkerFile is used to track if repository plugins have been initialized
	// Separate from monitoring's .plugins-initialized to avoid conflicts
	repoPluginsMarkerFile = ".repo-plugins-initialized"

	// keystoreVolumeName is the emptyDir volume for the keystore
	keystoreVolumeName = "opensearch-keystore"

	// secretsMountBase is the base path for mounted credential secrets
	secretsMountBase = "/mnt/secrets"
)

// RepositoryPluginInstaller manages repository plugin installation and keystore setup
type RepositoryPluginInstaller struct {
	Plugins      []wazuhv1.RepositoryPluginConfig
	IndexerImage string
}

// NewFromCluster creates a RepositoryPluginInstaller from a WazuhCluster
func NewFromCluster(cluster *wazuhv1.WazuhCluster) *RepositoryPluginInstaller {
	if cluster == nil || cluster.Spec.Indexer == nil || len(cluster.Spec.Indexer.RepositoryPlugins) == 0 {
		return nil
	}

	image := fmt.Sprintf("%s:%s", constants.DefaultWazuhIndexerImage, cluster.Spec.Version)
	if cluster.Spec.Indexer.Image != nil && cluster.Spec.Indexer.Image.Repository != "" {
		repo := cluster.Spec.Indexer.Image.Repository
		tag := cluster.Spec.Version
		if cluster.Spec.Indexer.Image.Tag != "" {
			tag = cluster.Spec.Indexer.Image.Tag
		}
		image = fmt.Sprintf("%s:%s", repo, tag)
	}

	return &RepositoryPluginInstaller{
		Plugins:      cluster.Spec.Indexer.RepositoryPlugins,
		IndexerImage: image,
	}
}

// NeedsInstallation returns true if there are plugins to install
func (i *RepositoryPluginInstaller) NeedsInstallation() bool {
	return i != nil && len(i.Plugins) > 0
}

// BuildInstallInitContainer creates an init container to install repository plugins
func (i *RepositoryPluginInstaller) BuildInstallInitContainer() corev1.Container {
	pluginNames := make([]string, len(i.Plugins))
	for idx, p := range i.Plugins {
		pluginNames[idx] = p.Name
	}

	installScript := fmt.Sprintf(`
set -e
echo "Repository plugin installer: %s"

# Check if repository plugins have already been initialized
if [ -f "/mnt/plugins/%s" ]; then
    echo "Repository plugins already initialized"
    exit 0
fi

# If monitoring plugin has already initialized base plugins, skip base copy
if [ -f "/mnt/plugins/.plugins-initialized" ]; then
    echo "Base plugins already present (monitoring plugin initialized)"
else
    echo "Copying built-in plugins to persistent volume..."
    cp -r /usr/share/wazuh-indexer/plugins/* /mnt/plugins/
fi

# Install each repository plugin
%s

# Mark repository plugins as initialized
touch /mnt/plugins/%s
echo "Repository plugins initialization completed"
`, strings.Join(pluginNames, ", "), repoPluginsMarkerFile, i.buildPluginInstallCommands(), repoPluginsMarkerFile)

	return corev1.Container{
		Name:    "install-repository-plugins",
		Image:   i.IndexerImage,
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
				Name:      constants.VolumeNameIndexerData,
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

// buildPluginInstallCommands generates the shell commands to install each plugin
func (i *RepositoryPluginInstaller) buildPluginInstallCommands() string {
	var commands []string
	for _, p := range i.Plugins {
		cmd := fmt.Sprintf(`echo "Installing %s..."
/usr/share/wazuh-indexer/bin/opensearch-plugin install -b %s || {
    echo "ERROR: Failed to install %s, continuing..."
}
# Copy the plugin to persistent volume if installed
pluginDir="/usr/share/wazuh-indexer/plugins/%s"
if [ -d "$pluginDir" ]; then
    cp -r "$pluginDir" /mnt/plugins/
    echo "%s installed successfully"
else
    echo "WARNING: %s not found after installation"
fi`, p.Name, p.Name, p.Name, p.Name, p.Name, p.Name)
		commands = append(commands, cmd)
	}
	return strings.Join(commands, "\n")
}

// BuildKeystoreInitContainer creates an init container to set up the OpenSearch keystore
// The keystore is created fresh on every restart (in emptyDir) so it picks up Secret changes
func (i *RepositoryPluginInstaller) BuildKeystoreInitContainer() corev1.Container {
	keystoreScript := i.buildKeystoreScript()

	mounts := []corev1.VolumeMount{
		{
			Name:      keystoreVolumeName,
			MountPath: "/mnt/keystore",
		},
	}

	// Add secret volume mounts for each plugin with credentials
	for _, p := range i.Plugins {
		if p.CredentialsSecret == nil {
			continue
		}
		shortName := pluginShortName(p.Name)
		mounts = append(mounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("repo-secret-%s", shortName),
			MountPath: fmt.Sprintf("%s/%s", secretsMountBase, shortName),
			ReadOnly:  true,
		})
	}

	return corev1.Container{
		Name:         "setup-keystore",
		Image:        i.IndexerImage,
		Command:      []string{"sh", "-c"},
		Args:         []string{keystoreScript},
		VolumeMounts: mounts,
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

// buildKeystoreScript generates the shell script to create the OpenSearch keystore
func (i *RepositoryPluginInstaller) buildKeystoreScript() string {
	var keystoreCommands []string

	for _, p := range i.Plugins {
		if p.CredentialsSecret == nil {
			continue
		}

		shortName := pluginShortName(p.Name)
		clientName := p.ClientName
		if clientName == "" {
			clientName = "default"
		}
		secretPath := fmt.Sprintf("%s/%s", secretsMountBase, shortName)

		switch p.Name {
		case "repository-s3":
			accessKey := getKeyOrDefault(p.CredentialsSecret.Keys, "access-key", "access-key")
			secretKey := getKeyOrDefault(p.CredentialsSecret.Keys, "secret-key", "secret-key")
			keystoreCommands = append(keystoreCommands,
				fmt.Sprintf(`echo "Adding S3 credentials for client '%s'..."
cat %s/%s | /usr/share/wazuh-indexer/bin/opensearch-keystore add -f s3.client.%s.access_key
cat %s/%s | /usr/share/wazuh-indexer/bin/opensearch-keystore add -f s3.client.%s.secret_key`,
					clientName,
					secretPath, accessKey, clientName,
					secretPath, secretKey, clientName))

		case "repository-gcs":
			credsFile := getKeyOrDefault(p.CredentialsSecret.Keys, "credentials-file", "credentials-file")
			keystoreCommands = append(keystoreCommands,
				fmt.Sprintf(`echo "Adding GCS credentials for client '%s'..."
/usr/share/wazuh-indexer/bin/opensearch-keystore add-file -f gcs.client.%s.credentials_file %s/%s`,
					clientName, clientName, secretPath, credsFile))

		case "repository-azure":
			account := getKeyOrDefault(p.CredentialsSecret.Keys, "account", "account")
			key := getKeyOrDefault(p.CredentialsSecret.Keys, "key", "key")
			keystoreCommands = append(keystoreCommands,
				fmt.Sprintf(`echo "Adding Azure credentials for client '%s'..."
cat %s/%s | /usr/share/wazuh-indexer/bin/opensearch-keystore add -f azure.client.%s.account
cat %s/%s | /usr/share/wazuh-indexer/bin/opensearch-keystore add -f azure.client.%s.key`,
					clientName,
					secretPath, account, clientName,
					secretPath, key, clientName))

		case "repository-hdfs":
			// HDFS does not use keystore credentials
			continue
		}
	}

	if len(keystoreCommands) == 0 {
		return `echo "No keystore credentials to configure"
exit 0`
	}

	return fmt.Sprintf(`set -e
echo "Setting up OpenSearch keystore..."

# Fix sysconfig reference: Wazuh indexer opensearch-env sources /etc/sysconfig/wazuh-indexer
# which doesn't exist and can't be created (non-root). Replace reference with /dev/null.
sed -i 's|/etc/sysconfig/wazuh-indexer|/dev/null|g' /usr/share/wazuh-indexer/bin/opensearch-env 2>/dev/null || true

# Point keystore tool to our emptyDir volume
export OPENSEARCH_PATH_CONF=/mnt/keystore

# Create a fresh keystore (picks up Secret changes on every restart)
/usr/share/wazuh-indexer/bin/opensearch-keystore create

%s

echo "Keystore setup completed"
ls -la /mnt/keystore/opensearch.keystore 2>/dev/null || echo "No keystore file found"
`, strings.Join(keystoreCommands, "\n"))
}

// GetSecretVolumes returns the volumes needed for credential secrets
func (i *RepositoryPluginInstaller) GetSecretVolumes() []corev1.Volume {
	var volumes []corev1.Volume
	for _, p := range i.Plugins {
		if p.CredentialsSecret == nil {
			continue
		}
		shortName := pluginShortName(p.Name)
		volumes = append(volumes, corev1.Volume{
			Name: fmt.Sprintf("repo-secret-%s", shortName),
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: p.CredentialsSecret.Name,
				},
			},
		})
	}
	return volumes
}

// GetKeystoreVolume returns the emptyDir volume for the keystore
func (i *RepositoryPluginInstaller) GetKeystoreVolume() corev1.Volume {
	return corev1.Volume{
		Name: keystoreVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				SizeLimit: func() *resource.Quantity { q := resource.MustParse("10Mi"); return &q }(),
			},
		},
	}
}

// GetPluginsVolumeMount returns the volume mount for the plugins directory in the main container.
// This mounts the PVC's plugins subpath over /usr/share/wazuh-indexer/plugins so that
// installed repository plugins are visible to the OpenSearch process.
func (i *RepositoryPluginInstaller) GetPluginsVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      constants.VolumeNameIndexerData,
		MountPath: "/usr/share/wazuh-indexer/plugins",
		SubPath:   "plugins",
	}
}

// GetKeystoreVolumeMount returns the volume mount for the keystore in the main container
func (i *RepositoryPluginInstaller) GetKeystoreVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      keystoreVolumeName,
		MountPath: "/usr/share/wazuh-indexer/config/opensearch.keystore",
		SubPath:   "opensearch.keystore",
		ReadOnly:  true,
	}
}

// pluginShortName extracts the short name from a plugin name (e.g., "repository-s3" → "s3")
func pluginShortName(name string) string {
	return strings.TrimPrefix(name, "repository-")
}

// getKeyOrDefault returns the value from the map for the given key, or the default if not found
func getKeyOrDefault(keys map[string]string, key, defaultValue string) string {
	if keys == nil {
		return defaultValue
	}
	if v, ok := keys[key]; ok {
		return v
	}
	return defaultValue
}
