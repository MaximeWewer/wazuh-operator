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
	"strings"
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewFromCluster_NilCluster(t *testing.T) {
	installer := NewFromCluster(nil)
	if installer != nil {
		t.Error("expected nil installer for nil cluster")
	}
}

func TestNewFromCluster_NoPlugins(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.2",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{},
		},
	}
	installer := NewFromCluster(cluster)
	if installer != nil {
		t.Error("expected nil installer when no plugins configured")
	}
}

func TestNewFromCluster_WithPlugins(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.2",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				RepositoryPlugins: []wazuhv1.RepositoryPluginConfig{
					{Name: "repository-s3"},
				},
			},
		},
	}
	installer := NewFromCluster(cluster)
	if installer == nil {
		t.Fatal("expected non-nil installer")
	}
	if !installer.NeedsInstallation() {
		t.Error("expected NeedsInstallation to return true")
	}
	if len(installer.Plugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(installer.Plugins))
	}
	if !strings.Contains(installer.IndexerImage, "4.9.2") {
		t.Errorf("expected image to contain version, got %s", installer.IndexerImage)
	}
}

func TestNewFromCluster_CustomImage(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{
		Spec: wazuhv1.WazuhClusterSpec{
			Version: "4.9.2",
			Indexer: &wazuhv1.WazuhIndexerClusterSpec{
				Image: &wazuhv1.ImageSpec{
					Repository: "my-registry/indexer",
					Tag:        "custom",
				},
				RepositoryPlugins: []wazuhv1.RepositoryPluginConfig{
					{Name: "repository-gcs"},
				},
			},
		},
	}
	installer := NewFromCluster(cluster)
	if installer == nil {
		t.Fatal("expected non-nil installer")
	}
	if installer.IndexerImage != "my-registry/indexer:custom" {
		t.Errorf("expected custom image, got %s", installer.IndexerImage)
	}
}

func TestBuildInstallInitContainer(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{Name: "repository-s3"},
			{Name: "repository-gcs"},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildInstallInitContainer()

	if container.Name != "install-repository-plugins" {
		t.Errorf("expected container name 'install-repository-plugins', got %s", container.Name)
	}
	if container.Image != "wazuh/wazuh-indexer:4.9.2" {
		t.Errorf("expected image 'wazuh/wazuh-indexer:4.9.2', got %s", container.Image)
	}
	if len(container.Args) != 1 {
		t.Fatal("expected 1 arg (script)")
	}

	script := container.Args[0]
	if !strings.Contains(script, "repository-s3") {
		t.Error("script should install repository-s3")
	}
	if !strings.Contains(script, "repository-gcs") {
		t.Error("script should install repository-gcs")
	}
	if !strings.Contains(script, repoPluginsMarkerFile) {
		t.Error("script should reference repo plugins marker file")
	}
	// Should check for monitoring marker file
	if !strings.Contains(script, ".plugins-initialized") {
		t.Error("script should check for monitoring marker file")
	}
}

func TestBuildKeystoreInitContainer_S3(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{
				Name:       "repository-s3",
				ClientName: "minio",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "s3-creds",
				},
			},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildKeystoreInitContainer()

	if container.Name != "setup-keystore" {
		t.Errorf("expected container name 'setup-keystore', got %s", container.Name)
	}

	script := container.Args[0]
	if !strings.Contains(script, "s3.client.minio.access_key") {
		t.Error("script should add S3 access_key for client 'minio'")
	}
	if !strings.Contains(script, "s3.client.minio.secret_key") {
		t.Error("script should add S3 secret_key for client 'minio'")
	}
	if !strings.Contains(script, "opensearch-keystore create") {
		t.Error("script should create keystore")
	}

	// Should have secret volume mount
	foundSecretMount := false
	for _, m := range container.VolumeMounts {
		if strings.HasPrefix(m.Name, "repo-secret-") {
			foundSecretMount = true
			if !m.ReadOnly {
				t.Error("secret mount should be read-only")
			}
		}
	}
	if !foundSecretMount {
		t.Error("expected secret volume mount")
	}
}

func TestBuildKeystoreInitContainer_GCS(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{
				Name:       "repository-gcs",
				ClientName: "default",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "gcs-creds",
				},
			},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildKeystoreInitContainer()
	script := container.Args[0]

	if !strings.Contains(script, "gcs.client.default.credentials_file") {
		t.Error("script should add GCS credentials_file")
	}
	if !strings.Contains(script, "add-file") {
		t.Error("script should use add-file for GCS")
	}
}

func TestBuildKeystoreInitContainer_Azure(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{
				Name: "repository-azure",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "azure-creds",
					Keys: map[string]string{
						"account": "my-account-key",
						"key":     "my-secret-key",
					},
				},
			},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildKeystoreInitContainer()
	script := container.Args[0]

	if !strings.Contains(script, "azure.client.default.account") {
		t.Error("script should add Azure account")
	}
	if !strings.Contains(script, "azure.client.default.key") {
		t.Error("script should add Azure key")
	}
	if !strings.Contains(script, "my-account-key") {
		t.Error("script should use custom key name for account")
	}
}

func TestBuildKeystoreInitContainer_HDFS(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{Name: "repository-hdfs"},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildKeystoreInitContainer()
	script := container.Args[0]

	// HDFS doesn't need keystore
	if strings.Contains(script, "opensearch-keystore add") {
		t.Error("HDFS should not add keystore entries")
	}
}

func TestBuildKeystoreInitContainer_NoCredentials(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{Name: "repository-gcs"}, // GCS without credentials = Workload Identity
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	container := installer.BuildKeystoreInitContainer()
	script := container.Args[0]

	if !strings.Contains(script, "No keystore credentials to configure") {
		t.Error("should output no credentials message when none configured")
	}
}

func TestGetSecretVolumes(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{
				Name: "repository-s3",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "s3-creds",
				},
			},
			{
				Name: "repository-gcs",
				// No credentials (Workload Identity)
			},
			{
				Name: "repository-azure",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "azure-creds",
				},
			},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	volumes := installer.GetSecretVolumes()
	if len(volumes) != 2 {
		t.Errorf("expected 2 secret volumes (s3 + azure), got %d", len(volumes))
	}

	// Verify volume names
	names := make(map[string]bool)
	for _, v := range volumes {
		names[v.Name] = true
	}
	if !names["repo-secret-s3"] {
		t.Error("expected repo-secret-s3 volume")
	}
	if !names["repo-secret-azure"] {
		t.Error("expected repo-secret-azure volume")
	}
}

func TestGetKeystoreVolume(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins:      []wazuhv1.RepositoryPluginConfig{{Name: "repository-s3"}},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	vol := installer.GetKeystoreVolume()
	if vol.Name != keystoreVolumeName {
		t.Errorf("expected volume name %s, got %s", keystoreVolumeName, vol.Name)
	}
	if vol.VolumeSource.EmptyDir == nil {
		t.Error("keystore volume should be emptyDir")
	}
}

func TestGetKeystoreVolumeMount(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins:      []wazuhv1.RepositoryPluginConfig{{Name: "repository-s3"}},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	mount := installer.GetKeystoreVolumeMount()
	if mount.Name != keystoreVolumeName {
		t.Errorf("expected mount name %s, got %s", keystoreVolumeName, mount.Name)
	}
	if !mount.ReadOnly {
		t.Error("keystore mount should be read-only")
	}
	if mount.SubPath != "opensearch.keystore" {
		t.Errorf("expected subPath 'opensearch.keystore', got %s", mount.SubPath)
	}
}

func TestPluginShortName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"repository-s3", "s3"},
		{"repository-gcs", "gcs"},
		{"repository-azure", "azure"},
		{"repository-hdfs", "hdfs"},
	}
	for _, tt := range tests {
		got := pluginShortName(tt.input)
		if got != tt.expected {
			t.Errorf("pluginShortName(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestGetKeyOrDefault(t *testing.T) {
	keys := map[string]string{"foo": "bar"}

	if getKeyOrDefault(keys, "foo", "default") != "bar" {
		t.Error("should return existing key value")
	}
	if getKeyOrDefault(keys, "missing", "default") != "default" {
		t.Error("should return default for missing key")
	}
	if getKeyOrDefault(nil, "foo", "default") != "default" {
		t.Error("should return default for nil map")
	}
}

func TestMultiplePlugins(t *testing.T) {
	installer := &RepositoryPluginInstaller{
		Plugins: []wazuhv1.RepositoryPluginConfig{
			{
				Name:       "repository-s3",
				ClientName: "minio",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "s3-creds",
				},
			},
			{
				Name:       "repository-gcs",
				ClientName: "prod",
				CredentialsSecret: &wazuhv1.RepositoryPluginCredentials{
					Name: "gcs-creds",
				},
			},
		},
		IndexerImage: "wazuh/wazuh-indexer:4.9.2",
	}

	// Install container should reference both plugins
	installContainer := installer.BuildInstallInitContainer()
	script := installContainer.Args[0]
	if !strings.Contains(script, "repository-s3") || !strings.Contains(script, "repository-gcs") {
		t.Error("install script should reference both plugins")
	}

	// Keystore container should have both credentials
	keystoreContainer := installer.BuildKeystoreInitContainer()
	kScript := keystoreContainer.Args[0]
	if !strings.Contains(kScript, "s3.client.minio") {
		t.Error("keystore script should have S3 client 'minio'")
	}
	if !strings.Contains(kScript, "gcs.client.prod") {
		t.Error("keystore script should have GCS client 'prod'")
	}

	// Should have 2 secret volume mounts
	secretMounts := 0
	for _, m := range keystoreContainer.VolumeMounts {
		if strings.HasPrefix(m.Name, "repo-secret-") {
			secretMounts++
		}
	}
	if secretMounts != 2 {
		t.Errorf("expected 2 secret volume mounts, got %d", secretMounts)
	}
}
