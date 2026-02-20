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

package reconciler

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestSnapshotRepositoryReconciler_buildRepositorySettings(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name         string
		repo         *wazuhv1.OpenSearchSnapshotRepository
		secret       *corev1.Secret
		wantKeys     []string
		wantErr      bool
		checkValues  map[string]any
	}{
		{
			name: "S3 repository with full settings",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "s3-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeS3,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket:               "my-bucket",
						BasePath:             "snapshots",
						Region:               "us-east-1",
						Endpoint:             "s3.amazonaws.com",
						Protocol:             "https",
						Compress:             true,
						ServerSideEncryption: true,
						StorageClass:         "standard",
						CannedACL:            "private",
						PathStyleAccess:      true,
					},
				},
			},
			wantKeys: []string{"bucket", "base_path", "region", "endpoint", "protocol", "compress", "server_side_encryption", "storage_class", "canned_acl", "path_style_access"},
			checkValues: map[string]any{
				"bucket":                 "my-bucket",
				"base_path":              "snapshots",
				"region":                 "us-east-1",
				"endpoint":               "s3.amazonaws.com",
				"compress":               true,
				"server_side_encryption": true,
				"path_style_access":      true,
			},
		},
		{
			name: "FS repository with location",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fs-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeFS,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Location: "/mnt/snapshots",
						Compress: true,
					},
				},
			},
			wantKeys: []string{"location", "compress"},
			checkValues: map[string]any{
				"location": "/mnt/snapshots",
				"compress": true,
			},
		},
		{
			name: "Azure repository",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azure-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeAzure,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Container:      "snapshots-container",
						BasePath:       "backups",
						EndpointSuffix: "core.windows.net",
					},
				},
			},
			wantKeys: []string{"container", "base_path", "endpoint_suffix"},
			checkValues: map[string]any{
				"container":       "snapshots-container",
				"base_path":       "backups",
				"endpoint_suffix": "core.windows.net",
			},
		},
		{
			name: "GCS repository",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gcs-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeGCS,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket:          "gcs-bucket",
						ApplicationName: "my-app",
					},
				},
			},
			wantKeys: []string{"bucket", "application_name"},
			checkValues: map[string]any{
				"bucket":           "gcs-bucket",
				"application_name": "my-app",
			},
		},
		{
			name: "HDFS repository",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "hdfs-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeHDFS,
					Settings: wazuhv1.SnapshotRepositorySettings{
						URI:               "hdfs://namenode:8020",
						Path:              "/opensearch/snapshots",
						SecurityPrincipal: "opensearch@REALM",
						HadoopConf: map[string]string{
							"dfs.replication": "3",
						},
					},
				},
			},
			wantKeys: []string{"uri", "path", "security.principal", "conf.dfs.replication"},
			checkValues: map[string]any{
				"uri":                    "hdfs://namenode:8020",
				"path":                   "/opensearch/snapshots",
				"security.principal":     "opensearch@REALM",
				"conf.dfs.replication":   "3",
			},
		},
		{
			name: "common settings - chunk size and bandwidth limits",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bandwidth-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeS3,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket:                 "bucket",
						ChunkSize:              "1gb",
						MaxRestoreBytesPerSec:  "40mb",
						MaxSnapshotBytesPerSec: "40mb",
						ReadOnly:               true,
					},
				},
			},
			wantKeys: []string{"bucket", "chunk_size", "max_restore_bytes_per_sec", "max_snapshot_bytes_per_sec", "readonly"},
			checkValues: map[string]any{
				"chunk_size":                 "1gb",
				"max_restore_bytes_per_sec":  "40mb",
				"max_snapshot_bytes_per_sec": "40mb",
				"readonly":                   true,
			},
		},
		{
			name: "S3 with credentials from secret (keystore bypass)",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "creds-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeS3,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket: "creds-bucket",
						CredentialsSecret: &wazuhv1.RepositoryCredentialsRef{
							Name: "s3-creds",
						},
						UseKeystore: false,
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "s3-creds",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"access-key": []byte("AKIAIOSFODNN7EXAMPLE"),
					"secret-key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				},
			},
			wantKeys: []string{"bucket", "access_key", "secret_key"},
			checkValues: map[string]any{
				"access_key": "AKIAIOSFODNN7EXAMPLE",
				"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		},
		{
			name: "Azure with credentials from secret",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azure-creds-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeAzure,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Container: "my-container",
						CredentialsSecret: &wazuhv1.RepositoryCredentialsRef{
							Name: "azure-creds",
						},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azure-creds",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"access-key": []byte("myaccount"),
					"secret-key": []byte("mykey123"),
				},
			},
			wantKeys: []string{"container", "account", "key"},
			checkValues: map[string]any{
				"account": "myaccount",
				"key":     "mykey123",
			},
		},
		{
			name: "credentials skipped when UseKeystore is true",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "keystore-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeS3,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket: "keystore-bucket",
						CredentialsSecret: &wazuhv1.RepositoryCredentialsRef{
							Name: "s3-creds",
						},
						UseKeystore: true,
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "s3-creds",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"access-key": []byte("AKIAIOSFODNN7EXAMPLE"),
					"secret-key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				},
			},
			wantKeys: []string{"bucket"},
		},
		{
			name: "client setting for non-default client",
			repo: &wazuhv1.OpenSearchSnapshotRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client-repo",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchSnapshotRepositorySpec{
					Type: constants.RepositoryTypeS3,
					Settings: wazuhv1.SnapshotRepositorySettings{
						Bucket: "client-bucket",
						Client: "secondary",
					},
				},
			},
			wantKeys: []string{"bucket", "client"},
			checkValues: map[string]any{
				"client": "secondary",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			if tt.secret != nil {
				objs = append(objs, tt.secret)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
			r := NewSnapshotRepositoryReconciler(c, scheme)

			got, err := r.buildRepositorySettings(context.Background(), tt.repo)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildRepositorySettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			for _, key := range tt.wantKeys {
				if _, ok := got[key]; !ok {
					t.Errorf("buildRepositorySettings() missing expected key %q", key)
				}
			}

			for key, wantVal := range tt.checkValues {
				gotVal, ok := got[key]
				if !ok {
					t.Errorf("buildRepositorySettings() missing key %q for value check", key)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("buildRepositorySettings() key %q = %v, want %v", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestSnapshotRepositoryReconciler_loadCredentials(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name          string
		secret        *corev1.Secret
		ref           *wazuhv1.RepositoryCredentialsRef
		wantAccessKey string
		wantSecretKey string
		wantErr       bool
	}{
		{
			name: "default keys",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "creds-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"access-key": []byte("myAccessKey"),
					"secret-key": []byte("mySecretKey"),
				},
			},
			ref: &wazuhv1.RepositoryCredentialsRef{
				Name: "creds-secret",
			},
			wantAccessKey: "myAccessKey",
			wantSecretKey: "mySecretKey",
		},
		{
			name: "custom keys",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "custom-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"aws-access-key-id":     []byte("customAccess"),
					"aws-secret-access-key": []byte("customSecret"),
				},
			},
			ref: &wazuhv1.RepositoryCredentialsRef{
				Name:         "custom-secret",
				AccessKeyKey: "aws-access-key-id",
				SecretKeyKey: "aws-secret-access-key",
			},
			wantAccessKey: "customAccess",
			wantSecretKey: "customSecret",
		},
		{
			name:   "missing secret",
			secret: nil,
			ref: &wazuhv1.RepositoryCredentialsRef{
				Name: "nonexistent-secret",
			},
			wantErr: true,
		},
		{
			name: "missing access key in secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "partial-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"secret-key": []byte("onlySecretKey"),
				},
			},
			ref: &wazuhv1.RepositoryCredentialsRef{
				Name: "partial-secret",
			},
			wantErr: true,
		},
		{
			name: "missing secret key in secret",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "partial-secret-2",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"access-key": []byte("onlyAccessKey"),
				},
			},
			ref: &wazuhv1.RepositoryCredentialsRef{
				Name: "partial-secret-2",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			if tt.secret != nil {
				objs = append(objs, tt.secret)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
			r := NewSnapshotRepositoryReconciler(c, scheme)

			accessKey, secretKey, err := r.loadCredentials(context.Background(), "default", tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if accessKey != tt.wantAccessKey {
					t.Errorf("loadCredentials() accessKey = %v, want %v", accessKey, tt.wantAccessKey)
				}
				if secretKey != tt.wantSecretKey {
					t.Errorf("loadCredentials() secretKey = %v, want %v", secretKey, tt.wantSecretKey)
				}
			}
		})
	}
}
