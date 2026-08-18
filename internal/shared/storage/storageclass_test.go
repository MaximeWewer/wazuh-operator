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

package storage

import "testing"

func TestIsNetworkStorageProvisioner(t *testing.T) {
	tests := []struct {
		provisioner string
		want        bool
	}{
		// Network / shared-file provisioners: unsafe for SQLite.
		{"nfs.csi.k8s.io", true},
		{"cluster.local/nfs-subdir-external-provisioner", true},
		{"efs.csi.aws.com", true},
		{"file.csi.azure.com", true},
		{"smb.csi.k8s.io", true},
		{"cephfs.csi.ceph.com", true},
		{"kubernetes.io/glusterfs", true},
		{"NFS.CSI.K8S.IO", true}, // case-insensitive

		// Block / local provisioners: safe.
		{"ebs.csi.aws.com", false},
		{"disk.csi.azure.com", false},
		{"pd.csi.storage.gke.io", false},
		{"rancher.io/local-path", false},
		{"kubernetes.io/no-provisioner", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsNetworkStorageProvisioner(tt.provisioner); got != tt.want {
			t.Errorf("IsNetworkStorageProvisioner(%q) = %v, want %v", tt.provisioner, got, tt.want)
		}
	}
}
