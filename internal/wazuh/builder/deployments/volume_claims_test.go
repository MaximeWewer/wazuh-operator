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
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func vctNames(sts *appsv1.StatefulSet) []string {
	var names []string
	for _, vct := range sts.Spec.VolumeClaimTemplates {
		names = append(names, vct.Name)
	}
	return names
}

func findVCT(sts *appsv1.StatefulSet, name string) *corev1.PersistentVolumeClaim {
	for i := range sts.Spec.VolumeClaimTemplates {
		if sts.Spec.VolumeClaimTemplates[i].Name == name {
			return &sts.Spec.VolumeClaimTemplates[i]
		}
	}
	return nil
}

// mainMounts returns the main container's volume mounts.
func mainMounts(sts *appsv1.StatefulSet) []corev1.VolumeMount {
	return sts.Spec.Template.Spec.Containers[0].VolumeMounts
}

func findMount(mounts []corev1.VolumeMount, mountPath string) (corev1.VolumeMount, int) {
	for i, m := range mounts {
		if m.MountPath == mountPath {
			return m, i
		}
	}
	return corev1.VolumeMount{}, -1
}

func findInit(sts *appsv1.StatefulSet, name string) (corev1.Container, int) {
	for i, c := range sts.Spec.Template.Spec.InitContainers {
		if c.Name == name {
			return c, i
		}
	}
	return corev1.Container{}, -1
}

func TestSplitVolumeName(t *testing.T) {
	cases := map[string]string{
		"/var/ossec/queue/db": "wazuh-data-queue-db",
		"/var/ossec/logs":     "wazuh-data-logs",
		"/var/ossec/queue":    "wazuh-data-queue",
	}
	for path, want := range cases {
		if got := SplitVolumeName(path); got != want {
			t.Errorf("SplitVolumeName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestVolumeClaims_DefaultUnchanged(t *testing.T) {
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").WithVersion("4.9.0").Build()

	if names := vctNames(sts); len(names) != 1 || names[0] != constants.VolumeNameWazuhData {
		t.Fatalf("expected a single %q VCT, got %v", constants.VolumeNameWazuhData, names)
	}
	// /var/ossec/queue must still be a wazuh-data subPath mount.
	m, idx := findMount(mainMounts(sts), constants.PathWazuhQueue)
	if idx < 0 {
		t.Fatal("missing /var/ossec/queue mount")
	}
	if m.Name != constants.VolumeNameWazuhData || m.SubPath != constants.SubPathWazuhQueue {
		t.Errorf("queue mount = %+v, want wazuh-data subPath %q", m, constants.SubPathWazuhQueue)
	}
	if _, i := findInit(sts, constants.InitContainerNameMigrateData); i >= 0 {
		t.Error("migrate-data init container must be absent when no volumeClaims are declared")
	}
}

func TestVolumeClaims_SplitNested(t *testing.T) {
	block := "block"
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
		WithVolumeClaims([]ManagerVolumeClaimRef{
			{Path: "/var/ossec/queue/db", Size: "5Gi", StorageClass: &block, AccessMode: corev1.ReadWriteOnce},
		}).Build()

	// Two VCTs: default + the dedicated queue/db one.
	vct := findVCT(sts, "wazuh-data-queue-db")
	if vct == nil {
		t.Fatalf("missing dedicated VCT, got %v", vctNames(sts))
	}
	if vct.Spec.StorageClassName == nil || *vct.Spec.StorageClassName != block {
		t.Errorf("dedicated VCT storageClass = %v, want %q", vct.Spec.StorageClassName, block)
	}
	if got := vct.Spec.Resources.Requests.Storage().String(); got != "5Gi" {
		t.Errorf("dedicated VCT size = %s, want 5Gi", got)
	}

	// The dedicated mount has NO subPath and comes AFTER the parent /var/ossec/queue mount.
	mounts := mainMounts(sts)
	child, ci := findMount(mounts, "/var/ossec/queue/db")
	parent, pi := findMount(mounts, constants.PathWazuhQueue)
	if ci < 0 || pi < 0 {
		t.Fatalf("missing queue (%d) or queue/db (%d) mount", pi, ci)
	}
	if child.SubPath != "" || child.Name != "wazuh-data-queue-db" {
		t.Errorf("queue/db mount = %+v, want dedicated PVC with no subPath", child)
	}
	if !(pi < ci) {
		t.Errorf("parent /var/ossec/queue (idx %d) must precede child /var/ossec/queue/db (idx %d)", pi, ci)
	}
	_ = parent

	// migrate-data init container present, first, copies from the old wazuh-data subpath.
	mig, mi := findInit(sts, constants.InitContainerNameMigrateData)
	if mi != 0 {
		t.Fatalf("migrate-data must be the first init container, index=%d", mi)
	}
	script := strings.Join(mig.Command, " ")
	if !strings.Contains(script, "/wazuh-data/wazuh/queue/db") {
		t.Errorf("migrate script missing source /wazuh-data/wazuh/queue/db:\n%s", script)
	}
	if !strings.Contains(script, ".migrated") {
		t.Error("migrate script missing idempotency marker")
	}
}

func TestVolumeClaims_SplitExactBase(t *testing.T) {
	sts := NewWorkerStatefulSetBuilder("cluster", "ns").
		WithVolumeClaims([]ManagerVolumeClaimRef{
			{Path: constants.PathWazuhLogs, Size: "20Gi"},
		}).Build()

	m, idx := findMount(mainMounts(sts), constants.PathWazuhLogs)
	if idx < 0 {
		t.Fatal("missing /var/ossec/logs mount")
	}
	if m.SubPath != "" || m.Name != "wazuh-data-logs" {
		t.Errorf("logs mount = %+v, want dedicated PVC with no subPath (subPath replaced)", m)
	}
}

func TestBoundedVolumeName(t *testing.T) {
	// Short name: unchanged.
	if got := boundedVolumeName("wazuh-activeresponse", "firewall-drop"); got != "wazuh-activeresponse-firewall-drop" {
		t.Errorf("short name changed: %q", got)
	}
	// Long name (the prod case): must be <=63 and stay DNS-1123.
	long := boundedVolumeName("wazuh-activeresponse", "wazuh-cluster-prod-ar-block-dest-ip-activeresponse")
	if len(long) > 63 {
		t.Errorf("bounded name too long (%d): %q", len(long), long)
	}
	if strings.HasSuffix(long, "-") {
		t.Errorf("name ends with dash: %q", long)
	}
	// Deterministic + distinct keys -> distinct names.
	k1 := boundedVolumeName("agentgroup-files", "wazuh-cluster-prod-machine-admin-agentgroup-files")
	k2 := boundedVolumeName("agentgroup-files", "wazuh-cluster-prod-machine-admin-agentgroup-files")
	k3 := boundedVolumeName("agentgroup-files", "wazuh-cluster-prod-other-group-name-longlong-agentgroup-files")
	if k1 != k2 {
		t.Error("not deterministic")
	}
	if k1 == k3 || len(k3) > 63 {
		t.Errorf("collision or too long: %q vs %q", k1, k3)
	}
}
