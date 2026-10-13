package deployments

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestCDBListInstallScript runs the generated install script against a fake filesystem:
// each list becomes a regular file holding the ConfigMap content (replacing the empty
// file a former subPath mount left), a list removed since the previous start is deleted
// with its .cdb, and files the operator did not install are kept.
func TestCDBListInstallScript(t *testing.T) {
	refs := []CDBListConfigMapRef{
		{Name: "cm-ip", FileName: "ioc/ip", Key: "ip"},
		{Name: "cm-users", FileName: "users", Key: "users"},
	}
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, ref := range refs {
		write(filepath.Join("src", boundedVolumeName("wazuh-cdblist", ref.Name), ref.Key), ref.Key+"-content\n")
	}
	write("var/ossec/etc/lists/ioc/ip", "")                   // former subPath mount point
	write("var/ossec/etc/lists/audit-keys", "stock\n")        // image default, not managed
	write("var/ossec/etc/lists/old", "old\n")                 // installed by a previous start
	write("var/ossec/etc/lists/old.cdb", "compiled")          // its compiled list
	write("var/ossec/etc/.operator-cdblists", "old\nusers\n") // previous manifest

	script := cdbListInstallScript(refs)
	script = strings.ReplaceAll(script, constants.PathWazuhCDBListSources, filepath.Join(root, "src"))
	script = strings.ReplaceAll(script, constants.PathWazuhBase, filepath.Join(root, "var/ossec"))
	if out, err := exec.CommandContext(t.Context(), "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	lists := filepath.Join(root, "var/ossec/etc/lists")
	for _, ref := range refs {
		p := filepath.Join(lists, ref.FileName)
		got, err := os.ReadFile(p)
		if err != nil || string(got) != ref.Key+"-content\n" {
			t.Errorf("etc/lists/%s = %q, %v; want the ConfigMap content", ref.FileName, got, err)
		}
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("etc/lists/%s is not a regular file: %v", ref.FileName, err)
		}
	}
	for _, removed := range []string{"old", "old.cdb"} {
		if _, err := os.Lstat(filepath.Join(lists, removed)); !os.IsNotExist(err) {
			t.Errorf("etc/lists/%s of a removed list kept: %v", removed, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(lists, "audit-keys")); string(got) != "stock\n" {
		t.Errorf("unmanaged list changed: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "var/ossec/etc/.operator-cdblists")); string(got) != "ioc/ip\nusers\n" {
		t.Errorf("manifest = %q", got)
	}
}

// TestCDBListConfigMapsOnlyInInitContainer asserts the CDB list ConfigMaps are mounted in
// the fix-permissions init container only, which copies them into etc/lists, and that a
// cluster without lists keeps its init script unchanged.
func TestCDBListConfigMapsOnlyInInitContainer(t *testing.T) {
	cdb := []CDBListConfigMapRef{{Name: "cm-cdb", FileName: "ioc/ip", Key: "ip"}}
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").WithCDBListConfigMaps(cdb).Build()
	for _, m := range sts.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "wazuh-cdblist-cm-cdb" {
			t.Errorf("CDB list ConfigMap mounted in the manager container at %s", m.MountPath)
		}
	}
	initScript := func(sts *appsv1.StatefulSet) (string, []string) {
		c, idx := findInit(sts, constants.InitContainerNamePermissions)
		if idx < 0 {
			t.Fatal("fix-permissions init container not rendered")
		}
		var mounts []string
		for _, m := range c.VolumeMounts {
			mounts = append(mounts, m.MountPath)
		}
		return c.Command[len(c.Command)-1], mounts
	}
	s, mounts := initScript(sts)
	if !strings.Contains(s, "cp '/cdblists-src/wazuh-cdblist-cm-cdb/ip' '/var/ossec/etc/lists/ioc/ip.tmp'") {
		t.Errorf("fix-permissions does not install the list:\n%s", s)
	}
	if !slices.Contains(mounts, "/cdblists-src/wazuh-cdblist-cm-cdb") {
		t.Errorf("fix-permissions does not mount the list ConfigMap: %v", mounts)
	}
	plain := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
	if s, _ := initScript(plain); strings.Contains(s, "cdblist") {
		t.Errorf("init script changed for a cluster without CDB lists:\n%s", s)
	}
}
