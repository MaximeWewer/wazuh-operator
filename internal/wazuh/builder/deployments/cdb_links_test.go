package deployments

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestCDBListLinkScript runs the generated link script against a fake /var/ossec: each list
// resolves to its ConfigMap directory, the empty file a former subPath mount left is
// replaced, links to removed lists are dropped and other files are kept.
func TestCDBListLinkScript(t *testing.T) {
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
	sources := strings.TrimPrefix(constants.PathWazuhCDBListSources, constants.PathWazuhBase+"/")
	for _, ref := range refs {
		write(filepath.Join(sources, boundedVolumeName("wazuh-cdblist", ref.Name), ref.Key), ref.Key+"-content\n")
	}
	write("etc/lists/ioc/ip", "")            // former subPath mount point
	write("etc/lists/audit-keys", "stock\n") // image default, not managed
	if err := os.Symlink("../../cdblists/wazuh-cdblist-cm-old/old", filepath.Join(root, "etc/lists/old")); err != nil {
		t.Fatal(err)
	}

	script := strings.ReplaceAll(cdbListLinkScript(refs), constants.PathWazuhBase, root)
	if out, err := exec.CommandContext(t.Context(), "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	for _, ref := range refs {
		got, err := os.ReadFile(filepath.Join(root, "etc/lists", ref.FileName))
		if err != nil || string(got) != ref.Key+"-content\n" {
			t.Errorf("etc/lists/%s = %q, %v; want the ConfigMap content", ref.FileName, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/lists/old")); !os.IsNotExist(err) {
		t.Errorf("link to a removed list kept: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "etc/lists/audit-keys")); string(got) != "stock\n" {
		t.Errorf("unmanaged list changed: %q", got)
	}
}

// TestCDBListMountsAreDirectories asserts the CDB list ConfigMaps are mounted without a
// subPath (the kubelet never updates a subPath mount) and linked by the init container,
// and that a cluster without lists keeps its init script unchanged.
func TestCDBListMountsAreDirectories(t *testing.T) {
	cdb := []CDBListConfigMapRef{{Name: "cm-cdb", FileName: "ioc/ip", Key: "ip"}}
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").WithCDBListConfigMaps(cdb).Build()
	for _, m := range sts.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "wazuh-cdblist-cm-cdb" && m.SubPath != "" {
			t.Errorf("CDB list mounted with subPath %q", m.SubPath)
		}
	}
	initScript := func(sts *appsv1.StatefulSet) string {
		c, idx := findInit(sts, constants.InitContainerNamePermissions)
		if idx < 0 {
			t.Fatal("fix-permissions init container not rendered")
		}
		return c.Command[len(c.Command)-1]
	}
	if s := initScript(sts); !strings.Contains(s, "ln -s '../../../cdblists/wazuh-cdblist-cm-cdb/ip' '/var/ossec/etc/lists/ioc/ip'") {
		t.Errorf("fix-permissions does not link the list:\n%s", s)
	}
	plain := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
	if s := initScript(plain); strings.Contains(s, "cdblists") {
		t.Errorf("init script changed for a cluster without CDB lists:\n%s", s)
	}
}
