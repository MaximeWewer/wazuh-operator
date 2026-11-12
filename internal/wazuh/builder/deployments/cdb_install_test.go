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
	script = strings.ReplaceAll(script, constants.PathWazuhContentSources, filepath.Join(root, "src"))
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
	if !strings.Contains(s, "cp '/content-src/wazuh-cdblist-cm-cdb/ip' '/var/ossec/etc/lists/ioc/ip.tmp'") {
		t.Errorf("fix-permissions does not install the list:\n%s", s)
	}
	if !slices.Contains(mounts, "/content-src/wazuh-cdblist-cm-cdb") {
		t.Errorf("fix-permissions does not mount the list ConfigMap: %v", mounts)
	}
	plain := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
	if s, _ := initScript(plain); strings.Contains(s, "/content-src/") {
		t.Errorf("init script copies content for a cluster without CDB lists:\n%s", s)
	}
}

// TestInitRemovesEmptyRulesetFiles runs the init script's cleanup of the empty rule and
// decoder files kubelet leaves as subPath mount points: analysisd stops on an empty
// ruleset file, so a removed WazuhDecoder would keep every manager down.
func TestInitRemovesEmptyRulesetFiles(t *testing.T) {
	var cleanup string
	for line := range strings.SplitSeq(initScriptHead, "\n") {
		if strings.HasPrefix(line, "find /var/ossec/etc/rules /var/ossec/etc/decoders") {
			cleanup = line
		}
	}
	if cleanup == "" {
		t.Fatal("init script does not remove the empty ruleset files")
	}
	root := t.TempDir()
	files := map[string]string{
		"etc/decoders/removed.xml":       "",
		"etc/decoders/local_decoder.xml": "<decoder/>",
		"etc/rules/removed.xml":          "",
		"etc/rules/local_rules.xml":      "<group/>",
		"etc/rules/notes.txt":            "",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.ReplaceAll(cleanup, "/var/ossec", root)
	if out, err := exec.CommandContext(t.Context(), "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("cleanup failed: %v\n%s", err, out)
	}
	for rel := range files {
		_, err := os.Stat(filepath.Join(root, rel))
		wantGone := strings.HasSuffix(rel, "removed.xml")
		if gone := os.IsNotExist(err); gone != wantGone {
			t.Errorf("%s removed = %v, want %v", rel, gone, wantGone)
		}
	}
}

// TestContentInstalledByInitContainer asserts rules and decoders, like CDB lists, are copied
// by the fix-permissions init container from their ConfigMaps and never mounted in the
// manager container: a subPath mount cannot be updated through the Wazuh API and leaves an
// empty file behind when it is removed.
func TestContentInstalledByInitContainer(t *testing.T) {
	for role, sts := range map[string]*appsv1.StatefulSet{
		"master": NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithRuleConfigMaps([]RuleConfigMapRef{{Name: "cm-rule", FileName: "r.xml"}}).
			WithDecoderConfigMaps([]DecoderConfigMapRef{{Name: "cm-dec", FileName: "d.xml"}}).Build(),
		"worker": NewWorkerStatefulSetBuilder("cluster", "ns").
			WithRuleConfigMaps([]RuleConfigMapRef{{Name: "cm-rule", FileName: "r.xml"}}).
			WithDecoderConfigMaps([]DecoderConfigMapRef{{Name: "cm-dec", FileName: "d.xml"}}).Build(),
	} {
		for _, m := range sts.Spec.Template.Spec.Containers[0].VolumeMounts {
			if m.Name == "wazuh-rule-cm-rule" || m.Name == "wazuh-decoder-cm-dec" {
				t.Errorf("%s: %s mounted in the manager container at %s", role, m.Name, m.MountPath)
			}
		}
		c, idx := findInit(sts, constants.InitContainerNamePermissions)
		if idx < 0 {
			t.Fatalf("%s: fix-permissions not rendered", role)
		}
		script := c.Command[len(c.Command)-1]
		for _, want := range []string{
			"cp '/content-src/wazuh-rule-cm-rule/r.xml' '/var/ossec/etc/rules/r.xml.tmp'",
			"cp '/content-src/wazuh-decoder-cm-dec/d.xml' '/var/ossec/etc/decoders/d.xml.tmp'",
			"'/var/ossec/etc/.operator-rules'",
			"'/var/ossec/etc/.operator-decoders'",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("%s: fix-permissions script missing %q", role, want)
			}
		}
		var mounts []string
		for _, m := range c.VolumeMounts {
			mounts = append(mounts, m.MountPath)
		}
		for _, want := range []string{"/content-src/wazuh-rule-cm-rule", "/content-src/wazuh-decoder-cm-dec"} {
			if !slices.Contains(mounts, want) {
				t.Errorf("%s: fix-permissions does not mount %s: %v", role, want, mounts)
			}
		}
	}
}

// TestContentInstallScriptEmptySet asserts the files an earlier start installed are deleted
// once the last one of the set is removed, as for any other removed file.
func TestContentInstallScriptEmptySet(t *testing.T) {
	root := t.TempDir()
	set := contentFileSet{what: "decoders", dir: filepath.Join(root, "decoders"), manifest: filepath.Join(root, ".operator-decoders")}
	for rel, content := range map[string]string{"decoders/gone.xml": "<decoder/>", "decoders/local_decoder.xml": "<decoder/>", ".operator-decoders": "gone.xml\n"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.CommandContext(t.Context(), "sh", "-c", contentInstallScript(set)).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	for rel, wantGone := range map[string]bool{"decoders/gone.xml": true, "decoders/local_decoder.xml": false, ".operator-decoders": true} {
		_, err := os.Stat(filepath.Join(root, rel))
		if os.IsNotExist(err) != wantGone {
			t.Errorf("%s removed = %v, want %v", rel, os.IsNotExist(err), wantGone)
		}
	}
}
