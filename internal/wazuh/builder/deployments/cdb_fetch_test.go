package deployments

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// findInitContainer returns the named init container and whether it was found.
func findInitContainer(cs []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

// TestCDBFetchInitContainersRender asserts the cdb-download (manager image, curl with the
// config from the CDB fetch Secret) and cdb-fetch (busybox conversion) init containers are
// rendered with their volumes, ordered between fix-permissions and fix-ownership, and that
// the pod spec carries no fetch credential.
func TestCDBFetchInitContainersRender(t *testing.T) {
	fetches := []CDBListInitFetchRef{
		{ConfigKey: "list-a.curlrc", ListName: "malicious-ioc/malicious-ip", URL: "https://example.com/${KEY}/blocklist.txt", Format: "iplist", SkipLines: 3},
	}
	for role, b := range map[string]interface {
		build() []corev1.Container
		volumes() []corev1.Volume
	}{
		"master": managerFetchBuild{NewManagerStatefulSetBuilder("cluster", "ns", "master").WithCDBListInitFetches(fetches)},
		"worker": workerFetchBuild{NewWorkerStatefulSetBuilder("cluster", "ns").WithCDBListInitFetches(fetches)},
	} {
		inits := b.build()
		download, ok := findInitContainer(inits, constants.InitContainerNameCDBDownload)
		if !ok {
			t.Fatalf("%s: cdb-download init container not rendered", role)
		}
		if download.Image == constants.ImageBusyboxInit {
			t.Errorf("%s: cdb-download runs busybox, whose wget does not verify TLS", role)
		}
		dl := download.Command[2]
		for _, want := range []string{"curl -K '/cdb-fetch-config/list-a.curlrc' -o '/cdb-fetch-raw/0.raw'", "keeping existing file"} {
			if !strings.Contains(dl, want) {
				t.Errorf("%s: cdb-download script missing %q:\n%s", role, want, dl)
			}
		}
		if strings.Contains(dl, "wget") || strings.Contains(dl, "--insecure") || strings.Contains(dl, " -k ") {
			t.Errorf("%s: cdb-download script must take every option from the curl config:\n%s", role, dl)
		}

		convert, ok := findInitContainer(inits, constants.InitContainerNameCDBFetch)
		if !ok {
			t.Fatalf("%s: cdb-fetch init container not rendered", role)
		}
		if convert.Image != constants.ImageBusyboxInit {
			t.Errorf("%s: cdb-fetch image = %q, want %q (awk parity is tested with busybox)", role, convert.Image, constants.ImageBusyboxInit)
		}
		for _, want := range []string{"tail -n +4 '/cdb-fetch-raw/0.raw'", "RSTART,RLENGTH", "'/var/ossec/etc/lists/malicious-ioc/malicious-ip'"} {
			if !strings.Contains(convert.Command[2], want) {
				t.Errorf("%s: cdb-fetch script missing %q:\n%s", role, want, convert.Command[2])
			}
		}

		idx := map[string]int{}
		for i, ic := range inits {
			idx[ic.Name] = i
		}
		if idx[constants.InitContainerNamePermissions] >= idx[constants.InitContainerNameCDBDownload] ||
			idx[constants.InitContainerNameCDBDownload] >= idx[constants.InitContainerNameCDBFetch] ||
			idx[constants.InitContainerNameCDBFetch] >= idx[constants.InitContainerNameFixOwnership] {
			t.Errorf("%s: init containers out of order: %v", role, idx)
		}

		var secret *corev1.SecretVolumeSource
		for _, v := range b.volumes() {
			if v.Name == cdbFetchConfigVolume {
				secret = v.Secret
			}
		}
		if secret == nil || secret.SecretName != constants.CDBFetchSecretName("cluster") || secret.Optional == nil || !*secret.Optional {
			t.Errorf("%s: fetch config volume = %+v, want the optional %s Secret", role, secret, constants.CDBFetchSecretName("cluster"))
		}
	}
}

type managerFetchBuild struct{ b *ManagerStatefulSetBuilder }

func (m managerFetchBuild) build() []corev1.Container {
	return m.b.Build().Spec.Template.Spec.InitContainers
}
func (m managerFetchBuild) volumes() []corev1.Volume { return m.b.Build().Spec.Template.Spec.Volumes }

type workerFetchBuild struct{ b *WorkerStatefulSetBuilder }

func (w workerFetchBuild) build() []corev1.Container {
	return w.b.Build().Spec.Template.Spec.InitContainers
}
func (w workerFetchBuild) volumes() []corev1.Volume { return w.b.Build().Spec.Template.Spec.Volumes }

// TestCDBFetchScriptsEndToEnd runs the generated scripts with the real curl and busybox:
// a list is downloaded with the header from its config and converted in place, a failed
// download or a missing config keeps the existing file.
func TestCDBFetchScriptsEndToEnd(t *testing.T) {
	busybox, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("busybox not installed")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feed" || r.Header.Get("Auth-Key") != "secret" {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		_, _ = w.Write([]byte("# header\nabc\ndef\n"))
	}))
	t.Cleanup(srv.Close)

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
	write("config/ok.curlrc", "url = \""+srv.URL+"/feed\"\nheader = \"Auth-Key: secret\"\nfail\nsilent\nshow-error\n")
	write("config/gone.curlrc", "url = \""+srv.URL+"/old\"\nfail\nsilent\nshow-error\n")
	write("raw/.keep", "")
	write("var/ossec/etc/lists/gone", "previous\n")
	write("var/ossec/etc/lists/noconfig", "previous\n")

	b := NewManagerStatefulSetBuilder("cluster", "ns", "master").WithCDBListInitFetches([]CDBListInitFetchRef{
		{ConfigKey: "ok.curlrc", ListName: "ioc/hashes", Format: "keylist", SkipLines: 1},
		{ConfigKey: "gone.curlrc", ListName: "gone", Format: "keylist"},
		{ConfigKey: "missing.curlrc", ListName: "noconfig", Format: "keylist"},
	})
	containers := b.buildCDBFetchInitContainers("manager-image")
	rewrite := strings.NewReplacer(cdbFetchConfigDir, filepath.Join(root, "config"), cdbFetchRawDir, filepath.Join(root, "raw"),
		constants.PathWazuhBase, filepath.Join(root, "var/ossec"))
	if out, err := exec.CommandContext(t.Context(), "sh", "-c", rewrite.Replace(containers[0].Command[2])).CombinedOutput(); err != nil {
		t.Fatalf("cdb-download failed: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(t.Context(), busybox, "sh", "-c", rewrite.Replace(containers[1].Command[2])).CombinedOutput(); err != nil {
		t.Fatalf("cdb-fetch failed: %v\n%s", err, out)
	}

	for list, want := range map[string]string{"ioc/hashes": "abc:\ndef:\n", "gone": "previous\n", "noconfig": "previous\n"} {
		got, err := os.ReadFile(filepath.Join(root, "var/ossec/etc/lists", list))
		if err != nil || string(got) != want {
			t.Errorf("etc/lists/%s = %q, %v; want %q", list, got, err, want)
		}
	}
}

// TestNoCDBFetchInitContainersWhenEmpty asserts the containers and volumes are omitted
// with no init-fetch lists.
func TestNoCDBFetchInitContainersWhenEmpty(t *testing.T) {
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
	for _, name := range []string{constants.InitContainerNameCDBDownload, constants.InitContainerNameCDBFetch} {
		if _, ok := findInitContainer(sts.Spec.Template.Spec.InitContainers, name); ok {
			t.Errorf("%s init container rendered without init-fetch lists", name)
		}
	}
	for _, v := range sts.Spec.Template.Spec.Volumes {
		if v.Name == cdbFetchConfigVolume || v.Name == cdbFetchRawVolume {
			t.Errorf("volume %s rendered without init-fetch lists", v.Name)
		}
	}
}
