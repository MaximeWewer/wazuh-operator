package deployments

import (
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

// TestCDBFetchInitContainerRendersScript asserts the cdb-fetch init container is rendered
// with a well-formed busybox script for an init-fetch list, guarding against shell/awk
// quoting regressions and the ordering relative to fix-permissions / fix-ownership.
func TestCDBFetchInitContainerRendersScript(t *testing.T) {
	fetches := []CDBListInitFetchRef{
		{ListName: "malicious-ioc/malicious-ip", URL: "https://example.com/blocklist.txt", Format: "iplist", SkipLines: 3},
	}
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
		WithCDBListInitFetches(fetches).Build()

	inits := sts.Spec.Template.Spec.InitContainers
	c, ok := findInitContainer(inits, constants.InitContainerNameCDBFetch)
	if !ok {
		t.Fatal("cdb-fetch init container not rendered")
	}
	if c.Image != constants.ImageBusyboxInit {
		t.Errorf("image = %q, want %q", c.Image, constants.ImageBusyboxInit)
	}
	if len(c.Command) != 3 || c.Command[0] != "/bin/sh" || c.Command[1] != "-c" {
		t.Fatalf("unexpected command: %v", c.Command)
	}
	script := c.Command[2]

	// The data volume must be mounted so /var/ossec/etc/lists is writable.
	mounted := false
	for _, m := range c.VolumeMounts {
		if m.Name == constants.VolumeNameWazuhData && m.MountPath == constants.PathWazuhConfig {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("cdb-fetch container does not mount the data volume at %s: %+v", constants.PathWazuhConfig, c.VolumeMounts)
	}

	for _, want := range []string{
		"https://example.com/blocklist.txt",                 // source URL
		"tail -n +4",                                        // SkipLines 3 -> tail +4
		"RSTART,RLENGTH",                                    // iplist awk marker
		"/var/ossec/etc/lists/malicious-ioc/malicious-ip",   // destination path
		"wget -q -O",                                        // download
		"mv",                                                // atomic publish
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\n---\n%s", want, script)
		}
	}
	// Insecure was false, so no --no-check-certificate flag.
	if strings.Contains(script, "--no-check-certificate") {
		t.Errorf("script unexpectedly contains --no-check-certificate:\n%s", script)
	}

	// Ordering: cdb-fetch between fix-permissions and fix-ownership.
	idx := map[string]int{}
	for i, ic := range inits {
		idx[ic.Name] = i
	}
	if !(idx[constants.InitContainerNamePermissions] < idx[constants.InitContainerNameCDBFetch] &&
		idx[constants.InitContainerNameCDBFetch] < idx["fix-ownership"]) {
		t.Errorf("cdb-fetch not ordered between fix-permissions and fix-ownership: %v", idx)
	}
}

// TestCDBFetchInitContainerInsecureAndFormats checks the insecure flag and format routing.
func TestCDBFetchInitContainerInsecureAndFormats(t *testing.T) {
	fetches := []CDBListInitFetchRef{
		{ListName: "hashes", URL: "https://feeds.example/hashes.txt", Format: "keylist", Insecure: true},
	}
	sts := NewWorkerStatefulSetBuilder("cluster", "ns").
		WithCDBListInitFetches(fetches).Build()
	c, ok := findInitContainer(sts.Spec.Template.Spec.InitContainers, constants.InitContainerNameCDBFetch)
	if !ok {
		t.Fatal("cdb-fetch init container not rendered on worker")
	}
	script := c.Command[2]
	if !strings.Contains(script, "--no-check-certificate") {
		t.Errorf("insecure list missing --no-check-certificate:\n%s", script)
	}
	// keylist awk marker.
	if !strings.Contains(script, `substr($0,1,1)=="#"`) {
		t.Errorf("keylist awk converter not selected:\n%s", script)
	}
}

// TestNoCDBFetchInitContainerWhenEmpty asserts the container is omitted with no init-fetch lists.
func TestNoCDBFetchInitContainerWhenEmpty(t *testing.T) {
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").Build()
	if _, ok := findInitContainer(sts.Spec.Template.Spec.InitContainers, constants.InitContainerNameCDBFetch); ok {
		t.Error("cdb-fetch init container should not be rendered when there are no init-fetch lists")
	}
}
