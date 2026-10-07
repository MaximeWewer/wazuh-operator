package deployments

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestSeedDefaultsInitContainer guards the fix for PVC-backed /var/ossec/etc never receiving
// the image defaults: the operator's subPath mounts (authd.pass, content ConfigMaps) make the
// directory non-empty, so the Wazuh entrypoint skips its seed. The seed-defaults init
// container must restore missing defaults with a no-clobber copy, before fix-permissions,
// on both the master and the workers.
func TestSeedDefaultsInitContainer(t *testing.T) {
	builds := map[string]*appsv1.StatefulSet{
		"master": NewManagerStatefulSetBuilder("cluster", "ns", "master").Build(),
		"worker": NewWorkerStatefulSetBuilder("cluster", "ns").Build(),
	}
	for role, sts := range builds {
		c, idx := findInit(sts, constants.InitContainerNameSeedDefaults)
		if idx < 0 {
			t.Fatalf("%s: seed-defaults init container not rendered", role)
		}
		if _, permIdx := findInit(sts, constants.InitContainerNamePermissions); permIdx < idx {
			t.Errorf("%s: seed-defaults (%d) must run before fix-permissions (%d)", role, idx, permIdx)
		}
		script := c.Command[len(c.Command)-1]
		if !strings.Contains(script, `cp -an "$BACKUP$dir/." "$dir/"`) {
			t.Errorf("%s: seed must be a no-clobber copy from the image backup, got:\n%s", role, script)
		}
		for _, p := range seedDefaultsPaths {
			if !strings.Contains(script, p) {
				t.Errorf("%s: script does not seed %s", role, p)
			}
			m, mi := findMount(c.VolumeMounts, p)
			if mi < 0 {
				t.Errorf("%s: %s not mounted in seed-defaults", role, p)
				continue
			}
			if m.ReadOnly {
				t.Errorf("%s: %s mounted read-only", role, p)
			}
		}
	}
}

// TestSeedDefaultsFollowsVolumeClaims asserts the seed writes to the dedicated PVC when a
// seeded path is split onto its own volume claim.
func TestSeedDefaultsFollowsVolumeClaims(t *testing.T) {
	sts := NewManagerStatefulSetBuilder("cluster", "ns", "master").
		WithVolumeClaims([]ManagerVolumeClaimRef{
			{Path: constants.PathWazuhConfig, Size: "5Gi"},
		}).Build()

	c, idx := findInit(sts, constants.InitContainerNameSeedDefaults)
	if idx < 0 {
		t.Fatal("seed-defaults init container not rendered")
	}
	m, mi := findMount(c.VolumeMounts, constants.PathWazuhConfig)
	if mi < 0 {
		t.Fatal("/var/ossec/etc not mounted in seed-defaults")
	}
	if m.Name != SplitVolumeName(constants.PathWazuhConfig) || m.SubPath != "" {
		t.Errorf("etc mount = %+v, want the dedicated PVC", m)
	}
}
