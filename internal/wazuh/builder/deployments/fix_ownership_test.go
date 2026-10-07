package deployments

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestFixOwnershipWalksVolumesOnly guards the slow manager start: fix-ownership used to walk
// the whole /var/ossec, chowning every image file (owned by root) inside its own throw-away
// overlay layer - a full copy-up of the image tree on every pod start. It must only walk the
// writable volume mounts, without nested duplicates.
func TestFixOwnershipWalksVolumesOnly(t *testing.T) {
	builds := map[string]*appsv1.StatefulSet{
		"master": NewManagerStatefulSetBuilder("cluster", "ns", "master").
			WithVolumeClaims([]ManagerVolumeClaimRef{{Path: "/var/ossec/queue/db", Size: "5Gi"}}).Build(),
		"worker": NewWorkerStatefulSetBuilder("cluster", "ns").Build(),
	}
	for role, sts := range builds {
		c, idx := findInit(sts, constants.InitContainerNameFixOwnership)
		if idx < 0 {
			t.Fatalf("%s: fix-ownership init container not rendered", role)
		}
		script := c.Command[len(c.Command)-1]
		if strings.Contains(script, "find /var/ossec ") {
			t.Errorf("%s: fix-ownership walks the whole /var/ossec image tree: %s", role, script)
		}
		for _, p := range []string{constants.PathWazuhConfig, constants.PathWazuhQueue, constants.PathWazuhLogs} {
			if !strings.Contains(script, "'"+p+"'") {
				t.Errorf("%s: fix-ownership does not cover volume %s: %s", role, p, script)
			}
		}
		if strings.Contains(script, "'/var/ossec/queue/db'") {
			t.Errorf("%s: nested mount walked twice: %s", role, script)
		}
		if !strings.Contains(script, "-writable ! -user 999") {
			t.Errorf("%s: fix-ownership must skip read-only and already-owned files: %s", role, script)
		}
	}
}

// TestManagerStartupProbe asserts a slow first start is covered by a startup probe instead
// of being killed by the liveness probe (90s + 3x30s).
func TestManagerStartupProbe(t *testing.T) {
	for role, sts := range map[string]*appsv1.StatefulSet{
		"master": NewManagerStatefulSetBuilder("cluster", "ns", "master").Build(),
		"worker": NewWorkerStatefulSetBuilder("cluster", "ns").Build(),
	} {
		p := sts.Spec.Template.Spec.Containers[0].StartupProbe
		if p == nil {
			t.Fatalf("%s: no startupProbe on the manager container", role)
		}
		if budget := p.PeriodSeconds * p.FailureThreshold; budget < 300 {
			t.Errorf("%s: startup budget %ds is too short", role, budget)
		}
	}
}
