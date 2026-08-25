package deployments

import (
	"strings"
	"testing"
)

// TestInitScriptSeedsDefaultGroup guards the fix for the "Unable to find the id of the
// group 'default'" bug: /var/ossec/etc is PVC-backed, so on a fresh volume the default
// agent group shipped in the image is shadowed by the empty mount. The init container must
// recreate it, or every agent stays permanently unassigned.
func TestInitScriptSeedsDefaultGroup(t *testing.T) {
	if !strings.Contains(initScriptHead, "mkdir -p /var/ossec/etc/shared/default") {
		t.Fatalf("init script does not create the default agent group directory")
	}
	if !strings.Contains(initScriptHead, "/var/ossec/etc/shared/default/agent.conf") {
		t.Fatalf("init script does not seed the default group agent.conf")
	}
	// Must not clobber an existing agent.conf (and its generated merged.mg) on restart.
	if !strings.Contains(initScriptHead, "if [ ! -f /var/ossec/etc/shared/default/agent.conf ]") {
		t.Fatalf("init script overwrites default/agent.conf unconditionally; existing groups would be clobbered on restart")
	}
}
