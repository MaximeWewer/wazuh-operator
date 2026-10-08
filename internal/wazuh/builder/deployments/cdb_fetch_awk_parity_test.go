package deployments

import (
	"fmt"
	"math/rand/v2"
	"os/exec"
	"strings"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/cdblist"
)

// TestCDBFetchAWKIPListParity runs the busybox awk iplist converter used by the cdb-fetch
// init container and asserts it produces exactly what cdblist.IPListToCDB bakes into a
// ConfigMap, so a list keeps the same content whether it is inlined or init-fetched.
// Skipped when busybox is not installed.
func TestCDBFetchAWKIPListParity(t *testing.T) {
	busybox, err := exec.LookPath("busybox")
	if err != nil {
		t.Skip("busybox not installed")
	}

	lines := []string{
		"# FireHOL-style header",
		"1.2.3.4", "8.8.8.8 trailing note", "1.1.1.1\r",
		"10.0.0.0/8", "172.16.0.0/16", "192.168.1.0/24", "203.0.113.5/32",
		"0.0.0.0/0", "224.0.0.0/3", "100.64.0.0/10", "172.16.0.0/12",
		"10.0.0.0/23", "192.168.3.77/22", "198.51.100.9/30", "198.51.100.9/31",
		"10.0.0.0/33", "300.1.1.0/24", "1.2.3.4/08", "not an ip", "",
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 300 {
		lines = append(lines, fmt.Sprintf("%d.%d.%d.%d/%d",
			r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(256), r.IntN(33)))
	}
	input := strings.Join(lines, "\n") + "\n"

	cmd := exec.CommandContext(t.Context(), busybox, "awk", cdbFetchAWKIPList)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("busybox awk failed: %v", err)
	}

	want := cdblist.IPListToCDB(input)
	if string(out) != want {
		gotLines, wantLines := strings.Split(string(out), "\n"), strings.Split(want, "\n")
		for i := range min(len(gotLines), len(wantLines)) {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("awk and Go diverge at line %d: awk %q, go %q", i+1, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("awk and Go differ in length: awk %d lines, go %d lines", len(gotLines), len(wantLines))
	}
}
