package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/pkg/versions"
)

func mkRow(t *testing.T, wv, os string) row {
	t.Helper()
	p, err := versions.ParseVersion(wv)
	if err != nil {
		t.Fatalf("parse %s: %v", wv, err)
	}
	return row{wazuh: wv, openSrch: os, plugin: os + ".0", parsedVer: p}
}

const sampleMap = `var wazuhVersionMapping = map[string]WazuhVersionInfo{
	// BEGIN generated-mapping
	"4.14.5": {WazuhVersion: "4.14.5", OpenSearchVersion: "2.19.5", PrometheusExporterPluginVersion: "2.19.5.0"},
	"4.13.1": {WazuhVersion: "4.13.1", OpenSearchVersion: "2.19.2", PrometheusExporterPluginVersion: "2.19.2.0"},
	"4.10.3": {WazuhVersion: "4.10.3", OpenSearchVersion: "2.16.0", PrometheusExporterPluginVersion: "2.16.0.0"},
	"4.9.0": {WazuhVersion: "4.9.0", OpenSearchVersion: "2.13.0", PrometheusExporterPluginVersion: "2.13.0.0"},
	// END generated-mapping
}`

// mapKeyOrder returns the Wazuh version keys in the order they appear in src.
func mapKeyOrder(src string) []string {
	re := regexp.MustCompile(`(?m)^\s*"(\d+\.\d+\.\d+)":`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestInsertRowsKeepsDescendingOrder(t *testing.T) {
	// New patch for an existing minor (4.14.6), a mid-list patch (4.13.2),
	// and a top-of-list new minor (4.15.0) must all land in sorted position.
	got, err := insertRows(sampleMap, []row{
		mkRow(t, "4.13.2", "2.19.2"),
		mkRow(t, "4.14.6", "2.19.5"),
		mkRow(t, "4.15.0", "2.20.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"4.15.0", "4.14.6", "4.14.5", "4.13.2", "4.13.1", "4.10.3", "4.9.0"}
	order := mapKeyOrder(got)
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order mismatch:\n got  %v\n want %v", order, want)
	}
	// Existing lines must be preserved verbatim.
	for _, keep := range []string{
		`"4.14.5": {WazuhVersion: "4.14.5", OpenSearchVersion: "2.19.5", PrometheusExporterPluginVersion: "2.19.5.0"},`,
		`"4.9.0": {WazuhVersion: "4.9.0", OpenSearchVersion: "2.13.0", PrometheusExporterPluginVersion: "2.13.0.0"},`,
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("existing row was altered/lost: %s", keep)
		}
	}
}

const commentedMap = `var wazuhVersionMapping = map[string]WazuhVersionInfo{
	// BEGIN generated-mapping
	// Wazuh 4.14.x - OpenSearch 2.19.3+
	"4.14.5": {WazuhVersion: "4.14.5", OpenSearchVersion: "2.19.5", PrometheusExporterPluginVersion: "2.19.5.0"},
	"4.14.0": {WazuhVersion: "4.14.0", OpenSearchVersion: "2.19.3", PrometheusExporterPluginVersion: "2.19.3.0"},
	// Wazuh 4.13.x - OpenSearch 2.19.2
	"4.13.1": {WazuhVersion: "4.13.1", OpenSearchVersion: "2.19.2", PrometheusExporterPluginVersion: "2.19.2.0"},
	// END generated-mapping
}`

func TestInsertRowsPreservesAndGeneratesComments(t *testing.T) {
	got, err := insertRows(commentedMap, []row{
		mkRow(t, "4.14.6", "2.19.5"), // new patch, existing minor -> no new comment
		mkRow(t, "4.13.2", "2.19.2"), // new patch, existing minor -> no new comment
		mkRow(t, "4.15.0", "2.20.0"), // brand-new minor -> generated header
	})
	if err != nil {
		t.Fatal(err)
	}

	// Existing hand-written section comments must survive untouched.
	for _, c := range []string{"// Wazuh 4.14.x - OpenSearch 2.19.3+", "// Wazuh 4.13.x - OpenSearch 2.19.2"} {
		if !strings.Contains(got, c) {
			t.Errorf("existing comment dropped: %q", c)
		}
	}
	// A brand-new minor gets exactly one generated header.
	if n := strings.Count(got, "// Wazuh 4.15.x - OpenSearch 2.20.x"); n != 1 {
		t.Errorf("new-minor header count = %d, want 1", n)
	}
	// New patches of existing minors must NOT spawn a header.
	if strings.Contains(got, "// Wazuh 4.14.6") || strings.Contains(got, "4.14.x - OpenSearch 2.19.5") {
		t.Error("new patch 4.14.6 should not create a section comment")
	}
	// The new minor's header sits above the 4.14 header (block ordered high->low).
	if strings.Index(got, "4.15.x - OpenSearch") > strings.Index(got, "4.14.x - OpenSearch 2.19.3+") {
		t.Error("4.15.x header should precede the 4.14.x header")
	}
	// Order sanity.
	want := []string{"4.15.0", "4.14.6", "4.14.5", "4.14.0", "4.13.2", "4.13.1"}
	if order := mapKeyOrder(got); strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order mismatch:\n got  %v\n want %v", order, want)
	}
}

func TestInsertRowsGroupsNewMinorUnderOneComment(t *testing.T) {
	base := `var wazuhVersionMapping = map[string]WazuhVersionInfo{
	// BEGIN generated-mapping
	// Wazuh 4.14.x - OpenSearch 2.19.3+
	"4.14.5": {WazuhVersion: "4.14.5", OpenSearchVersion: "2.19.5", PrometheusExporterPluginVersion: "2.19.5.0"},
	// END generated-mapping
}`
	// Several patches of a brand-new 4.15 minor arriving in one run.
	got, err := insertRows(base, []row{
		mkRow(t, "4.15.0", "2.20.0"),
		mkRow(t, "4.15.2", "2.20.1"),
		mkRow(t, "4.15.1", "2.20.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got, "// Wazuh 4.15.x"); n != 1 {
		t.Fatalf("expected exactly one 4.15.x header, got %d", n)
	}
	// All three 4.15 rows must sit below that single header and above the 4.14 header.
	h15 := strings.Index(got, "// Wazuh 4.15.x")
	h14 := strings.Index(got, "// Wazuh 4.14.x")
	for _, v := range []string{`"4.15.0"`, `"4.15.1"`, `"4.15.2"`} {
		idx := strings.Index(got, v)
		if idx < h15 || idx > h14 {
			t.Errorf("%s not grouped under the 4.15.x header", v)
		}
	}

	// A later run adding 4.15.3 (map already has a 4.15 section) must NOT duplicate the header.
	got2, err := insertRows(got, []row{mkRow(t, "4.15.3", "2.20.2")})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got2, "// Wazuh 4.15.x"); n != 1 {
		t.Fatalf("second run duplicated the 4.15.x header (count=%d)", n)
	}
	if order := mapKeyOrder(got2); order[0] != "4.15.3" {
		t.Errorf("4.15.3 not placed at top of its section: %v", order)
	}
}

func TestParseExistingRowsBuildsMinorInvariant(t *testing.T) {
	_, minorOS := parseExistingRows(sampleMap)
	cases := map[string]string{"4.14": "2.19", "4.13": "2.19", "4.10": "2.16", "4.9": "2.13"}
	for k, want := range cases {
		if minorOS[k] != want {
			t.Errorf("minorOS[%q] = %q, want %q", k, minorOS[k], want)
		}
	}
}

// TestConsistencyGate documents the rule that rejects v4.10.4 (OpenSearch 2.19)
// against the established 4.10 -> 2.16 line, while accepting a matching patch.
func TestConsistencyGate(t *testing.T) {
	_, minorOS := parseExistingRows(sampleMap)
	check := func(wv, os string) bool { // true == would be rejected
		wp, _ := versions.ParseVersion(wv)
		op, _ := versions.ParseVersion(os)
		minorKey := itoaMinor(wp)
		known, ok := minorOS[minorKey]
		return ok && known != itoaMinor(op)
	}
	if !check("4.10.4", "2.19.5") {
		t.Error("4.10.4 -> 2.19.5 should be rejected (4.10 line is 2.16)")
	}
	if check("4.14.6", "2.19.5") {
		t.Error("4.14.6 -> 2.19.5 should be accepted (matches 4.14 line)")
	}
	if check("4.15.0", "2.20.0") {
		t.Error("4.15.0 -> new minor should be accepted (no prior 4.15 rows)")
	}
}

func itoaMinor(v *versions.Version) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}
