/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command version-sync keeps the wazuhVersionMapping table in
// pkg/versions/versions.go in step with upstream releases, without spinning up
// any cluster or container. It works entirely from three cheap HTTP sources:
//
//  1. Wazuh indexer git tags        -> the set of published Wazuh versions
//     (github.com/wazuh/wazuh-indexer, tags like "v4.14.6")
//  2. buildSrc/version.properties   -> the exact OpenSearch version each tag pins
//     (raw.githubusercontent.com/wazuh/wazuh-indexer/<tag>/buildSrc/version.properties)
//  3. prometheus-exporter releases  -> confirms the matching plugin zip exists
//     (github.com/opensearch-project/opensearch-prometheus-exporter)
//
// A Wazuh version is only added when its "<opensearch>.0" prometheus-exporter
// release actually exists: the indexer image has no fallback for the exporter
// plugin, so a mapping row without a real plugin release would break the build.
//
// New rows are inserted between the BEGIN/END generated-mapping markers in
// versions.go. Existing rows are never rewritten.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MaximeWewer/wazuh-operator/pkg/versions"
)

// errNotFound signals a clean HTTP 404 (resource legitimately absent), as opposed
// to any other error (network, rate limit, 5xx) which must abort the run rather
// than be mistaken for "not published yet".
var errNotFound = errors.New("not found")

const (
	indexerRepo  = "wazuh/wazuh-indexer"
	exporterRepo = "opensearch-project/opensearch-prometheus-exporter"

	beginMarker = "// BEGIN generated-mapping"
	endMarker   = "// END generated-mapping"

	// minWazuh is the oldest Wazuh version the operator supports; older tags are ignored.
	minWazuhMajor = 4
	minWazuhMinor = 9
)

var (
	stableTag = regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`) // rejects alpha/beta/rc/build suffixes
	osVerLine = regexp.MustCompile(`(?m)^\s*opensearch\s*=\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$`)
)

func main() {
	var (
		file      = flag.String("file", "pkg/versions/versions.go", "path to versions.go to update")
		dryRun    = flag.Bool("dry-run", false, "print planned changes without writing")
		summaryFn = flag.String("summary", os.Getenv("GITHUB_STEP_SUMMARY"), "optional file to append a markdown summary to")
	)
	flag.Parse()

	if err := run(*file, *dryRun, *summaryFn); err != nil {
		fmt.Fprintf(os.Stderr, "version-sync: %v\n", err)
		os.Exit(1)
	}
}

type row struct {
	wazuh     string
	openSrch  string
	plugin    string
	parsedVer *versions.Version
}

func run(file string, dryRun bool, summaryFn string) error {
	src, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	existing, minorOS := parseExistingRows(string(src))

	tags, err := fetchIndexerTags()
	if err != nil {
		return fmt.Errorf("fetch indexer tags: %w", err)
	}

	var (
		newRows []row
		skipped []string
	)
	for _, wv := range tags {
		if _, seen := existing[wv]; seen {
			continue
		}
		parsed, err := versions.ParseVersion(wv)
		if err != nil {
			continue
		}
		if !isSupported(parsed) {
			continue
		}

		osVer, err := fetchOpenSearchVersion("v" + wv)
		if errors.Is(err, errNotFound) {
			// Tag has no buildSrc/version.properties (very old layout) - genuinely skippable.
			skipped = append(skipped, fmt.Sprintf("%s: no version.properties at this tag", wv))
			continue
		}
		if err != nil {
			// Network / rate-limit / 5xx: abort rather than risk an incomplete update.
			return fmt.Errorf("resolve OpenSearch version for %s: %w", wv, err)
		}

		// Consistency gate: within a Wazuh minor line the OpenSearch minor never
		// changes. If this candidate disagrees with the OpenSearch minor already
		// recorded for its Wazuh minor, upstream almost certainly mis-tagged or
		// rebased the release (e.g. v4.10.4 tagged onto OpenSearch 2.19 long after
		// the 4.10 line shipped on 2.16). Flag for a human instead of trusting it.
		minorKey := fmt.Sprintf("%d.%d", parsed.Major, parsed.Minor)
		osParsed, err := versions.ParseVersion(osVer)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: unparseable OpenSearch version %q", wv, osVer))
			continue
		}
		candOSMinor := fmt.Sprintf("%d.%d", osParsed.Major, osParsed.Minor)
		if known, ok := minorOS[minorKey]; ok && known != candOSMinor {
			skipped = append(skipped, fmt.Sprintf(
				"%s: OpenSearch %s conflicts with the %s line's established %s.x - likely a mis-tagged upstream release, needs manual review",
				wv, osVer, minorKey, known))
			continue
		}

		plugin := osVer + ".0"

		ok, err := exporterReleaseExists(plugin)
		if err != nil {
			return fmt.Errorf("check exporter release %s (for Wazuh %s): %w", plugin, wv, err)
		}
		if !ok {
			skipped = append(skipped, fmt.Sprintf("%s: prometheus-exporter release %s not published yet", wv, plugin))
			continue
		}

		newRows = append(newRows, row{wazuh: wv, openSrch: osVer, plugin: plugin, parsedVer: parsed})
	}

	// Descending so the newest lands right under the BEGIN marker, matching the
	// existing newest-first ordering of the table.
	sort.Slice(newRows, func(i, j int) bool {
		return newRows[i].parsedVer.Compare(newRows[j].parsedVer) > 0
	})

	report(newRows, skipped, summaryFn)

	if len(newRows) == 0 {
		fmt.Println("version-sync: mapping already up to date")
		return nil
	}
	if dryRun {
		fmt.Println("version-sync: dry-run, not writing")
		return nil
	}

	updated, err := insertRows(string(src), newRows)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	fmt.Printf("version-sync: added %d row(s) to %s\n", len(newRows), file)
	return nil
}

func isSupported(v *versions.Version) bool {
	if v.Major > minWazuhMajor {
		return true
	}
	return v.Major == minWazuhMajor && v.Minor >= minWazuhMinor
}

var mapRowRe = regexp.MustCompile(
	`(?m)^\s*"(\d+\.\d+\.\d+)":\s*\{WazuhVersion:\s*"[\d.]+",\s*OpenSearchVersion:\s*"(\d+\.\d+\.\d+)"`)

// parseExistingRows reads the current map and returns:
//   - seen: the set of Wazuh versions already keyed
//   - minorOS: Wazuh "major.minor" -> the OpenSearch "major.minor" the existing
//     rows in that line use. This is the compatibility invariant: every patch of
//     a Wazuh minor ships the same OpenSearch minor, so a candidate that disagrees
//     is almost certainly a mis-tagged/rebased upstream release and must not be
//     added automatically.
func parseExistingRows(src string) (seen map[string]struct{}, minorOS map[string]string) {
	seen = map[string]struct{}{}
	minorOS = map[string]string{}
	for _, m := range mapRowRe.FindAllStringSubmatch(src, -1) {
		wv, osv := m[1], m[2]
		seen[wv] = struct{}{}
		wp, err1 := versions.ParseVersion(wv)
		op, err2 := versions.ParseVersion(osv)
		if err1 != nil || err2 != nil {
			continue
		}
		minorOS[fmt.Sprintf("%d.%d", wp.Major, wp.Minor)] = fmt.Sprintf("%d.%d", op.Major, op.Minor)
	}
	return seen, minorOS
}

// insertRows merges the new rows into the marker block in descending version
// order, matching the map's newest-first convention. Every existing line is kept
// verbatim; a new row is spliced in just before the first existing row whose
// version is lower than it.
func insertRows(src string, rows []row) (string, error) {
	lines := strings.Split(src, "\n")
	beginIdx, endIdx := -1, -1
	for i, ln := range lines {
		if strings.Contains(ln, beginMarker) {
			beginIdx = i
		}
		if strings.Contains(ln, endMarker) {
			endIdx = i
			break
		}
	}
	if beginIdx == -1 || endIdx == -1 || endIdx < beginIdx {
		return "", fmt.Errorf("could not locate %q / %q markers in versions.go", beginMarker, endMarker)
	}

	rowKeyRe := regexp.MustCompile(`^\s*"(\d+\.\d+\.\d+)":`)
	block := lines[beginIdx+1 : endIdx]

	render := func(r row) string {
		return fmt.Sprintf(
			"\t%q: {WazuhVersion: %q, OpenSearchVersion: %q, PrometheusExporterPluginVersion: %q},",
			r.wazuh, r.wazuh, r.openSrch, r.plugin,
		)
	}
	minorOf := func(v *versions.Version) string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }
	// higherMinor reports whether a's Wazuh minor line sits above b's.
	higherMinor := func(a, b *versions.Version) bool {
		return a.Major > b.Major || (a.Major == b.Major && a.Minor > b.Minor)
	}

	// Which Wazuh minors already have a section in the block: a new patch of an
	// existing minor tucks under that minor's comment silently, whereas a brand-new
	// minor gets its own generated "// Wazuh X.Y.x - OpenSearch A.B.x" header.
	hasMinor := map[string]bool{}
	for _, ln := range block {
		if m := rowKeyRe.FindStringSubmatch(ln); m != nil {
			if v, err := versions.ParseVersion(m[1]); err == nil {
				hasMinor[minorOf(v)] = true
			}
		}
	}

	pending := append([]row(nil), rows...)
	sort.Slice(pending, func(i, j int) bool { return pending[i].parsedVer.Compare(pending[j].parsedVer) > 0 })

	out := make([]string, 0, len(lines)+2*len(pending))
	out = append(out, lines[:beginIdx+1]...) // through the BEGIN marker

	emit := func(r row) {
		mk := minorOf(r.parsedVer)
		if !hasMinor[mk] { // first row of a new minor line: add a section header
			if osv, err := versions.ParseVersion(r.openSrch); err == nil {
				out = append(out, fmt.Sprintf("\t// Wazuh %s.x - OpenSearch %d.%d.x", mk, osv.Major, osv.Minor))
			}
			hasMinor[mk] = true
		}
		out = append(out, render(r))
	}
	// flush emits every pending row (highest first) for which pred holds.
	flush := func(pred func(r row) bool) {
		for len(pending) > 0 && pred(pending[0]) {
			emit(pending[0])
			pending = pending[1:]
		}
	}
	// nextRowVersion looks ahead from block[i] to the version of the next row line.
	nextRowVersion := func(i int) *versions.Version {
		for _, ln := range block[i:] {
			if m := rowKeyRe.FindStringSubmatch(ln); m != nil {
				if v, err := versions.ParseVersion(m[1]); err == nil {
					return v
				}
			}
		}
		return nil
	}

	for i, ln := range block {
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "//"):
			// Before an existing section comment, drop any pending row that belongs
			// to a strictly higher minor so its new section lands above this one.
			if nv := nextRowVersion(i); nv != nil {
				flush(func(r row) bool { return higherMinor(r.parsedVer, nv) })
			}
		case rowKeyRe.MatchString(ln):
			// Before an existing row, drop any pending row that outranks it.
			cur, _ := versions.ParseVersion(rowKeyRe.FindStringSubmatch(ln)[1])
			flush(func(r row) bool { return cur != nil && r.parsedVer.Compare(cur) > 0 })
		}
		out = append(out, ln)
	}
	flush(func(row) bool { return true }) // anything lower than every existing row

	out = append(out, lines[endIdx:]...) // END marker onward
	return strings.Join(out, "\n"), nil
}

func report(newRows []row, skipped []string, summaryFn string) {
	var b strings.Builder
	if len(newRows) > 0 {
		b.WriteString("## version-sync: new Wazuh mappings\n\n")
		b.WriteString("| Wazuh | OpenSearch | Prometheus exporter |\n|---|---|---|\n")
		for _, r := range newRows {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", r.wazuh, r.openSrch, r.plugin)
		}
		b.WriteString("\n")
	}
	if len(skipped) > 0 {
		b.WriteString("### Skipped\n\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}
	if b.Len() == 0 {
		return
	}
	fmt.Print(b.String())
	if summaryFn != "" {
		f, err := os.OpenFile(summaryFn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			defer f.Close()
			_, _ = f.WriteString(b.String())
		}
	}
}

// ---- HTTP helpers ----------------------------------------------------------

var httpClient = &http.Client{Timeout: 30 * time.Second}

func ghGet(url string, into any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// fetchIndexerTags returns the stable Wazuh versions (bare "X.Y.Z") published as
// wazuh-indexer git tags, across the first few pages.
func fetchIndexerTags() ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for page := 1; page <= 3; page++ {
		var tags []struct {
			Name string `json:"name"`
		}
		url := fmt.Sprintf("https://api.github.com/repos/%s/tags?per_page=100&page=%d", indexerRepo, page)
		if err := ghGet(url, &tags); err != nil {
			return nil, err
		}
		if len(tags) == 0 {
			break
		}
		for _, t := range tags {
			m := stableTag.FindStringSubmatch(t.Name)
			if m == nil {
				continue
			}
			if _, dup := seen[m[1]]; dup {
				continue
			}
			seen[m[1]] = struct{}{}
			out = append(out, m[1])
		}
	}
	return out, nil
}

// fetchOpenSearchVersion reads buildSrc/version.properties at the given tag and
// returns the pinned OpenSearch version (e.g. "2.19.5").
func fetchOpenSearchVersion(tag string) (string, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/buildSrc/version.properties", indexerRepo, tag)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := osVerLine.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("no opensearch version line in version.properties")
	}
	return string(m[1]), nil
}

// exporterCache memoises release lookups: many Wazuh versions share the same
// OpenSearch (hence plugin) version, so this collapses ~1 call per Wazuh version
// down to 1 per distinct plugin - keeping a full regeneration well under the
// unauthenticated GitHub rate limit.
var exporterCache = map[string]bool{}

// exporterReleaseExists reports whether a prometheus-exporter release with the
// given tag (e.g. "2.19.5.0") exists and ships a downloadable .zip asset.
func exporterReleaseExists(pluginVer string) (bool, error) {
	if v, ok := exporterCache[pluginVer]; ok {
		return v, nil
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", exporterRepo, pluginVer)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		exporterCache[pluginVer] = false
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Do not cache: rate limit / 5xx must be retryable and abort the run.
		return false, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return false, err
	}
	exists := false
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, ".zip") {
			exists = true
			break
		}
	}
	exporterCache[pluginVer] = exists
	return exists, nil
}
