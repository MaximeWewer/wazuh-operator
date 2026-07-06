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
	existing := existingWazuhVersions(string(src))

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
			// Tag has no buildSrc/version.properties (very old layout) — genuinely skippable.
			skipped = append(skipped, fmt.Sprintf("%s: no version.properties at this tag", wv))
			continue
		}
		if err != nil {
			// Network / rate-limit / 5xx: abort rather than risk an incomplete update.
			return fmt.Errorf("resolve OpenSearch version for %s: %w", wv, err)
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

// existingWazuhVersions returns the set of Wazuh versions already keyed in the map.
func existingWazuhVersions(src string) map[string]struct{} {
	re := regexp.MustCompile(`(?m)^\s*"(\d+\.\d+\.\d+)":\s*\{`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// insertRows places the new rows immediately after the BEGIN marker line,
// leaving every existing row untouched.
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

	rendered := make([]string, 0, len(rows))
	for _, r := range rows {
		rendered = append(rendered, fmt.Sprintf(
			"\t%q: {WazuhVersion: %q, OpenSearchVersion: %q, PrometheusExporterPluginVersion: %q},",
			r.wazuh, r.wazuh, r.openSrch, r.plugin,
		))
	}

	out := make([]string, 0, len(lines)+len(rendered))
	out = append(out, lines[:beginIdx+1]...)
	out = append(out, rendered...)
	out = append(out, lines[beginIdx+1:]...)
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
// down to 1 per distinct plugin — keeping a full regeneration well under the
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
