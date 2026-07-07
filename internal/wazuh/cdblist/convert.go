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

// Package cdblist provides helpers to build Wazuh CDB list content.
//
// A CDB list is a plain text file of "key:value" lines (the value may be empty,
// yielding "key:"). See https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html
package cdblist

import (
	"regexp"
	"strings"
)

// ipLineRegex matches lines that start with an IPv4 address and an optional CIDR mask.
// Group 1 is the address, group 2 (optional) is the mask. Mirrors the regex used by
// Wazuh's iplist-to-cdblist.py conversion script.
var ipLineRegex = regexp.MustCompile(`^((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:/(\d{1,2}))?`)

// cidrOctets maps a supported CIDR mask to the number of leading octets kept.
var cidrOctets = map[string]int{"32": 4, "24": 3, "16": 2, "8": 1}

// IPListToCDB converts a plain IP/CIDR list into CDB list content, reproducing the
// behaviour of Wazuh's iplist-to-cdblist.py script:
//
//   - only lines that start with an IPv4 address are considered;
//   - a supported CIDR mask (/8, /16, /24, /32) truncates the address to the network
//     prefix and — for anything other than /32 — leaves a trailing dot so Wazuh matches
//     the whole subnet (e.g. "10.0.0.0/24" -> "10.0.0.");
//   - unsupported masks skip the line;
//   - each resulting address becomes a key-only entry ("ip:").
//
// Output entries are newline-separated with a trailing newline.
func IPListToCDB(input string) string {
	var entries []string
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimRight(line, "\r")
		m := ipLineRegex.FindStringSubmatch(line)
		if m == nil {
			continue // read just lines that start with an IP
		}
		ip := m[1]
		mask := m[2]
		if mask != "" {
			octets := strings.Split(ip, ".")
			keep, ok := cidrOctets[mask]
			if !ok || keep > len(octets) {
				continue // convert only allowed masks (32, 24, 16, 8)
			}
			ip = strings.Join(octets[:keep], ".")
			if mask != "32" {
				ip += "."
			}
		}
		entries = append(entries, ip+":")
	}
	return joinLines(entries)
}

// KeyListToCDB converts a plain list of keys (one per line) into CDB list content:
// each non-blank line is trimmed and becomes a key-only entry ("key:"). This is the
// generic converter for hash lists (e.g. VirusShare MD5 dumps, MalwareBazaar exports),
// domain lists, user lists, or any newline-separated set of lookup keys. Blank lines and
// comment lines (starting with "#", common in feed headers) are skipped. Lines already
// containing ":" are left untouched so pre-formatted content stays idempotent.
func KeyListToCDB(input string) string {
	var entries []string
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip blank lines and comments (feed headers)
		}
		if !strings.Contains(line, ":") {
			line += ":"
		}
		entries = append(entries, line)
	}
	return joinLines(entries)
}

// SkipLines drops the first n lines of content (e.g. a file header). n <= 0 is a no-op.
func SkipLines(input string, n int) string {
	if n <= 0 {
		return input
	}
	lines := strings.Split(input, "\n")
	if n >= len(lines) {
		return ""
	}
	return strings.Join(lines[n:], "\n")
}

// Entry is a key/value pair rendered into a CDB list line.
type Entry struct {
	Key   string
	Value string
}

// RenderEntries renders key/value pairs into CDB list content ("key:value" per line,
// or "key:" when the value is empty). Entries with an empty key are skipped.
func RenderEntries(entries []Entry) string {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Key == "" {
			continue
		}
		lines = append(lines, e.Key+":"+e.Value)
	}
	return joinLines(lines)
}

// Normalize trims trailing whitespace from each line, drops blank lines, and
// guarantees a trailing newline. Used for raw CDB content supplied inline or fetched.
func Normalize(content string) string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return joinLines(lines)
}

// CountEntries counts non-blank lines in rendered CDB content.
func CountEntries(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// joinLines joins lines with a newline and appends a trailing newline when non-empty.
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
