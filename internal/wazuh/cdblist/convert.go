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
	"strconv"
	"strings"
)

// ConverterVersion identifies the output of the format converters. Bump it whenever a
// converter produces different content for the same input: URL-sourced lists record the
// version they were converted with and are fetched again when it changes, instead of
// keeping the old conversion until the next refresh interval.
const ConverterVersion = 2

// ipLineRegex matches lines that start with an IPv4 address and an optional CIDR mask.
// Group 1 is the address, group 2 (optional) is the mask. Mirrors the regex used by
// Wazuh's iplist-to-cdblist.py conversion script.
var ipLineRegex = regexp.MustCompile(`^((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?`)

// IPListToCDB converts a plain IP/CIDR list into CDB list content, following Wazuh's
// iplist-to-cdblist.py script:
//
//   - only lines that start with an IPv4 address are considered;
//   - a /8, /16, /24 or /32 mask truncates the address to the network prefix and - for
//     anything other than /32 - leaves a trailing dot so Wazuh matches the whole subnet
//     (e.g. "10.0.0.0/24" -> "10.0.0.");
//   - each resulting address becomes a key-only entry ("ip:").
//
// Unlike the upstream script, which silently drops every other mask (about half of a feed
// like FireHOL level1), any other mask is expanded into the covering prefixes of the next
// octet boundary that address_match_key lookups understand: "10.0.0.0/23" yields
// "10.0.0." and "10.0.1.", a /12 yields 16 two-octet prefixes, a /30 yields 4 addresses.
// A mask covers at most 128 prefixes (/0 yields the 256 one-octet prefixes). Lines with a
// mask above 32 or an octet above 255 are skipped.
//
// Output entries are newline-separated with a trailing newline.
func IPListToCDB(input string) string {
	var entries []string
	for line := range strings.SplitSeq(input, "\n") {
		line = strings.TrimRight(line, "\r")
		m := ipLineRegex.FindStringSubmatch(line)
		if m == nil {
			continue // read just lines that start with an IP
		}
		if m[2] == "" {
			entries = append(entries, m[1]+":")
			continue
		}
		for _, prefix := range cidrPrefixes(m[1], m[2]) {
			entries = append(entries, prefix+":")
		}
	}
	return joinLines(entries)
}

// cidrPrefixes returns the address_match_key prefixes covering ip/mask, at the octet
// boundary at or below the mask. It returns nil for an invalid mask or address.
func cidrPrefixes(ip, mask string) []string {
	bits, err := strconv.Atoi(mask)
	if err != nil || bits > 32 {
		return nil
	}
	var addr uint32
	for o := range strings.SplitSeq(ip, ".") {
		v, err := strconv.Atoi(o)
		if err != nil || v > 255 {
			return nil
		}
		addr = addr<<8 | uint32(v)
	}

	keepOctets := max((bits+7)/8, 1)
	boundary := keepOctets * 8
	addr &^= uint32(uint64(1)<<(32-bits) - 1) // network address
	step := uint64(1) << (32 - boundary)
	count := 1 << (boundary - bits)

	prefixes := make([]string, 0, count)
	for i := range count {
		a := uint64(addr) + uint64(i)*step
		octets := make([]string, keepOctets)
		for j := range keepOctets {
			octets[j] = strconv.FormatUint(a>>(24-8*j)&0xff, 10)
		}
		prefix := strings.Join(octets, ".")
		if keepOctets < 4 {
			prefix += "."
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// KeyListToCDB converts a plain list of keys (one per line) into CDB list content:
// each non-blank line is trimmed and becomes a key-only entry ("key:"). This is the
// generic converter for hash lists (e.g. VirusShare MD5 dumps, MalwareBazaar exports),
// domain lists, user lists, or any newline-separated set of lookup keys. Blank lines and
// comment lines (starting with "#", common in feed headers) are skipped. Lines already
// containing ":" are left untouched so pre-formatted content stays idempotent.
func KeyListToCDB(input string) string {
	var entries []string
	for line := range strings.SplitSeq(input, "\n") {
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
	for line := range strings.SplitSeq(content, "\n") {
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
	for line := range strings.SplitSeq(content, "\n") {
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
