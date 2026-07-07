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

package cdblist

import "testing"

func TestIPListToCDB(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain ips",
			in:   "1.2.3.4\n8.8.8.8",
			want: "1.2.3.4:\n8.8.8.8:\n",
		},
		{
			name: "cidr masks",
			in:   "10.0.0.0/8\n172.16.0.0/16\n192.168.1.0/24\n203.0.113.5/32",
			want: "10.:\n172.16.:\n192.168.1.:\n203.0.113.5:\n",
		},
		{
			name: "unsupported mask skipped",
			in:   "10.0.0.0/25\n8.8.8.8",
			want: "8.8.8.8:\n",
		},
		{
			name: "non-ip lines and comments skipped",
			in:   "# a comment\nnot an ip\n1.1.1.1\n\n",
			want: "1.1.1.1:\n",
		},
		{
			name: "crlf line endings",
			in:   "1.1.1.1\r\n2.2.2.2\r\n",
			want: "1.1.1.1:\n2.2.2.2:\n",
		},
		{
			name: "trailing content after ip is ignored",
			in:   "1.1.1.1 some note",
			want: "1.1.1.1:\n",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPListToCDB(tt.in); got != tt.want {
				t.Errorf("IPListToCDB() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKeyListToCDB(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "md5 hashes",
			in:   "d41d8cd98f00b204e9800998ecf8427e\n098f6bcd4621d373cade4e832627b4f6",
			want: "d41d8cd98f00b204e9800998ecf8427e:\n098f6bcd4621d373cade4e832627b4f6:\n",
		},
		{
			name: "blank lines skipped and whitespace trimmed",
			in:   "  abc  \n\n def \n",
			want: "abc:\ndef:\n",
		},
		{
			name: "already formatted lines untouched",
			in:   "user1:admin\nuser2:",
			want: "user1:admin\nuser2:\n",
		},
		{
			name: "feed header comments skipped",
			in:   "# Feodo Tracker\n# Last updated: 2026\n\n1.2.3.4\nbad.example",
			want: "1.2.3.4:\nbad.example:\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyListToCDB(tt.in); got != tt.want {
				t.Errorf("KeyListToCDB() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSkipLines(t *testing.T) {
	// VirusShare-style header skip: drop the first 6 lines, then key-list convert.
	in := "# header 1\n# header 2\n# 3\n# 4\n# 5\n# 6\nhashA\nhashB"
	if got := SkipLines(in, 6); got != "hashA\nhashB" {
		t.Errorf("SkipLines() = %q", got)
	}
	if got := SkipLines("a\nb", 0); got != "a\nb" {
		t.Errorf("SkipLines(0) should be no-op, got %q", got)
	}
	if got := SkipLines("a\nb", 5); got != "" {
		t.Errorf("SkipLines(over) = %q, want empty", got)
	}
}

func TestRenderEntries(t *testing.T) {
	entries := []Entry{
		{Key: "badguy.com", Value: "malicious domain"},
		{Key: "1.2.3.4"},         // key only
		{Key: "", Value: "skip"}, // skipped
	}
	want := "badguy.com:malicious domain\n1.2.3.4:\n"
	if got := RenderEntries(entries); got != want {
		t.Errorf("RenderEntries() = %q, want %q", got, want)
	}
}

func TestNormalizeAndCount(t *testing.T) {
	in := "a:1\n\n  b:2  \r\n"
	want := "a:1\nb:2\n"
	if got := Normalize(in); got != want {
		t.Errorf("Normalize() = %q, want %q", got, want)
	}
	if got := CountEntries(want); got != 2 {
		t.Errorf("CountEntries() = %d, want 2", got)
	}
}
