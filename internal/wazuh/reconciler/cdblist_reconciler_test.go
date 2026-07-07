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

package reconciler

import "testing"

func TestCDBListDataKey(t *testing.T) {
	cases := map[string]string{
		"blocked-ips":                  "blocked-ips",
		"malicious-ioc/malicious-ip":   "malicious-ip",
		"a/b/c":                        "c",
		"malicious-ioc/malware-hashes": "malware-hashes",
	}
	for in, want := range cases {
		if got := cdbListDataKey(in); got != want {
			t.Errorf("cdbListDataKey(%q) = %q, want %q", in, got, want)
		}
	}
}
