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

func TestParsePVCName(t *testing.T) {
	sts := "wazuh-cluster-manager-master"
	tests := []struct {
		pvc     string
		wantVCT string
		wantOrd int
		wantOK  bool
	}{
		{"wazuh-data-" + sts + "-0", "wazuh-data", 0, true},
		{"wazuh-data-queue-db-" + sts + "-0", "wazuh-data-queue-db", 0, true},
		{"wazuh-data-queue-db-wazuh-cluster-manager-worker-3", "wazuh-data-queue-db", 3, false}, // wrong sts
		{"unrelated-pvc", "", 0, false},
	}
	for _, tt := range tests {
		vct, ord, ok := parsePVCName(tt.pvc, sts)
		if ok != tt.wantOK || (ok && (vct != tt.wantVCT || ord != tt.wantOrd)) {
			t.Errorf("parsePVCName(%q) = (%q,%d,%v), want (%q,%d,%v)", tt.pvc, vct, ord, ok, tt.wantVCT, tt.wantOrd, tt.wantOK)
		}
	}
}

func TestDeriveSubPathForVCT(t *testing.T) {
	cases := map[string]string{
		"wazuh-data-queue-db": "wazuh/queue/db",
		"wazuh-data-logs":     "wazuh/logs",
	}
	for vct, want := range cases {
		if got := deriveSubPathForVCT(vct); got != want {
			t.Errorf("deriveSubPathForVCT(%q) = %q, want %q", vct, got, want)
		}
	}
}

func TestReverseMigrationJobName(t *testing.T) {
	short := reverseMigrationJobName("wazuh-data-queue-db-c-manager-master-0")
	if short != "revmig-wazuh-data-queue-db-c-manager-master-0" {
		t.Errorf("unexpected job name %q", short)
	}
	long := reverseMigrationJobName("wazuh-data-queue-db-a-very-long-cluster-name-manager-master-10")
	if len(long) > 63 {
		t.Errorf("job name exceeds 63 chars: %d (%q)", len(long), long)
	}
}
