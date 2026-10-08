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

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/cdblist"
)

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

func TestCDBListShouldRefetch(t *testing.T) {
	fresh := func(converter int32) *wazuhv1.WazuhCDBList {
		return &wazuhv1.WazuhCDBList{
			ObjectMeta: metav1.ObjectMeta{Generation: 1},
			Spec: wazuhv1.WazuhCDBListSpec{Source: &wazuhv1.CDBListSource{
				URL:             "https://example.org/list",
				RefreshInterval: &metav1.Duration{Duration: 6 * time.Hour},
			}},
			Status: wazuhv1.WazuhCDBListStatus{
				ObservedGeneration: 1,
				ContentHash:        "abc",
				LastFetchTime:      &metav1.Time{Time: time.Now()},
				ConverterVersion:   converter,
			},
		}
	}
	r := &CDBListReconciler{}

	if r.shouldRefetch(fresh(cdblist.ConverterVersion)) {
		t.Error("recently fetched list with the current converter must not be fetched again")
	}
	// A list converted by an operator release before ConverterVersion existed (0), or by
	// any other converter version, is fetched again right away.
	for _, v := range []int32{0, cdblist.ConverterVersion - 1} {
		if !r.shouldRefetch(fresh(v)) {
			t.Errorf("list converted with version %d must be fetched again", v)
		}
	}
}
