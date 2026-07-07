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

package validation

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func cdbList(listName string) *wazuhv1.WazuhCDBList {
	return &wazuhv1.WazuhCDBList{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "wazuh"},
		Spec: wazuhv1.WazuhCDBListSpec{
			ClusterRefs: []wazuhv1.WazuhClusterRef{{Name: "c", Namespace: "wazuh"}},
			ListName:    listName,
			Entries:     []wazuhv1.CDBListEntry{{Key: "k"}},
		},
	}
}

func TestCDBListName_SubdirAndTraversal(t *testing.T) {
	// nil client -> skips duplicate check; we only exercise listName validation.
	v := NewCDBListValidator(nil)
	cases := []struct {
		name  string
		valid bool
	}{
		{"blocked-ips", true},
		{"malicious-ioc/malicious-ip", true},
		{"a/b/c", true},
		{"a_b-c/d_e-f", true},
		{"/leading", false},
		{"trailing/", false},
		{"double//slash", false},
		{"..", false},
		{"a/../b", false},
		{"a/./b", false},
		{"has space", false},
		{"has.dot", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := v.Validate(context.Background(), cdbList(tc.name))
			if res.Valid != tc.valid {
				t.Errorf("listName %q: got valid=%v want %v (errors: %v)", tc.name, res.Valid, tc.valid, res.Errors)
			}
		})
	}
}
