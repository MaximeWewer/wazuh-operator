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

package controllers

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestSpecChangedPredicate(t *testing.T) {
	base := func() *wazuhv1.WazuhRole {
		return &wazuhv1.WazuhRole{ObjectMeta: metav1.ObjectMeta{
			Name: "r", Generation: 1, ResourceVersion: "1",
			Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"},
			Finalizers: []string{"f"},
		}}
	}
	now := metav1.Now()
	cases := map[string]struct {
		mutate func(*wazuhv1.WazuhRole)
		want   bool
	}{
		"status only": {func(o *wazuhv1.WazuhRole) {
			o.ResourceVersion = "2"
			o.Status.Phase = wazuhv1.WazuhRBACPhaseFailed
			o.Status.Message = "wazuh API unavailable"
		}, false},
		"spec":       {func(o *wazuhv1.WazuhRole) { o.Generation = 2 }, true},
		"label":      {func(o *wazuhv1.WazuhRole) { o.Labels["a"] = "2" }, true},
		"annotation": {func(o *wazuhv1.WazuhRole) { o.Annotations["force-sync"] = "1" }, true},
		"finalizer":  {func(o *wazuhv1.WazuhRole) { o.Finalizers = nil }, true},
		"deletion":   {func(o *wazuhv1.WazuhRole) { o.DeletionTimestamp = &now }, true},
	}
	p := specChangedPredicate()
	for name, c := range cases {
		old, cur := base(), base()
		c.mutate(cur)
		if got := p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: cur}); got != c.want {
			t.Errorf("%s: Update = %v, want %v", name, got, c.want)
		}
	}
	if !p.Create(event.CreateEvent{Object: base()}) || !p.Delete(event.DeleteEvent{Object: base()}) {
		t.Error("creations and deletions must pass")
	}
}
