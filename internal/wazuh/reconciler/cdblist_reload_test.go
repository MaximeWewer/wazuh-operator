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
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

type fakeReloadAPI struct {
	files           map[string]string // list key -> content the master serves
	synced          bool
	clusterRestarts int
	managerRestarts int
	clusterErr      error
}

func (f *fakeReloadAPI) GetListFile(_ context.Context, name string) (string, error) {
	content, ok := f.files[name]
	if !ok {
		return "", errors.New("get list file failed with status 404")
	}
	return content, nil
}

func (f *fakeReloadAPI) RulesetSynchronized(context.Context) (bool, error) { return f.synced, nil }

func (f *fakeReloadAPI) RestartCluster(context.Context) (*adapters.RestartResponse, error) {
	f.clusterRestarts++
	return &adapters.RestartResponse{}, f.clusterErr
}

func (f *fakeReloadAPI) RestartManager(context.Context) (*adapters.RestartResponse, error) {
	f.managerRestarts++
	return &adapters.RestartResponse{}, nil
}

func cdbInfo(name, content string) CDBListConfigMapInfo {
	return CDBListConfigMapInfo{FileName: name, Key: name, Mode: cdbDeliveryConfigMap, ContentHash: computeCDBListHash(content)}
}

func newReloadFixture(t *testing.T, annotations map[string]string) (*ClusterReconciler, *appsv1.StatefulSet) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "c-manager-master", Namespace: "ns", Annotations: annotations}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sts).Build()
	got := &appsv1.StatefulSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, got); err != nil {
		t.Fatal(err)
	}
	return &ClusterReconciler{Client: c}, got
}

func reloadAnnotations(t *testing.T, r *ClusterReconciler, sts *appsv1.StatefulSet) map[string]string {
	t.Helper()
	got := &appsv1.StatefulSet{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, got); err != nil {
		t.Fatal(err)
	}
	return got.Annotations
}

func TestCDBListContentHash(t *testing.T) {
	a, b := cdbInfo("a", "1:x\n"), cdbInfo("b", "2:y\n")
	fetched := CDBListConfigMapInfo{FileName: "big", Mode: cdbDeliveryInitFetch}
	if CDBListContentHash([]CDBListConfigMapInfo{a, b, fetched}) != CDBListContentHash([]CDBListConfigMapInfo{b, a}) {
		t.Error("hash depends on the order or on init-fetch lists")
	}
	if CDBListContentHash([]CDBListConfigMapInfo{a, b}) == CDBListContentHash([]CDBListConfigMapInfo{a, cdbInfo("b", "2:z\n")}) {
		t.Error("hash ignores a content change")
	}
	if CDBListContentHash([]CDBListConfigMapInfo{fetched}) != "" {
		t.Error("hash of init-fetch lists only should be empty")
	}
}

// TestReconcileCDBListReloadAdoptsUnknownState asserts a StatefulSet without the content
// annotation (new, or created by an older operator) records the current content without
// restarting anything: its pods loaded that content at start.
func TestReconcileCDBListReloadAdoptsUnknownState(t *testing.T) {
	r, sts := newReloadFixture(t, nil)
	infos := []CDBListConfigMapInfo{cdbInfo("a", "1:x\n")}
	if err := r.reconcileCDBListReload(context.Background(), &wazuhv1.WazuhCluster{}, sts, infos); err != nil {
		t.Fatal(err)
	}
	if got := reloadAnnotations(t, r, sts)[constants.AnnotationCDBListContentHash]; got != CDBListContentHash(infos) {
		t.Errorf("content hash annotation = %q, want %q", got, CDBListContentHash(infos))
	}
}

func TestReloadCDBLists(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	infos := []CDBListConfigMapInfo{cdbInfo("a", "1:new\n"), cdbInfo("b", "2:y\n")}
	want := CDBListContentHash(infos)

	for _, tc := range []struct {
		name            string
		files           map[string]string
		synced          bool
		pendingSince    string
		clusterErr      error
		wantRestarts    int
		wantManager     int
		wantApplied     string
		wantPendingFrom string
	}{
		{name: "master still serves the old content: wait and record since when",
			files: map[string]string{"a": "1:old\n", "b": "2:y\n"}, synced: true,
			wantApplied: "old", wantPendingFrom: now.Format(time.RFC3339)},
		{name: "list missing on the master: wait",
			files: map[string]string{"b": "2:y\n"}, synced: true, pendingSince: now.Add(-time.Minute).Format(time.RFC3339),
			wantApplied: "old", wantPendingFrom: now.Add(-time.Minute).Format(time.RFC3339)},
		{name: "a worker is not in sync yet: wait",
			files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: false,
			wantApplied: "old", wantPendingFrom: now.Format(time.RFC3339)},
		{name: "every node holds the new content: one cluster restart",
			files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true, pendingSince: now.Add(-time.Minute).Format(time.RFC3339),
			wantRestarts: 1, wantApplied: want},
		{name: "still stale after the max wait: restart anyway",
			files: map[string]string{"a": "1:old\n", "b": "2:y\n"}, synced: true, pendingSince: now.Add(-cdbListReloadMaxWait).Format(time.RFC3339),
			wantRestarts: 1, wantApplied: want},
		{name: "cluster restart rejected: restart the manager",
			files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true, clusterErr: errors.New("cluster restart failed with status 400"),
			wantRestarts: 1, wantManager: 1, wantApplied: want},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ann := map[string]string{constants.AnnotationCDBListContentHash: "old"}
			if tc.pendingSince != "" {
				ann[constants.AnnotationCDBListReloadPendingSince] = tc.pendingSince
			}
			r, sts := newReloadFixture(t, ann)
			api := &fakeReloadAPI{files: tc.files, synced: tc.synced, clusterErr: tc.clusterErr}
			if err := r.reloadCDBLists(context.Background(), &wazuhv1.WazuhCluster{}, sts, api, infos, want, now); err != nil {
				t.Fatal(err)
			}
			if api.clusterRestarts != tc.wantRestarts || api.managerRestarts != tc.wantManager {
				t.Errorf("restarts: cluster %d manager %d, want %d %d", api.clusterRestarts, api.managerRestarts, tc.wantRestarts, tc.wantManager)
			}
			got := reloadAnnotations(t, r, sts)
			if got[constants.AnnotationCDBListContentHash] != tc.wantApplied {
				t.Errorf("applied hash = %q, want %q", got[constants.AnnotationCDBListContentHash], tc.wantApplied)
			}
			if got[constants.AnnotationCDBListReloadPendingSince] != tc.wantPendingFrom {
				t.Errorf("pending since = %q, want %q", got[constants.AnnotationCDBListReloadPendingSince], tc.wantPendingFrom)
			}
		})
	}
}
