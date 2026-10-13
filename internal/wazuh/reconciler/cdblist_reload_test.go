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
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	reloads         int
	reloadErr       error
	uploads         []string
}

func (f *fakeReloadAPI) UploadListFile(_ context.Context, name, content string) error {
	f.uploads = append(f.uploads, name)
	f.files[name] = content
	return nil
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

func (f *fakeReloadAPI) ReloadAnalysisd(context.Context) error {
	f.reloads++
	return f.reloadErr
}

func cdbInfo(name, content string) CDBListConfigMapInfo {
	return CDBListConfigMapInfo{ConfigMapName: "cm-" + name, FileName: name, Key: name, Mode: cdbDeliveryConfigMap, ContentHash: computeCDBListHash(content)}
}

// newReloadFixture returns a reconciler whose client holds the master StatefulSet and, for
// each list in configMaps, its content ConfigMap "cm-<list>".
func newReloadFixture(t *testing.T, annotations map[string]string, configMaps map[string]string) (*ClusterReconciler, *appsv1.StatefulSet) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "c-manager-master", Namespace: "ns", Annotations: annotations}}
	b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sts)
	for list, content := range configMaps {
		b = b.WithObjects(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm-" + list, Namespace: "ns"}, Data: map[string]string{list: content}})
	}
	c := b.Build()
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
	if CDBListContentHash([]CDBListConfigMapInfo{fetched, cdbInfo("dir/c", "3:z\n")}) != "" {
		t.Error("hash of lists the API cannot update should be empty")
	}
}

// TestReconcileCDBListReloadAdoptsUnknownState asserts a StatefulSet without the content
// annotation (new, or created by an older operator) records the current content without
// restarting anything: its pods loaded that content at start.
func TestSupportsAnalysisdReload(t *testing.T) {
	for v, want := range map[string]bool{"4.9.0": false, "4.12.1": false, "4.13.0": true, "4.14.8": true, "5.0.0": true, "": false} {
		if got := supportsAnalysisdReload(v); got != want {
			t.Errorf("supportsAnalysisdReload(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestReconcileCDBListReloadAdoptsUnknownState(t *testing.T) {
	r, sts := newReloadFixture(t, nil, nil)
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
	// "dir/c" sits in a subdirectory: the API cannot update it, a change rolls the pods.
	infos := []CDBListConfigMapInfo{cdbInfo("a", "1:new\n"), cdbInfo("b", "2:y\n"), cdbInfo("dir/c", "3:z\n")}
	want := CDBListContentHash(infos)
	current := map[string]string{"a": "1:new\n", "b": "2:y\n"}
	lagging := map[string]string{"a": "1:old\n", "b": "2:y\n"}

	for _, tc := range []struct {
		name            string
		version         string
		configMaps      map[string]string // ConfigMap content per list
		files           map[string]string // content the master serves
		synced          bool
		pendingSince    string
		clusterErr      error
		reloadErr       error
		wantErr         bool
		wantUploads     int
		wantReloads     int
		wantRestarts    int
		wantManager     int
		wantApplied     string
		wantPendingFrom string
	}{
		{name: "master serves the old content: upload it, then wait for the workers",
			configMaps: current, files: map[string]string{"a": "1:old\n", "b": "2:y\n"}, synced: false,
			wantUploads: 1, wantApplied: "old", wantPendingFrom: now.Format(time.RFC3339)},
		{name: "list missing on the master: upload it and restart once the nodes are in sync",
			configMaps: current, files: map[string]string{"b": "2:y\n"}, synced: true,
			wantUploads: 1, wantRestarts: 1, wantApplied: want},
		{name: "ConfigMap not updated yet: wait",
			configMaps: lagging, files: map[string]string{"a": "1:old\n", "b": "2:y\n"}, synced: true, pendingSince: now.Add(-time.Minute).Format(time.RFC3339),
			wantApplied: "old", wantPendingFrom: now.Add(-time.Minute).Format(time.RFC3339)},
		{name: "a worker is not in sync yet: wait",
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: false,
			wantApplied: "old", wantPendingFrom: now.Format(time.RFC3339)},
		{name: "every node holds the new content: one cluster restart",
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true, pendingSince: now.Add(-time.Minute).Format(time.RFC3339),
			wantRestarts: 1, wantApplied: want},
		{name: "still stale after the max wait: restart anyway",
			configMaps: lagging, files: map[string]string{"a": "1:old\n", "b": "2:y\n"}, synced: true, pendingSince: now.Add(-cdbListReloadMaxWait).Format(time.RFC3339),
			wantRestarts: 1, wantApplied: want},
		{name: "cluster restart rejected: restart the manager",
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true, clusterErr: errors.New("cluster restart failed with status 400"),
			wantRestarts: 1, wantManager: 1, wantApplied: want},
		{name: "4.13+: ruleset reload, no restart", version: "4.14.8",
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true,
			wantReloads: 1, wantApplied: want},
		{name: "4.13+ worker not in sync: wait, no reload", version: "4.13.0",
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: false,
			wantApplied: "old", wantPendingFrom: now.Format(time.RFC3339)},
		{name: "reload endpoint missing: restart instead", version: "4.13.0", reloadErr: fmt.Errorf("analysisd reload: %w", adapters.ErrEndpointNotFound),
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true,
			wantReloads: 1, wantRestarts: 1, wantApplied: want},
		{name: "reload rejected: keep the old state and retry", version: "4.14.8", reloadErr: errors.New("analysisd reload failed on 1 node(s)"),
			configMaps: current, files: map[string]string{"a": "1:new\n", "b": "2:y\n"}, synced: true,
			wantErr: true, wantReloads: 1, wantApplied: "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ann := map[string]string{constants.AnnotationCDBListContentHash: "old"}
			if tc.pendingSince != "" {
				ann[constants.AnnotationCDBListReloadPendingSince] = tc.pendingSince
			}
			r, sts := newReloadFixture(t, ann, tc.configMaps)
			api := &fakeReloadAPI{files: tc.files, synced: tc.synced, clusterErr: tc.clusterErr, reloadErr: tc.reloadErr}
			cluster := &wazuhv1.WazuhCluster{ObjectMeta: metav1.ObjectMeta{Namespace: "ns"}, Spec: wazuhv1.WazuhClusterSpec{Version: tc.version}}
			err := r.reloadCDBLists(context.Background(), cluster, sts, api, infos, want, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("reloadCDBLists error = %v, want error %v", err, tc.wantErr)
			}
			if len(api.uploads) != tc.wantUploads || api.reloads != tc.wantReloads {
				t.Errorf("uploads %v, reloads %d; want %d uploads, %d reloads", api.uploads, api.reloads, tc.wantUploads, tc.wantReloads)
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

// TestCDBListRestartHash asserts a content change rolls the manager pods only for a list
// the API cannot update (in a subdirectory of etc/lists).
func TestCDBListRestartHash(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	list := func(name, listName, contentHash string) *wazuhv1.WazuhCDBList {
		return &wazuhv1.WazuhCDBList{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
			Spec: wazuhv1.WazuhCDBListSpec{ListName: listName,
				ClusterRefs: []wazuhv1.WazuhClusterRef{{Name: "c", Namespace: "ns"}}},
			Status: wazuhv1.WazuhCDBListStatus{ContentHash: contentHash, ClusterStatuses: []wazuhv1.CDBListClusterStatus{{
				Name: "c", Namespace: "ns", Phase: wazuhv1.CDBListPhaseApplied, DeliveryMode: cdbDeliveryConfigMap,
				ConfigMapRef: &wazuhv1.ConfigMapReference{Name: "cm", Namespace: "ns"},
			}}},
		}
	}
	restartHash := func(lists ...*wazuhv1.WazuhCDBList) string {
		t.Helper()
		b := fake.NewClientBuilder().WithScheme(scheme)
		for _, l := range lists {
			b = b.WithObjects(l)
		}
		r := &CDBListReconciler{Client: b.Build()}
		_, hash, err := r.GetCDBListConfigMapsForCluster(context.Background(), "c", "ns")
		if err != nil {
			t.Fatal(err)
		}
		return hash
	}

	if restartHash(list("top", "ips", "h1")) != restartHash(list("top", "ips", "h2")) {
		t.Error("a content change of a list under etc/lists changes the restart hash")
	}
	if restartHash(list("sub", "ioc/ips", "h1")) == restartHash(list("sub", "ioc/ips", "h2")) {
		t.Error("a content change of a list in a subdirectory does not change the restart hash")
	}
	if restartHash(list("top", "ips", "h1")) == restartHash(list("top", "ips", "h1"), list("other", "users", "h1")) {
		t.Error("adding a list does not change the restart hash")
	}
}
