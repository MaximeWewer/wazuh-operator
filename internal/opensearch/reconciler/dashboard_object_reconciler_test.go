package reconciler

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/dashboards"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// fakeDashboardAPI records the calls of one target cluster.
type fakeDashboardAPI struct {
	imports   []string // tenant of each import
	deleted   []string // "tenant:type/id"
	importErr error
	deleteErr error
}

func (f *fakeDashboardAPI) Import(_ context.Context, tenant string, ndjson []byte) (int, error) {
	f.imports = append(f.imports, tenant)
	if f.importErr != nil {
		return 0, f.importErr
	}
	objs, err := dashboards.ParseNDJSON(ndjson)
	return len(objs), err
}

func (f *fakeDashboardAPI) Delete(_ context.Context, tenant string, obj dashboards.ObjectRef) error {
	f.deleted = append(f.deleted, tenant+":"+obj.String())
	return f.deleteErr
}

const (
	twoObjects = `{"type":"index-pattern","id":"wazuh-alerts","attributes":{}}
{"type":"dashboard","id":"soc","attributes":{}}`
	oneObject = `{"type":"dashboard","id":"soc","attributes":{}}`
)

func newDashboardObjectFixture(t *testing.T, obj *wazuhv1.OpenSearchDashboardObject, extra ...client.Object) (*DashboardObjectReconciler, client.Client, map[string]*fakeDashboardAPI) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)
	objs := append([]client.Object{obj}, extra...)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&wazuhv1.OpenSearchDashboardObject{}).Build()
	apis := map[string]*fakeDashboardAPI{}
	r := NewDashboardObjectReconciler(c, scheme, nil)
	r.NewAPI = func(_ context.Context, ref wazuhv1.WazuhClusterRef) (DashboardObjectsAPI, error) {
		api, ok := apis[ref.Name]
		if !ok {
			return nil, fmt.Errorf("dashboard of %s not reachable", ref.Name)
		}
		return api, nil
	}
	return r, c, apis
}

func dashboardObject(source wazuhv1.DashboardObjectSource, clusters ...string) *wazuhv1.OpenSearchDashboardObject {
	obj := &wazuhv1.OpenSearchDashboardObject{
		ObjectMeta: metav1.ObjectMeta{Name: "soc", Namespace: "wazuh", Generation: 1},
		Spec:       wazuhv1.OpenSearchDashboardObjectSpec{Source: source},
	}
	for _, c := range clusters {
		obj.Spec.ClusterRefs = append(obj.Spec.ClusterRefs, wazuhv1.WazuhClusterRef{Name: c, Namespace: "wazuh"})
	}
	return obj
}

func reload(t *testing.T, c client.Client, obj *wazuhv1.OpenSearchDashboardObject) *wazuhv1.OpenSearchDashboardObject {
	t.Helper()
	got := &wazuhv1.OpenSearchDashboardObject{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}, got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDashboardObjectImportsAndSchedulesResync(t *testing.T) {
	obj := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: twoObjects}, "c1", "c2")
	obj.Spec.ResyncInterval = &metav1.Duration{Duration: 2 * time.Minute}
	r, c, apis := newDashboardObjectFixture(t, obj)
	apis["c1"], apis["c2"] = &fakeDashboardAPI{}, &fakeDashboardAPI{}

	after, err := r.Reconcile(context.Background(), obj)
	if err != nil {
		t.Fatal(err)
	}
	if after != 2*time.Minute {
		t.Errorf("requeueAfter = %v, want the resync interval", after)
	}
	got := reload(t, c, obj)
	if got.Status.Phase != wazuhv1.OpenSearchResourcePhaseReady || got.Status.ObjectCount != 2 || len(got.Status.Objects) != 2 {
		t.Errorf("status = %+v", got.Status)
	}
	if len(apis["c1"].imports) != 1 || len(apis["c2"].imports) != 1 {
		t.Errorf("each cluster must be imported once: c1=%v c2=%v", apis["c1"].imports, apis["c2"].imports)
	}
	if got.Status.LastSyncTime == nil || got.Status.LastAppliedHash == "" {
		t.Error("lastSyncTime and lastAppliedHash must be set")
	}

	// Git is the truth: an unchanged source is re-imported at every sync.
	if _, err := r.Reconcile(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if len(apis["c1"].imports) != 2 {
		t.Errorf("unchanged source not re-imported at resync: %v", apis["c1"].imports)
	}
}

func TestDashboardObjectPrunesObjectsRemovedFromSource(t *testing.T) {
	obj := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: oneObject}, "c1")
	obj.Status.Objects = []wazuhv1.DashboardObjectStatusRef{{Type: "index-pattern", ID: "wazuh-alerts"}, {Type: "dashboard", ID: "soc"}}
	r, c, apis := newDashboardObjectFixture(t, obj)
	apis["c1"] = &fakeDashboardAPI{}

	if _, err := r.Reconcile(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if len(apis["c1"].deleted) != 1 || apis["c1"].deleted[0] != ":index-pattern/wazuh-alerts" {
		t.Errorf("deleted = %v, want only the object removed from the source", apis["c1"].deleted)
	}
	if got := reload(t, c, obj); len(got.Status.Objects) != 1 {
		t.Errorf("managed objects = %v", got.Status.Objects)
	}

	// prune: false keeps the removed object.
	obj2 := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: oneObject}, "c1")
	obj2.Spec.Prune = new(bool)
	obj2.Status.Objects = []wazuhv1.DashboardObjectStatusRef{{Type: "index-pattern", ID: "wazuh-alerts"}}
	r2, _, apis2 := newDashboardObjectFixture(t, obj2)
	apis2["c1"] = &fakeDashboardAPI{}
	if _, err := r2.Reconcile(context.Background(), obj2); err != nil {
		t.Fatal(err)
	}
	if len(apis2["c1"].deleted) != 0 {
		t.Errorf("prune disabled but deleted %v", apis2["c1"].deleted)
	}
}

func TestDashboardObjectTenantChangeRemovesOldTenantObjects(t *testing.T) {
	obj := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: oneObject}, "c1")
	obj.Spec.Tenant = "secops"
	obj.Status.Tenant = "global"
	obj.Status.Objects = []wazuhv1.DashboardObjectStatusRef{{Type: "dashboard", ID: "soc"}}
	r, c, apis := newDashboardObjectFixture(t, obj)
	apis["c1"] = &fakeDashboardAPI{}

	if _, err := r.Reconcile(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if apis["c1"].imports[0] != "secops" || len(apis["c1"].deleted) != 1 || apis["c1"].deleted[0] != "global:dashboard/soc" {
		t.Errorf("imports=%v deleted=%v", apis["c1"].imports, apis["c1"].deleted)
	}
	if got := reload(t, c, obj); got.Status.Tenant != "secops" {
		t.Errorf("status.tenant = %q", got.Status.Tenant)
	}
}

func TestDashboardObjectFailureKeepsObjectsToPrune(t *testing.T) {
	obj := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: oneObject}, "c1", "down")
	obj.Status.Objects = []wazuhv1.DashboardObjectStatusRef{{Type: "index-pattern", ID: "old"}, {Type: "dashboard", ID: "soc"}}
	r, c, apis := newDashboardObjectFixture(t, obj)
	apis["c1"] = &fakeDashboardAPI{}

	if _, err := r.Reconcile(context.Background(), obj); err == nil {
		t.Fatal("expected an error while a target dashboard is unreachable")
	}
	got := reload(t, c, obj)
	if got.Status.Phase != wazuhv1.OpenSearchResourcePhasePending {
		t.Errorf("phase = %s, want Pending", got.Status.Phase)
	}
	if len(got.Status.Objects) != 2 {
		t.Errorf("objects still to prune on the unreachable cluster were dropped: %v", got.Status.Objects)
	}
}

func TestDashboardObjectReadsConfigMap(t *testing.T) {
	obj := dashboardObject(wazuhv1.DashboardObjectSource{
		ConfigMapRef: &wazuhv1.DashboardObjectConfigMapRef{Name: "soc-dashboards"},
	}, "c1")
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "soc-dashboards", Namespace: "wazuh"},
		Data:       map[string]string{"export.ndjson": twoObjects},
	}
	r, c, apis := newDashboardObjectFixture(t, obj, cm)
	apis["c1"] = &fakeDashboardAPI{}

	if _, err := r.Reconcile(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if got := reload(t, c, obj); got.Status.ObjectCount != 2 {
		t.Errorf("objectCount = %d, want 2", got.Status.ObjectCount)
	}
}

func TestDashboardObjectInvalidSourceFailsWithoutCallingDashboard(t *testing.T) {
	for name, src := range map[string]wazuhv1.DashboardObjectSource{
		"invalid ndjson":    {NDJSON: "not json"},
		"missing configmap": {ConfigMapRef: &wazuhv1.DashboardObjectConfigMapRef{Name: "nope"}},
	} {
		obj := dashboardObject(src, "c1")
		r, c, apis := newDashboardObjectFixture(t, obj)
		apis["c1"] = &fakeDashboardAPI{}
		if _, err := r.Reconcile(context.Background(), obj); err != nil {
			t.Fatalf("%s: reconcile error %v (the failure belongs in the status)", name, err)
		}
		if got := reload(t, c, obj); got.Status.Phase != wazuhv1.OpenSearchResourcePhaseFailed {
			t.Errorf("%s: phase = %s, want Failed", name, got.Status.Phase)
		}
		if len(apis["c1"].imports) != 0 {
			t.Errorf("%s: dashboard called with an invalid source", name)
		}
	}
}

func TestDashboardObjectDeletionRemovesObjects(t *testing.T) {
	now := metav1.Now()
	obj := dashboardObject(wazuhv1.DashboardObjectSource{NDJSON: oneObject}, "c1", "gone")
	obj.DeletionTimestamp = &now
	obj.Finalizers = []string{constants.DashboardObjectFinalizer}
	obj.Status.Tenant = "secops"
	obj.Status.Objects = []wazuhv1.DashboardObjectStatusRef{{Type: "dashboard", ID: "soc"}}
	r, c, apis := newDashboardObjectFixture(t, obj)
	failing := &fakeDashboardAPI{deleteErr: fmt.Errorf("HTTP 503")}
	apis["c1"] = failing

	// A failed delete keeps the finalizer: the objects must not be leaked.
	if _, err := r.Reconcile(context.Background(), obj); err == nil {
		t.Fatal("expected an error while the delete fails")
	}
	if got := reload(t, c, obj); len(got.Finalizers) != 1 {
		t.Fatal("finalizer removed although the objects were not deleted")
	}

	apis["c1"] = &fakeDashboardAPI{}
	r.NewAPI = func(_ context.Context, ref wazuhv1.WazuhClusterRef) (DashboardObjectsAPI, error) {
		if ref.Name == "gone" {
			return nil, fmt.Errorf("WazuhCluster wazuh/gone has no dashboard")
		}
		return apis["c1"], nil
	}
	if _, err := r.Reconcile(context.Background(), reload(t, c, obj)); err != nil {
		t.Fatal(err)
	}
	if len(apis["c1"].deleted) != 1 || apis["c1"].deleted[0] != "secops:dashboard/soc" {
		t.Errorf("deleted = %v", apis["c1"].deleted)
	}
	got := &wazuhv1.OpenSearchDashboardObject{}
	err := c.Get(context.Background(), types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}, got)
	if err == nil && len(got.Finalizers) != 0 {
		t.Error("finalizer not removed after a successful cleanup")
	}
}
