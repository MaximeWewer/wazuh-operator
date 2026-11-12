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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func newFetchFixture(t *testing.T, objs ...runtime.Object) *CDBListReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)
	return &CDBListReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()}
}

func sourceList(url string, src func(*wazuhv1.CDBListSource)) *wazuhv1.WazuhCDBList {
	l := &wazuhv1.WazuhCDBList{
		ObjectMeta: metav1.ObjectMeta{Name: "l", Namespace: "ns"},
		Spec:       wazuhv1.WazuhCDBListSpec{ListName: "l", Source: &wazuhv1.CDBListSource{URL: url}},
	}
	if src != nil {
		src(l.Spec.Source)
	}
	return l
}

func TestResolveURL(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "abuse", Namespace: "ns"},
		Data:       map[string][]byte{"AUTH_KEY": []byte("k3y"), "OTHER": []byte("x")},
	}
	r := newFetchFixture(t, secret)
	ref := func(key string) func(*wazuhv1.CDBListSource) {
		return func(s *wazuhv1.CDBListSource) { s.URLSecretRef = &wazuhv1.SecretReference{Name: "abuse", Key: key} }
	}
	for name, tc := range map[string]struct {
		list    *wazuhv1.WazuhCDBList
		want    string
		wantErr bool
	}{
		"no placeholder":                  {list: sourceList("https://a/feed", nil), want: "https://a/feed"},
		"placeholder resolved":            {list: sourceList("https://a/${AUTH_KEY}/recent.csv", ref("")), want: "https://a/k3y/recent.csv"},
		"Key limits the values":           {list: sourceList("https://a/${OTHER}", ref("AUTH_KEY")), wantErr: true},
		"placeholder without secret":      {list: sourceList("https://a/${AUTH_KEY}", nil), wantErr: true},
		"unknown placeholder":             {list: sourceList("https://a/${NOPE}", ref("")), wantErr: true},
		"missing secret":                  {list: sourceList("https://a/${AUTH_KEY}", func(s *wazuhv1.CDBListSource) { s.URLSecretRef = &wazuhv1.SecretReference{Name: "none"} }), wantErr: true},
		"dollar without braces untouched": {list: sourceList("https://a/$AUTH_KEY", ref("")), want: "https://a/$AUTH_KEY"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := r.resolveURL(context.Background(), tc.list)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("resolveURL = %q, %v; want %q, error %v", got, err, tc.want, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "k3y") {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
}

func TestCDBFetchCurlConfigRejectsInjection(t *testing.T) {
	for name, tc := range map[string]struct {
		url     string
		headers map[string]string
	}{
		"line break in URL":         {url: "https://a/x\nurl = \"https://evil\""},
		"line break in header":      {url: "https://a/x", headers: map[string]string{"Auth-Key": "k\noutput = \"/etc/passwd\""}},
		"header name with a colon":  {url: "https://a/x", headers: map[string]string{"X: y": "z"}},
		"header name with a space":  {url: "https://a/x", headers: map[string]string{"X y": "z"}},
		"carriage return in header": {url: "https://a/x", headers: map[string]string{"Auth-Key": "k\r"}},
	} {
		if _, err := cdbFetchCurlConfig(tc.url, tc.headers, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCDBFetchCurlConfigWithCurl feeds the rendered config to the real curl: the URL and
// headers (quotes and backslashes included) reach the server unchanged, an HTTP error
// fails the download, and TLS is verified unless the source opts out.
func TestCDBFetchCurlConfigWithCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	var gotKey, gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath = r.Header.Get("Auth-Key"), r.URL.Path
		if r.URL.Path == "/gone" {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		_, _ = w.Write([]byte("abc\n"))
	})
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	tlsSrv := httptest.NewTLSServer(handler)
	t.Cleanup(tlsSrv.Close)

	run := func(url string, headers map[string]string, insecure bool) (string, error) {
		t.Helper()
		config, err := cdbFetchCurlConfig(url, headers, insecure)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "c.curlrc")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.CommandContext(t.Context(), "curl", "-K", path).Output()
		return string(out), err
	}

	key := `a"b\c`
	if out, err := run(plain.URL+"/k3y/feed", map[string]string{"Auth-Key": key}, false); err != nil || out != "abc\n" {
		t.Fatalf("download = %q, %v", out, err)
	}
	if gotKey != key || gotPath != "/k3y/feed" {
		t.Errorf("server got header %q path %q; want %q /k3y/feed", gotKey, gotPath, key)
	}
	if _, err := run(plain.URL+"/gone", nil, false); err == nil {
		t.Error("HTTP 410 did not fail the download")
	}
	if _, err := run(tlsSrv.URL+"/feed", nil, false); err == nil {
		t.Error("self-signed certificate accepted without insecureSkipVerify")
	}
	if out, err := run(tlsSrv.URL+"/feed", nil, true); err != nil || out != "abc\n" {
		t.Errorf("insecureSkipVerify download = %q, %v", out, err)
	}
}

// TestCDBFetchConfigs asserts every init-fetch list gets its config (URL placeholders and
// headers resolved from Secrets) and a list whose Secret is missing is left out.
func TestCDBFetchConfigs(t *testing.T) {
	ok := sourceList("https://a/${AUTH_KEY}/feed", func(s *wazuhv1.CDBListSource) {
		s.URLSecretRef = &wazuhv1.SecretReference{Name: "abuse"}
		s.HeadersSecretRef = &wazuhv1.SecretReference{Name: "headers"}
	})
	broken := sourceList("https://a/${AUTH_KEY}/feed", func(s *wazuhv1.CDBListSource) {
		s.URLSecretRef = &wazuhv1.SecretReference{Name: "missing"}
	})
	broken.Name = "broken"
	r := newFetchFixture(t, ok, broken,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "abuse", Namespace: "ns"}, Data: map[string][]byte{"AUTH_KEY": []byte("k3y")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "headers", Namespace: "ns"}, Data: map[string][]byte{"X-Token": []byte("t")}},
	)
	infos := []CDBListConfigMapInfo{
		{ListCRName: "l", ListCRNamespace: "ns", Mode: cdbDeliveryInitFetch, FetchConfigKey: "k-ok"},
		{ListCRName: "broken", ListCRNamespace: "ns", Mode: cdbDeliveryInitFetch, FetchConfigKey: "k-broken"},
		{ListCRName: "cm", ListCRNamespace: "ns", Mode: cdbDeliveryConfigMap},
	}
	configs := r.CDBFetchConfigs(context.Background(), infos)
	if len(configs) != 1 {
		t.Fatalf("configs = %v, want only k-ok", configs)
	}
	got := string(configs["k-ok"])
	for _, want := range []string{`url = "https://a/k3y/feed"`, `header = "X-Token: t"`, "fail\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "insecure") {
		t.Errorf("config disables TLS verification:\n%s", got)
	}
	if cdbFetchConfigKey("ioc/a") == cdbFetchConfigKey("ioc_a") {
		t.Error("config keys collide")
	}
}

// TestReconcileCDBFetchSecret asserts the Secret holds the fetch configs, is owned by the
// cluster, and is deleted once the cluster has no init-fetch list.
func TestReconcileCDBFetchSecret(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns", UID: "uid"}}
	list := sourceList("https://a/feed", nil)
	cdb := newFetchFixture(t, cluster, list)
	r := &ClusterReconciler{Client: cdb.Client, Scheme: cdb.Client.Scheme(), CDBListReconciler: cdb}
	infos := []CDBListConfigMapInfo{{ListCRName: "l", ListCRNamespace: "ns", Mode: cdbDeliveryInitFetch, FetchConfigKey: "k"}}

	if err := r.reconcileCDBFetchSecret(context.Background(), cluster, infos); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c-cdb-fetch", Namespace: "ns"}, secret); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secret.Data["k"]), `url = "https://a/feed"`) || len(secret.OwnerReferences) != 1 {
		t.Errorf("secret = %v, owners %v", secret.Data, secret.OwnerReferences)
	}

	if err := r.reconcileCDBFetchSecret(context.Background(), cluster, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "c-cdb-fetch", Namespace: "ns"}, secret); !apierrors.IsNotFound(err) {
		t.Errorf("secret kept without init-fetch lists: %v", err)
	}
}
