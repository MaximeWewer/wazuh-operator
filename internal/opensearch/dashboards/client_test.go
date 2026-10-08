package dashboards

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
)

const sampleExport = `{"attributes":{"title":"wazuh-alerts-*"},"id":"wazuh-alerts","type":"index-pattern"}
{"attributes":{"title":"SOC overview"},"id":"soc-overview","type":"dashboard"}

{"exportedCount":2,"missingRefCount":0,"missingReferences":[]}
`

func TestParseNDJSON(t *testing.T) {
	objs, err := ParseNDJSON([]byte(sampleExport))
	if err != nil {
		t.Fatal(err)
	}
	want := []ObjectRef{{"index-pattern", "wazuh-alerts"}, {"dashboard", "soc-overview"}}
	if len(objs) != len(want) || objs[0] != want[0] || objs[1] != want[1] {
		t.Fatalf("ParseNDJSON() = %v, want %v", objs, want)
	}

	for name, in := range map[string]string{
		"invalid json":    "{not json}\n",
		"missing id":      `{"type":"dashboard"}`,
		"duplicate":       `{"type":"dashboard","id":"a"}` + "\n" + `{"type":"dashboard","id":"a"}`,
		"only summary":    `{"exportedCount":0}`,
		"empty":           "\n\n",
		"array not lines": `[{"type":"dashboard","id":"a"}]`,
	} {
		if _, err := ParseNDJSON([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// newTLSClient starts a TLS test server and returns a Client trusting its certificate.
func newTLSClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := NewClient(&security.DashboardConnectionInfo{
		BaseURL: srv.URL, Username: "admin", Password: "secret", CACert: caPEM,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestImportSendsMultipartWithOverwriteAndTenant(t *testing.T) {
	var gotTenant, gotXSRF, gotQuery, gotFile string
	var gotAuthOK bool
	c := newTLSClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/saved_objects/_import" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		gotAuthOK = ok && user == "admin" && pass == "secret"
		gotTenant, gotXSRF, gotQuery = r.Header.Get("securitytenant"), r.Header.Get("osd-xsrf"), r.URL.RawQuery
		f, _, err := r.FormFile("file")
		if err != nil {
			t.Errorf("no multipart file: %v", err)
		} else {
			b, _ := io.ReadAll(f)
			gotFile = string(b)
		}
		_, _ = io.WriteString(w, `{"success":true,"successCount":2}`)
	})

	n, err := c.Import(context.Background(), "private", []byte(sampleExport))
	if err != nil || n != 2 {
		t.Fatalf("Import() = %d, %v", n, err)
	}
	if !gotAuthOK || gotXSRF != "true" || gotQuery != "overwrite=true" || gotTenant != "__user__" || gotFile != sampleExport {
		t.Errorf("request: auth=%v xsrf=%q query=%q tenant=%q file-match=%v",
			gotAuthOK, gotXSRF, gotQuery, gotTenant, gotFile == sampleExport)
	}
}

func TestImportReportsRejectedObjects(t *testing.T) {
	c := newTLSClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":false,"successCount":1,"errors":[{"type":"visualization","id":"v1","error":{"type":"missing_references"}}]}`)
	})
	_, err := c.Import(context.Background(), "", []byte(sampleExport))
	if err == nil || !strings.Contains(err.Error(), "visualization/v1 (missing_references)") {
		t.Fatalf("Import() error = %v, want the rejected object", err)
	}
}

func TestImportHTTPError(t *testing.T) {
	c := newTLSClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
	})
	_, err := c.Import(context.Background(), "", []byte(sampleExport))
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "custom jwtHeader") {
		t.Fatalf("Import() error = %v, want HTTP 401 with the custom JWT header hint", err)
	}
}

func TestDeleteToleratesMissingObject(t *testing.T) {
	var gotPath, gotTenant string
	status := http.StatusNotFound
	c := newTLSClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotTenant = r.URL.EscapedPath(), r.Header.Get("securitytenant")
		w.WriteHeader(status)
	})
	if err := c.Delete(context.Background(), "", ObjectRef{"index-pattern", "wazuh alerts"}); err != nil {
		t.Fatalf("Delete() of a missing object = %v", err)
	}
	if gotPath != "/api/saved_objects/index-pattern/wazuh%20alerts" || gotTenant != "" {
		t.Errorf("path=%q tenant=%q", gotPath, gotTenant)
	}
	status = http.StatusForbidden
	if err := c.Delete(context.Background(), "secops", ObjectRef{"dashboard", "d"}); err == nil {
		t.Fatal("Delete() must fail on HTTP 403")
	}
	if gotTenant != "secops" {
		t.Errorf("custom tenant header = %q", gotTenant)
	}
}

// TestTenantHeader guards the header values verified against a live Wazuh dashboard: the
// global tenant is "global_tenant" ("global" is rejected with HTTP 403).
func TestTenantHeader(t *testing.T) {
	for tenant, want := range map[string]string{"": "", "global": "global_tenant", "private": "__user__", "secops": "secops"} {
		if got := tenantHeader(tenant); got != want {
			t.Errorf("tenantHeader(%q) = %q, want %q", tenant, got, want)
		}
	}
}
