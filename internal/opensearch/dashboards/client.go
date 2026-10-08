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

// Package dashboards is a minimal client for the OpenSearch Dashboards saved objects API,
// used to manage dashboards, visualizations, index patterns and saved searches as code.
package dashboards

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
)

// TenantGlobal and TenantPrivate are the reserved OpenSearch Dashboards tenant names.
const (
	TenantGlobal  = "global"
	TenantPrivate = "private"
)

// ObjectRef identifies one saved object.
type ObjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// String returns "type/id".
func (o ObjectRef) String() string { return o.Type + "/" + o.ID }

// Client calls the saved objects API of one OpenSearch Dashboards instance.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient builds a client from the connection info of a cluster's dashboard.
func NewClient(info *security.DashboardConnectionInfo, timeout time.Duration) (*Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(info.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(info.CACert) {
			return nil, fmt.Errorf("failed to parse dashboard CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL:  strings.TrimRight(info.BaseURL, "/"),
		username: info.Username,
		password: info.Password,
		httpClient: &http.Client{
			Transport: telemetry.WrapTransport(&http.Transport{TLSClientConfig: tlsConfig}, "opensearch-dashboards-api"),
			Timeout:   timeout,
		},
	}, nil
}

// ImportError is one object the import API rejected.
type ImportError struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Title string `json:"title"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type importResponse struct {
	Success      bool          `json:"success"`
	SuccessCount int           `json:"successCount"`
	Errors       []ImportError `json:"errors"`
}

// Import imports an NDJSON saved objects export into tenant, overwriting the objects that
// already exist with the same type and id (Git is the source of truth). It returns the
// number of imported objects.
func (c *Client) Import(ctx context.Context, tenant string, ndjson []byte) (int, error) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "export.ndjson")
	if err != nil {
		return 0, err
	}
	if _, err := part.Write(ndjson); err != nil {
		return 0, err
	}
	if err := form.Close(); err != nil {
		return 0, err
	}

	resp, err := c.do(ctx, http.MethodPost, "/api/saved_objects/_import?overwrite=true", tenant, &body, form.FormDataContentType())
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("import failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		if resp.StatusCode == http.StatusUnauthorized {
			// The dashboard forwards any Authorization header to the indexer, except when its
			// JWT authentication reads the token from a custom header.
			err = fmt.Errorf("%w (the dashboard ignores the Authorization header: JWT with a custom jwtHeader is not supported)", err)
		}
		return 0, err
	}

	var result importResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, fmt.Errorf("failed to decode import response: %w", err)
	}
	if !result.Success {
		msgs := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			reason := e.Error.Type
			if e.Error.Message != "" {
				reason += ": " + e.Error.Message
			}
			msgs = append(msgs, fmt.Sprintf("%s/%s (%s)", e.Type, e.ID, reason))
		}
		return result.SuccessCount, fmt.Errorf("import rejected %d object(s): %s", len(result.Errors), strings.Join(msgs, "; "))
	}
	return result.SuccessCount, nil
}

// Delete deletes a saved object from tenant. A missing object is not an error.
func (c *Client) Delete(ctx context.Context, tenant string, obj ObjectRef) error {
	path := "/api/saved_objects/" + url.PathEscape(obj.Type) + "/" + url.PathEscape(obj.ID)
	resp, err := c.do(ctx, http.MethodDelete, path, tenant, nil, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("delete %s failed: HTTP %d: %s", obj, resp.StatusCode, strings.TrimSpace(string(raw)))
}

func (c *Client) do(ctx context.Context, method, path, tenant string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	// Required by OpenSearch Dashboards on every mutating API call (CSRF protection).
	req.Header.Set("osd-xsrf", "true")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if h := tenantHeader(tenant); h != "" {
		req.Header.Set("securitytenant", h)
	}
	return c.httpClient.Do(req)
}

// tenantHeader maps a tenant name to the securitytenant header value the security plugin
// expects: "global_tenant" and "__user__" are the internal names of the global and private
// tenants ("global" itself is rejected with a 403 as an unknown tenant). Empty means the
// header is not sent: the dashboard then uses the user's default tenant (the private one
// when multi-tenancy is enabled).
func tenantHeader(tenant string) string {
	switch tenant {
	case "":
		return ""
	case TenantGlobal:
		return "global_tenant"
	case TenantPrivate:
		return "__user__"
	default:
		return tenant
	}
}

// ParseNDJSON validates an NDJSON saved objects export and returns the objects it holds,
// in order. Blank lines and the export summary line ({"exportedCount":...}) are skipped;
// every other line must be a JSON object with a non-empty type and id.
func ParseNDJSON(data []byte) ([]ObjectRef, error) {
	var objs []ObjectRef
	seen := map[ObjectRef]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 16<<20)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			return nil, fmt.Errorf("line %d: invalid JSON: %w", line, err)
		}
		if _, summary := raw["exportedCount"]; summary {
			continue
		}
		var obj ObjectRef
		_ = json.Unmarshal([]byte(text), &obj)
		if obj.Type == "" || obj.ID == "" {
			return nil, fmt.Errorf("line %d: saved object without type or id", line)
		}
		if seen[obj] {
			return nil, fmt.Errorf("line %d: duplicate saved object %s", line, obj)
		}
		seen[obj] = true
		objs = append(objs, obj)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read NDJSON: %w", err)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("no saved object found")
	}
	return objs, nil
}
