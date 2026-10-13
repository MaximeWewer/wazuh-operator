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

package adapters

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeWazuhAPI serves logins and GET /manager/info, answering status for the latter.
type fakeWazuhAPI struct {
	logins   atomic.Int32
	requests atomic.Int32
	status   atomic.Int32
}

func (f *fakeWazuhAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security/user/authenticate" {
			f.logins.Add(1)
			time.Sleep(20 * time.Millisecond) // widen the window for concurrent logins
			_, _ = w.Write([]byte(`{"data":{"token":"t"},"error":0}`))
			return
		}
		f.requests.Add(1)
		w.WriteHeader(int(f.status.Load()))
		_, _ = w.Write([]byte(`{"data":{},"error":0}`))
	})
}

func newFakeWazuhAPI(t *testing.T) (*fakeWazuhAPI, *WazuhAPIAdapter) {
	t.Helper()
	f := &fakeWazuhAPI{}
	f.status.Store(http.StatusOK)
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	return f, NewWazuhAPIAdapter(WazuhAPIConfig{BaseURL: srv.URL, Username: "u", Password: "p", Insecure: true})
}

func TestWazuhAPIAdapterConcurrentCallersShareOneLogin(t *testing.T) {
	f, a := newFakeWazuhAPI(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := a.GetManagerInfo(context.Background()); err != nil {
				t.Errorf("GetManagerInfo: %v", err)
			}
		})
	}
	wg.Wait()
	if n := f.logins.Load(); n != 1 {
		t.Errorf("logins = %d, want 1 for 20 concurrent callers", n)
	}
}

func TestWazuhAPIAdapterBacksOffWhileUnavailable(t *testing.T) {
	f, a := newFakeWazuhAPI(t)
	ctx := context.Background()

	f.status.Store(http.StatusTooManyRequests)
	if _, err := a.GetManagerInfo(ctx); !errors.Is(err, ErrAPIUnavailable) {
		t.Fatalf("on 429: err = %v, want ErrAPIUnavailable", err)
	}
	sent := f.requests.Load()

	// During the back-off every call fails fast without reaching the API.
	for range 10 {
		if _, err := a.GetManagerInfo(ctx); !errors.Is(err, ErrAPIUnavailable) {
			t.Fatalf("during back-off: err = %v, want ErrAPIUnavailable", err)
		}
	}
	if n := f.requests.Load(); n != sent {
		t.Errorf("requests during back-off = %d, want 0", n-sent)
	}

	// Once the back-off is over and the API answers again, calls go through and the
	// back-off is reset.
	f.status.Store(http.StatusOK)
	a.mu.Lock()
	a.unavailableUntil = time.Now()
	a.mu.Unlock()
	if _, err := a.GetManagerInfo(ctx); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	a.mu.Lock()
	failures := a.failures
	a.mu.Unlock()
	if failures != 0 {
		t.Errorf("failures after recovery = %d, want 0", failures)
	}
}

func TestWazuhAPIAdapterBackoffGrows(t *testing.T) {
	a := NewWazuhAPIAdapter(WazuhAPIConfig{BaseURL: "https://127.0.0.1:1"})
	var got []time.Duration
	for range 6 {
		start := time.Now()
		_ = a.markUnavailable(0, errors.New("down"))
		got = append(got, a.unavailableUntil.Sub(start).Round(time.Second))
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("back-off %d = %s, want %s", i+1, got[i], want[i])
		}
	}
}

func TestWazuhAPIAdapterUnreachableIsUnavailable(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more: connection refused

	a := NewWazuhAPIAdapter(WazuhAPIConfig{BaseURL: url, Username: "u", Password: "p", Insecure: true})
	if _, err := a.GetManagerInfo(context.Background()); !errors.Is(err, ErrAPIUnavailable) {
		t.Errorf("err = %v, want ErrAPIUnavailable", err)
	}
}

func TestSharedWazuhAPIAdapter(t *testing.T) {
	cfg := WazuhAPIConfig{BaseURL: "https://shared.test:55000", Username: "u", Password: "p1", Insecure: true}
	a1 := SharedWazuhAPIAdapter(cfg)
	if a2 := SharedWazuhAPIAdapter(cfg); a2 != a1 {
		t.Error("same config must return the same adapter")
	}
	cfg.Password = "p2"
	a3 := SharedWazuhAPIAdapter(cfg)
	if a3 == a1 {
		t.Error("a new password must return a new adapter")
	}
	cfg.Password = "p1"
	if a4 := SharedWazuhAPIAdapter(cfg); a4 == a1 {
		t.Error("the adapter of the replaced password must have been dropped")
	}
}

func TestWazuhAPIAdapterRateLimit(t *testing.T) {
	f, a := newFakeWazuhAPI(t)
	f.status.Store(http.StatusTooManyRequests)

	start := time.Now()
	_, err := a.GetManagerInfo(context.Background())
	if !errors.Is(err, ErrAPIRateLimited) || !errors.Is(err, ErrAPIUnavailable) {
		t.Fatalf("on 429: err = %v, want ErrAPIRateLimited wrapping ErrAPIUnavailable", err)
	}
	// The pause covers the API quota window plus jitter, not the 5s of an outage.
	a.mu.Lock()
	wait := a.unavailableUntil.Sub(start)
	a.mu.Unlock()
	if wait < apiRateLimitBackoff || wait > apiRateLimitBackoff+apiRateLimitJitter+time.Second {
		t.Errorf("back-off after 429 = %s, want between 1m and 1m15s", wait)
	}
	// A rate-limited API is up: health checks must not report it down, during the
	// back-off either.
	if !a.IsHealthy(context.Background()) {
		t.Error("IsHealthy = false for a rate-limited API, want true")
	}
}

func TestGetUserRunAs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security/user/authenticate" {
			_, _ = w.Write([]byte(`{"data":{"token":"t"},"error":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"affected_items":[` +
			`{"id":1,"username":"wazuh","allow_run_as":false},` +
			`{"id":100,"username":"wazuh-wui","allow_run_as":true}]},"error":0}`))
	}))
	t.Cleanup(srv.Close)
	a := NewWazuhAPIAdapter(WazuhAPIConfig{BaseURL: srv.URL, Username: "u", Password: "p", Insecure: true})

	id, runAs, err := a.GetUserRunAs(context.Background(), "wazuh-wui")
	if err != nil || id != 100 || !runAs {
		t.Errorf("GetUserRunAs(wazuh-wui) = %d, %v, %v; want 100, true, nil", id, runAs, err)
	}
	if id, _, err := a.GetUserRunAs(context.Background(), "missing"); err != nil || id != 0 {
		t.Errorf("GetUserRunAs(missing) = %d, %v; want 0, nil", id, err)
	}
}
