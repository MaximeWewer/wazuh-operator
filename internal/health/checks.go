package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// InformerSyncChecker returns a healthz.Checker that verifies the manager's
// informer cache has synced. Before cache sync, the operator cannot read
// resources reliably and should not be considered ready.
func InformerSyncChecker(mgr manager.Manager) healthz.Checker {
	return func(_ *http.Request) error {
		// Use an already-cancelled context so WaitForCacheSync returns
		// immediately with the current sync state instead of blocking.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return fmt.Errorf("informer cache not synced")
		}
		return nil
	}
}

// LeaderElectionChecker returns a healthz.Checker that verifies this instance
// is the current leader. The Elected() channel is closed once leadership is
// acquired (or immediately when leader election is disabled).
func LeaderElectionChecker(mgr manager.Manager) healthz.Checker {
	return func(_ *http.Request) error {
		select {
		case <-mgr.Elected():
			return nil
		default:
			return fmt.Errorf("not the leader")
		}
	}
}

// Watchdog tracks whether the main reconcile loop has run recently.
// The reconciler calls Touch() after each successful reconcile; health
// checks call Check() to verify the loop is not stuck.
type Watchdog struct {
	mu       sync.Mutex
	lastSeen time.Time
	timeout  time.Duration
	now      func() time.Time // for testing
}

// NewWatchdog creates a Watchdog that considers the reconcile loop stuck
// if Touch() has not been called within the given timeout.
// The initial grace period equals the timeout — the check will pass
// until the first timeout elapses even if Touch() has never been called.
func NewWatchdog(timeout time.Duration) *Watchdog {
	return &Watchdog{
		lastSeen: time.Now(),
		timeout:  timeout,
		now:      time.Now,
	}
}

// Touch records that the reconcile loop ran successfully.
func (w *Watchdog) Touch() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastSeen = w.now()
}

// Check returns nil if Touch() was called within the timeout, or an error otherwise.
func (w *Watchdog) Check() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	elapsed := w.now().Sub(w.lastSeen)
	if elapsed > w.timeout {
		return fmt.Errorf("reconcile loop has not run for %s (timeout %s)", elapsed.Round(time.Second), w.timeout)
	}
	return nil
}

// WatchdogChecker returns a healthz.Checker backed by the given Watchdog.
func WatchdogChecker(w *Watchdog) healthz.Checker {
	return func(_ *http.Request) error {
		return w.Check()
	}
}
