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
//
// It works by waiting (non-blocking) for the manager to be elected leader,
// then performing a blocking WaitForCacheSync with a short deadline.
// Before election, the check fails immediately without calling into the cache.
func InformerSyncChecker(mgr manager.Manager) healthz.Checker {
	return func(_ *http.Request) error {
		// Before the manager is fully started (leader elected, cache started),
		// WaitForCacheSync cannot succeed. Check Elected() first to avoid
		// calling WaitForCacheSync with a canceled context (which always
		// returns false because the internal startWait channel races with
		// the canceled Done channel).
		select {
		case <-mgr.Elected():
			// Manager is started and cache is running.
		default:
			return fmt.Errorf("manager not yet started")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

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
	mu        sync.Mutex
	lastSeen  time.Time
	timeout   time.Duration
	activated bool          // true after the first Touch() call
	now       func() time.Time // for testing
}

// NewWatchdog creates a Watchdog that considers the reconcile loop stuck
// if Touch() has not been called within the given timeout.
// The watchdog stays healthy until the first Touch() activates it.
// This avoids false alarms when there are no resources to reconcile.
func NewWatchdog(timeout time.Duration) *Watchdog {
	return &Watchdog{
		timeout: timeout,
		now:     time.Now,
	}
}

// Touch records that the reconcile loop ran successfully.
// The first call activates the watchdog; before that, Check() always passes.
func (w *Watchdog) Touch() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.activated = true
	w.lastSeen = w.now()
}

// Check returns nil if the watchdog has not been activated (no resources to
// reconcile) or if Touch() was called within the timeout. Returns an error
// only when the reconcile loop was active but has not run recently.
func (w *Watchdog) Check() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.activated {
		return nil
	}

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
