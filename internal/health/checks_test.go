package health

import (
	"context"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// --- Minimal fakes for manager.Manager ---

// fakeCache implements cache.Cache just enough for WaitForCacheSync.
type fakeCache struct {
	cache.Cache
	synced bool
}

func (f *fakeCache) WaitForCacheSync(_ context.Context) bool {
	return f.synced
}

// fakeManager implements the subset of manager.Manager used by the checkers.
type fakeManager struct {
	manager.Manager
	cache *fakeCache
}

func (f *fakeManager) GetCache() cache.Cache {
	return f.cache
}

// --- Tests ---

// TestInformerSyncChecker asserts readiness follows the cache sync only, never leadership:
// a standby replica must be ready or rolling updates of the operator deadlock.
func TestInformerSyncChecker(t *testing.T) {
	tests := []struct {
		name    string
		synced  bool
		wantErr bool
	}{
		{"synced returns nil", true, false},
		{"unsynced returns error", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &fakeManager{cache: &fakeCache{synced: tt.synced}}
			checker := InformerSyncChecker(mgr)
			err := checker(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("InformerSyncChecker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWatchdog(t *testing.T) {
	t.Run("fresh watchdog passes (not activated)", func(t *testing.T) {
		w := NewWatchdog(1 * time.Minute)
		if err := w.Check(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("unactivated watchdog stays healthy even after timeout", func(t *testing.T) {
		now := time.Now()
		w := &Watchdog{
			timeout: 1 * time.Minute,
			now:     func() time.Time { return now.Add(10 * time.Minute) },
		}
		if err := w.Check(); err != nil {
			t.Errorf("expected nil for unactivated watchdog, got %v", err)
		}
	})

	t.Run("touch activates and resets timer", func(t *testing.T) {
		now := time.Now()
		w := &Watchdog{
			activated: true,
			lastSeen:  now.Add(-2 * time.Minute),
			timeout:   1 * time.Minute,
			now:       func() time.Time { return now },
		}
		// Before touch: should fail (activated and expired)
		if err := w.Check(); err == nil {
			t.Error("expected error for expired watchdog, got nil")
		}
		// Touch and re-check
		w.Touch()
		if err := w.Check(); err != nil {
			t.Errorf("expected nil after Touch(), got %v", err)
		}
	})

	t.Run("expired activated watchdog fails", func(t *testing.T) {
		now := time.Now()
		w := &Watchdog{
			activated: true,
			lastSeen:  now.Add(-10 * time.Minute),
			timeout:   5 * time.Minute,
			now:       func() time.Time { return now },
		}
		if err := w.Check(); err == nil {
			t.Error("expected error for expired watchdog, got nil")
		}
	})

	t.Run("first touch activates watchdog", func(t *testing.T) {
		w := NewWatchdog(1 * time.Minute)
		if w.activated {
			t.Error("expected watchdog to start unactivated")
		}
		w.Touch()
		if !w.activated {
			t.Error("expected watchdog to be activated after Touch()")
		}
	})

	t.Run("watchdog checker delegates to Check", func(t *testing.T) {
		w := NewWatchdog(1 * time.Minute)
		checker := WatchdogChecker(w)
		if err := checker(nil); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
}
