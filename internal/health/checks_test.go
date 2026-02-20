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
	cache   *fakeCache
	elected chan struct{}
}

func (f *fakeManager) GetCache() cache.Cache {
	return f.cache
}

func (f *fakeManager) Elected() <-chan struct{} {
	return f.elected
}

// --- Tests ---

func TestInformerSyncChecker(t *testing.T) {
	tests := []struct {
		name    string
		synced  bool
		wantErr bool
	}{
		{"synced cache returns nil", true, false},
		{"unsynced cache returns error", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &fakeManager{
				cache: &fakeCache{synced: tt.synced},
			}
			checker := InformerSyncChecker(mgr)
			err := checker(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("InformerSyncChecker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLeaderElectionChecker(t *testing.T) {
	tests := []struct {
		name    string
		elected bool
		wantErr bool
	}{
		{"elected returns nil", true, false},
		{"not elected returns error", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan struct{})
			if tt.elected {
				close(ch)
			}
			mgr := &fakeManager{elected: ch}
			checker := LeaderElectionChecker(mgr)
			err := checker(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("LeaderElectionChecker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWatchdog(t *testing.T) {
	t.Run("fresh watchdog passes", func(t *testing.T) {
		w := NewWatchdog(1 * time.Minute)
		if err := w.Check(); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("touch resets timer", func(t *testing.T) {
		now := time.Now()
		w := &Watchdog{
			lastSeen: now.Add(-2 * time.Minute),
			timeout:  1 * time.Minute,
			now:      func() time.Time { return now },
		}
		// Before touch: should fail
		if err := w.Check(); err == nil {
			t.Error("expected error for expired watchdog, got nil")
		}
		// Touch and re-check
		w.Touch()
		if err := w.Check(); err != nil {
			t.Errorf("expected nil after Touch(), got %v", err)
		}
	})

	t.Run("expired watchdog fails", func(t *testing.T) {
		now := time.Now()
		w := &Watchdog{
			lastSeen: now.Add(-10 * time.Minute),
			timeout:  5 * time.Minute,
			now:      func() time.Time { return now },
		}
		if err := w.Check(); err == nil {
			t.Error("expected error for expired watchdog, got nil")
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
