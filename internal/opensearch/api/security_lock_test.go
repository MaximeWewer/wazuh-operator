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

package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWithSecurityWriteLock_SameKeySerializes ensures concurrent writers on the same
// cluster key never overlap (no version-conflict-inducing concurrency).
func TestWithSecurityWriteLock_SameKeySerializes(t *testing.T) {
	const key = "https://cluster-a:9200"
	var inCritical int32
	var maxObserved int32
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = WithSecurityWriteLock(key, func() error {
				n := atomic.AddInt32(&inCritical, 1)
				for {
					m := atomic.LoadInt32(&maxObserved)
					if n <= m || atomic.CompareAndSwapInt32(&maxObserved, m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&inCritical, -1)
				return nil
			})
		}()
	}
	wg.Wait()

	if maxObserved != 1 {
		t.Errorf("same-key writers overlapped: max concurrent = %d, want 1", maxObserved)
	}
}

// TestWithSecurityWriteLock_DifferentKeysConcurrent ensures different clusters do not
// block each other.
func TestWithSecurityWriteLock_DifferentKeysConcurrent(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 2)

	run := func(key string) {
		go func() {
			_ = WithSecurityWriteLock(key, func() error {
				entered <- struct{}{}
				<-release
				return nil
			})
		}()
	}
	run("https://cluster-a:9200")
	run("https://cluster-b:9200")

	// Both must enter their critical sections concurrently (different keys).
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("different-key writers blocked each other")
		}
	}
	close(release)
}
