// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWaitGroupChan(t *testing.T) {
	wg := NewWaitGroupChan()

	wantNotDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
			t.Fatal("done too early")
		default:
		}
	}

	wantDone := func() {
		t.Helper()
		select {
		case <-wg.DoneChan():
		default:
			t.Fatal("expected to be done")
		}
	}

	wg.Add(2)
	wantNotDone()

	wg.Decr()
	wantNotDone()

	wg.Decr()
	wantDone()
	wantDone()
}

func TestClosedChan(t *testing.T) {
	ch := ClosedChan()
	for i := 0; i < 2; i++ {
		select {
		case <-ch:
		default:
			t.Fatal("not closed")
		}
	}
}

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)
	s.Acquire()
	if !s.TryAcquire() {
		t.Fatal("want true")
	}
	if s.TryAcquire() {
		t.Fatal("want false")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.AcquireContext(ctx) {
		t.Fatal("want false")
	}
	s.Release()
	if !s.AcquireContext(context.Background()) {
		t.Fatal("want true")
	}
	s.Release()
	s.Release()
}

func TestMap(t *testing.T) {
	var m Map[string, int]
	if v, ok := m.Load("noexist"); v != 0 || ok {
		t.Errorf(`Load("noexist") = (%v, %v), want (0, false)`, v, ok)
	}
	m.Store("one", 1)
	if v, ok := m.LoadOrStore("one", -1); v != 1 || !ok {
		t.Errorf(`LoadOrStore("one", 1) = (%v, %v), want (1, true)`, v, ok)
	}
	if v, ok := m.Load("one"); v != 1 || !ok {
		t.Errorf(`Load("one") = (%v, %v), want (1, true)`, v, ok)
	}
	if v, ok := m.LoadOrStore("two", 2); v != 2 || ok {
		t.Errorf(`LoadOrStore("two", 2) = (%v, %v), want (2, false)`, v, ok)
	}
	got := map[string]int{}
	want := map[string]int{"one": 1, "two": 2}
	m.Range(func(k string, v int) bool {
		got[k] = v
		return true
	})
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}
	if v, ok := m.LoadAndDelete("two"); v != 2 || !ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (2, true)`, v, ok)
	}
	if v, ok := m.LoadAndDelete("two"); v != 0 || ok {
		t.Errorf(`LoadAndDelete("two) = (%v, %v), want (0, false)`, v, ok)
	}
	m.Delete("one")
	m.Delete("noexist")
	got = map[string]int{}
	want = map[string]int{}
	m.Range(func(k string, v int) bool {
		got[k] = v
		return true
	})
	if d := cmp.Diff(got, want); d != "" {
		t.Errorf("Range mismatch (-got +want):\n%s", d)
	}

	t.Run("LoadOrStore", func(t *testing.T) {
		var m Map[string, string]
		var wg WaitGroup
		var ok1, ok2 bool
		wg.Go(func() { _, ok1 = m.LoadOrStore("", "") })
		wg.Go(func() { _, ok2 = m.LoadOrStore("", "") })
		wg.Wait()
		if ok1 == ok2 {
			t.Errorf("exactly one LoadOrStore should load")
		}
	})

	t.Run("RangeMutable", func(t *testing.T) {
		var m Map[string, string]
		m.Store("hello", "goodbye")
		m.Store("fizz", "buzz")

		var wg WaitGroup
		defer wg.Wait()
		wg.Go(func() { m.Load("hello") })
		wg.Go(func() { m.Store("hello", "goodbye") })
		wg.Go(func() { m.LoadOrStore("hello", "goodbye") })
		wg.Go(func() { m.LoadAndDelete("noexist") })
		wg.Go(func() { m.Delete("noexist") })
		wg.Go(func() { m.Range(func(k, v string) bool { return true }) })
		wg.Go(func() { m.Len() })
		wg.Go(func() {
			m.RangeMutable(func(m *Map[string, string], k, v string) bool {
				if v2, ok := m.Load(k); v != v2 || !ok {
					t.Errorf("Load = (%v, %v), want (%v, %v)", v2, ok, v, true)
				}
				m.Store(k, v)
				if v2, ok := m.LoadOrStore(k, v); v != v2 || !ok {
					t.Errorf("LoadOrStore = (%v, %v), want (%v, %v)", v2, ok, v, true)
				}
				if v2, ok := m.LoadAndDelete("noexist"); v2 != "" || ok {
					t.Errorf("LoadAndDelete = (%v, %v), want (%v, %v)", v2, ok, "", false)
				}
				m.Delete("noexist")
				m.Range(func(k, v string) bool { return true })
				m.RangeMutable(func(m *Map[string, string], k, v string) bool {
					m.Store(k, v)
					return true
				})
				if got, want := m.Len(), 2; got != want {
					t.Errorf("Len = %d, want %d", got, want)
				}
				return true
			})
		})
	})

	t.Run("RangeDelete", func(t *testing.T) {
		var m Map[int, int]
		for i := 0; i < 10; i++ {
			m.Store(i, i)
		}

		m.RangeMutable(func(m *Map[int, int], k, v int) bool {
			if k%2 == 0 {
				m.Delete(k)
			}
			return true
		})

		got := map[int]int{}
		want := map[int]int{1: 1, 3: 3, 5: 5, 7: 7, 9: 9}
		m.Range(func(k, v int) bool {
			got[k] = v
			return true
		})
		if d := cmp.Diff(got, want); d != "" {
			t.Errorf("Range mismatch (-got +want):\n%s", d)
		}
	})
}
