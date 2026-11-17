package dohres

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDNS struct {
	hits    atomic.Int64
	fail    atomic.Bool
	delay   time.Duration
	address string
}

func (f *fakeDNS) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if f.fail.Load() {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		addr := f.address
		if addr == "" {
			addr = "203.0.113.7"
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = fmt.Fprintf(w, `{"Status":0,"Answer":[{"type":1,"data":%q}]}`, addr)
	}))
}

func newTestResolver(t *testing.T, f *fakeDNS, failTTL time.Duration) (*Resolver, *[]string) {
	t.Helper()
	srv := f.server(t)
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var logs []string
	r := New(Options{
		TTL:       time.Minute,
		FailTTL:   failTTL,
		Timeout:   time.Second,
		Endpoints: []string{srv.URL + "/resolve?name=%s&type=A"},
		Log: func(format string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
	})
	return r, &logs
}

func TestResolveSharesOneQuery(t *testing.T) {
	f := &fakeDNS{delay: 80 * time.Millisecond}
	r, _ := newTestResolver(t, f, time.Second)

	const workers = 64
	var wg sync.WaitGroup
	results := make([]string, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.Resolve(context.Background(), "nct.example.jp")
		}(i)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if results[i] != "203.0.113.7" {
			t.Fatalf("worker %d got %q", i, results[i])
		}
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("lookup ran %d times, want 1", got)
	}
}

func TestResolveUsesCache(t *testing.T) {
	f := &fakeDNS{}
	r, _ := newTestResolver(t, f, time.Second)

	if _, err := r.Resolve(context.Background(), "a.example.jp"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "a.example.jp"); err != nil {
		t.Fatal(err)
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("lookup ran %d times, want 1", got)
	}
	if ip, ok := r.Cached("a.example.jp"); !ok || ip != "203.0.113.7" {
		t.Fatalf("cached = %q, %v", ip, ok)
	}
}

func TestFailureIsNotRepeated(t *testing.T) {
	f := &fakeDNS{}
	f.fail.Store(true)
	r, logs := newTestResolver(t, f, 30*time.Second)

	if _, err := r.Resolve(context.Background(), "b.example.jp"); err == nil {
		t.Fatal("want an error")
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("lookup ran %d times, want 1", got)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Resolve(context.Background(), "b.example.jp"); !errors.Is(err, ErrSkipped) {
				t.Errorf("want ErrSkipped, got %v", err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("skipped lookups took %s", elapsed)
	}
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("lookup ran %d times, want 1", got)
	}
	if len(*logs) != 1 {
		t.Fatalf("logged %d lines, want 1: %v", len(*logs), *logs)
	}
}

func TestFailureRetriedAfterWindow(t *testing.T) {
	f := &fakeDNS{}
	f.fail.Store(true)
	r, _ := newTestResolver(t, f, 60*time.Millisecond)

	if _, err := r.Resolve(context.Background(), "c.example.jp"); err == nil {
		t.Fatal("want an error")
	}
	f.fail.Store(false)
	if _, err := r.Resolve(context.Background(), "c.example.jp"); !errors.Is(err, ErrSkipped) {
		t.Fatalf("want ErrSkipped, got %v", err)
	}
	time.Sleep(90 * time.Millisecond)
	ip, err := r.Resolve(context.Background(), "c.example.jp")
	if err != nil || ip != "203.0.113.7" {
		t.Fatalf("after retry got %q, %v", ip, err)
	}
}

func TestResolveStopsOnCancel(t *testing.T) {
	f := &fakeDNS{delay: 300 * time.Millisecond}
	r, _ := newTestResolver(t, f, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := r.Resolve(ctx, "d.example.jp"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestManyNamesUnderLoad は、名前が混ざった大量の照会でも壊れないことを見る。
func TestManyNamesUnderLoad(t *testing.T) {
	f := &fakeDNS{}
	r, _ := newTestResolver(t, f, 50*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("host%d.example.jp", i%5)
			if _, err := r.Resolve(context.Background(), host); err != nil {
				t.Errorf("resolve %s: %v", host, err)
			}
		}(i)
	}
	wg.Wait()
	if got := f.hits.Load(); got > 5 {
		t.Fatalf("lookup ran %d times, want at most 5", got)
	}
}
