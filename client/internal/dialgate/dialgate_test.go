package dialgate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireLimitsRunningDials(t *testing.T) {
	g := New(2, 2)
	ctx := context.Background()

	first, err := g.Acquire(ctx)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	second, err := g.Acquire(ctx)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if g.Running() != 2 {
		t.Fatalf("running = %d, want 2", g.Running())
	}

	// 3本目は、空くまで待つ。
	got := make(chan error, 1)
	go func() {
		release, aerr := g.Acquire(ctx)
		if aerr == nil {
			release()
		}
		got <- aerr
	}()
	time.Sleep(50 * time.Millisecond)
	if g.Waiting() != 1 {
		t.Fatalf("waiting = %d, want 1", g.Waiting())
	}
	select {
	case err := <-got:
		t.Fatalf("third acquire returned early: %v", err)
	default:
	}

	first()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("third acquire: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("third acquire never got its turn")
	}
	second()
	if g.Running() != 0 || g.Waiting() != 0 {
		t.Fatalf("running=%d waiting=%d after release, want 0/0", g.Running(), g.Waiting())
	}
}

func TestAcquireFailsWhenTheQueueIsFull(t *testing.T) {
	g := New(1, 1)
	ctx := context.Background()

	release, err := g.Acquire(ctx)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	go func() {
		_, _ = g.Acquire(ctx)
	}()
	deadline := time.Now().Add(time.Second)
	for g.Waiting() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := g.Acquire(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("acquire beyond the queue = %v, want ErrBusy", err)
	}
	release()
}

func TestCloseStopsWaitingDials(t *testing.T) {
	g := New(1, 1)
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	got := make(chan error, 1)
	go func() {
		_, aerr := g.Acquire(context.Background())
		got <- aerr
	}()
	deadline := time.Now().Add(time.Second)
	for g.Waiting() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	g.Close()
	select {
	case err := <-got:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("waiting dial woke with %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting dial was not woken by Close")
	}
	release()

	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("acquire after close = %v, want ErrClosed", err)
	}
}

func TestCancelStopsWaitingDials(t *testing.T) {
	g := New(1, 1)
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan error, 1)
	go func() {
		_, aerr := g.Acquire(ctx)
		got <- aerr
	}()
	deadline := time.Now().Add(time.Second)
	for g.Waiting() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-got:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting dial woke with %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting dial was not woken by cancel")
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	g := New(1, 0)
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release()
	if g.Waiting() != 0 || g.Running() != 0 {
		t.Fatalf("running=%d waiting=%d, want 0/0", g.Running(), g.Waiting())
	}
	if _, err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
}
