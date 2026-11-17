package logqueue

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQueueKeepsOrderAndDropsOldest(t *testing.T) {
	q := New(3)
	for _, line := range []string{"1", "2", "3", "4", "5"} {
		q.Push(line)
	}
	got := q.Take()
	if len(got) != 4 {
		t.Fatalf("got %d lines: %v", len(got), got)
	}
	if got[1] != "1" || got[3] != "3" {
		t.Fatalf("unexpected lines: %v", got)
	}
	if got[0] != OverflowNotice(2) {
		t.Fatalf("missing overflow notice: %v", got)
	}
	if again := q.Take(); again != nil {
		t.Fatalf("take should be empty, got %v", again)
	}
}

// TestLogQueueUnderLoad は、1000 行が同時に来ても取りこぼさず壊れないことを見る。
func TestQueueUnderLoad(t *testing.T) {
	q := New(4000)
	const writers = 100
	const perWriter = 10
	const want = writers * perWriter

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				q.Push(fmt.Sprintf("writer %d line %d", w, i))
			}
		}(w)
	}

	// 書き込みと並行して取り出す。
	taken := 0
	deadline := time.Now().Add(5 * time.Second)
	for taken < want && time.Now().Before(deadline) {
		taken += len(q.Take())
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	taken += len(q.Take())
	if taken < want {
		t.Fatalf("took %d lines, want at least %d", taken, want)
	}
}
