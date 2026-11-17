package routepick

import (
	"sync"
	"testing"
	"time"
)

func TestFailedStageRests(t *testing.T) {
	s := New(nil, time.Minute)
	s.Rest("alt:2053")
	if !s.Resting("alt:2053") {
		t.Fatal("a failed stage should rest")
	}
}

func TestGoodStageIsNeverRested(t *testing.T) {
	s := New(nil, time.Minute)
	s.Wake("alt:8443")
	s.Rest("alt:8443")
	if s.Resting("alt:8443") {
		t.Fatal("the stage that once worked must stay available")
	}
	got := s.Filter([]string{"alt:8443"})
	if len(got) != 1 || got[0] != "alt:8443" {
		t.Fatalf("filter returned %v", got)
	}
}

func TestFilterNeverEmpty(t *testing.T) {
	s := New(nil, time.Minute)
	all := []string{"alt:8443", "alt:2053", "alt:2083"}
	for _, label := range all {
		s.Rest(label)
	}
	got := s.Filter(all)
	if len(got) != len(all) {
		t.Fatalf("filter returned %v, want every stage back", got)
	}
}

func TestRestExpires(t *testing.T) {
	s := New(nil, 30*time.Millisecond)
	s.Rest("frag")
	if !s.Resting("frag") {
		t.Fatal("should rest right away")
	}
	time.Sleep(60 * time.Millisecond)
	if s.Resting("frag") {
		t.Fatal("rest should end")
	}
}

func TestGoodIsSharedAcrossSets(t *testing.T) {
	shared := NewShared()
	pool := New(shared, time.Minute)
	other := New(shared, time.Minute)
	pool.Wake("alt:8443")
	if shared.Good() != "alt:8443" {
		t.Fatalf("good = %q", shared.Good())
	}
	other.Rest("alt:8443")
	if other.Resting("alt:8443") {
		t.Fatal("another transport must not rest the stage that works")
	}
}

// TestConcurrentUse は、補充の連打の中でも壊れず、候補が空にならないことを見る。
func TestConcurrentUse(t *testing.T) {
	shared := NewShared()
	pool := New(shared, 40*time.Millisecond)
	stages := []string{"alt:8443", "alt:2053", "alt:2083", "alt:2087", "alt:2096", "frag", "any"}

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			label := stages[i%len(stages)]
			switch i % 3 {
			case 0:
				pool.Rest(label)
			case 1:
				pool.Wake(label)
			default:
				if got := pool.Filter(stages); len(got) == 0 {
					t.Errorf("filter left no stage")
				}
				_ = pool.Resting(label)
			}
		}(i)
	}
	wg.Wait()
	if got := pool.Filter(stages); len(got) == 0 {
		t.Fatal("no stage is left after concurrent use")
	}
}

// TestRefillKeepsWorkingStage は、補充が成功した道筋を使い続けることを見る。
func TestRefillKeepsWorkingStage(t *testing.T) {
	s := New(nil, time.Minute)
	// 1本目は alt:8443 で通った。
	s.Wake("alt:8443")
	// 残りの補充のうち、いくつかは失敗した。
	s.Rest("alt:2053")
	s.Rest("alt:2083")
	order := []string{"alt:8443", "alt:2053", "alt:2083", "frag"}
	got := s.Filter(order)
	if len(got) == 0 || got[0] != "alt:8443" {
		t.Fatalf("refill should try the working stage first, got %v", got)
	}
}
