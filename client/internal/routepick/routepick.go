// Package routepick は、試す道筋のうち、どれを休ませるかを決める。
//
// 通らなかった道筋でも、通信の形や時間帯が変われば通ることがある。
// そのため休ませるのは一定の間だけにし、一度通った道筋は休ませない。
// すべて休んでいるように見えるときは、もう一度すべてを候補に戻す。
package routepick

import (
	"sync"
	"time"
)

const DefaultCooldown = 10 * time.Second

// Shared は、接続全体で通った道筋を覚えておく。
type Shared struct {
	mu   sync.Mutex
	good string
}

func NewShared() *Shared { return &Shared{} }

func (s *Shared) Good() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.good
}

func (s *Shared) SetGood(label string) {
	s.mu.Lock()
	s.good = label
	s.mu.Unlock()
}

// Set は、一つの方法だけの休みを管理する。
type Set struct {
	shared   *Shared
	cooldown time.Duration

	mu   sync.Mutex
	rest map[string]time.Time
}

func New(shared *Shared, cooldown time.Duration) *Set {
	if shared == nil {
		shared = NewShared()
	}
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	return &Set{shared: shared, cooldown: cooldown, rest: map[string]time.Time{}}
}

// Rest は、道筋をしばらく候補から外す。
// 一度通ったことのある道筋は外さない。
func (s *Set) Rest(label string) {
	if label == "" || label == s.shared.Good() {
		return
	}
	s.mu.Lock()
	s.rest[label] = time.Now().Add(s.cooldown)
	s.mu.Unlock()
}

// Wake は、道筋を候補に戻し、通った道筋として覚える。
func (s *Set) Wake(label string) {
	if label == "" {
		return
	}
	s.mu.Lock()
	delete(s.rest, label)
	s.mu.Unlock()
	s.shared.SetGood(label)
}

// Resting は、いま候補から外れているかを返す。
func (s *Set) Resting(label string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.rest[label]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(s.rest, label)
	return false
}

// Filter は、休んでいない道筋だけを残す。
// 残るものが無いときは、休みを無視して全部を返す。
func (s *Set) Filter(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		if !s.Resting(label) {
			out = append(out, label)
		}
	}
	if len(out) == 0 {
		return labels
	}
	return out
}
