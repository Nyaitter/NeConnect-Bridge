// Package dialgate は、ブリッジへ流れを張る作業の本数を絞る。
//
// 流れが尽きたときに、来た接続の数だけ一斉に張り出しが始まると、
// 回線も接続枠も使い切って、他の通信まで通らなくなる。
// ここで同時に走る本数と、待たせる本数の上限を決めておく。
//
// 閉じたあとは新しい張り出しを始めない。合図として使える。
package dialgate

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrClosed は、閉じたあとに張り出そうとしたときの失敗。
	ErrClosed = errors.New("dial gate is closed")
	// ErrBusy は、待たせられる数を使い切ったときの失敗。
	ErrBusy = errors.New("too many dials are waiting")
)

// Gate は、同時に走らせる本数と、待たせる本数を決めた関所。同時に使える。
type Gate struct {
	slots   chan struct{}
	maxWait int

	mu      sync.Mutex
	waiting int
	closed  bool
	done    chan struct{}
}

// New は、同時に走らせる本数 slots と、その手前で待たせる本数 maxWait の関所を作る。
func New(slots, maxWait int) *Gate {
	if slots < 1 {
		slots = 1
	}
	if maxWait < 0 {
		maxWait = 0
	}
	return &Gate{
		slots:   make(chan struct{}, slots),
		maxWait: maxWait,
		done:    make(chan struct{}),
	}
}

// Acquire は、一本張り出す許可を取る。返ってきた関数を必ず一度呼ぶ。
// 待ちが長引くときは、ctx が終わるか閉じたときに諦める。
func (g *Gate) Acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, ErrClosed
	}
	if g.waiting >= cap(g.slots)+g.maxWait {
		g.mu.Unlock()
		return nil, ErrBusy
	}
	g.waiting++
	g.mu.Unlock()

	select {
	case g.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-g.slots
				g.drop()
			})
		}, nil
	case <-g.done:
		g.drop()
		return nil, ErrClosed
	case <-ctx.Done():
		g.drop()
		return nil, ctx.Err()
	}
}

// Close は、待っている張り出しをすべて諦めさせ、以後の許可を止める。
func (g *Gate) Close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	close(g.done)
	g.mu.Unlock()
}

// Running は、いま走っている本数を返す。
func (g *Gate) Running() int { return len(g.slots) }

// Waiting は、いま順番を待っている本数を返す。
func (g *Gate) Waiting() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	waiting := g.waiting - len(g.slots)
	if waiting < 0 {
		return 0
	}
	return waiting
}

func (g *Gate) drop() {
	g.mu.Lock()
	if g.waiting > 0 {
		g.waiting--
	}
	g.mu.Unlock()
}
