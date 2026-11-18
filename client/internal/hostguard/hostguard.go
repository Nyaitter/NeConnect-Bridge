// Package hostguard は、同じ相手への中継接続が短時間に集中したとき、
// その相手をしばらく休ませる。
//
// 常駐のフィルタリングソフトなどは、つながらない相手へ何十回も続けて接続を試す。
// その一つずつがブリッジの流れを一本ずつ使い切るため、放っておくとプールが尽きて、
// ブラウザなど他の通信まで巻き添えで通らなくなる。
//
// ここでは相手ごとに「試した回数」と「すぐ切れた・失敗した回数」を数え、
// 明らかな集中だけを止める。ブラウザが同じ相手へ数本つなぐ程度では動かない。
package hostguard

import (
	"sync"
	"time"
)

const (
	// 試した回数を数える幅と、その中での上限。
	burstWindow = 1 * time.Second
	burstLimit  = 10

	// 失敗と、すぐ切れた接続を数える幅と上限。
	failWindow     = 3 * time.Second
	failLimit      = 4
	shortLivedSpan = 2 * time.Second

	// CoolDown は、集中した相手を休ませる長さ。
	CoolDown = 10 * time.Second

	// 覚えておく相手の数の目安。これを超えたら古いものから忘れる。
	maxHosts = 512
)

// Guard は、相手ごとの集中を見張る。同時に使える。
type Guard struct {
	// now は、いまの時刻。試験で時間を進めるために差し替える。
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	attempts []time.Time
	fails    []time.Time
	until    time.Time
	rejected int
}

// New は、何も休ませていない状態の見張りを作る。
func New() *Guard {
	return &Guard{now: time.Now, entries: map[string]*entry{}}
}

// Allow は、いまその相手へつないでよいかを返す。
// 休ませている間は、残りの時間と false を返す。断った回数は数えない。
func (g *Guard) Allow(host string) (time.Duration, bool) {
	if host == "" {
		return 0, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[host]
	if e == nil {
		return 0, true
	}
	left := e.until.Sub(g.now())
	if left <= 0 {
		return 0, true
	}
	return left, false
}

// Resting は、その相手を休ませているかを返す。断った回数は数えない。
func (g *Guard) Resting(host string) bool {
	_, ok := g.Allow(host)
	return !ok
}

// NoteAttempt は、これから一本つなぐことを記録する。
// その結果として相手を休ませ始めたときは true を返す。
func (g *Guard) NoteAttempt(host string) bool {
	if host == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entry(host)
	now := g.now()
	if now.Before(e.until) {
		// 休ませている最中の試行は数えない。
		return false
	}
	e.attempts = append(e.attempts, now)
	e.attempts = prune(e.attempts, now.Add(-burstWindow))
	if len(e.attempts) >= burstLimit {
		g.rest(host, e)
		return true
	}
	return false
}

// NoteFailure は、つなげなかったことを記録する。
// その結果として相手を休ませ始めたときは true を返す。
func (g *Guard) NoteFailure(host string) bool {
	return g.noteShort(host)
}

// NoteClosed は、つないだ接続がどれだけ続いたかを記録する。
// すぐ切れた接続は失敗と同じように数える。
// その結果として相手を休ませ始めたときは true を返す。
func (g *Guard) NoteClosed(host string, lived time.Duration) bool {
	if lived >= shortLivedSpan {
		return false
	}
	return g.noteShort(host)
}

func (g *Guard) noteShort(host string) bool {
	if host == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entry(host)
	now := g.now()
	if now.Before(e.until) {
		return false
	}
	e.fails = append(e.fails, now)
	e.fails = prune(e.fails, now.Add(-failWindow))
	if len(e.fails) >= failLimit {
		g.rest(host, e)
		return true
	}
	return false
}

// NoteRejected は、休ませている間に断った回数を数え、その回数を返す。
func (g *Guard) NoteRejected(host string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entry(host)
	e.rejected++
	return e.rejected
}

// rest は、相手をしばらく休ませる。数えた記録は消して、明けた直後に
// また同じ集中で止まらないようにする。呼び出し側で鍵を持つ。
func (g *Guard) rest(host string, e *entry) {
	e.until = g.now().Add(CoolDown)
	e.attempts = nil
	e.fails = nil
}

// entry は、相手の記録を取り出す。無ければ作り、多すぎれば忘れる。
// 呼び出し側で鍵を持つ。
func (g *Guard) entry(host string) *entry {
	if e, ok := g.entries[host]; ok {
		return e
	}
	if len(g.entries) >= maxHosts {
		g.forget()
	}
	e := &entry{}
	g.entries[host] = e
	return e
}

// forget は、休みも記録も済んだ相手を忘れる。
func (g *Guard) forget() {
	now := g.now()
	for host, e := range g.entries {
		if now.Before(e.until) {
			continue
		}
		if len(e.attempts) > 0 || len(e.fails) > 0 {
			continue
		}
		delete(g.entries, host)
	}
	// それでも減らないときは、休み中の相手を残して空にする。
	if len(g.entries) >= maxHosts {
		for host, e := range g.entries {
			if now.Before(e.until) {
				continue
			}
			delete(g.entries, host)
		}
	}
}

// prune は、古い記録を落とす。
func prune(times []time.Time, since time.Time) []time.Time {
	keep := times[:0]
	for _, t := range times {
		if t.After(since) {
			keep = append(keep, t)
		}
	}
	return keep
}
