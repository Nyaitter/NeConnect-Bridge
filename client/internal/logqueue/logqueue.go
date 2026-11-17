package logqueue

import (
	"fmt"
	"sync"
)

// Queue は、画面へ渡す前のログ行を預かる。
// 書き出す側がいくつ同時に来ても取りこぼさず、溢れたら古い行から捨てる。
type Queue struct {
	mu      sync.Mutex
	max     int
	lines   []string
	dropped int
}

func New(max int) *Queue {
	if max <= 0 {
		max = 4000
	}
	return &Queue{max: max}
}

// Push は一行預ける。溢れたときは捨てた行数を数える。
func (q *Queue) Push(line string) {
	q.mu.Lock()
	if len(q.lines) < q.max {
		q.lines = append(q.lines, line)
	} else {
		q.dropped++
	}
	q.mu.Unlock()
}

// Take は預かった行をすべて渡し、手元から空にする。
// 捨てた行があれば、その知らせを先頭に添える。
func (q *Queue) Take() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.lines) == 0 && q.dropped == 0 {
		return nil
	}
	out := q.lines
	q.lines = nil
	if q.dropped > 0 {
		out = append([]string{OverflowNotice(q.dropped)}, out...)
		q.dropped = 0
	}
	return out
}

// Pending は、いま預かっている行数を返す。
func (q *Queue) Pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.lines)
}

// OverflowNotice は、捨てた行があることを伝える一行を作る。
func OverflowNotice(n int) string {
	return fmt.Sprintf("… ログが多いため %d 行を省略しました", n)
}
