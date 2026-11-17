// Package relaylog は、手元の入口と中継先のあいだの写しを取り、
// 途中で切れたときに、それを記録へ残すかどうかを決める。
//
// ブラウザやアプリが自分から接続を閉じただけのときは、記録を埋めるだけなので黙る。
// 中継先やトンネル側で起きた失敗は、そのまま記録に残す。
package relaylog

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

// Side は、切れたのがどちら側か。
type Side int

const (
	// Client は、手元のブラウザやアプリ側。
	Client Side = iota
	// Tunnel は、中継先（トンネル）側。
	Tunnel
)

// other は、反対側を返す。読めなくなった側の反対が、書き込めなくなった側になる。
func (s Side) other() Side {
	if s == Client {
		return Tunnel
	}
	return Client
}

// Logf は、一行を記録へ流す先。nil なら何も書かない。
type Logf func(format string, args ...any)

// Result は、一方向の写しが終わったときの様子。
type Result struct {
	Bytes int64
	Side  Side
	Err   error
}

// Report は、この結果を記録に残すべきかを返す。
func (r Result) Report() bool { return Report(r.Side, r.Err) }

// Report は、その側で起きた失敗を記録に残すべきかを返す。
func Report(side Side, err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		// きれいに終わっただけ。
		return false
	}
	// 自分で閉じたあとの後始末は、どちら側でも記録しない。
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return false
	}
	if side == Tunnel {
		// 中継先・トンネル側の失敗は、そのまま知らせる。
		return true
	}
	// 手元の側が自分から閉じた・切っただけのときは黙る。
	return !closedByPeer(err)
}

// closedByPeer は、相手が接続を切った・リセットしただけの失敗かを返す。
func closedByPeer(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, text := range peerCloseText {
		if strings.Contains(msg, text) {
			return true
		}
	}
	return false
}

// peerCloseText は、OS が違っても表れる、相手からの切断の言い回し。
var peerCloseText = []string{
	"forcibly closed",                       // Windows: wsarecv: An existing connection was forcibly closed by the remote host.
	"an established connection was aborted", // Windows: wsarecv: An established connection was aborted by the software in your host machine.
	"aborted by the software in your host machine",
	"connection aborted",
	"connection reset", // connection reset by peer
	"broken pipe",
	"use of closed network connection",
}

// Copy は、src から dst へ一方向に写す。切れたときは、どちら側で何が起きたかを返す。
func Copy(dst, src net.Conn, srcSide Side, buf []byte) Result {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var n int64
	for {
		rn, rerr := src.Read(buf)
		if rn > 0 {
			wn, werr := dst.Write(buf[:rn])
			n += int64(wn)
			if werr != nil {
				return Result{Bytes: n, Side: srcSide.other(), Err: werr}
			}
			if wn < rn {
				return Result{Bytes: n, Side: srcSide.other(), Err: io.ErrShortWrite}
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return Result{Bytes: n}
			}
			return Result{Bytes: n, Side: srcSide, Err: rerr}
		}
	}
}

// Relay は両方向を中継する。片方が終わっても、もう片方の続きを打ち切らない。
func Relay(label string, browser, remote net.Conn, pool *sync.Pool, log Logf) {
	var wg sync.WaitGroup
	wg.Add(2)
	half := func(tag string, dst, src net.Conn, srcSide Side) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				write(log, "%s copy %s stopped: %v", label, tag, r)
			}
		}()
		var buf []byte
		if pool != nil {
			bp := pool.Get().(*[]byte)
			buf = *bp
			defer pool.Put(bp)
		}
		res := Copy(dst, src, srcSide, buf)
		if res.Report() {
			write(log, "%s copy %s ended after %d bytes: %v", label, tag, res.Bytes, res.Err)
		}
		if res.Err != nil {
			// 途中で切れたときだけ、両側を閉じる。
			_ = dst.Close()
			_ = src.Close()
			return
		}
		// 読み手が送り終えた。送り先にも終わりを伝え、反対向きの返事は待つ。
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}
	// up は手元から中継先へ、down は中継先から手元へ。
	go half("up", remote, browser, Client)
	go half("down", browser, remote, Tunnel)
	wg.Wait()
}

func write(log Logf, format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}
