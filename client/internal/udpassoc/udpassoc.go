// Package udpassoc は、SOCKS5 の UDP ASSOCIATE で来た通信を、中継の向こうへ渡す。
//
// 手元のアプリから見えるのは普通の SOCKS5 の入口だけ。
// 一つの入口で受けたまとまりは、宛先を添えて中継の一つの流れに載せ、
// 返ってきた分は受け取った相手の住所を添えてアプリへ返す。
package udpassoc

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"neconnectbridge/internal/udpframe"
)

// 中継の向こうとやり取りする流れ。
type Tunnel struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

// Open は、中継の向こうに UDP のまとまりを開いてもらう。
func Open(conn net.Conn) (*Tunnel, error) {
	t := &Tunnel{conn: conn, r: bufio.NewReaderSize(conn, 64*1024)}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], udpframe.Request)
	if _, err := conn.Write(head[:]); err != nil {
		return nil, err
	}
	status, err := t.r.ReadByte()
	if err != nil {
		return nil, err
	}
	if status != 0x00 {
		if status == 0x02 {
			return nil, errors.New("bridge is too busy for another UDP association")
		}
		return nil, fmt.Errorf("bridge refused the UDP association (status %d)", status)
	}
	_ = conn.SetDeadline(time.Time{})
	return t, nil
}

// WriteTo は、一つのまとまりを宛先を添えて送る。
func (t *Tunnel) WriteTo(a udpframe.Addr, payload []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return udpframe.WriteFrame(t.conn, a, payload)
}

// ReadFrom は、中継の向こうから届いた一つ分を読む。
func (t *Tunnel) ReadFrom() (udpframe.Addr, []byte, error) {
	return udpframe.ReadFrame(t.r)
}

func (t *Tunnel) Close() error {
	return t.conn.Close()
}

// Options は、一つの入口を動かすための決まり。
type Options struct {
	// Blocked は、その相手へ送らないときに true を返す。
	Blocked func(host string) bool
	// Logf は、様子を残す先。
	Logf func(format string, args ...any)
	// Idle は、何も無いまま閉じるまでの時間。
	Idle time.Duration
}

// Run は、入口のソケットと中継をつなぎ、閉じるまで動き続ける。
func Run(tcp net.Conn, tun *Tunnel, local *net.UDPConn, opts Options) error {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Idle <= 0 {
		opts.Idle = 120 * time.Second
	}

	var (
		mu     sync.Mutex
		client *net.UDPAddr
		last   = time.Now()
	)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	defer func() {
		stop()
		_ = tun.Close()
		_ = local.Close()
	}()

	touch := func() {
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}
	clientAddr := func() *net.UDPAddr {
		mu.Lock()
		defer mu.Unlock()
		return client
	}

	// 入口の制御の接続が切れたら、このまとまりも終わりにする。
	go func() {
		_, _ = io.Copy(io.Discard, tcp)
		stop()
	}()

	// アプリから来た分を、中継の向こうへ渡す。
	go func() {
		defer stop()
		buf := make([]byte, 65535)
		for {
			n, from, err := local.ReadFromUDP(buf)
			if err != nil {
				return
			}
			touch()
			mu.Lock()
			if client == nil {
				client = from
			}
			known := client
			mu.Unlock()
			if known == nil || !samePeer(known, from) {
				continue
			}
			addr, payload, perr := udpframe.UnmarshalSocksUDP(buf[:n])
			if perr != nil {
				continue
			}
			if opts.Blocked != nil && opts.Blocked(addr.Host) {
				continue
			}
			if werr := tun.WriteTo(addr, payload); werr != nil {
				opts.Logf("UDP の中継を続けられません: %v", werr)
				return
			}
		}
	}()

	// 中継の向こうから返った分を、アプリへ返す。
	go func() {
		defer stop()
		for {
			addr, payload, err := tun.ReadFrom()
			if err != nil {
				return
			}
			touch()
			to := clientAddr()
			if to == nil {
				continue
			}
			packet, merr := udpframe.MarshalSocksUDP(addr, payload)
			if merr != nil {
				continue
			}
			if _, werr := local.WriteToUDP(packet, to); werr != nil {
				opts.Logf("UDP の返りを届けられません: %v", werr)
				return
			}
		}
	}()

	// 何も無いまま使い続けられないよう、区切りで閉じる。
	idleCheck := opts.Idle / 4
	if idleCheck < time.Second {
		idleCheck = time.Second
	}
	go func() {
		ticker := time.NewTicker(idleCheck)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mu.Lock()
				idle := time.Since(last)
				mu.Unlock()
				if idle >= opts.Idle {
					stop()
					return
				}
			}
		}
	}()

	<-done
	return nil
}

// samePeer は、同じ相手から来た分かを見る。
func samePeer(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
