package relaylog

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestReport(t *testing.T) {
	cases := []struct {
		name string
		side Side
		err  error
		want bool
	}{
		{
			name: "client-forcibly-closed",
			side: Client,
			err:  errors.New("read tcp 127.0.0.1:63503->127.0.0.1:50438: wsarecv: An existing connection was forcibly closed by the remote host."),
			want: false,
		},
		{
			name: "client-aborted-by-host-software",
			side: Client,
			err:  errors.New("read tcp 127.0.0.1:5000->127.0.0.1:5001: wsarecv: An established connection was aborted by the software in your host machine."),
			want: false,
		},
		{
			name: "client-reset-by-peer",
			side: Client,
			err:  errors.New("read tcp 127.0.0.1:41000->127.0.0.1:8080: read: connection reset by peer"),
			want: false,
		},
		{
			name: "client-broken-pipe",
			side: Client,
			err:  errors.New("write tcp 127.0.0.1:41000->127.0.0.1:8080: write: broken pipe"),
			want: false,
		},
		{name: "client-closed", side: Client, err: net.ErrClosed, want: false},
		{name: "client-closed-wrapped", side: Client, err: fmt.Errorf("read: %w", net.ErrClosed), want: false},
		{name: "client-econnreset", side: Client, err: fmt.Errorf("read: %w", syscall.ECONNRESET), want: false},
		{name: "client-eof", side: Client, err: io.EOF, want: false},
		{name: "nothing", side: Client, err: nil, want: false},
		// 手元の側でも、切断ではない失敗は残す。
		{name: "client-timeout", side: Client, err: errors.New("read tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout"), want: true},
		{name: "client-short-write", side: Client, err: io.ErrShortWrite, want: true},
		// 中継先・トンネル側の失敗は、同じ言い回しでも残す。
		{
			name: "tunnel-forcibly-closed",
			side: Tunnel,
			err:  errors.New("read tcp 127.0.0.1:5000->127.0.0.1:5001: wsarecv: An existing connection was forcibly closed by the remote host."),
			want: true,
		},
		{name: "tunnel-econnreset", side: Tunnel, err: syscall.ECONNRESET, want: true},
		// 自分で閉じたあとの後始末は、中継先の側でも記録しない。
		{name: "tunnel-closed-by-us", side: Tunnel, err: net.ErrClosed, want: false},
		{name: "tunnel-timeout", side: Tunnel, err: errors.New("read: i/o timeout"), want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Report(c.side, c.err); got != c.want {
				t.Fatalf("Report(%v, %v) = %v, want %v", c.side, c.err, got, c.want)
			}
		})
	}
}

// TestCopyPointsAtFailingSide は、読めなかった側・書けなかった側を正しく見分けるかを見る。
func TestCopyPointsAtFailingSide(t *testing.T) {
	t.Run("read-from-client", func(t *testing.T) {
		src := &scriptedConn{readErr: fmt.Errorf("read: %w", syscall.ECONNRESET)}
		res := Copy(&scriptedConn{}, src, Client, nil)
		if res.Side != Client || res.Err == nil {
			t.Fatalf("got side %v err %v", res.Side, res.Err)
		}
		if res.Report() {
			t.Fatal("client read failure should stay quiet")
		}
	})
	t.Run("write-to-tunnel", func(t *testing.T) {
		src := &scriptedConn{data: []byte("hello")}
		res := Copy(&scriptedConn{writeErr: errors.New("write: boom")}, src, Client, nil)
		if res.Side != Tunnel || res.Err == nil {
			t.Fatalf("got side %v err %v", res.Side, res.Err)
		}
		if !res.Report() {
			t.Fatal("tunnel write failure should be recorded")
		}
	})
	t.Run("clean-end", func(t *testing.T) {
		src := &scriptedConn{data: []byte("hello")}
		res := Copy(&scriptedConn{}, src, Client, nil)
		if res.Err != nil || res.Report() {
			t.Fatalf("got err %v, report %v", res.Err, res.Report())
		}
		if res.Bytes != 5 {
			t.Fatalf("copied %d bytes, want 5", res.Bytes)
		}
	})
}

// TestRelayQuietWhenClientClosesAbruptly は、手元のアプリが自分から切っただけのときに、
// 記録が増えないことを見る。
func TestRelayQuietWhenClientClosesAbruptly(t *testing.T) {
	app, browser := tcpPair(t)
	remote, peer := tcpPair(t)
	defer peer.Close()

	var lines lineSink
	done := make(chan struct{})
	go func() {
		Relay("HTTP CONNECT filter.example:443", browser, remote, nil, lines.add)
		close(done)
	}()

	// 返事を待たずに切る。フィルタリングソフトなどがこの切れ方をする。
	_, _ = app.Write([]byte("GET / HTTP/1.1\r\nHost: filter.example\r\n\r\n"))
	_ = app.SetLinger(0)
	_ = app.Close()

	waitDone(t, done)
	if got := lines.take(); len(got) != 0 {
		t.Fatalf("client close was recorded: %v", got)
	}
}

// TestRelayRecordsTunnelFailure は、中継先・トンネル側が切れたときは、
// これまでどおり記録に残ることを見る。
func TestRelayRecordsTunnelFailure(t *testing.T) {
	app, browser := tcpPair(t)
	defer app.Close()
	remote, peer := tcpPair(t)

	var lines lineSink
	done := make(chan struct{})
	go func() {
		Relay("HTTP CONNECT example.test:443", browser, remote, nil, lines.add)
		close(done)
	}()

	// 中継先が切る。こちらは待ち受けている最中に切られる。
	_ = peer.SetLinger(0)
	_ = peer.Close()

	waitDone(t, done)
	got := lines.take()
	if len(got) != 1 {
		t.Fatalf("got %d lines, want 1: %v", len(got), got)
	}
	if want := "HTTP CONNECT example.test:443 copy down ended"; !strings.Contains(got[0], want) {
		t.Fatalf("unexpected line: %v", got[0])
	}
}

// TestRelayCleanRoundTrip は、普通に往復して終わるときは黙ったままであることを見る。
func TestRelayCleanRoundTrip(t *testing.T) {
	app, browser := tcpPair(t)
	defer app.Close()
	remote, peer := tcpPair(t)

	go func() {
		buf := make([]byte, 64)
		n, _ := peer.Read(buf)
		_, _ = peer.Write(append([]byte("pong:"), buf[:n]...))
		_ = peer.Close()
	}()

	var lines lineSink
	done := make(chan struct{})
	go func() {
		Relay("SOCKS5 127.0.0.1:80", browser, remote, nil, lines.add)
		close(done)
	}()

	_ = app.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := app.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 送り終えたことを伝え、返事を最後まで読む。
	_ = app.CloseWrite()
	reply, err := io.ReadAll(app)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "pong:ping" {
		t.Fatalf("got reply %q", reply)
	}

	waitDone(t, done)
	if got := lines.take(); len(got) != 0 {
		t.Fatalf("clean round trip was recorded: %v", got)
	}
}

type lineSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *lineSink) add(format string, args ...any) {
	s.mu.Lock()
	s.lines = append(s.lines, fmt.Sprintf(format, args...))
	s.mu.Unlock()
}

func (s *lineSink) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lines
	s.lines = nil
	return out
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type accepted struct {
		c   *net.TCPConn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptTCP()
		ch <- accepted{c, err}
	}()
	a, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() {
		_ = a.Close()
		_ = r.c.Close()
	})
	return a, r.c
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}

// scriptedConn は、読み書きの結果を決めておける相手。
type scriptedConn struct {
	data     []byte
	readErr  error
	writeErr error
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if len(c.data) > 0 {
		n := copy(p, c.data)
		c.data = c.data[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }
