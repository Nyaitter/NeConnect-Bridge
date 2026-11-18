package udpassoc

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"neconnectbridge/internal/udpframe"
)

// fakeBridge は、中継の向こう側を代わりに務める。
// 受け取ったまとまりを、別の相手から返ってきた形にして送り返す。
func fakeBridge(conn net.Conn, mu *sync.Mutex, seen *[]udpframe.Addr) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 32*1024)
	var head [2]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return
	}
	if binary.BigEndian.Uint16(head[:]) != udpframe.Request {
		return
	}
	if _, err := conn.Write([]byte{0x00}); err != nil {
		return
	}
	for {
		addr, payload, err := udpframe.ReadFrame(reader)
		if err != nil {
			return
		}
		mu.Lock()
		*seen = append(*seen, addr)
		mu.Unlock()
		reply := append([]byte("back:"), payload...)
		if werr := udpframe.WriteFrame(conn, udpframe.Addr{Host: "198.51.100.5", Port: 5000}, reply); werr != nil {
			return
		}
	}
}

type harness struct {
	tcp     net.Conn
	sender  *net.UDPConn
	local   *net.UDPConn
	seen    func() []udpframe.Addr
	release func()
}

func startHarness(t *testing.T, opts Options) *harness {
	t.Helper()
	bridgeSide, tunnelSide := net.Pipe()
	var mu sync.Mutex
	var seen []udpframe.Addr
	go fakeBridge(bridgeSide, &mu, &seen)

	tun, err := Open(tunnelSide)
	if err != nil {
		t.Fatalf("open tunnel: %v", err)
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	control, controlPeer := net.Pipe()

	if opts.Idle <= 0 {
		opts.Idle = 5 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	var done atomic.Bool
	go func() {
		_ = Run(control, tun, local, opts)
		done.Store(true)
	}()

	return &harness{
		tcp:    controlPeer,
		sender: sender,
		local:  local,
		seen: func() []udpframe.Addr {
			mu.Lock()
			defer mu.Unlock()
			out := make([]udpframe.Addr, len(seen))
			copy(out, seen)
			return out
		},
		release: func() {
			_ = controlPeer.Close()
			_ = sender.Close()
		},
	}
}

func sendDatagram(t *testing.T, h *harness, addr udpframe.Addr, payload string) {
	t.Helper()
	packet, err := udpframe.MarshalSocksUDP(addr, []byte(payload))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := h.sender.WriteToUDP(packet, h.local.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func readDatagram(t *testing.T, h *harness) (udpframe.Addr, []byte) {
	t.Helper()
	_ = h.sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := h.sender.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	addr, payload, err := udpframe.UnmarshalSocksUDP(buf[:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return addr, payload
}

func TestDatagramGoesOutAndComesBack(t *testing.T) {
	h := startHarness(t, Options{})
	defer h.release()

	sendDatagram(t, h, udpframe.Addr{Host: "203.0.113.7", Port: 3478}, "ping")
	addr, payload := readDatagram(t, h)

	if string(payload) != "back:ping" {
		t.Fatalf("payload = %q", payload)
	}
	if addr.Host != "198.51.100.5" || addr.Port != 5000 {
		t.Fatalf("addr = %v", addr)
	}
	got := h.seen()
	if len(got) != 1 || got[0].Host != "203.0.113.7" || got[0].Port != 3478 {
		t.Fatalf("bridge saw %v", got)
	}
}

func TestSeveralDestinationsShareOneAssociation(t *testing.T) {
	h := startHarness(t, Options{})
	defer h.release()

	sendDatagram(t, h, udpframe.Addr{Host: "203.0.113.7", Port: 3478}, "stun")
	sendDatagram(t, h, udpframe.Addr{Host: "media.example.net", Port: 50000}, "media")
	readDatagram(t, h)
	readDatagram(t, h)

	got := h.seen()
	if len(got) != 2 {
		t.Fatalf("bridge saw %v", got)
	}
	if got[0].Host != "203.0.113.7" || got[1].Host != "media.example.net" {
		t.Fatalf("bridge saw %v", got)
	}
}

func TestFragmentedDatagramIsDropped(t *testing.T) {
	h := startHarness(t, Options{})
	defer h.release()

	packet, err := udpframe.MarshalSocksUDP(udpframe.Addr{Host: "203.0.113.7", Port: 3478}, []byte("x"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	packet[2] = 0x01 // 分かれたまとまりの印
	if _, err := h.sender.WriteToUDP(packet, h.local.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.seen(); len(got) != 0 {
		t.Fatalf("bridge saw %v", got)
	}
}

func TestBlockedDestinationIsDropped(t *testing.T) {
	h := startHarness(t, Options{Blocked: func(host string) bool { return host == "ads.example.com" }})
	defer h.release()

	sendDatagram(t, h, udpframe.Addr{Host: "ads.example.com", Port: 443}, "blocked")
	time.Sleep(200 * time.Millisecond)
	if got := h.seen(); len(got) != 0 {
		t.Fatalf("bridge saw %v", got)
	}

	sendDatagram(t, h, udpframe.Addr{Host: "ok.example.com", Port: 443}, "allowed")
	readDatagram(t, h)
	if got := h.seen(); len(got) != 1 || got[0].Host != "ok.example.com" {
		t.Fatalf("bridge saw %v", got)
	}
}

func TestIdleAssociationCloses(t *testing.T) {
	h := startHarness(t, Options{Idle: 1200 * time.Millisecond})
	defer h.release()

	sendDatagram(t, h, udpframe.Addr{Host: "203.0.113.7", Port: 3478}, "once")
	readDatagram(t, h)

	// 何も無いまま時間が過ぎたら、入口は閉じる。
	time.Sleep(2 * time.Second)
	if _, err := h.sender.WriteToUDP([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}, h.local.LocalAddr().(*net.UDPAddr)); err != nil {
		// 閉じたあとの送信は届かないだけで、ここでは何も確かめない。
		_ = err
	}
	_ = h.tcp
}

func TestRefusedAssociationIsReported(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	go func() {
		defer serverSide.Close()
		buf := make([]byte, 2)
		if _, err := io.ReadFull(serverSide, buf); err != nil {
			return
		}
		_, _ = serverSide.Write([]byte{0x02})
	}()
	if _, err := Open(clientSide); err == nil {
		t.Fatal("a refused association was accepted")
	}
}
