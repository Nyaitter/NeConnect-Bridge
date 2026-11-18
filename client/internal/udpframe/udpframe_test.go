package udpframe

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

func TestAddrRoundTrip(t *testing.T) {
	cases := []Addr{
		{Host: "203.0.113.7", Port: 3478},
		{Host: "stun.example.com", Port: 19302},
		{Host: "2001:db8::1", Port: 443},
	}
	for _, want := range cases {
		encoded, err := MarshalAddr(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		got, size, err := UnmarshalAddr(encoded)
		if err != nil {
			t.Fatalf("unmarshal %v: %v", want, err)
		}
		if size != len(encoded) {
			t.Fatalf("%v: size %d, want %d", want, size, len(encoded))
		}
		if got.Host != want.Host || got.Port != want.Port {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAddrRejectsBrokenInput(t *testing.T) {
	if _, err := MarshalAddr(Addr{Host: "", Port: 80}); err == nil {
		t.Fatal("empty destination was accepted")
	}
	if _, _, err := UnmarshalAddr([]byte{0x09, 1, 2, 3, 4, 0, 80}); err == nil {
		t.Fatal("unknown type was accepted")
	}
	if _, _, err := UnmarshalAddr([]byte{0x03, 5, 'a'}); err == nil {
		t.Fatal("short name was accepted")
	}
}

func TestRequestMarkerDoesNotLookLikeALength(t *testing.T) {
	target := []byte("example.com:443")
	if int(Request)&0x8000 == 0 {
		t.Fatal("request marker must set the top bit")
	}
	if len(target) >= int(Request) {
		t.Fatal("a normal target length must stay below the marker")
	}
}

func TestFrameSurvivesBeingSplit(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	var composed bytes.Buffer
	if err := WriteFrame(&composed, Addr{Host: "203.0.113.9", Port: 9000}, []byte("hello")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	want := composed.Bytes()

	go func() {
		for i := 0; i < len(want); i += 3 {
			end := i + 3
			if end > len(want) {
				end = len(want)
			}
			if _, err := left.Write(want[i:end]); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	reader := bufio.NewReaderSize(right, 8)
	addr, payload, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if addr.Host != "203.0.113.9" || addr.Port != 9000 {
		t.Fatalf("addr = %v", addr)
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestReadFrameRejectsImpossibleLength(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x01, 0x01}))
	if _, _, err := ReadFrame(reader); err == nil {
		t.Fatal("a one byte frame was accepted")
	}
}

func TestSocksDatagramRoundTrip(t *testing.T) {
	want := Addr{Host: "media.example.net", Port: 50000}
	packet, err := MarshalSocksUDP(want, []byte("frame"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, payload, err := UnmarshalSocksUDP(packet)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}
	if string(payload) != "frame" {
		t.Fatalf("payload = %q", payload)
	}

	// 分かれたまとまりは扱わない。
	broken := append([]byte(nil), packet...)
	broken[2] = 0x01
	if _, _, err := UnmarshalSocksUDP(broken); err == nil {
		t.Fatal("fragmented datagram was accepted")
	}
}
