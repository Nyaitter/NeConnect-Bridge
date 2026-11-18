//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testEngine(t *testing.T) *bridgeEngine {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return newEngineBase("https://bridge.example.test/bridge/server", "https://bridge.example.test/bridge/poll", signer)
}

// 閉じたあとに来た接続は、何も張り出さずにすぐ断る。
func TestDialTargetAfterCloseFailsAtOnce(t *testing.T) {
	e := testEngine(t)
	e.close()

	start := time.Now()
	if _, err := e.dialTarget("example.com:443"); err == nil {
		t.Fatal("dialTarget succeeded after close")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("dialTarget error = %v, want closed", err)
	}
	if spent := time.Since(start); spent > time.Second {
		t.Fatalf("dialTarget took %s after close", spent)
	}
}

// 閉じたあとの張り出しは、予算を待たずに諦める。
func TestDialRawWSAfterCloseStopsAtOnce(t *testing.T) {
	e := testEngine(t)
	e.close()

	done := make(chan struct{})
	go func() {
		_, _, _ = e.dialRawWS("speed", nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dialRawWS kept trying after close")
	}
}

// 閉じたあとの流れの補充は、何もせずに終わる。
func TestFillPoolAfterCloseDoesNothing(t *testing.T) {
	e := testEngine(t)
	e.pool = make(chan net.Conn, poolSize)
	e.close()
	if err := e.fillPool(poolRefillMax); err != nil {
		t.Fatalf("fillPool after close = %v, want nil", err)
	}
	if len(e.pool) != 0 {
		t.Fatalf("pool changed after close: %d", len(e.pool))
	}
}

// 中継中の一本は、閉じたときに一緒に切る。
func TestCloseDropsRunningStreams(t *testing.T) {
	e := testEngine(t)
	left, right := net.Pipe()
	defer right.Close()

	tracked := e.trackStream("example.com", left)
	if len(e.streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(e.streams))
	}
	e.close()

	if _, err := tracked.Read(make([]byte, 1)); err == nil {
		t.Fatal("tracked stream is still open after close")
	}
	if len(e.streams) != 0 {
		t.Fatalf("streams = %d after close, want 0", len(e.streams))
	}
}
