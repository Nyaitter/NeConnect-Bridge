package hostguard

import (
	"testing"
	"time"
)

// clock は、時間を手で進められる見張りを作る。
func clock(t *testing.T) (*Guard, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	g := New()
	g.now = func() time.Time { return now }
	return g, &now
}

func TestOrdinaryParallelConnectionsAreLeftAlone(t *testing.T) {
	g, now := clock(t)

	// ブラウザが同じ相手へ数本つなぎ、1本はすぐ切れた、という普通の形。
	for i := 0; i < 6; i++ {
		if g.NoteAttempt("www.example.com") {
			t.Fatalf("attempt %d started a rest for an ordinary host", i+1)
		}
	}
	if g.NoteClosed("www.example.com", 500*time.Millisecond) {
		t.Fatal("one short connection started a rest")
	}
	if left, ok := g.Allow("www.example.com"); !ok {
		t.Fatalf("ordinary host is resting for %s", left)
	}

	// 少し間を置いた再接続も、数が増えなければ通す。
	*now = now.Add(2 * time.Second)
	for i := 0; i < 6; i++ {
		if g.NoteAttempt("www.example.com") {
			t.Fatalf("reconnect %d started a rest", i+1)
		}
	}
	if g.Resting("www.example.com") {
		t.Fatal("ordinary reconnects started a rest")
	}
}

func TestBurstOfAttemptsRestsTheHost(t *testing.T) {
	g, now := clock(t)

	burst := 0
	for i := 0; i < burstLimit; i++ {
		*now = now.Add(20 * time.Millisecond)
		if g.NoteAttempt("gi-s72m.iss.netstar-inc.com") {
			burst++
		}
	}
	if burst != 1 {
		t.Fatalf("burst started %d rests, want 1", burst)
	}
	left, ok := g.Allow("gi-s72m.iss.netstar-inc.com")
	if ok {
		t.Fatal("host is still allowed after a burst")
	}
	if left <= 0 || left > CoolDown {
		t.Fatalf("remaining rest is %s, want within %s", left, CoolDown)
	}

	// 別の相手は、巻き添えにならない。
	if left, ok := g.Allow("www.google.com"); !ok {
		t.Fatalf("other host is resting for %s", left)
	}
}

func TestBurstOlderThanWindowIsForgotten(t *testing.T) {
	g, now := clock(t)

	for i := 0; i < burstLimit-1; i++ {
		g.NoteAttempt("slow.example.com")
		*now = now.Add(400 * time.Millisecond)
	}
	if g.Resting("slow.example.com") {
		t.Fatal("rest started although the attempts were spread out")
	}
}

func TestRepeatedShortConnectionsRestTheHost(t *testing.T) {
	g, now := clock(t)

	rests := 0
	for i := 0; i < failLimit; i++ {
		*now = now.Add(300 * time.Millisecond)
		if g.NoteClosed("flaky.example.com", 200*time.Millisecond) {
			rests++
		}
	}
	if rests != 1 {
		t.Fatalf("short connections started %d rests, want 1", rests)
	}
	if !g.Resting("flaky.example.com") {
		t.Fatal("host is not resting after repeated short connections")
	}
}

func TestLongLivedConnectionsAndFailuresMix(t *testing.T) {
	g, now := clock(t)

	// 長く続いた接続と、少しの失敗では休ませない。
	if g.NoteClosed("busy.example.com", 30*time.Second) {
		t.Fatal("a long lived connection started a rest")
	}
	for i := 0; i < failLimit-1; i++ {
		*now = now.Add(100 * time.Millisecond)
		if g.NoteFailure("busy.example.com") {
			t.Fatalf("failure %d started a rest too early", i+1)
		}
	}
	if g.Resting("busy.example.com") {
		t.Fatal("a few failures started a rest")
	}
}

func TestRestEndsAndDoesNotExtendByRejections(t *testing.T) {
	g, now := clock(t)

	for i := 0; i < burstLimit; i++ {
		g.NoteAttempt("chatty.example.com")
	}
	if !g.Resting("chatty.example.com") {
		t.Fatal("rest did not start")
	}
	// 休み中に来た接続を何度断っても、休みは延びない。
	*now = now.Add(CoolDown / 2)
	for i := 0; i < 50; i++ {
		if n := g.NoteRejected("chatty.example.com"); n != i+1 {
			t.Fatalf("rejected count = %d, want %d", n, i+1)
		}
		g.NoteAttempt("chatty.example.com")
		g.NoteFailure("chatty.example.com")
	}
	*now = now.Add(CoolDown/2 + time.Millisecond)
	if left, ok := g.Allow("chatty.example.com"); !ok {
		t.Fatalf("host is still resting for %s after the rest ended", left)
	}

	// 明けた直後は、記録が消えているので1本目で止まらない。
	if g.NoteAttempt("chatty.example.com") {
		t.Fatal("rest started again right after it ended")
	}
}

func TestRestIsCountedPerHost(t *testing.T) {
	g, now := clock(t)

	for i := 0; i < burstLimit; i++ {
		g.NoteAttempt("noisy.example.com")
	}
	if !g.Resting("noisy.example.com") {
		t.Fatal("rest did not start")
	}
	if g.Resting("noisy2.example.com") {
		t.Fatal("a different host was rested")
	}
	if g.NoteFailure("noisy2.example.com") {
		t.Fatal("failures on another host started a rest")
	}
	_ = now
}

func TestEmptyHostIsIgnored(t *testing.T) {
	g := New()
	if g.Resting("") {
		t.Fatal("empty host is resting")
	}
	for i := 0; i < burstLimit*2; i++ {
		if g.NoteAttempt("") || g.NoteFailure("") {
			t.Fatal("empty host started a rest")
		}
	}
}

func TestEntriesAreBounded(t *testing.T) {
	g, now := clock(t)

	for i := 0; i < maxHosts*2; i++ {
		host := "host" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + "."
		g.NoteAttempt(host)
		*now = now.Add(time.Millisecond)
	}
	if len(g.entries) > maxHosts {
		t.Fatalf("entries = %d, want at most %d", len(g.entries), maxHosts)
	}
}
