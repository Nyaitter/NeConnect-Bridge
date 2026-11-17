package adblock

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, lines ...string) *Blocker {
	t.Helper()
	b, err := Parse(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return b
}

func TestAdGuardStyleRulesBlockDomainAndSubdomains(t *testing.T) {
	b := mustParse(t, "||ad.example.com^")
	for _, host := range []string{"ad.example.com", "sub.ad.example.com", "AD.Example.COM", "ad.example.com:443"} {
		if !b.Blocked(host) {
			t.Errorf("%s は止めるべき", host)
		}
	}
	// 名前の途中が同じだけのものは止めない。
	for _, host := range []string{"badad.example.com", "ad.example.com.evil.test", "example.com"} {
		if b.Blocked(host) {
			t.Errorf("%s は通すべき", host)
		}
	}
}

func TestExceptionRuleWins(t *testing.T) {
	b := mustParse(t,
		"||ad.example.com^",
		"@@||safe.ad.example.com^",
	)
	if b.Blocked("safe.ad.example.com") {
		t.Fatal("外す指定のある名前は通すべき")
	}
	if !b.Blocked("other.ad.example.com") {
		t.Fatal("外す指定の外は、上の規則で止めるべき")
	}
	if !b.Blocked("ad.example.com") {
		t.Fatal("元の名前は止めるべき")
	}
}

func TestHostsAndWildcardForms(t *testing.T) {
	b := mustParse(t,
		"# コメント",
		"0.0.0.0 tracker.example.net",
		"127.0.0.1 metric.example.net # 後ろの注釈",
		"*.wild.example.org",
		"plain.example.io",
		"! Adblock の注釈",
	)
	cases := map[string]bool{
		"tracker.example.net":    true,
		"a.tracker.example.net":  true,
		"metric.example.net":     true,
		"wild.example.org":       true,
		"x.wild.example.org":     true,
		"plain.example.io":       true,
		"www.plain.example.io":   true,
		"unrelated.example.com":  false,
		"nottracker.example.net": false,
		"example.net":            false,
	}
	for host, want := range cases {
		if got := b.Blocked(host); got != want {
			t.Errorf("%s: got %v want %v", host, got, want)
		}
	}
}

func TestLocalNamesAndAddressesAreNeverBlocked(t *testing.T) {
	// 一覧に紛れていても、端末の中と住所は止めない。
	b := mustParse(t,
		"||localhost^",
		"||local^",
		"||127.0.0.1^",
		"10.0.0.5",
		"router",
	)
	for _, host := range []string{"localhost", "localhost:8080", "127.0.0.1", "10.0.0.5", "192.168.1.20", "router", "printer.local", "::1", "[::1]:8090"} {
		if b.Blocked(host) {
			t.Errorf("%s は止めてはいけない", host)
		}
	}
}

func TestPathAndRegexRulesAreIgnored(t *testing.T) {
	// 名前だけの判定に持ち込むと広がりすぎる規則は読まない。
	b := mustParse(t,
		"/banner/*/img^",
		"||example.com/ads.js",
		"|https://ads.example.com^",
		"||ok.example.com^",
	)
	if b.Blocked("example.com") {
		t.Fatal("道筋つきの規則で名前ごと止めてはいけない")
	}
	if !b.Blocked("ok.example.com") {
		t.Fatal("読める規則は効くべき")
	}
}

func TestModifiersDoNotHideTheDomain(t *testing.T) {
	b := mustParse(t,
		"||ads.example.com^$third-party",
		"||track.example.com^$important,domain=other.test",
	)
	if !b.Blocked("ads.example.com") || !b.Blocked("track.example.com") {
		t.Fatal("言い換えが付いていても名前は読むべき")
	}
}

func TestEmbeddedListsLoad(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stats := b.Stats()
	if stats.Blocked < 100000 {
		t.Fatalf("組み込みの一覧が小さすぎます: %d", stats.Blocked)
	}
	// 代表的な広告配信元と、代表的な基盤は期待どおりに分かれる。
	if !b.Blocked("doubleclick.net") {
		t.Error("doubleclick.net は止めるべき")
	}
	if !b.Blocked("pagead2.googlesyndication.com") {
		t.Error("pagead2.googlesyndication.com は止めるべき")
	}
	for _, host := range []string{"github.com", "google.com", "www.google.com", "localhost", "127.0.0.1"} {
		if b.Blocked(host) {
			t.Errorf("%s は通すべき", host)
		}
	}
	t.Logf("止める %d 件 / 通す %d 件", stats.Blocked, stats.Allowed)
}

func TestNilBlockerPassesEverything(t *testing.T) {
	var b *Blocker
	if b.Blocked("ads.example.com") {
		t.Fatal("読み込む前は何も止めない")
	}
}

func BenchmarkBlockedHit(b *testing.B) {
	blocker, err := Load()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blocker.Blocked("pagead2.googlesyndication.com")
	}
}

func BenchmarkBlockedMiss(b *testing.B) {
	blocker, err := Load()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blocker.Blocked("www.example.com")
	}
}
