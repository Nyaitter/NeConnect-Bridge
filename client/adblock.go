package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"neconnectbridge/internal/adblock"
)

// 広告ブロックの状態。接続の処理から何度も読むので、鍵を取らずに読める形で持つ。
var (
	adblockOn       atomic.Bool
	adblockBlocker  atomic.Pointer[adblock.Blocker]
	adblockHitCount atomic.Uint64

	adblockAllowMu    sync.RWMutex
	adblockAllowHosts = map[string]struct{}{}
)

// setAdBlockEnabled は、止めるかどうかを切り替える。
// 切り替えた瞬間から、つながっている接続にも効く。
func setAdBlockEnabled(on bool) {
	adblockOn.Store(on)
	if !on {
		logf("広告ブロック: オフ")
		return
	}
	if b := adblockBlocker.Load(); b != nil {
		stats := b.Stats()
		logf("広告ブロック: オン（%d 件）", stats.Blocked)
		return
	}
	logf("広告ブロック: オン（一覧を読み込み中）")
	startAdBlockLoad()
}

// startAdBlockLoad は、一覧の読み込みを一度だけ始める。
// 読み終わるまでは何も止めないので、接続を待たせない。
var adblockLoadOnce sync.Once

func startAdBlockLoad() {
	adblockLoadOnce.Do(func() {
		goSafe("adblock load", func() {
			b, err := adblock.Load()
			if err != nil {
				logf("広告ブロックの一覧を読めませんでした: %v", err)
				return
			}
			adblockBlocker.Store(b)
			stats := b.Stats()
			if adblockOn.Load() {
				logf("広告ブロックの一覧を読み込みました（%d 件）", stats.Blocked)
			}
		})
	})
}

// setAdBlockHosts は、ブリッジの接続先を止めない側へ入れる。
// 接続に使う名前を一覧が止めてしまうと、更新も中継も届かなくなるため。
func setAdBlockHosts(serverURLs string) {
	hosts := map[string]struct{}{}
	for _, raw := range splitServerURLs(serverURLs) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		hosts[host] = struct{}{}
		// 名前の後ろの部分も通す（同じ配下の受け口を使うことがあるため）。
		for i := strings.IndexByte(host, '.'); i >= 0 && i < len(host)-1; {
			rest := host[i+1:]
			if strings.Contains(rest, ".") {
				hosts[rest] = struct{}{}
			}
			next := strings.IndexByte(rest, '.')
			if next < 0 {
				break
			}
			i = i + 1 + next
		}
	}
	adblockAllowMu.Lock()
	adblockAllowHosts = hosts
	adblockAllowMu.Unlock()
}

// adBlockAllows は、その名前を通す側に書かれているかを見る。
func adBlockAllows(host string) bool {
	adblockAllowMu.RLock()
	defer adblockAllowMu.RUnlock()
	if len(adblockAllowHosts) == 0 {
		return false
	}
	name := adblock.NormalizeHost(host)
	if _, ok := adblockAllowHosts[name]; ok {
		return true
	}
	for i := strings.IndexByte(name, '.'); i >= 0 && i < len(name)-1; {
		rest := name[i+1:]
		if _, ok := adblockAllowHosts[rest]; ok {
			return true
		}
		next := strings.IndexByte(rest, '.')
		if next < 0 {
			break
		}
		i = i + 1 + next
	}
	return false
}

// shouldBlockHost は、その名前への接続を止めるかを返す。
func shouldBlockHost(host string) bool {
	if !adblockOn.Load() {
		return false
	}
	b := adblockBlocker.Load()
	if b == nil {
		return false
	}
	name := adblock.NormalizeHost(host)
	if name == "" || net.ParseIP(name) != nil || adBlockAllows(name) {
		return false
	}
	return b.Blocked(name)
}

// noteAdBlockHit は、止めたことを控えめに記録する。
// 広告の多いページでは1ページで何十件も出るので、窓を埋めないよう間引く。
func noteAdBlockHit(host string) {
	total := adblockHitCount.Add(1)
	// 初めの数件と、その後は 200 件ごとにだけ残す。
	switch {
	case total <= 5:
		logf("Adblock blocked: %s", adblock.NormalizeHost(host))
	case total%200 == 0:
		logf("広告ブロック: これまでに %d 件を止めました（直近: %s）", total, adblock.NormalizeHost(host))
	}
}

// adBlockSummary は、いまの止めた件数を返す。
func adBlockSummary() string {
	total := adblockHitCount.Load()
	if total == 0 {
		return "広告ブロック: オン"
	}
	return fmt.Sprintf("広告ブロック: オン（%d 件を停止）", total)
}
