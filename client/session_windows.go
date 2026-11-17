package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const activeSocksFile = "active_socks.json"

// session は 1 本のブリッジ接続とローカル入口を持つ。
type session struct {
	dir    string
	signer ssh.Signer

	mu     sync.Mutex
	eng    *bridgeEngine
	ln     net.Listener
	backup *sysProxyBackup
	port   int
	closed bool
}

func newSession(dir string, signer ssh.Signer) *session {
	return &session{dir: dir, signer: signer}
}

func (s *session) socksPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

func (s *session) connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng != nil && !s.closed
}

// connect はブリッジへ接続し、ローカルの入口を開く。
// 前回つながった経路があれば、それを先に試す。
func (s *session) connect(serverURLs string, cached *routeCache, withSystemProxy bool, setStatus func(string)) (*routeCache, error) {
	if setStatus == nil {
		setStatus = func(string) {}
	}
	urlList := splitServerURLs(serverURLs)
	if len(urlList) == 0 {
		return nil, fmt.Errorf("ブリッジURLが指定されていません")
	}
	logf("Connect start: urls=%v", urlList)

	var eng *bridgeEngine
	var route *routeCache
	var allErrs []string

	// 前回の経路を先に試す。表示は通常の接続と同じまま、順番だけ先に置く。
	total := len(urlList)
	pos := 1
	if cached != nil {
		raw := strings.TrimSpace(cached.URL)
		switch {
		case raw == "" || cached.Method == "":
			// 手がかりがないときは何もしない。
		case !containsURL(urlList, raw):
			logf("cached route skipped: %s is not in the list", raw)
		default:
			total++
			setStatus(fmt.Sprintf("接続中... [%d/%d]", pos, total))
			pos++
			e, cerr := s.dialRoute(*cached, raw)
			if cerr != nil {
				logf("cached route failed: %v", cerr)
				allErrs = append(allErrs, "cached: "+cerr.Error())
			} else {
				eng = e
				saved := *cached
				route = &saved
				logf("connected via %s", routeLabelText(route))
			}
		}
	}

	if eng == nil {
		for _, rawURL := range urlList {
			_, httpURL, uerr := toWSURL(rawURL, "auto")
			if uerr != nil {
				allErrs = append(allErrs, rawURL+": "+uerr.Error())
				continue
			}
			setStatus(fmt.Sprintf("接続中... [%d/%d]", pos, total))
			pos++
			e, cerr := newBridgeEngine(httpURL, pollURLFor(httpURL), s.signer)
			if cerr == nil {
				eng = e
				route = e.routeCacheFor(rawURL)
				logf("connected via %s", routeLabelText(route))
				break
			}
			logf("URL %s failed: %v", rawURL, cerr)
			allErrs = append(allErrs, rawURL+": "+cerr.Error())
		}
	}

	if eng == nil {
		return nil, fmt.Errorf("接続に失敗しました:\n%s", strings.Join(allErrs, "\n"))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		eng.close()
		return nil, fmt.Errorf("ローカル接続口を確保できませんでした: %v", err)
	}
	pool := &bufPool64
	if eng.pool != nil {
		pool = &bufPool256
	}
	go serveLocalProxy(ln, eng.dialTarget, pool)

	addr, _ := ln.Addr().(*net.TCPAddr)
	port := 0
	if addr != nil {
		port = addr.Port
	}

	s.mu.Lock()
	s.eng = eng
	s.ln = ln
	s.port = port
	s.closed = false
	s.mu.Unlock()

	logf("Local entry ready on 127.0.0.1:%d", port)

	if withSystemProxy {
		setStatus("まわりのアプリにも反映しています...")
		bk, berr := setSystemSOCKSProxy(ln.Addr().String())
		if berr != nil {
			logf("system proxy setting failed: %v", berr)
		} else {
			s.mu.Lock()
			s.backup = bk
			s.mu.Unlock()
		}
	}
	return route, nil
}

// dialRoute は、保存した経路だけで接続を試す。
func (s *session) dialRoute(route routeCache, rawURL string) (*bridgeEngine, error) {
	_, httpURL, uerr := toWSURL(rawURL, "auto")
	if uerr != nil {
		return nil, uerr
	}
	return newBridgeEngineForRoute(route, httpURL, pollURLFor(httpURL), s.signer)
}

func containsURL(list []string, want string) bool {
	for _, item := range list {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

// cleanup は接続を閉じ、必要なら元の状態へ戻す。
func (s *session) cleanup() {
	s.mu.Lock()
	if s.closed && s.eng == nil && s.ln == nil && s.backup == nil {
		s.mu.Unlock()
		return
	}
	s.closed = true
	bk := s.backup
	ln := s.ln
	eng := s.eng
	s.backup = nil
	s.ln = nil
	s.eng = nil
	s.port = 0
	s.mu.Unlock()

	runBounded("listener", 800*time.Millisecond, func() {
		if ln != nil {
			_ = ln.Close()
		}
	})
	runBounded("tunnel", 1500*time.Millisecond, func() {
		if eng != nil {
			eng.close()
		}
	})
	runBounded("proxy", 1500*time.Millisecond, func() {
		if bk != nil {
			bk.restore()
		}
	})
}

// ---- 共有情報ファイル -------------------------------------------------

type activeSocksInfo struct {
	PID   int    `json:"pid"`
	Port  int    `json:"port"`
	Mode  string `json:"mode"`
	Since string `json:"since"`
}

func writeActiveSocks(dir string, port int, mode string) {
	info := activeSocksInfo{PID: os.Getpid(), Port: port, Mode: mode, Since: time.Now().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(info, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, activeSocksFile), b, 0600); err != nil {
		logf("write %s failed: %v", activeSocksFile, err)
	}
}

func clearActiveSocks(dir string) {
	p := filepath.Join(dir, activeSocksFile)
	_ = os.Remove(p)
}

// probeSocks は、そのポートで入口が答えているかを短く確かめる。
func probeSocks(port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return reply[0] == 0x05 && reply[1] == 0x00
}

// readActiveSocks は生きている接続の入口を返す。
// 前に落ちたときの情報が残っていても、そのまま使わない。
func readActiveSocks(dir string) (activeSocksInfo, bool) {
	var info activeSocksInfo
	b, err := os.ReadFile(filepath.Join(dir, activeSocksFile))
	if err != nil {
		return info, false
	}
	if err := json.Unmarshal(b, &info); err != nil {
		clearActiveSocks(dir)
		return info, false
	}
	if info.Port <= 0 || info.Port > 65535 || info.PID <= 0 || !isPIDAlive(uint32(info.PID)) {
		logf("shared entry stale (pid=%d port=%d)", info.PID, info.Port)
		clearActiveSocks(dir)
		return info, false
	}
	if !probeSocks(info.Port, 900*time.Millisecond) {
		logf("shared entry did not answer (pid=%d port=%d)", info.PID, info.Port)
		return info, false
	}
	return info, true
}
