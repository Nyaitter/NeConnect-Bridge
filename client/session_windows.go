package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const activeSocksFile = "active_socks.json"

// session は 1 本のブリッジ接続とローカル入口を持つ。
type session struct {
	dir    string
	signer ssh.Signer

	mu        sync.Mutex
	eng       *bridgeEngine
	ln        net.Listener
	backup    *sysProxyBackup
	modeLabel string
	port      int
	closed    bool
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
func (s *session) connect(serverURLs string, modeIdx int, withSystemProxy bool, setStatus func(string)) error {
	modeChoices := []string{"auto", "speed", "balance", "secure"}
	modeLabels := map[string]string{"auto": "オート", "speed": "スピード", "balance": "バランス", "secure": "セキュア"}
	if modeIdx < 0 || modeIdx >= len(modeChoices) {
		modeIdx = 0
	}
	if setStatus == nil {
		setStatus = func(string) {}
	}
	selectedMode := modeChoices[modeIdx]
	urlList := splitServerURLs(serverURLs)
	logf("Connect start: mode=%s urls=%v", selectedMode, urlList)

	var eng *bridgeEngine
	var label string
	var allErrs []string

	for idx, rawURL := range urlList {
		var wsBaseHTTP string
		sshHost := defaultSSHHost
		obfsHost := defaultObfsHost
		isSSHOnly := false
		if len(rawURL) > 6 && rawURL[:6] == "ssh://" {
			isSSHOnly = true
			sshHost = rawURL[6:]
			if !containsColon(sshHost) {
				sshHost += ":22"
			}
		} else {
			_, httpURL, uerr := toWSURL(rawURL, "balance")
			if uerr != nil {
				allErrs = append(allErrs, rawURL+": "+uerr.Error())
				continue
			}
			wsBaseHTTP = httpURL
			meta := fetchMeta(httpURL)
			sshHost = meta.SSHHost
			obfsHost = meta.ObfsHost
		}
		if isSSHOnly && selectedMode == "speed" {
			continue
		}
		setStatus(fmt.Sprintf("%sモードで接続中... [%d/%d]", modeLabels[selectedMode], idx+1, len(urlList)))
		var pollURL string
		if !isSSHOnly {
			pollURL = trimServerSuffix(wsBaseHTTP) + "/poll"
		}
		e, cerr := newBridgeEngine(selectedMode, wsBaseHTTP, pollURL, sshHost, obfsHost, s.signer)
		if cerr == nil {
			eng = e
			label = modeLabels[selectedMode]
			break
		}
		logf("URL %s failed (%s): %v", rawURL, selectedMode, cerr)
		allErrs = append(allErrs, rawURL+"["+selectedMode+"]: "+cerr.Error())
	}

	if eng == nil {
		return fmt.Errorf("接続に失敗しました [%s]:\n%v", modeLabels[selectedMode], allErrs)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		eng.close()
		return fmt.Errorf("ローカル接続口を確保できませんでした: %v", err)
	}
	go serveSOCKS5(ln, eng)

	addr, _ := ln.Addr().(*net.TCPAddr)
	port := 0
	if addr != nil {
		port = addr.Port
	}

	s.mu.Lock()
	s.eng = eng
	s.ln = ln
	s.port = port
	s.modeLabel = label
	s.closed = false
	s.mu.Unlock()

	logf("Local entry ready on 127.0.0.1:%d [%s]", port, label)

	if withSystemProxy {
		setStatus("まわりのアプリにも反映しています...")
		bk, berr := setSystemSOCKSProxy(ln.Addr().String())
		if berr != nil {
			logf("setSystemSOCKSProxy failed: %v", berr)
		} else {
			s.mu.Lock()
			s.backup = bk
			s.mu.Unlock()
		}
	}
	return nil
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

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

func trimServerSuffix(u string) string {
	if len(u) >= 7 && u[len(u)-7:] == "/server" {
		return u[:len(u)-7]
	}
	return u
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
