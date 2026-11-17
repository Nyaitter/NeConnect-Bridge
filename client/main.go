package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"neconnectbridge/internal/covert"
	"neconnectbridge/internal/e2e"
	"neconnectbridge/internal/httptunnel"
	"neconnectbridge/internal/obfs"
	"neconnectbridge/internal/wsconn"
)

//go:embed id_ed25519_nctb
var embeddedKey []byte

// 中継の難読化に使う合言葉。自分のサーバーに合わせて差し替える。
const obfsPassphrase = "replace-with-your-secret"

var obfsKey = sha256.Sum256([]byte(obfsPassphrase))

const (
	officialSSHHostKeyLine = ""
	defaultServerURL       = "https://bridge.example.com/bridge/server"
	browserUA              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

// routeCache は、前回つながった経路の手がかり。
type routeCache struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Param  string `json:"param,omitempty"`
	At     string `json:"at,omitempty"`
}

type Config struct {
	ClientID  string      `json:"client_id"`
	ServerURL string      `json:"server_url"`
	TargetIdx int         `json:"target_idx"`
	AppPath   string      `json:"app_path"`
	URLSet    int         `json:"url_set"`
	Route     *routeCache `json:"last_route,omitempty"`
}

var (
	globalUI   *mainUI
	logMu      sync.Mutex
	logFile    *os.File
	bufPool64  = sync.Pool{New: func() any { b := make([]byte, 128*1024); return &b }}
	bufPool256 = sync.Pool{New: func() any { b := make([]byte, 256*1024); return &b }}
)

func initLogger(dir string) {
	path := filepath.Join(dir, "nctb.log")
	// 記録が大きくなりすぎたら、前の分を退けてから書き始める。
	if st, err := os.Stat(path); err == nil && st.Size() > 4*1024*1024 {
		old := path + ".1"
		_ = os.Remove(old)
		_ = os.Rename(path, old)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile = f
		logf("=== NeConnect Bridge started ===")
	}
}

func logf(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s", ts, msg)
	logMu.Lock()
	if logFile != nil {
		_, _ = fmt.Fprintln(logFile, line)
	}
	logMu.Unlock()
	uiAppendLog(line)
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

const defaultMultiURLs = "https://bridge.example.com/bridge/server"

// urlSetVersion はブリッジURLの初期一覧を更新したときに上げる。
const urlSetVersion = 2

func loadConfig(dir string) Config {
	cfg := Config{
		ServerURL: defaultMultiURLs,
		TargetIdx: targetBrowser,
	}
	b, err := os.ReadFile(filepath.Join(dir, "nctb_config.json"))
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		var b [16]byte
		_, _ = rand.Read(b[:])
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		cfg.ClientID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		saveConfig(dir, cfg)
	}
	if strings.TrimSpace(cfg.ServerURL) == "" {
		cfg.ServerURL = defaultMultiURLs
	}
	// 前の版が保存した接続先はそのまま使わず、今の一覧へ入れ替える。
	if cfg.URLSet < urlSetVersion {
		cfg.ServerURL = defaultMultiURLs
		cfg.URLSet = urlSetVersion
		saveConfig(dir, cfg)
	}
	if cfg.TargetIdx < 0 || cfg.TargetIdx > targetApp {
		cfg.TargetIdx = targetBrowser
	}
	return cfg
}

func saveConfig(dir string, cfg Config) {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "nctb_config.json"), b, 0600)
}

func splitServerURLs(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || seen[s] {
			continue
		}
		// 直結の指定は使わず、ブリッジURLだけを扱う。
		if strings.HasPrefix(strings.ToLower(s), "ssh://") {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		out = append(out, defaultServerURL)
	}
	return out
}

func findFirstExisting(list []string) string {
	for _, p := range list {
		if p != "" {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	return ""
}

func findPortableChromium(dir string) string {
	cands := []string{
		filepath.Join(dir, "runtime", "chrome-win64", "chrome.exe"),
		filepath.Join(dir, "runtime", "chrome.exe"),
	}
	return findFirstExisting(cands)
}

var (
	dohMu    sync.Mutex
	dohCache = map[string]struct {
		ip  string
		exp time.Time
	}{}
)

func resolveDoH(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	dohMu.Lock()
	if ent, ok := dohCache[host]; ok && time.Now().Before(ent.exp) {
		dohMu.Unlock()
		return ent.ip, nil
	}
	dohMu.Unlock()
	endpoints := []string{
		"https://1.1.1.1/dns-query?name=" + url.QueryEscape(host) + "&type=A",
		"https://8.8.8.8/resolve?name=" + url.QueryEscape(host) + "&type=A",
	}
	hc := &http.Client{Timeout: 4 * time.Second}
	for _, ep := range endpoints {
		req, err := http.NewRequest("GET", ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := hc.Do(req)
		if err != nil {
			logf("DoH query failed (%s): %v", ep, err)
			continue
		}
		var res struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(resp.Body).Decode(&res)
		_ = resp.Body.Close()
		if err == nil {
			for _, ans := range res.Answer {
				if ans.Type == 1 && net.ParseIP(ans.Data) != nil {
					logf("DoH resolved %s -> %s", host, ans.Data)
					dohMu.Lock()
					dohCache[host] = struct {
						ip  string
						exp time.Time
					}{ans.Data, time.Now().Add(10 * time.Minute)}
					dohMu.Unlock()
					return ans.Data, nil
				}
			}
		}
	}
	return "", fmt.Errorf("DoH resolution failed for %s", host)
}

func proxyFunc(req *http.Request) (*url.URL, error) {
	if u := getSystemHTTPProxy(); u != nil {
		return u, nil
	}
	return http.ProxyFromEnvironment(req)
}

var cfAnycastIPs = []string{"104.21.64.170", "172.67.153.171", "104.16.132.229"}

func makeCFDirectHTTPClient(timeout time.Duration, cfIP string) *http.Client {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					port = "443"
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(cfIP, port))
			},
		},
	}
}

func makeDoHHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// 自分自身の通信はまわりの設定に左右されないよう、そのままつなぐ。
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := dialer.DialContext(ctx, network, addr)
				if err == nil {
					return c, nil
				}
				host, port, serr := net.SplitHostPort(addr)
				if serr != nil {
					return nil, err
				}
				ip, derr := resolveDoH(host)
				if derr != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
	}
}

func ensurePortableChromium(dir string, socksPort int, setStatus func(string)) (string, error) {
	if p := findPortableChromium(dir); p != "" {
		return p, nil
	}

	setStatus("ブラウザを準備中...")
	logf("Downloading portable Chromium via local entry (port=%d)...", socksPort)
	hc := socksHTTPClient(socksPort, 10*time.Minute)

	const metaURL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
	resp, err := hc.Get(metaURL)
	if err != nil {
		logf("Tunnel meta fetch failed (%v), trying direct", err)
		hc = &http.Client{Timeout: 10 * time.Minute}
		resp, err = hc.Get(metaURL)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()

	var manifest struct {
		Channels struct {
			Stable struct {
				Downloads struct {
					Chrome []struct {
						Platform string `json:"platform"`
						URL      string `json:"url"`
					} `json:"chrome"`
				} `json:"downloads"`
			} `json:"Stable"`
		} `json:"channels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", err
	}

	var dlURL string
	for _, d := range manifest.Channels.Stable.Downloads.Chrome {
		if d.Platform == "win64" {
			dlURL = d.URL
			break
		}
	}
	if dlURL == "" {
		return "", errors.New("win64 Chromium download URL not found")
	}

	runtimeDir := filepath.Join(dir, "runtime")
	_ = os.MkdirAll(runtimeDir, 0755)
	zipPath := filepath.Join(runtimeDir, "chromium.zip")

	dlResp, err := hc.Get(dlURL)
	if err != nil {
		return "", err
	}
	defer dlResp.Body.Close()

	out, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}

	total := dlResp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)
	lastPct := -1
	for {
		n, rerr := dlResp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return "", werr
			}
			downloaded += int64(n)
			if total > 0 {
				pct := int(downloaded * 100 / total)
				if pct != lastPct {
					lastPct = pct
					setStatus(fmt.Sprintf("内部Chromiumをダウンロード中... %d%%", pct))
				}
			} else {
				setStatus(fmt.Sprintf("内部Chromiumをダウンロード中... %.1f MB", float64(downloaded)/(1024*1024)))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return "", rerr
		}
	}
	out.Close()

	setStatus("内部Chromiumを展開中...")
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		_ = os.Remove(zipPath)
		return "", err
	}
	defer zr.Close()

	stageDir := filepath.Join(runtimeDir, ".staging")
	_ = os.RemoveAll(stageDir)
	_ = os.MkdirAll(stageDir, 0755)
	cleanRuntime := filepath.Clean(stageDir) + string(os.PathSeparator)
	for _, f := range zr.File {
		dest := filepath.Join(stageDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(dest)+string(os.PathSeparator), cleanRuntime) && filepath.Clean(dest) != filepath.Clean(stageDir) {
			continue
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(dest, 0755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(dest), 0755)
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		w, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return "", err
		}
		_, err = io.Copy(w, rc)
		w.Close()
		rc.Close()
		if err != nil {
			return "", err
		}
	}
	_ = zr.Close()
	_ = os.Remove(zipPath)
	targetWin64 := filepath.Join(runtimeDir, "chrome-win64")
	_ = os.RemoveAll(targetWin64)
	if err := os.Rename(filepath.Join(stageDir, "chrome-win64"), targetWin64); err != nil {
		return "", err
	}
	_ = os.RemoveAll(stageDir)

	p := findPortableChromium(dir)
	if p == "" {
		return "", errors.New("chrome.exe not found after extraction")
	}
	logf("Portable Chromium ready: %s", p)
	return p, nil
}

func toWSURL(rawURL, mode string) (string, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	httpURL := u.String()
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	q := u.Query()
	q.Set("mode", mode)
	u.RawQuery = q.Encode()
	return u.String(), httpURL, nil
}

// pollURLFor は、ブリッジURLからポーリング用のURLを作る。
func pollURLFor(httpURL string) string {
	u, err := url.Parse(httpURL)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(u.Path, "/server")
	if path == "" {
		path = "/bridge"
	}
	u.Path = path + "/poll"
	u.RawQuery = ""
	return u.String()
}

type bridgeEngine struct {
	methods     []connMethod
	preferParam string
	routeLabel  string
	wsBase      string
	pollURL     string
	sshCfg      *ssh.ClientConfig
	dialer      *websocket.Dialer
	dohDialer   *websocket.Dialer
	mu          sync.Mutex
	sshClient   *ssh.Client
	pool        chan net.Conn
	stopCh      chan struct{}
	closed      bool
}

type methodKind int

const (
	methodWSPool methodKind = iota
	methodWSTunnel
	methodDoHWS
	methodHTTPPoll
	methodCFDirectWS
	methodCFDirectPoll
	methodTLSFrag
	methodAltPorts
	methodSSEForm
	methodAssetCookie
)

type connMethod struct {
	name string
	kind methodKind
}

// connectionMethods は速い順に並べた接続方法の一覧。
// いつもこの順に試す。
var connectionMethods = []connMethod{
	{"wsPool", methodWSPool},
	{"wsTunnel", methodWSTunnel},
	{"dohWS", methodDoHWS},
	{"httpPoll", methodHTTPPoll},
	{"cfDirectWS", methodCFDirectWS},
	{"cfDirectPoll", methodCFDirectPoll},
	{"tlsFrag", methodTLSFrag},
	{"altPorts", methodAltPorts},
	{"sseForm", methodSSEForm},
	{"assetCookie", methodAssetCookie},
}

func methodByName(name string) (connMethod, bool) {
	for _, m := range connectionMethods {
		if m.name == name {
			return m, true
		}
	}
	return connMethod{}, false
}

// splitRouteLabel は「altPorts:8443」のような手がかりを分解する。
func splitRouteLabel(label string) (string, string) {
	if i := strings.Index(label, ":"); i >= 0 {
		return label[:i], label[i+1:]
	}
	return label, ""
}

func officialHostKeyCallback() ssh.HostKeyCallback {
	if strings.TrimSpace(officialSSHHostKeyLine) == "" {
		logf("ssh host key is not configured; set officialSSHHostKeyLine for your server")
		return ssh.InsecureIgnoreHostKey()
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(officialSSHHostKeyLine))
	if err != nil {
		logf("ssh host key could not be read (%v); continuing without pinning", err)
		return ssh.InsecureIgnoreHostKey()
	}
	return ssh.FixedHostKey(pk)
}

func newEngineBase(wsBase, pollURL string, signer ssh.Signer) *bridgeEngine {
	netDialer := &net.Dialer{Timeout: 6 * time.Second}
	e := &bridgeEngine{
		wsBase:  wsBase,
		pollURL: pollURL,
		sshCfg: &ssh.ClientConfig{
			User:              "ubuntu",
			Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback:   officialHostKeyCallback(),
			HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
			Timeout:           8 * time.Second,
		},
		dialer: &websocket.Dialer{
			Proxy:             proxyFunc,
			HandshakeTimeout:  8 * time.Second,
			ReadBufferSize:    128 * 1024,
			WriteBufferSize:   128 * 1024,
			EnableCompression: false,
		},
		dohDialer: &websocket.Dialer{
			HandshakeTimeout:  8 * time.Second,
			ReadBufferSize:    128 * 1024,
			WriteBufferSize:   128 * 1024,
			EnableCompression: false,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return netDialer.DialContext(ctx, network, addr)
				}
				ip, derr := resolveDoH(host)
				if derr != nil {
					return netDialer.DialContext(ctx, network, addr)
				}
				return netDialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
		stopCh: make(chan struct{}),
	}
	return e
}

// newBridgeEngine は、速い順にすべての方法を試せる状態で組み立てる。
func newBridgeEngine(wsBase, pollURL string, signer ssh.Signer) (*bridgeEngine, error) {
	e := newEngineBase(wsBase, pollURL, signer)
	e.methods = connectionMethods

	if len(e.methods) > 0 && e.methods[0].kind == methodWSPool {
		if e.wsBase == "" {
			e.methods = e.methods[1:]
			if len(e.methods) == 0 {
				return nil, errors.New("bridge url is required")
			}
		}
	}
	if len(e.methods) > 0 && e.methods[0].kind == methodWSPool {
		if perr := e.warmPool(); perr != nil {
			logf("wsPool unavailable: %v", perr)
			e.methods = e.methods[1:]
			if len(e.methods) == 0 {
				return nil, perr
			}
		}
	}
	if e.pool == nil {
		if err := e.ensureSSH(); err != nil {
			return nil, err
		}
		go e.sshKeepaliveLoop()
	}

	return e, nil
}

// newBridgeEngineForRoute は、前回つながった経路だけを試す。
func newBridgeEngineForRoute(route routeCache, wsBase, pollURL string, signer ssh.Signer) (*bridgeEngine, error) {
	m, ok := methodByName(route.Method)
	if !ok {
		return nil, fmt.Errorf("unknown route: %s", route.Method)
	}
	e := newEngineBase(wsBase, pollURL, signer)
	e.methods = []connMethod{m}
	e.preferParam = route.Param

	if m.kind == methodWSPool {
		if e.wsBase == "" {
			return nil, errors.New("bridge url is required")
		}
		if err := e.warmPool(); err != nil {
			return nil, err
		}
		return e, nil
	}
	if err := e.ensureSSH(); err != nil {
		return nil, err
	}
	go e.sshKeepaliveLoop()
	return e, nil
}

func (e *bridgeEngine) warmPool() error {
	e.pool = make(chan net.Conn, 12)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logf("pool warm dial stopped: %v", r)
				}
			}()
			c, err := e.dialRawWS("speed", false)
			if err != nil {
				c, err = e.dialRawWS("speed", true)
			}
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			select {
			case e.pool <- c:
			default:
				_ = c.Close()
			}
		}()
	}
	wg.Wait()
	if len(e.pool) == 0 {
		e.pool = nil
		if firstErr == nil {
			firstErr = errors.New("no stream connected")
		}
		return firstErr
	}
	logf("wsPool connected with %d streams", len(e.pool))
	e.noteRoute("wsPool")
	go e.refillLoop()
	return nil
}

// noteRoute は、実際につながった経路を覚えておく。
func (e *bridgeEngine) noteRoute(label string) {
	e.mu.Lock()
	if e.routeLabel == "" {
		e.routeLabel = label
	}
	e.mu.Unlock()
}

// routeCacheFor は、保存しておく手がかりをまとめる。
func (e *bridgeEngine) routeCacheFor(rawURL string) *routeCache {
	e.mu.Lock()
	label := e.routeLabel
	e.mu.Unlock()
	if label == "" {
		return nil
	}
	method, param := splitRouteLabel(label)
	return &routeCache{
		URL:    strings.TrimSpace(rawURL),
		Method: method,
		Param:  param,
		At:     time.Now().Format(time.RFC3339),
	}
}

func (e *bridgeEngine) rawWSURL(mode string) (string, error) {
	if e.wsBase == "" {
		return "", errors.New("bridge url is empty")
	}
	wsURL, _, err := toWSURL(e.wsBase, mode)
	return wsURL, err
}

func (e *bridgeEngine) dialRawWS(mode string, useDoH bool) (net.Conn, error) {
	wsURL, err := e.rawWSURL(mode)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{}
	hdr.Set("User-Agent", browserUA)
	d := e.dialer
	if useDoH {
		d = e.dohDialer
	}
	ws, resp, derr := d.Dial(wsURL, hdr)
	if derr != nil {
		if resp != nil {
			return nil, fmt.Errorf("%w (http %d)", derr, resp.StatusCode)
		}
		return nil, derr
	}
	raw := wsconn.Wrap(ws)
	if mode == "speed" {
		enc, eerr := e2e.WrapClient(raw)
		if eerr != nil {
			_ = raw.Close()
			return nil, eerr
		}
		return enc, nil
	}
	return raw, nil
}

func (e *bridgeEngine) tryObfsSSH(name string, dialFn func() (net.Conn, error)) (*ssh.Client, error) {
	raw, err := dialFn()
	if err != nil {
		logf("[%s] transport failed: %v", name, err)
		return nil, err
	}
	// 相手が黙ったままでも待ち続けないよう、手順の間に上限を置く。
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	obfsConn, err := obfs.Wrap(raw, obfsKey)
	if err != nil {
		_ = raw.Close()
		logf("[%s] handshake failed: %v", name, err)
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	// SSHはトンネルの中を通るので、接続先の名前は固定で構わない。
	c, chans, reqs, err := ssh.NewClientConn(obfsConn, "bridge", e.sshCfg)
	if err != nil {
		_ = obfsConn.Close()
		logf("[%s] ssh handshake failed: %v", name, err)
		return nil, err
	}
	logf("[%s] connected!", name)
	return ssh.NewClient(c, chans, reqs), nil
}

func (e *bridgeEngine) dialTCPNoDelay(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	return conn, err
}

func (e *bridgeEngine) dialSSHTransport() (*ssh.Client, error) {
	var errs []string
	for _, m := range e.methods {
		if m.kind == methodWSPool {
			continue
		}
		c, label, err := e.dialMethod(m)
		if err == nil {
			e.noteRoute(label)
			return c, nil
		}
		errs = append(errs, m.name+": "+err.Error())
	}
	return nil, errors.New(strings.Join(errs, "\n"))
}

func (e *bridgeEngine) dialMethod(m connMethod) (*ssh.Client, string, error) {
	switch m.kind {
	case methodWSTunnel:
		c, err := e.tryObfsSSH(m.name, func() (net.Conn, error) {
			return e.dialRawWS("secure", false)
		})
		return c, m.name, err
	case methodDoHWS:
		c, err := e.tryObfsSSH(m.name, func() (net.Conn, error) {
			return e.dialRawWS("secure", true)
		})
		return c, m.name, err
	case methodHTTPPoll:
		c, err := e.tryObfsSSH(m.name, func() (net.Conn, error) {
			return httptunnel.Dial(e.pollURL, makeDoHHTTPClient(35*time.Second))
		})
		return c, m.name, err
	case methodCFDirectWS:
		c, label, err := e.dialCFDirectWS(m.name)
		return c, label, err
	case methodCFDirectPoll:
		c, label, err := e.dialCFDirectPoll(m.name)
		return c, label, err
	case methodTLSFrag:
		c, err := e.tryObfsSSH(m.name, func() (net.Conn, error) {
			return e.dialFragWS()
		})
		return c, m.name, err
	case methodAltPorts:
		c, label, err := e.dialAltPorts(m.name)
		return c, label, err
	case methodSSEForm:
		c, err := e.dialSSEForm(m.name)
		return c, m.name, err
	case methodAssetCookie:
		c, err := e.dialAssetCookie(m.name)
		return c, m.name, err
	}
	return nil, "", fmt.Errorf("unsupported method: %s", m.name)
}

func (e *bridgeEngine) origin() (string, error) {
	u, err := url.Parse(e.wsBase)
	if err != nil || u.Host == "" {
		return "", errors.New("bridge url is empty")
	}
	return u.Scheme + "://" + u.Host, nil
}

func (e *bridgeEngine) dialWebSocketURL(address string) (net.Conn, error) {
	header := http.Header{}
	header.Set("User-Agent", browserUA)
	ws, resp, err := e.dialer.Dial(address, header)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("%w (http %d)", err, resp.StatusCode)
		}
		return nil, err
	}
	return wsconn.Wrap(ws), nil
}

func (e *bridgeEngine) dialFragWS() (net.Conn, error) {
	address, err := e.rawWSURL("secure")
	if err != nil {
		return nil, err
	}
	dialer := &websocket.Dialer{
		Proxy:            proxyFunc,
		HandshakeTimeout: 8 * time.Second,
		ReadBufferSize:   128 * 1024,
		WriteBufferSize:  128 * 1024,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, derr := (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, network, addr)
			if derr != nil {
				return nil, derr
			}
			return covert.NewFragConn(raw), nil
		},
	}
	header := http.Header{}
	header.Set("User-Agent", browserUA)
	ws, _, err := dialer.Dial(address, header)
	if err != nil {
		return nil, err
	}
	return wsconn.Wrap(ws), nil
}

func (e *bridgeEngine) dialAltPorts(name string) (*ssh.Client, string, error) {
	if e.wsBase == "" {
		return nil, "", errors.New("bridge url is empty")
	}
	ports := []string{"2053", "2083", "2087", "2096", "8443"}
	if e.preferParam != "" {
		ports = []string{e.preferParam}
	}
	var errs []string
	for _, port := range ports {
		alt, err := covert.AltPortURL(e.wsBase, port)
		if err != nil {
			return nil, "", err
		}
		address, _, err := toWSURL(alt, "secure")
		if err != nil {
			continue
		}
		label := name + ":" + port
		c, cerr := e.tryObfsSSH(label, func() (net.Conn, error) {
			return e.dialWebSocketURL(address)
		})
		if cerr == nil {
			return c, label, nil
		}
		errs = append(errs, cerr.Error())
	}
	return nil, "", errors.New(strings.Join(errs, "\n"))
}

func (e *bridgeEngine) dialSSEForm(name string) (*ssh.Client, error) {
	origin, err := e.origin()
	if err != nil {
		return nil, err
	}
	return e.tryObfsSSH(name, func() (net.Conn, error) {
		return covert.DialSSE(origin, makeDoHHTTPClient(40*time.Second))
	})
}

func (e *bridgeEngine) dialAssetCookie(name string) (*ssh.Client, error) {
	origin, err := e.origin()
	if err != nil {
		return nil, err
	}
	return e.tryObfsSSH(name, func() (net.Conn, error) {
		return covert.DialAsset(origin, makeDoHHTTPClient(40*time.Second))
	})
}

func (e *bridgeEngine) dialCFDirectWS(name string) (*ssh.Client, string, error) {
	wsURL, err := e.rawWSURL("secure")
	if err != nil {
		return nil, "", err
	}
	ips := cfAnycastIPs
	if e.preferParam != "" {
		ips = []string{e.preferParam}
	}
	var errs []string
	for _, cfIP := range ips {
		ip := cfIP
		cfDialer := &websocket.Dialer{
			HandshakeTimeout: 6 * time.Second,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				if port == "" {
					port = "443"
				}
				return e.dialTCPNoDelay(net.JoinHostPort(ip, port), 5*time.Second)
			},
		}
		c, err := e.tryObfsSSH(name+":"+ip, func() (net.Conn, error) {
			hdr := http.Header{}
			hdr.Set("User-Agent", browserUA)
			ws, _, derr := cfDialer.Dial(wsURL, hdr)
			if derr != nil {
				return nil, derr
			}
			return wsconn.Wrap(ws), nil
		})
		if err == nil {
			return c, name + ":" + ip, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, "", errors.New(strings.Join(errs, "\n"))
}

func (e *bridgeEngine) dialCFDirectPoll(name string) (*ssh.Client, string, error) {
	if e.pollURL == "" {
		return nil, "", errors.New("poll url is empty")
	}
	ips := cfAnycastIPs
	if e.preferParam != "" {
		ips = []string{e.preferParam}
	}
	var errs []string
	for _, cfIP := range ips {
		ip := cfIP
		c, err := e.tryObfsSSH(name+":"+ip, func() (net.Conn, error) {
			return httptunnel.Dial(e.pollURL, makeCFDirectHTTPClient(35*time.Second, ip))
		})
		if err == nil {
			return c, name + ":" + ip, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, "", errors.New(strings.Join(errs, "\n"))
}

func (e *bridgeEngine) ensureSSH() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}
	if e.sshClient != nil {
		return nil
	}
	c, err := e.dialSSHTransport()
	if err != nil {
		return err
	}
	e.sshClient = c
	return nil
}

func (e *bridgeEngine) reconnectSSH(failed *ssh.Client) (*ssh.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, errors.New("engine closed")
	}
	if e.sshClient != nil && e.sshClient != failed {
		return e.sshClient, nil
	}
	if e.sshClient != nil {
		_ = e.sshClient.Close()
		e.sshClient = nil
	}
	c, err := e.dialSSHTransport()
	if err != nil {
		return nil, err
	}
	e.sshClient = c
	return c, nil
}

func (e *bridgeEngine) sshKeepaliveLoop() {
	defer func() {
		if r := recover(); r != nil {
			logf("keepalive loop stopped: %v", r)
		}
	}()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.mu.Lock()
			c := e.sshClient
			e.mu.Unlock()
			if c == nil {
				_, _ = e.reconnectSSH(nil)
				continue
			}
			if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				logf("SSH keepalive failed: %v, reconnecting...", err)
				_, _ = e.reconnectSSH(c)
			}
		}
	}
}

func (e *bridgeEngine) refillLoop() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	defer func() {
		if r := recover(); r != nil {
			logf("refill loop stopped: %v", r)
		}
	}()
	failures := 0
	var nextTry time.Time
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			if time.Now().Before(nextTry) {
				continue
			}
			e.mu.Lock()
			closed := e.closed
			e.mu.Unlock()
			if closed {
				return
			}
			if e.pool == nil || len(e.pool) >= 10 {
				continue
			}
			c, err := e.dialRawWS("speed", false)
			if err != nil {
				c, err = e.dialRawWS("speed", true)
			}
			if err != nil {
				failures++
				backoff := time.Duration(failures) * 500 * time.Millisecond
				if backoff > 8*time.Second {
					backoff = 8 * time.Second
				}
				nextTry = time.Now().Add(backoff)
				logf("pool refill failed (%v), retrying in %s", err, backoff)
				continue
			}
			failures = 0
			select {
			case e.pool <- c:
			default:
				_ = c.Close()
			}
		}
	}
}

func (e *bridgeEngine) takeStream() (net.Conn, error) {
	select {
	case stream := <-e.pool:
		return stream, nil
	default:
	}
	c, err := e.dialRawWS("speed", false)
	if err != nil {
		logf("wsStream dial failed (%v), retrying with DoH", err)
		c, err = e.dialRawWS("speed", true)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (e *bridgeEngine) dialTarget(target string) (net.Conn, error) {
	if e.pool == nil {
		e.mu.Lock()
		c := e.sshClient
		e.mu.Unlock()
		if c == nil {
			var err error
			c, err = e.reconnectSSH(nil)
			if err != nil {
				return nil, err
			}
		}
		conn, err := c.Dial("tcp", target)
		if err == nil {
			return conn, nil
		}
		logf("dialTarget %s failed (%v), reconnecting...", target, err)
		c2, rerr := e.reconnectSSH(c)
		if rerr != nil {
			return nil, err
		}
		return c2.Dial("tcp", target)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		stream, err := e.takeStream()
		if err != nil {
			lastErr = err
			logf("dialTarget %s: stream unavailable (attempt %d): %v", target, attempt+1, err)
			continue
		}
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

		tb := []byte(target)
		pkt := make([]byte, 2+len(tb))
		binary.BigEndian.PutUint16(pkt[:2], uint16(len(tb)))
		copy(pkt[2:], tb)
		if _, err := stream.Write(pkt); err != nil {
			_ = stream.Close()
			lastErr = err
			logf("dialTarget %s: write failed (attempt %d): %v", target, attempt+1, err)
			continue
		}

		var status [1]byte
		if _, err := io.ReadFull(stream, status[:]); err != nil {
			_ = stream.Close()
			lastErr = fmt.Errorf("stream closed before reply: %w", err)
			logf("dialTarget %s: no reply (attempt %d): %v", target, attempt+1, err)
			continue
		}
		if status[0] != 0x00 {
			_ = stream.Close()
			lastErr = errors.New("remote dial failed (target unreachable from bridge)")
			logf("dialTarget %s: bridge reported failure (attempt %d)", target, attempt+1)
			return nil, lastErr
		}
		_ = stream.SetDeadline(time.Time{})
		return stream, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no stream available")
	}
	return nil, lastErr
}

func (e *bridgeEngine) close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	close(e.stopCh)
	if e.sshClient != nil {
		_ = e.sshClient.Close()
		e.sshClient = nil
	}
	e.mu.Unlock()
	if e.pool != nil {
		for {
			select {
			case c := <-e.pool:
				_ = c.Close()
			default:
				return
			}
		}
	}
}

// runBounded は fn を別ゴルーチンで実行し、上限時間を過ぎたら切り上げる。
// 応答しないネットワークやレジストリ操作でアプリ全体が固まるのを防ぐ。
func runBounded(name string, limit time.Duration, fn func()) {
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("cleanup %s panic: %v", name, r)
			}
			close(done)
		}()
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		logf("cleanup %s timed out after %s", name, limit)
	}
}

// parseLaunchArgs は --launch 指定を読み取る。
func parseLaunchArgs(args []string, cfg Config) (launchRequest, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--launch" || args[i] == "/launch" {
			val := ""
			if i+1 < len(args) {
				val = args[i+1]
			}
			return launchRequestFromValue(val, cfg), true
		}
	}
	return launchRequest{}, false
}

func launchRequestFromValue(v string, cfg Config) launchRequest {
	val := strings.TrimSpace(v)
	switch strings.ToLower(val) {
	case "chrome":
		return launchRequest{kind: targetChrome}
	case "edge":
		return launchRequest{kind: targetEdge}
	case "browser":
		return launchRequest{kind: targetBrowser}
	case "bash":
		return launchRequest{kind: targetBash}
	case "":
		return launchRequest{kind: cfg.TargetIdx, appPath: cfg.AppPath}
	default:
		return launchRequest{kind: targetApp, appPath: strings.Trim(val, `"`)}
	}
}

// shortcutPreset はショートカットに書く起動指定を組み立てる。
func shortcutPreset(dir string, kind int, appPath string) (argValue, iconExe, displayName, workDir string) {
	switch kind {
	case targetChrome:
		return "chrome", detectChrome(), "Chrome", ""
	case targetEdge:
		return "edge", detectEdge(), "Edge", ""
	case targetBrowser:
		return "browser", filepath.Join(dir, "runtime", "chrome-win64", "chrome.exe"), "NCTB Browser", ""
	case targetBash:
		return "bash", filepath.Join(dir, "runtime", "nctb-bash.exe"), "NCTB Bash", ""
	default:
		p := strings.Trim(strings.TrimSpace(appPath), `"`)
		if p == "" {
			return "", "", "", ""
		}
		name := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		if name == "" {
			name = "アプリ"
		}
		return p, p, name, filepath.Dir(p)
	}
}

// runLaunchMode は --launch で起動されたときの処理。
func runLaunchMode(dir string, cfg Config, signer ssh.Signer, req launchRequest) {
	status := func(string) {}
	port := 0
	var own *session

	if info, ok := readActiveSocks(dir); ok {
		port = info.Port
		logf("launch: using running entry port=%d", port)
	} else {
		own = newSession(dir, signer)
		route, cerr := own.connect(cfg.ServerURL, cfg.Route, false, status)
		if cerr != nil {
			logf("launch connect failed: %v", cerr)
			showError("NeConnect Bridge", fmt.Sprintf("接続できませんでした:\n%v", cerr))
			return
		}
		if route != nil {
			cfg.Route = route
			saveConfig(dir, cfg)
		}
		port = own.socksPort()
	}

	proc, exe, err := startLaunch(dir, req, port, status)
	if err != nil {
		logf("launch failed: %v", err)
		if own != nil {
			own.cleanup()
		}
		showError("NeConnect Bridge", err.Error())
		return
	}
	waitForLaunched(proc, exe)
	logf("launched app exited")
	if own != nil {
		own.cleanup()
	}
}

// runGUIMode は通常の画面を出す。
func runGUIMode(dir string, cfg Config, signer ssh.Signer) {
	sess := newSession(dir, signer)

	var launchMu sync.Mutex
	activeLaunch := 0
	var cfgMu sync.Mutex

	readCfg := func() Config {
		cfgMu.Lock()
		defer cfgMu.Unlock()
		return cfg
	}

	persist := func(serverURLs string, targetIdx int, appPath string, route *routeCache) {
		cfgMu.Lock()
		cfg = Config{
			ClientID:  cfg.ClientID,
			ServerURL: serverURLs,
			TargetIdx: targetIdx,
			AppPath:   appPath,
			URLSet:    cfg.URLSet,
			Route:     route,
		}
		saved := cfg
		cfgMu.Unlock()
		saveConfig(dir, saved)
	}

	hooks := uiHooks{}

	generateURL = func(currentURLs string) {
		generateURLImpl(dir, readCfg(), signer, currentURLs)
	}

	hooks.onConnect = func(serverURLs string) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logf("connect panic: %v", r)
					globalUI.setRunState(false, false)
					globalUI.setStatus("待機中 — 接続に失敗しました")
				}
			}()
			globalUI.setRunState(true, false)
			globalUI.setStatus("接続準備中...")
			cur := readCfg()
			persist(serverURLs, cur.TargetIdx, cur.AppPath, cur.Route)
			route, err := sess.connect(serverURLs, cur.Route, true, globalUI.setStatus)
			if err != nil {
				logf("connect failed: %v", err)
				globalUI.setRunState(false, false)
				globalUI.setStatus("待機中 — 接続に失敗しました")
				showError("NeConnect Bridge", fmt.Sprintf("%v", err))
				return
			}
			persist(serverURLs, cur.TargetIdx, cur.AppPath, route)
			writeActiveSocks(dir, sess.socksPort(), routeLabelText(route))
			globalUI.setRunState(false, true)
			globalUI.setStatus("接続中")
		}()
	}

	hooks.onDisconnect = func() {
		go func() {
			globalUI.setStatus("切断しています...")
			sess.cleanup()
			clearActiveSocks(dir)
			globalUI.setRunState(false, false)
			globalUI.setStatus("待機中")
		}()
	}

	hooks.onLaunch = func(targetIdx int, appPath, serverURLs string) {
		launchMu.Lock()
		if activeLaunch > 0 {
			launchMu.Unlock()
			showError("NeConnect Bridge", "すでに起動処理中です。少し待ってからもう一度お試しください。")
			return
		}
		activeLaunch++
		launchMu.Unlock()

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logf("launch panic: %v", r)
					globalUI.setStatus("待機中 — 起動に失敗しました")
				}
				launchMu.Lock()
				activeLaunch--
				launchMu.Unlock()
			}()
			persist(serverURLs, targetIdx, appPath, readCfg().Route)
			req := launchRequest{kind: targetIdx, appPath: appPath}

			port := 0
			var own *session
			if sess.connected() {
				port = sess.socksPort()
			} else if info, ok := readActiveSocks(dir); ok {
				port = info.Port
			}
			if port == 0 {
				own = newSession(dir, signer)
				globalUI.setStatus("接続しています...")
				route, cerr := own.connect(serverURLs, readCfg().Route, false, globalUI.setStatus)
				if cerr != nil {
					logf("launch connect failed: %v", cerr)
					showError("NeConnect Bridge", fmt.Sprintf("接続できませんでした:\n%v", cerr))
					globalUI.setStatus("待機中 — 接続に失敗しました")
					return
				}
				persist(serverURLs, targetIdx, appPath, route)
				port = own.socksPort()
			}

			proc, exe, err := startLaunch(dir, req, port, globalUI.setStatus)
			if err != nil {
				logf("launch failed: %v", err)
				if own != nil {
					own.cleanup()
				}
				showError("NeConnect Bridge", err.Error())
				globalUI.setStatus("待機中 — 起動できませんでした")
				return
			}

			if own != nil {
				globalUI.setStatus("起動しました — 閉じると切断します")
				waitForLaunched(proc, exe)
				own.cleanup()
				globalUI.setStatus("待機中 — 切断しました")
			} else {
				globalUI.setStatus("起動しました")
				go func() {
					waitForLaunched(proc, exe)
					logf("launched app exited (session kept)")
				}()
			}
		}()
	}

	hooks.onCreateShortcut = func(targetIdx int, appPath string) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logf("shortcut panic: %v", r)
				}
			}()
			argValue, iconExe, displayName, workDir := shortcutPreset(dir, targetIdx, appPath)
			if argValue == "" {
				showError("NeConnect Bridge", "起動するアプリが指定されていません。")
				return
			}
			self, err := os.Executable()
			if err != nil || self == "" {
				showError("NeConnect Bridge", "このアプリの場所を取得できませんでした。")
				return
			}
			args := "--launch " + argValue
			if targetIdx == targetApp {
				args = "--launch " + quoteArg(argValue)
			}
			if _, err := os.Stat(iconExe); err != nil {
				iconExe = self
			}
			defName := displayName + " - NeConnect Bridge.lnk"

			owner := globalUI.windowHandle()
			var picked string
			_ = withCOM(func() error {
				p, ok := pickShortcutPath(owner, defName)
				if ok {
					picked = p
				}
				return nil
			})
			if picked == "" {
				return
			}
			if err := createShortcut(picked, self, args, workDir, displayName, iconExe); err != nil {
				logf("shortcut create failed: %v", err)
				showError("NeConnect Bridge", err.Error())
				return
			}
			globalUI.setStatus("ショートカットを作成しました")
		}()
	}

	hooks.onClearCache = func() {
		go func() {
			cfgMu.Lock()
			had := cfg.Route != nil
			cfg.Route = nil
			saved := cfg
			cfgMu.Unlock()
			if !had {
				globalUI.setStatus("前回の接続は保存されていません")
				return
			}
			saveConfig(dir, saved)
			logf("connection cache cleared")
			globalUI.setStatus("接続キャッシュをクリアしました")
		}()
	}

	hooks.onOpenLog = func() {
		globalUI.showLogWindow()
	}

	runMainWindow(cfg, hooks, func() {
		clearActiveSocks(dir)
		sess.cleanup()
	})
}

func main() {
	dir := exeDir()
	initLogger(dir)
	cfg := loadConfig(dir)
	signer, err := ssh.ParsePrivateKey(embeddedKey)
	if err != nil {
		logf("Failed to parse embedded key: %v", err)
		showError("NeConnect Bridge", fmt.Sprintf("内蔵鍵の読み込みに失敗しました:\n%v", err))
		return
	}

	if req, ok := parseLaunchArgs(os.Args[1:], cfg); ok {
		runLaunchMode(dir, cfg, signer, req)
		return
	}
	runGUIMode(dir, cfg, signer)
}

// generateURL は画面から差し替えられる、ブリッジURLの取得処理。
var generateURL = func(currentURLs string) {}

// generateURLImpl はブリッジ経由で新しいブリッジURLを取りに行く。
func generateURLImpl(dir string, cfg Config, signer ssh.Signer, currentURLs string) {
	globalUI.setStatus("ブリッジURLをリクエスト中...")
	cands := splitServerURLs(currentURLs)
	hasDefault := false
	for _, c := range cands {
		if c == defaultServerURL {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		cands = append(cands, defaultServerURL)
	}

	parseGenResp := func(body []byte, statusCode int) (string, error) {
		var res struct {
			OK       bool   `json:"ok"`
			URL      string `json:"url"`
			Provider string `json:"provider"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			snip := strings.TrimSpace(string(body))
			if len(snip) > 160 {
				snip = snip[:160]
			}
			return "", fmt.Errorf("HTTP %d: %s", statusCode, snip)
		}
		if res.OK && res.URL != "" {
			logf("Generated URL via %s: %s", res.Provider, res.URL)
			return res.URL, nil
		}
		if res.Error != "" {
			return "", errors.New(res.Error)
		}
		return "", fmt.Errorf("HTTP %d: empty response", statusCode)
	}

	var generated string
	var errs []string

	genViaEngine := func(eng *bridgeEngine) (string, error) {
		thc := &http.Client{
			Timeout: 18 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return eng.dialTarget("127.0.0.1:8090")
				},
			},
		}
		resp, rerr := thc.Get("http://127.0.0.1:8090/bridge/generate?cid=" + url.QueryEscape(cfg.ClientID))
		if rerr != nil {
			return "", rerr
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		return parseGenResp(body, resp.StatusCode)
	}

	for _, raw := range cands {
		var httpURL string
		var pollURL string
		var uerr error
		_, httpURL, uerr = toWSURL(raw, "secure")
		if uerr != nil {
			errs = append(errs, "bridge("+raw+"): "+uerr.Error())
			continue
		}
		pollURL = pollURLFor(httpURL)
		logf("Connecting to bridge (%s) to generate URL...", raw)
		eng, cerr := newBridgeEngine(httpURL, pollURL, signer)
		if cerr != nil {
			errs = append(errs, "bridge("+raw+"): "+cerr.Error())
			continue
		}
		uStr, perr := genViaEngine(eng)
		eng.close()
		if perr == nil {
			generated = uStr
			break
		}
		errs = append(errs, "bridge("+raw+"): "+perr.Error())
	}

	if generated == "" {
		hc := makeDoHHTTPClient(18 * time.Second)
		for _, raw := range cands {
			if strings.HasPrefix(raw, "ssh://") {
				continue
			}
			_, httpURL, err := toWSURL(raw, "balance")
			if err != nil {
				continue
			}
			u, _ := url.Parse(httpURL)
			u.RawQuery = ""
			basePath := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/server")
			u.Path = basePath + "/generate"
			genURL := u.String()
			logf("Direct fallback generation from %s", genURL)
			req, _ := http.NewRequest("GET", genURL, nil)
			req.Header.Set("User-Agent", browserUA)
			resp, err := hc.Do(req)
			if err != nil {
				errs = append(errs, genURL+": "+err.Error())
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			_ = resp.Body.Close()
			uStr, perr := parseGenResp(body, resp.StatusCode)
			if perr == nil {
				generated = uStr
				break
			}
			errs = append(errs, genURL+": "+perr.Error())
		}
	}

	if generated == "" {
		globalUI.setStatus("待機中 — リクエストに失敗しました")
		showError("NeConnect Bridge", fmt.Sprintf("ブリッジURLの取得に失敗しました:\n%s", strings.Join(errs, "\n")))
		return
	}
	globalUI.appendGeneratedURL(generated)
	globalUI.setStatus("新しいブリッジURLを取得しました")
}
