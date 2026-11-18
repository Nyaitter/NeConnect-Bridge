package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"neconnectbridge/internal/covert"
	"neconnectbridge/internal/dialgate"
	"neconnectbridge/internal/dohres"
	"neconnectbridge/internal/e2e"
	"neconnectbridge/internal/endpoint"
	"neconnectbridge/internal/h2tunnel"
	"neconnectbridge/internal/hostguard"
	"neconnectbridge/internal/httptunnel"
	"neconnectbridge/internal/obfs"
	"neconnectbridge/internal/rangetunnel"
	"neconnectbridge/internal/selfupdate"
	"neconnectbridge/internal/wsconn"
)

//go:embed id_ed25519_nctb
var embeddedKey []byte

// appVersion は、この実行ファイルの版。ビルドのときに package.json の値が入る。
var appVersion = "0.0.0"

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
	AdBlock   bool        `json:"adblock"`
	Route     *routeCache `json:"last_route,omitempty"`
}

var (
	globalUI   *mainUI
	logMu      sync.Mutex
	logFile    *os.File
	crashMu    sync.Mutex
	crashFile  *os.File
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
		initCrashLog(dir)
		logf("=== NeConnect Bridge v%s を起動しました ===", appVersion)
	}
}

// initCrashLog は、落ちたときの記録を残す先を用意する。
// 画面のない作りなので、原因を後から追えるようにしておく。
func initCrashLog(dir string) {
	if crashFile != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "nctb_crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	crashFile = f
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
}

// writeCrashReport は、拾った異常とそのときの積み重なりを書き残す。
func writeCrashReport(name string, r any) {
	crashMu.Lock()
	defer crashMu.Unlock()
	if crashFile == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05.000")
	_, _ = fmt.Fprintf(crashFile, "[%s] %s: %v\n%s\n", ts, name, r, debug.Stack())
}

// goSafe は、別の流れで動かす処理を、異常が出ても本体を道連れにしない形で始める。
func goSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("%s stopped: %v", name, r)
				writeCrashReport(name, r)
			}
		}()
		fn()
	}()
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
		// 選べる対象が減ったときは、アプリ指定として扱う。
		cfg.TargetIdx = targetApp
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

// dohLookup は、名前を引くときの重複した照会をまとめる。
var dohLookup = dohres.New(dohres.Options{
	TTL:     10 * time.Minute,
	FailTTL: 30 * time.Second,
	Timeout: 4 * time.Second,
	Log:     func(format string, args ...any) { logf(format, args...) },
})

// resolveDoH は、名前から住所を引く。失敗した名前はしばらく引き直さない。
func resolveDoH(host string) (string, error) {
	return dohLookup.Resolve(context.Background(), host)
}

var cfAnycastIPs = []string{"104.21.64.170", "172.67.153.171", "104.16.132.229"}

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

// streamURLFor は、ブリッジURLから別の受け口のURLを作る。
func streamURLFor(httpURL, name string) string {
	u, err := url.Parse(httpURL)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(u.Path, "/server")
	if path == "" {
		path = "/bridge"
	}
	u.Path = path + "/" + name
	u.RawQuery = ""
	return u.String()
}

// pollURLFor は、ブリッジURLからポーリング用のURLを作る。
func pollURLFor(httpURL string) string {
	return streamURLFor(httpURL, "poll")
}

type bridgeEngine struct {
	methods     []connMethod
	preferParam string
	routeLabel  string
	wsBase      string
	pollURL     string
	h2URL       string
	rangeURL    string
	sshCfg      *ssh.ClientConfig
	td          *transportDialer
	dialMu      sync.Mutex
	methodTD    map[string]*transportDialer
	routeMu     sync.Mutex
	mu          sync.Mutex
	sshClient   *ssh.Client
	pool        chan net.Conn
	stopCh      chan struct{}
	closed      bool

	// ctx は、閉じたときに進行中の張り出しをすべて打ち切るための合図。
	ctx    context.Context
	cancel context.CancelFunc
	// gate は、同時に張り出す流れの本数を絞る。
	gate *dialgate.Gate
	// guard は、接続が集中した相手をしばらく休ませる。
	guard *hostguard.Guard
	// streams は、いま中継している接続。閉じるときに一緒に切る。
	streams   map[*targetStream]struct{}
	streamsMu sync.Mutex
}

type methodKind int

const (
	methodWSPool methodKind = iota
	methodH2Stream
	methodWSTunnel
	methodAltWS
	methodAltPorts
	methodSSEForm
	methodHTTPRange
	methodHTTPPoll
	methodAssetCookie
)

type connMethod struct {
	name string
	kind methodKind
}

// connectionMethods は速い順に並べた接続方法の一覧。
// 重なりがないよう、通信の形ごとに一つずつ並べる。
var connectionMethods = []connMethod{
	{"wsPool", methodWSPool},
	{"h2Stream", methodH2Stream},
	{"wsTunnel", methodWSTunnel},
	{"altWS", methodAltWS},
	{"altPorts", methodAltPorts},
	{"sseForm", methodSSEForm},
	{"httpRange", methodHTTPRange},
	{"httpPoll", methodHTTPPoll},
	{"assetCookie", methodAssetCookie},
}

// legacyMethods は、前の版が残した名前を今の方法へ読み替える。
var legacyMethods = map[string]connMethod{
	"dohWS":        {"wsTunnel", methodWSTunnel},
	"cfDirectWS":   {"wsTunnel", methodWSTunnel},
	"tlsFrag":      {"wsTunnel", methodWSTunnel},
	"cfDirectPoll": {"httpPoll", methodHTTPPoll},
}

func methodByName(name string) (connMethod, bool) {
	for _, m := range connectionMethods {
		if m.name == name {
			return m, true
		}
	}
	if m, ok := legacyMethods[name]; ok {
		return m, true
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
	ctx, cancel := context.WithCancel(context.Background())
	e := &bridgeEngine{
		wsBase:   wsBase,
		pollURL:  pollURL,
		h2URL:    streamURLFor(wsBase, "h2"),
		rangeURL: streamURLFor(wsBase, "range"),
		sshCfg: &ssh.ClientConfig{
			User:              "ubuntu",
			Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback:   officialHostKeyCallback(),
			HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
			Timeout:           8 * time.Second,
		},
		stopCh:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
		gate:    dialgate.New(dialSlots, dialQueue),
		guard:   hostguard.New(),
		streams: map[*targetStream]struct{}{},
	}
	host := ""
	if u, err := url.Parse(wsBase); err == nil {
		host = u.Hostname()
	}
	e.td = newTransportDialer(host)
	e.methodTD = map[string]*transportDialer{}
	return e
}

// dialerFor は、一つの接続方法だけの道筋の記憶を返す。
// 方法ごとに分けることで、他の方法で通らなかった道筋まで諦めない。
func (e *bridgeEngine) dialerFor(name string) *transportDialer {
	e.dialMu.Lock()
	defer e.dialMu.Unlock()
	if d, ok := e.methodTD[name]; ok {
		return d
	}
	d := e.td.forMethod(name)
	e.methodTD[name] = d
	return d
}

// newBridgeEngine は、速い順にすべての方法を試せる状態で組み立てる。
func newBridgeEngine(wsBase, pollURL string, signer ssh.Signer) (*bridgeEngine, error) {
	if strings.TrimSpace(wsBase) == "" {
		return nil, errors.New("bridge url is required")
	}
	e := newEngineBase(wsBase, pollURL, signer)
	e.methods = connectionMethods

	if err := e.warmPool(); err != nil {
		logf("wsPool unavailable: %v", err)
		e.methods = e.methods[1:]
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

// warmPool は、速いモードの流れをあらかじめ張っておく。
// まず一本で通り道を見つけ、その道筋で残りを並べて張る。
func (e *bridgeEngine) warmPool() error {
	if e.wsBase == "" {
		return errors.New("bridge url is empty")
	}
	first, stage, err := e.dialRawWS("speed", stagesForParam(e.preferParam))
	if err != nil {
		return err
	}
	e.pool = make(chan net.Conn, poolSize)
	e.pool <- first
	e.noteRoute("wsPool:" + stage.label())
	_ = e.fillPool(poolSize)
	logf("wsPool connected with %d streams via %s", len(e.pool), stage.label())
	go e.refillLoop()
	return nil
}

// fillPool は、足りない流れを並べて張る。
// 接続を閉じたあとは、新しい張り出しを残さない。
func (e *bridgeEngine) fillPool(parallel int) error {
	missing := poolSize - len(e.pool)
	if missing <= 0 || e.pool == nil || e.ctx.Err() != nil {
		return nil
	}
	deadline := time.Now().Add(poolWarmBudget)
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for i := 0; i < missing; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logf("pool fill stopped: %v", r)
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			if e.ctx.Err() != nil || time.Now().After(deadline) {
				return
			}
			c, _, derr := e.dialRawWS("speed", nil)
			if derr != nil {
				// 閉じただけのときは、失敗として記録に残さない。
				if e.ctx.Err() != nil {
					return
				}
				mu.Lock()
				if firstErr == nil {
					firstErr = derr
				}
				mu.Unlock()
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
	return firstErr
}

// noteRoute は、実際につながった経路を覚えておく。
func (e *bridgeEngine) noteRoute(label string) {
	e.routeMu.Lock()
	if e.routeLabel == "" {
		e.routeLabel = label
	}
	e.routeMu.Unlock()
}

// routeCacheFor は、保存しておく手がかりをまとめる。
func (e *bridgeEngine) routeCacheFor(rawURL string) *routeCache {
	e.routeMu.Lock()
	label := e.routeLabel
	e.routeMu.Unlock()
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

// dialRawWS は、速いモードの流れを一本張る。
// 同時に張り出す本数は絞り、閉じたあとは新しい張り出しを始めない。
func (e *bridgeEngine) dialRawWS(mode string, preferred []dialStage) (net.Conn, dialStage, error) {
	release, err := e.gate.Acquire(e.ctx)
	if err != nil {
		return nil, dialStage{}, err
	}
	defer release()
	td := e.dialerFor("wsPool")
	attempt := func(ctx context.Context, st dialStage) (net.Conn, error) {
		raw, err := e.wsConn(ctx, mode, st, td)
		if err != nil {
			return nil, err
		}
		if mode != "speed" {
			return raw, nil
		}
		// 速いモードは、流れごと暗号化して重ねる。
		enc, eerr := e2e.WrapClient(raw)
		if eerr != nil {
			_ = raw.Close()
			return nil, eerr
		}
		return enc, nil
	}
	return raceStages(e.ctx, methodBudget, td.order(preferred), attempt)
}

// wsConn は、一つの道筋で WebSocket を張る。
func (e *bridgeEngine) wsConn(ctx context.Context, mode string, stage dialStage, td *transportDialer) (net.Conn, error) {
	wsURL, err := e.rawWSURL(mode)
	if err != nil {
		return nil, err
	}
	ws, err := e.dialWSStage(ctx, wsURL, stage, td)
	if err != nil {
		return nil, err
	}
	return wsconn.Wrap(ws), nil
}

// dialWSStage は、WebSocket のやり取りを一つの道筋へ向ける。
func (e *bridgeEngine) dialWSStage(ctx context.Context, wsURL string, stage dialStage, td *transportDialer) (*websocket.Conn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	secure := u.Scheme != "ws"
	if port == "" {
		port = "443"
		if !secure {
			port = "80"
		}
	}
	d := &websocket.Dialer{
		HandshakeTimeout:  6 * time.Second,
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false,
		NetDialTLSContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return td.dialConn(dctx, stage, port, true, []string{"http/1.1"})
		},
		NetDialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return td.dialConn(dctx, stage, port, false, nil)
		},
	}
	if !secure {
		d.NetDialTLSContext = nil
	}
	header := http.Header{}
	header.Set("User-Agent", browserUA)
	ws, resp, derr := d.DialContext(ctx, wsURL, header)
	if derr != nil {
		if resp != nil {
			return nil, fmt.Errorf("%w (http %d)", derr, resp.StatusCode)
		}
		return nil, derr
	}
	return ws, nil
}

// obfsSSH は、中継の上に難読化と SSH を重ねる。
func (e *bridgeEngine) obfsSSH(name string, raw net.Conn) (*ssh.Client, error) {
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
	return nil, noRouteErr(errs)
}

func (e *bridgeEngine) dialMethod(m connMethod) (*ssh.Client, string, error) {
	preferred := stagesForParam(e.preferParam)
	td := e.dialerFor(m.name)
	switch m.kind {
	case methodWSTunnel:
		return e.dialWSMethod(m.name, td, td.order(preferred), "secure")
	case methodAltWS:
		// 代替ポートと記録の分割を重ねた道筋から先に試す。
		stages := append(altFragStages(), preferred...)
		return e.dialWSMethod(m.name, td, td.order(stages), "secure")
	case methodAltPorts:
		return e.dialAltPorts(m.name, td)
	case methodH2Stream:
		return e.dialStreamMethod(m.name, td, preferred, true, func(ctx context.Context, client *http.Client) (net.Conn, error) {
			return h2tunnel.Dial(ctx, e.h2URL, client)
		})
	case methodHTTPRange:
		return e.dialStreamMethod(m.name, td, preferred, false, func(ctx context.Context, client *http.Client) (net.Conn, error) {
			return rangetunnel.Dial(ctx, e.rangeURL, client)
		})
	case methodHTTPPoll:
		return e.dialStreamMethod(m.name, td, preferred, false, func(ctx context.Context, client *http.Client) (net.Conn, error) {
			return httptunnel.Dial(ctx, e.pollURL, client)
		})
	case methodSSEForm:
		origin, err := e.origin()
		if err != nil {
			return nil, "", err
		}
		return e.dialStreamMethod(m.name, td, preferred, false, func(ctx context.Context, client *http.Client) (net.Conn, error) {
			return covert.DialSSE(ctx, origin, client)
		})
	case methodAssetCookie:
		origin, err := e.origin()
		if err != nil {
			return nil, "", err
		}
		return e.dialStreamMethod(m.name, td, preferred, false, func(ctx context.Context, client *http.Client) (net.Conn, error) {
			return covert.DialAsset(ctx, origin, client)
		})
	}
	return nil, "", fmt.Errorf("unsupported method: %s", m.name)
}

// dialWSMethod は、WebSocket の上に難読化と SSH を重ねる。
func (e *bridgeEngine) dialWSMethod(name string, td *transportDialer, stages []dialStage, mode string) (*ssh.Client, string, error) {
	attempt := func(ctx context.Context, st dialStage) (*ssh.Client, error) {
		raw, err := e.wsConn(ctx, mode, st, td)
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			_ = raw.Close()
			return nil, ctx.Err()
		}
		c, cerr := e.obfsSSH(name+":"+st.label(), raw)
		if cerr != nil {
			return nil, cerr
		}
		if ctx.Err() != nil {
			_ = c.Close()
			return nil, ctx.Err()
		}
		return c, nil
	}
	c, stage, err := raceStages(e.ctx, methodBudget, stages, attempt)
	if err != nil {
		return nil, "", err
	}
	return c, name + ":" + stage.label(), nil
}

// dialStreamMethod は、HTTP のやり取りの上に難読化と SSH を重ねる。
func (e *bridgeEngine) dialStreamMethod(name string, td *transportDialer, preferred []dialStage, h2 bool, open func(context.Context, *http.Client) (net.Conn, error)) (*ssh.Client, string, error) {
	attempt := func(ctx context.Context, st dialStage) (*ssh.Client, error) {
		raw, err := open(ctx, td.httpClient(st, 0, h2))
		if err != nil {
			if errors.Is(err, endpoint.ErrUnavailable) {
				// この受け口が無いブリッジでは、道筋を変えても答えは変わらない。
				return nil, err
			}
			return nil, err
		}
		if ctx.Err() != nil {
			_ = raw.Close()
			return nil, ctx.Err()
		}
		c, cerr := e.obfsSSH(name+":"+st.label(), raw)
		if cerr != nil {
			return nil, cerr
		}
		if ctx.Err() != nil {
			_ = c.Close()
			return nil, ctx.Err()
		}
		return c, nil
	}
	c, stage, err := raceStages(e.ctx, methodBudget, td.order(preferred), attempt)
	if err != nil {
		return nil, "", err
	}
	return c, name + ":" + stage.label(), nil
}

// dialAltPorts は、代替ポートの上に難読化と SSH を重ねる。
// 実績のある 8443 を先頭にして、すべてのポートを予算の内に並べて試す。
func (e *bridgeEngine) dialAltPorts(name string, td *transportDialer) (*ssh.Client, string, error) {
	ports := append([]string{}, altPorts...)
	if e.preferParam != "" && e.preferParam != ports[0] {
		ports = append([]string{e.preferParam}, ports...)
	}
	stages := make([]dialStage, 0, len(ports))
	for _, port := range ports {
		stages = append(stages, dialStage{port: port})
	}
	return e.dialWSMethod(name, td, td.only(stages), "secure")
}

func (e *bridgeEngine) origin() (string, error) {
	u, err := url.Parse(e.wsBase)
	if err != nil || u.Host == "" {
		return "", errors.New("bridge url is empty")
	}
	return u.Scheme + "://" + u.Host, nil
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
	ticker := time.NewTicker(200 * time.Millisecond)
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
			if closed || e.ctx.Err() != nil {
				return
			}
			if e.pool == nil || len(e.pool) >= poolLowWater {
				continue
			}
			if err := e.fillPool(poolRefillMax); err != nil {
				// 閉じたあとの失敗は、もう知らせない。
				if e.ctx.Err() != nil {
					return
				}
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
		}
	}
}

func (e *bridgeEngine) takeStream() (net.Conn, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case stream := <-e.pool:
		return stream, nil
	default:
	}
	c, _, err := e.dialRawWS("speed", nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// errHostCooling は、接続が集中した相手を休ませている間に来た接続を表す。
// 呼び出し側では、これを記録に残さず黙って断る。
// 休ませ始めたことと、断った件数は、ここからだけ知らせる。
type errHostCooling struct {
	host string
	left time.Duration
}

func (e *errHostCooling) Error() string {
	return fmt.Sprintf("%s is resting for %s", e.host, e.left.Round(time.Second))
}

// hostOf は、中継先の住所から相手の名前を取る。
func hostOf(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

// targetStream は、中継している一本。
// 切られたときに、どれだけ続いたかを覚えておくために包む。
type targetStream struct {
	net.Conn
	engine  *bridgeEngine
	host    string
	started time.Time
	once    sync.Once
}

func (t *targetStream) Close() error {
	t.once.Do(func() {
		t.engine.forgetStream(t)
		if t.engine.guard.NoteClosed(t.host, time.Since(t.started)) {
			logf("%s への接続がすぐ切れ続けているため、しばらく中継しません（%s）", t.host, hostguard.CoolDown)
		}
	})
	return t.Conn.Close()
}

// CloseWrite は、送り終えたことを中継先へ伝える。
func (t *targetStream) CloseWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// trackStream は、中継している一本を覚えておく。
func (e *bridgeEngine) trackStream(host string, c net.Conn) net.Conn {
	st := &targetStream{Conn: c, engine: e, host: host, started: time.Now()}
	e.streamsMu.Lock()
	if e.streams == nil {
		e.streams = map[*targetStream]struct{}{}
	}
	e.streams[st] = struct{}{}
	e.streamsMu.Unlock()
	return st
}

func (e *bridgeEngine) forgetStream(st *targetStream) {
	e.streamsMu.Lock()
	delete(e.streams, st)
	e.streamsMu.Unlock()
}

// dialTarget は、中継の向こうの相手へ一本つなぐ。
// 接続を閉じたあとは何も始めない。
// 同じ相手への接続が集中している間は、流れを使わずにすぐ断る。
func (e *bridgeEngine) dialTarget(target string) (net.Conn, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, errors.New("bridge is closed")
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, errors.New("bridge is closed")
	}

	host := hostOf(target)
	if left, ok := e.guard.Allow(host); !ok {
		if n := e.guard.NoteRejected(host); n == 1 || n%200 == 0 {
			logf("%s を休ませています（%s ほど）。これまでの断り %d 件", host, left.Round(time.Second), n)
		}
		return nil, &errHostCooling{host: host, left: left}
	}
	if e.guard.NoteAttempt(host) {
		logf("%s への接続が集中したため、しばらく中継しません（%s）", host, hostguard.CoolDown)
	}

	conn, err := e.dialTargetStream(target)
	if err != nil {
		if e.ctx.Err() == nil && e.guard.NoteFailure(host) {
			logf("%s へつながらない状態が続いているため、しばらく中継しません（%s）", host, hostguard.CoolDown)
		}
		return nil, err
	}
	return e.trackStream(host, conn), nil
}

// dialTargetStream は、流れか SSH の上に相手への道を作る。
func (e *bridgeEngine) dialTargetStream(target string) (net.Conn, error) {
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
		if err := e.ctx.Err(); err != nil {
			return nil, errors.New("bridge is closed")
		}
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
	// 進行中の張り出しを打ち切る。これが無いと、切ったあとも裏で
	// 新しい流れを張り続けて、他の通信まで巻き添えにする。
	if e.cancel != nil {
		e.cancel()
	}
	if e.gate != nil {
		e.gate.Close()
	}
	if e.sshClient != nil {
		_ = e.sshClient.Close()
		e.sshClient = nil
	}
	e.mu.Unlock()

	// 中継中の一本も切る。残したままにすると通らなくなったあとも通信が残る。
	e.streamsMu.Lock()
	live := make([]*targetStream, 0, len(e.streams))
	for st := range e.streams {
		live = append(live, st)
	}
	e.streams = nil
	e.streamsMu.Unlock()
	for _, st := range live {
		_ = st.Close()
	}

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

	persist := func(serverURLs string, targetIdx int, appPath string, adblock bool, route *routeCache) {
		cfgMu.Lock()
		cfg = Config{
			ClientID:  cfg.ClientID,
			ServerURL: serverURLs,
			TargetIdx: targetIdx,
			AppPath:   appPath,
			URLSet:    cfg.URLSet,
			AdBlock:   adblock,
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
			persist(serverURLs, cur.TargetIdx, cur.AppPath, cur.AdBlock, cur.Route)
			// 接続に使う名前は、広告ブロックの対象にしない。
			setAdBlockHosts(serverURLs)
			route, err := sess.connect(serverURLs, cur.Route, true, globalUI.setStatus)
			if err != nil {
				logf("connect failed: %v", err)
				globalUI.setRunState(false, false)
				globalUI.setStatus("待機中 — 接続に失敗しました")
				showError("NeConnect Bridge", fmt.Sprintf("%v", err))
				return
			}
			persist(serverURLs, cur.TargetIdx, cur.AppPath, cur.AdBlock, route)
			writeActiveSocks(dir, sess.socksPort(), routeLabelText(route))
			globalUI.setRunState(false, true)
			globalUI.setStatus("接続完了")
			// つながったら、新しい版があるかを中継の上から確かめる。
			startUpdateCheck(sess.socksPort(), serverURLs, func() {
				sess.cleanup()
				clearActiveSocks(dir)
			})
		}()
	}

	hooks.onToggleAdBlock = func(enabled bool) {
		cur := readCfg()
		persist(cur.ServerURL, cur.TargetIdx, cur.AppPath, enabled, cur.Route)
		setAdBlockEnabled(enabled)
		if enabled {
			globalUI.setStatus(adBlockSummary())
		} else {
			globalUI.setStatus("広告ブロック: オフ")
		}
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
			curForLaunch := readCfg()
			persist(serverURLs, targetIdx, appPath, curForLaunch.AdBlock, curForLaunch.Route)
			setAdBlockHosts(serverURLs)
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
				globalUI.setStatus("接続中...")
				route, cerr := own.connect(serverURLs, readCfg().Route, false, globalUI.setStatus)
				if cerr != nil {
					logf("launch connect failed: %v", cerr)
					showError("NeConnect Bridge", fmt.Sprintf("接続できませんでした:\n%v", cerr))
					globalUI.setStatus("待機中 — 接続に失敗しました")
					return
				}
				persist(serverURLs, targetIdx, appPath, curForLaunch.AdBlock, route)
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
	// 前回の差し替えで残ったものを片づける。
	if self, err := os.Executable(); err == nil {
		selfupdate.Cleanup(self)
	}
	setAdBlockHosts(cfg.ServerURL)
	if cfg.AdBlock {
		setAdBlockEnabled(true)
	}
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
