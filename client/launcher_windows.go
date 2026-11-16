package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	targetChrome  = 0
	targetEdge    = 1
	targetBrowser = 2
	targetBash    = 3
	targetApp     = 4
)

var targetLabels = []string{"Chrome", "Edge", "NCTB Browser", "NCTB Bash", "任意のアプリケーション"}

func chromiumCandidates() []string {
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	local := os.Getenv("LocalAppData")
	return []string{
		filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
	}
}

func edgeCandidates() []string {
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	return []string{
		filepath.Join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
	}
}

func detectChrome() string { return findFirstExisting(chromiumCandidates()) }
func detectEdge() string   { return findFirstExisting(edgeCandidates()) }

// socksHTTPClient はローカルの入口経由で通信する HTTP クライアントを返す。
func socksHTTPClient(socksPort int, timeout time.Duration) *http.Client {
	if socksPort <= 0 {
		return &http.Client{Timeout: timeout}
	}
	u := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", socksPort)}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(u),
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
}

// downloadFile は入口経由で取得し、失敗したら直接取得を試す。
func downloadFile(socksPort int, rawURL, dest string, setStatus func(string), label string) error {
	try := func(hc *http.Client, via string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", browserUA)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		tmp := dest + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			return err
		}
		total := resp.ContentLength
		var done int64
		buf := make([]byte, 128*1024)
		last := -1
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := f.Write(buf[:n]); werr != nil {
					f.Close()
					os.Remove(tmp)
					return werr
				}
				done += int64(n)
				if setStatus != nil && total > 0 {
					pct := int(done * 100 / total)
					if pct != last && pct%5 == 0 {
						last = pct
						setStatus(fmt.Sprintf("%sを取得中... %d%%", label, pct))
					}
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				f.Close()
				os.Remove(tmp)
				return rerr
			}
		}
		f.Close()
		if err := os.Rename(tmp, dest); err != nil {
			return err
		}
		logf("Downloaded %s via %s (%d bytes)", rawURL, via, done)
		return nil
	}

	if socksPort > 0 {
		if err := try(socksHTTPClient(socksPort, 15*time.Minute), "bridge"); err == nil {
			return nil
		} else {
			logf("tunneled download failed (%v), trying direct", err)
		}
	}
	return try(&http.Client{Timeout: 15 * time.Minute}, "direct")
}

// ensureBusybox は内蔵シェル用の単体実行ファイルを用意する。
func ensureBusybox(dir string, socksPort int, setStatus func(string)) (string, error) {
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return "", err
	}
	dest := filepath.Join(runtimeDir, "nctb-bash.exe")
	if st, err := os.Stat(dest); err == nil && st.Size() > 100*1024 {
		return dest, nil
	}
	setStatus("シェルを準備中...")
	urls := []string{
		"https://frippery.org/files/busybox/busybox64u.exe",
		"https://frippery.org/files/busybox/busybox64.exe",
	}
	var lastErr error
	for _, u := range urls {
		if err := downloadFile(socksPort, u, dest, setStatus, "シェル"); err == nil {
			if st, err := os.Stat(dest); err == nil && st.Size() > 100*1024 {
				return dest, nil
			}
		} else {
			lastErr = err
			logf("busybox download failed (%s): %v", u, err)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("取得できませんでした")
	}
	return "", lastErr
}

func chromiumArgs(socksPort int, profileDir string) []string {
	port := fmt.Sprintf("%d", socksPort)
	args := []string{}
	if profileDir != "" {
		args = append(args, "--user-data-dir="+profileDir)
	}
	args = append(args,
		"--proxy-server=socks5://127.0.0.1:"+port,
		"--proxy-bypass-list=<-loopback>",
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
	)
	return args
}

// proxyEnv は起動するアプリへ渡す環境変数を組み立てる。
func proxyEnv(socksPort int, runtimeDir, hookDLL string) []string {
	env := []string{
		fmt.Sprintf("HTTP_PROXY=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("HTTPS_PROXY=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("ALL_PROXY=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("http_proxy=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("https_proxy=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("all_proxy=socks5h://127.0.0.1:%d", socksPort),
		fmt.Sprintf("NCTB_SOCKS_PORT=%d", socksPort),
		"NO_PROXY=127.0.0.1,localhost,::1",
		"no_proxy=127.0.0.1,localhost,::1",
	}
	if hookDLL != "" {
		env = append(env, "NCTB_HOOK_DLL="+hookDLL)
	}
	if runtimeDir != "" {
		if old := os.Getenv("PATH"); old != "" {
			env = append(env, "PATH="+runtimeDir+";"+old)
		} else {
			env = append(env, "PATH="+runtimeDir)
		}
	}
	return env
}

// launchRequest は起動したいものの指定。
type launchRequest struct {
	kind   int
	appPath string
}

// resolveLaunchExe は起動対象の実行ファイルを決める。
func resolveLaunchExe(dir string, req launchRequest, socksPort int, setStatus func(string)) (string, []string, string, bool, error) {
	switch req.kind {
	case targetChrome:
		exe := detectChrome()
		if exe == "" {
			return "", nil, "", false, errors.New("Chrome が見つかりません")
		}
		profile := filepath.Join(dir, "profile-chrome")
		_ = os.MkdirAll(profile, 0755)
		return exe, chromiumArgs(socksPort, profile), filepath.Dir(exe), false, nil
	case targetEdge:
		exe := detectEdge()
		if exe == "" {
			return "", nil, "", false, errors.New("Edge が見つかりません")
		}
		profile := filepath.Join(dir, "profile-edge")
		_ = os.MkdirAll(profile, 0755)
		return exe, chromiumArgs(socksPort, profile), filepath.Dir(exe), false, nil
	case targetBrowser:
		exe, err := ensurePortableChromium(dir, socksPort, setStatus)
		if err != nil {
			return "", nil, "", false, err
		}
		profile := filepath.Join(dir, "profile-nctb")
		_ = os.MkdirAll(profile, 0755)
		return exe, chromiumArgs(socksPort, profile), filepath.Dir(exe), false, nil
	case targetBash:
		exe, err := ensureBusybox(dir, socksPort, setStatus)
		if err != nil {
			return "", nil, "", false, err
		}
		home := filepath.Join(dir, "shell-home")
		_ = os.MkdirAll(home, 0755)
		return exe, []string{"sh"}, filepath.Dir(exe), true, nil
	default:
		p := strings.Trim(strings.TrimSpace(req.appPath), `"`)
		if p == "" {
			return "", nil, "", false, errors.New("起動するアプリが指定されていません")
		}
		if strings.EqualFold(filepath.Ext(p), ".lnk") {
			if t, _, err := shortcutTarget(p); err == nil && t != "" {
				p = t
			}
		}
		if _, err := os.Stat(p); err != nil {
			return "", nil, "", false, fmt.Errorf("アプリが見つかりません:\n%s", p)
		}
		return p, nil, filepath.Dir(p), false, nil
	}
}

// startLaunch は指定のアプリを補助モジュール付きで起動する。
func startLaunch(dir string, req launchRequest, socksPort int, setStatus func(string)) (*launchedProcess, string, error) {
	hookDLL, _ := ensureHookDLL(dir)
	exe, args, workDir, newConsole, err := resolveLaunchExe(dir, req, socksPort, setStatus)
	if err != nil {
		return nil, "", err
	}
	env := proxyEnv(socksPort, filepath.Join(dir, "runtime"), hookDLL)
	logf("Launching %s (kind=%d) via 127.0.0.1:%d hook=%v console=%v", exe, req.kind, socksPort, hookDLL, newConsole)
	proc, perr := startProcess(exe, args, workDir, env, hookDLL, newConsole)
	if perr != nil {
		return nil, exe, perr
	}
	return proc, exe, nil
}

// waitForLaunched は起動したアプリが終わるまで待つ。
// 起動用のプロセスが本体へ処理を渡してすぐ終わる種類にも備える。
func waitForLaunched(proc *launchedProcess, exe string) {
	start := time.Now()
	if proc != nil {
		proc.wait()
	}
	if exe == "" {
		return
	}
	// すぐに終わった場合は、同じ名前のアプリ本体へ処理を渡しただけの可能性がある。
	if time.Since(start) > 2500*time.Millisecond {
		logf("app finished: %s", exe)
		return
	}
	time.Sleep(1200 * time.Millisecond)
	// 同じ名前の別のアプリが開きっぱなしでも、見張り続けないようにする。
	deadline := time.Now().Add(12 * time.Hour)
	for time.Now().Before(deadline) {
		if countProcesses(exe) == 0 {
			logf("app finished: %s", exe)
			return
		}
		time.Sleep(2 * time.Second)
	}
	logf("stopped watching %s after the time limit", exe)
}
