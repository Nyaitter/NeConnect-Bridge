package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"neconnectbridge/internal/selfupdate"
)

// 更新の確認と取り寄せにかける時間。
// 取り寄せは中継の上を通るので、回線が細いときも最後まで待つ。
const (
	updateCheckTimeout    = 40 * time.Second
	updateDownloadTimeout = 12 * time.Minute
)

// updateOnce は、1回の起動で1度だけ確かめるためのもの。
var updateOnce sync.Once

// startUpdateCheck は、接続できたあとに新しい版があるかを確かめる。
// apply は、取得した版へ切り替える前に呼び出し側が接続を片づけるためのもの。
func startUpdateCheck(port int, serverURLs string, apply func()) {
	if port <= 0 {
		return
	}
	updateOnce.Do(func() {
		goSafe("update check", func() {
			runUpdateCheck(port, serverURLs, apply)
		})
	})
}

func runUpdateCheck(port int, serverURLs string, apply func()) {
	base := ""
	for _, raw := range splitServerURLs(serverURLs) {
		if b, err := selfupdate.BaseURL(raw); err == nil {
			base = b
			break
		}
	}
	if base == "" {
		logf("更新チェック: 接続先を読めませんでした")
		return
	}
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		logf("更新チェック: このアプリの場所を取得できませんでした")
		return
	}

	// 確認も取り寄せも、いま張った入口（SOCKS5）を通す。
	// 直結では弾かれる回線があるため、ここだけは必ず中継の上を通す。
	hc := socksHTTPClient(port, updateDownloadTimeout)

	// 一覧の確認は短く切り上げる。つながっている接続を長く待たせない。
	checkCtx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	rel, newer, err := selfupdate.Plan(checkCtx, hc, base, appVersion, logf)
	cancel()
	if err != nil {
		// 更新の確認に失敗しても、接続そのものは壊さない。
		logf("更新を確かめられませんでした: %v", err)
		return
	}
	if !newer {
		return
	}

	dlCtx, cancelDl := context.WithTimeout(context.Background(), updateDownloadTimeout)
	defer cancelDl()
	logf("更新 %s を取得します（いま %s）", rel.Version, appVersion)
	newPath := exe + ".new"
	_ = os.Remove(newPath)
	if err := selfupdate.Download(dlCtx, hc, base, rel, newPath); err != nil {
		_ = os.Remove(newPath)
		logf("更新を取得できませんでした: %v", err)
		return
	}
	if err := selfupdate.Apply(exe, newPath); err != nil {
		_ = os.Remove(newPath)
		logf("更新を適用できませんでした: %v", err)
		return
	}
	logf("更新 (v%s) を取得しました", rel.Version)
	if !askRestart("新しいバージョン (v" + rel.Version + ") を取得しました。今すぐ再起動して適用しますか？") {
		logf("次に起動したときから新しい版を使います")
		return
	}
	if apply != nil {
		apply()
	}
	restartSelf(exe)
}

// askRestart は、画面に確認を出す。窓が無いときは何もしない（次回起動で適用）。
func askRestart(text string) bool {
	ui := globalUI
	if ui == nil {
		return false
	}
	return ui.askConfirm("NeConnect Bridge", text)
}

// restartSelf は、差し替えた実行ファイルを起動して、自分は閉じる。
func restartSelf(exe string) {
	cmd := exec.Command(exe)
	cmd.Dir = filepath.Dir(exe)
	if err := cmd.Start(); err != nil {
		logf("新しい版を起動できませんでした: %v", err)
		return
	}
	logf("新しい版を起動しました")
	if h := globalUI.windowHandle(); h != 0 {
		procPostMessageW.Call(h, wmClose, 0, 0)
		return
	}
	os.Exit(0)
}
