package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.9", "1.2.8", 1},
		{"1.2.8", "1.2.9", -1},
		{"1.2.9", "1.2.9", 0},
		{"1.2.10", "1.2.9", 1},
		{"v1.3.0", "1.2.9", 1},
		{"1.3.0", "1.3.0-rc1", 1},
		{"1.3.0-rc1", "1.3.0", -1},
		{"1.3.0-rc2", "1.3.0-rc1", 1},
		{"1.3.0+build5", "1.3.0", 0},
		{"2.0", "1.9.9", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if !IsNewer("1.2.9", "1.2.8") {
		t.Error("1.2.9 は 1.2.8 より新しいはず")
	}
	if IsNewer("1.2.8", "1.2.8") {
		t.Error("同じ版を新しいと見てはいけない")
	}
}

func TestBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://nct.example.jp/bridge/server":    "https://nct.example.jp/bridge",
		"https://nct.example.jp/bridge/server/":   "https://nct.example.jp/bridge",
		"https://nct.example.jp/bridge":           "https://nct.example.jp/bridge",
		"https://relay.example/bridge/server?x=1": "https://relay.example/bridge",
		"http://127.0.0.1:8090/bridge/server":     "http://127.0.0.1:8090/bridge",
	}
	for in, want := range cases {
		got, err := BaseURL(in)
		if err != nil {
			t.Errorf("BaseURL(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("BaseURL(%q)=%q want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "ssh://host:22", "not a url", "https:///server"} {
		if _, err := BaseURL(bad); err == nil {
			t.Errorf("BaseURL(%q) は失敗すべき", bad)
		}
	}
}

func TestManifestURLs(t *testing.T) {
	base := "https://nct.example.jp/bridge"
	if got := ManifestURL(base); got != base+"/versions" {
		t.Errorf("ManifestURL=%q", got)
	}
	if got := DownloadURL(base, "1.2.9"); got != base+"/download?version=1.2.9" {
		t.Errorf("DownloadURL=%q", got)
	}
	if got := DownloadURL(base+"/", "1.3.0-rc1"); !strings.HasSuffix(got, "version=1.3.0-rc1") {
		t.Errorf("DownloadURL=%q", got)
	}
}

func TestParseManifestPicksNewest(t *testing.T) {
	body := `{"latest":"1.2.9","versions":[
		{"version":"1.2.8","size":10,"sha256":"aa"},
		{"version":"1.2.9","size":12,"sha256":"bb"},
		{"version":"1.2.7","size":9}]}`
	var m Manifest
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	rel, ok := m.Newest()
	if !ok || rel.Version != "1.2.9" || rel.SHA256 != "bb" || rel.Size != 12 {
		t.Fatalf("Newest=%+v ok=%v", rel, ok)
	}
	// latest が無い一覧でも、いちばん新しいものを選ぶ。
	m = Manifest{Versions: []Release{{Version: "1.9.0"}, {Version: "1.10.0"}, {Version: "1.2.0"}}}
	rel, ok = m.Newest()
	if !ok || rel.Version != "1.10.0" {
		t.Fatalf("Newest=%+v ok=%v", rel, ok)
	}
	if _, ok := (&Manifest{}).Newest(); ok {
		t.Fatal("空の一覧で見つかってはいけない")
	}
}

func payload() []byte { return []byte("new executable body\n") }

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fakeReleaseServer は、版の一覧と配布物を返す小さなサーバー。
func fakeReleaseServer(t *testing.T, version string, body []byte, digestOverride string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/bridge/versions", func(w http.ResponseWriter, r *http.Request) {
		sum := digest(body)
		if digestOverride != "" {
			sum = digestOverride
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, `{"latest":%q,"versions":[{"version":%q,"size":%d,"sha256":%q}]}`, version, version, len(body), sum)
	})
	mux.HandleFunc("/bridge/download", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("version"); got != version {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("content-type", "application/octet-stream")
		w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchAndDownload(t *testing.T) {
	body := payload()
	srv := fakeReleaseServer(t, "1.2.9", body, "")
	base := srv.URL + "/bridge"
	ctx := context.Background()
	m, err := Fetch(ctx, srv.Client(), base)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	rel, ok := m.Newest()
	if !ok || rel.Version != "1.2.9" {
		t.Fatalf("Newest=%+v", rel)
	}
	dest := filepath.Join(t.TempDir(), "NeConnectBridge.exe.new")
	if err := Download(ctx, srv.Client(), base, rel, dest); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("中身が違います: %q", got)
	}
}

func TestDownloadRefusesWrongDigest(t *testing.T) {
	body := payload()
	srv := fakeReleaseServer(t, "1.2.9", body, strings.Repeat("0", 64))
	base := srv.URL + "/bridge"
	rel := Release{Version: "1.2.9", Size: int64(len(body)), SHA256: strings.Repeat("0", 64)}
	dest := filepath.Join(t.TempDir(), "x.new")
	err := Download(context.Background(), srv.Client(), base, rel, dest)
	if err == nil || !strings.Contains(err.Error(), "照合値") {
		t.Fatalf("照合値の不一致で止まるべき: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("合わなかったものは残してはいけない")
	}
	if _, statErr := os.Stat(dest + ".part"); !os.IsNotExist(statErr) {
		t.Fatal("途中のファイルも残してはいけない")
	}
}

func TestDownloadRequiresDigest(t *testing.T) {
	srv := fakeReleaseServer(t, "1.2.9", payload(), "")
	rel := Release{Version: "1.2.9"}
	if err := Download(context.Background(), srv.Client(), srv.URL+"/bridge", rel, filepath.Join(t.TempDir(), "x")); err != ErrNoDigest {
		t.Fatalf("照合値の無いものは断るべき: %v", err)
	}
}

func TestApplySwapsFilesAndCleanupRemovesLeftovers(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "NeConnectBridge.exe")
	if err := os.WriteFile(exe, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	newPath := exe + ".new"
	if err := os.WriteFile(newPath, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Apply(exe, newPath); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cur, _ := os.ReadFile(exe)
	if string(cur) != "new" {
		t.Fatalf("新しい中身になっていません: %q", cur)
	}
	old, err := os.ReadFile(exe + ".old")
	if err != nil || string(old) != "old" {
		t.Fatalf("前の実行ファイルが残っていません: %q %v", old, err)
	}
	Cleanup(exe)
	for _, path := range []string{exe + ".old", exe + ".new"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s は片づけるべき", path)
		}
	}
}

func TestStageEndToEnd(t *testing.T) {
	body := []byte("version 1.2.9 binary\n")
	srv := fakeReleaseServer(t, "1.2.9", body, "")
	base := srv.URL + "/bridge"
	dir := t.TempDir()
	exe := filepath.Join(dir, "NeConnectBridge.exe")
	if err := os.WriteFile(exe, []byte("version 1.2.8 binary\n"), 0755); err != nil {
		t.Fatal(err)
	}
	var logs []string
	res, err := Stage(context.Background(), srv.Client(), base, "1.2.8", exe, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !res.Updated || res.Version != "1.2.9" {
		t.Fatalf("結果が違います: %+v", res)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != string(body) {
		t.Fatalf("差し替わっていません: %q", got)
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatal("取り寄せたものは .new として残さない")
	}
	if len(logs) == 0 {
		t.Fatal("何をしたか記録するべき")
	}

	// 同じ版なら何もしない。
	res, err = Stage(context.Background(), srv.Client(), base, "1.2.9", exe, nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if res.Updated {
		t.Fatal("同じ版で差し替えてはいけない")
	}
}

func TestStageKeepsCurrentFileOnBadDigest(t *testing.T) {
	body := []byte("broken download\n")
	sum := strings.Repeat("1", 64)
	srv := fakeReleaseServer(t, "1.3.0", body, sum)
	base := srv.URL + "/bridge"
	dir := t.TempDir()
	exe := filepath.Join(dir, "NeConnectBridge.exe")
	if err := os.WriteFile(exe, []byte("current\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(context.Background(), srv.Client(), base, "1.2.9", exe, nil); err == nil {
		t.Fatal("照合値が合わないのに進んではいけない")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "current\n" {
		t.Fatalf("いまの実行ファイルを壊してはいけない: %q", got)
	}
}
