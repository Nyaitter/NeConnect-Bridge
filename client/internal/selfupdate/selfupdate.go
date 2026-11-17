// Package selfupdate は、走っている版より新しい配布物があるかを確かめ、
// 取り寄せてから実行ファイルを差し替えるところまでを扱う。
//
// 通信は呼び出し側が渡す http.Client に任せる。ブリッジ経由で取りに行くのは
// 呼び出し側の役目で、ここは渡された道だけを使う。
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoDigest は、配布物の照合値が配られていないときに返す。
// 照合できないものは実行ファイルにしない。
var ErrNoDigest = errors.New("配布物の照合値がありません")

// ErrChecksum は、取り寄せた中身が照合値と合わなかったときに返す。
var ErrChecksum = errors.New("取り寄せた中身が照合値と合いません")

const maxReleaseSize = 128 << 20

// Release は、配られている1つの版を表す。
type Release struct {
	Version    string `json:"version"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	ReleasedAt string `json:"released_at"`
}

// Manifest は /versions の答え。
type Manifest struct {
	Latest   string    `json:"latest"`
	Versions []Release `json:"versions"`
}

// Result は、確かめた結果を表す。
type Result struct {
	Updated bool
	Version string
}

// BaseURL は、ブリッジURLから配布物の置き場所を導く。
// 例: https://host/bridge/server -> https://host/bridge
func BaseURL(serverURL string) (string, error) {
	raw := strings.TrimSpace(serverURL)
	if raw == "" {
		return "", errors.New("ブリッジURLが空です")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("扱えない接続先です: %s", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("接続先の名前がありません: %s", raw)
	}
	path := strings.TrimRight(u.Path, "/")
	path = strings.TrimSuffix(path, "/server")
	out := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: path}
	return out.String(), nil
}

// ManifestURL は、版の一覧を返す場所。
func ManifestURL(base string) string {
	return strings.TrimRight(base, "/") + "/versions"
}

// DownloadURL は、指定した版の配布物を返す場所。
func DownloadURL(base, version string) string {
	return strings.TrimRight(base, "/") + "/download?version=" + url.QueryEscape(version)
}

// Fetch は、版の一覧を取り寄せる。
func Fetch(ctx context.Context, client *http.Client, base string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ManifestURL(base), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("版の一覧を取得できませんでした (HTTP %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("版の一覧を読めませんでした: %w", err)
	}
	return &m, nil
}

// Newest は、いちばん新しい版を返す。
// latest が一覧に無いときは、一覧の中から最も新しいものを選ぶ。
func (m *Manifest) Newest() (Release, bool) {
	if m == nil {
		return Release{}, false
	}
	if v := strings.TrimSpace(m.Latest); v != "" {
		for _, rel := range m.Versions {
			if rel.Version == v {
				return rel, true
			}
		}
	}
	var best Release
	found := false
	for _, rel := range m.Versions {
		if strings.TrimSpace(rel.Version) == "" {
			continue
		}
		if !found || Compare(rel.Version, best.Version) > 0 {
			best = rel
			found = true
		}
	}
	return best, found
}

// Compare は版を比べる。a が新しければ正、古ければ負、同じなら 0。
// 1.2.10 は 1.2.9 より新しく、1.3.0-rc1 は 1.3.0 より古い。
func Compare(a, b string) int {
	left, right := splitVersion(a), splitVersion(b)
	for i := 0; i < len(left.core) || i < len(right.core); i++ {
		l, r := 0, 0
		if i < len(left.core) {
			l = left.core[i]
		}
		if i < len(right.core) {
			r = right.core[i]
		}
		if l != r {
			if l > r {
				return 1
			}
			return -1
		}
	}
	// 本番の版どうしが同じなら、後に付いた印で決める。
	switch {
	case left.pre == "" && right.pre == "":
		return 0
	case left.pre == "":
		return 1
	case right.pre == "":
		return -1
	}
	return comparePre(left.pre, right.pre)
}

func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an > bn {
					return 1
				}
				return -1
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}

type version struct {
	core []int
	pre  string
}

func splitVersion(v string) version {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	pre := ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	var core []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			// 数を読めない部分は 0 として扱い、比較を止めない。
			n = 0
		}
		core = append(core, n)
	}
	return version{core: core, pre: pre}
}

// IsNewer は、candidate が current より新しいかを返す。
func IsNewer(candidate, current string) bool {
	return Compare(candidate, current) > 0
}

// Download は、配布物を取り寄せて dest に置き、照合値を確かめる。
// 途中で失敗したときや、中身が合わなかったときは dest を残さない。
func Download(ctx context.Context, client *http.Client, base string, rel Release, dest string) error {
	if strings.TrimSpace(rel.SHA256) == "" {
		return ErrNoDigest
	}
	req, err := http.NewRequestWithContext(ctx, "GET", DownloadURL(base, rel.Version), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("配布物を取得できませんでした (HTTP %d)", resp.StatusCode)
	}

	part := dest + ".part"
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	hash := sha256.New()
	limit := int64(maxReleaseSize)
	if rel.Size > 0 {
		limit = rel.Size
	}
	written, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(part)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(part)
		return closeErr
	}
	if written > limit {
		_ = os.Remove(part)
		return fmt.Errorf("配布物が大きすぎます")
	}
	if rel.Size > 0 && written != rel.Size {
		_ = os.Remove(part)
		return fmt.Errorf("配布物の大きさが合いません (%d / %d)", written, rel.Size)
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(sum, strings.TrimSpace(rel.SHA256)) {
		_ = os.Remove(part)
		return ErrChecksum
	}
	if err := os.Rename(part, dest); err != nil {
		_ = os.Remove(part)
		return err
	}
	return nil
}

// Apply は、取り寄せたものを実行ファイルと入れ替える。
// 走っている最中でも、名前を変えるだけなら Windows でも通る。
func Apply(exePath, newPath string) error {
	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		return fmt.Errorf("いまの実行ファイルを退けられませんでした: %w", err)
	}
	if err := os.Rename(newPath, exePath); err != nil {
		// 入れ替えに失敗したら、元の名前へ戻す。
		_ = os.Rename(oldPath, exePath)
		return fmt.Errorf("新しい実行ファイルを置けませんでした: %w", err)
	}
	return nil
}

// Cleanup は、前回の入れ替えで残ったものを片づける。
func Cleanup(exePath string) {
	for _, suffix := range []string{".old", ".new", ".new.part"} {
		_ = os.Remove(exePath + suffix)
	}
}

// Stage は、新しい版があれば取り寄せて差し替える。
// 失敗しても、いま動いている実行ファイルはそのまま残る。
func Stage(ctx context.Context, client *http.Client, base, currentVersion, exePath string, logf func(string, ...any)) (Result, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	m, err := Fetch(ctx, client, base)
	if err != nil {
		return Result{}, err
	}
	rel, ok := m.Newest()
	if !ok {
		logf("更新チェック: 配られている版がありません")
		return Result{}, nil
	}
	if !IsNewer(rel.Version, currentVersion) {
		logf("更新チェック: 最新は %s です（いま %s）", rel.Version, currentVersion)
		return Result{}, nil
	}
	if strings.TrimSpace(rel.SHA256) == "" {
		return Result{}, ErrNoDigest
	}
	logf("更新 %s を取得します（いま %s）", rel.Version, currentVersion)
	newPath := exePath + ".new"
	_ = os.Remove(newPath)
	if err := Download(ctx, client, base, rel, newPath); err != nil {
		return Result{}, err
	}
	if err := Apply(exePath, newPath); err != nil {
		_ = os.Remove(newPath)
		return Result{}, err
	}
	return Result{Updated: true, Version: rel.Version}, nil
}
