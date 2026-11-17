// Package adblock は、広告と追跡の配信元を名前の段階で速く見分ける。
//
// 一覧はビルドに埋め込んだ圧縮ファイルから読み、接続のたびに外部へ取りに行かない。
// 判定は名前の後ろから順に区切りごとに照らし合わせるだけで、名前の長さに比例して終わる。
package adblock

import (
	"bufio"
	"compress/gzip"
	"embed"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

//go:embed lists/*.txt.gz
var listFiles embed.FS

// Blocker は、配信元の一覧と、そこから外す一覧を持つ。
type Blocker struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
}

// Stats は、読み込んだ件数を表す。
type Stats struct {
	Blocked int
	Allowed int
}

// builtinAllowed は、どの一覧にも関わらず通す名前。
// 端末の中や名前の解決そのものを止めないための最低限。
var builtinAllowed = map[string]struct{}{
	"localhost":             {},
	"localhost.localdomain": {},
	"local":                 {},
	"broadcasthost":         {},
	"ip6-localhost":         {},
	"ip6-loopback":          {},
	"localdomain":           {},
}

// alwaysAllowedSuffix は、その配下をまとめて通す名前。
var alwaysAllowedSuffix = []string{
	".localhost",
	".local",
	".localdomain",
	".home.arpa",
	".in-addr.arpa",
	".ip6.arpa",
	".onion",
}

// Load は、埋め込んだ一覧をすべて読み込む。
func Load() (*Blocker, error) {
	entries, err := listFiles.ReadDir("lists")
	if err != nil {
		return nil, err
	}
	b := &Blocker{blocked: map[string]struct{}{}, allowed: map[string]struct{}{}}
	read := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt.gz") {
			continue
		}
		f, err := listFiles.Open("lists/" + entry.Name())
		if err != nil {
			return nil, err
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := b.add(zr); err != nil {
			zr.Close()
			f.Close()
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		zr.Close()
		f.Close()
		read++
	}
	if read == 0 {
		return nil, errors.New("広告ブロックの一覧が見つかりません")
	}
	return b, nil
}

// Parse は、一覧の本文を読み込んで Blocker を組み立てる。
// テストや、外から一覧を渡したいときのために分けてある。
func Parse(readers ...io.Reader) (*Blocker, error) {
	b := &Blocker{blocked: map[string]struct{}{}, allowed: map[string]struct{}{}}
	for _, r := range readers {
		if err := b.add(r); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Stats は、いま持っている件数を返す。
func (b *Blocker) Stats() Stats {
	if b == nil {
		return Stats{}
	}
	return Stats{Blocked: len(b.blocked), Allowed: len(b.allowed)}
}

func (b *Blocker) add(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		domain, allow, ok := parseLine(sc.Text())
		if !ok {
			continue
		}
		if allow {
			b.allowed[domain] = struct{}{}
			continue
		}
		b.blocked[domain] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	// 同じ名前を通す側にも書かれていたら、通す側を優先する。
	for domain := range b.allowed {
		delete(b.blocked, domain)
	}
	return nil
}

// Blocked は、その名前への接続を止めるべきかを返す。
func (b *Blocker) Blocked(host string) bool {
	if b == nil {
		return false
	}
	name := NormalizeHost(host)
	if name == "" || net.ParseIP(name) != nil {
		// 住所そのものは一覧の対象にしない。
		return false
	}
	if _, ok := builtinAllowed[name]; ok {
		return false
	}
	for _, suffix := range alwaysAllowedSuffix {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	if !strings.Contains(name, ".") {
		return false
	}
	if matchSuffix(b.allowed, name) {
		// 外す指定のほうが細かく書かれているときは、そちらに従う。
		return false
	}
	return matchSuffix(b.blocked, name)
}

// matchSuffix は、名前の区切りごとに後ろから照らし合わせる。
// 名前の区切りの数だけ引くので、一覧が大きくなっても速さが変わらない。
func matchSuffix(set map[string]struct{}, name string) bool {
	if len(set) == 0 {
		return false
	}
	for i := 0; ; {
		if _, ok := set[name[i:]]; ok {
			return true
		}
		dot := strings.IndexByte(name[i:], '.')
		if dot < 0 {
			return false
		}
		i += dot + 1
	}
}

// NormalizeHost は、接続先の書き方の揺れをそろえる。
// ポートや角括弧、末尾の点、大文字は落とす。
func NormalizeHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			h = h[1:end]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		// 住所（IPv6）はそのまま扱い、名前の後ろのポートだけを落とす。
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// parseLine は、一覧の一行を名前と種別に直す。
// 読めない行は黙って飛ばす。一覧の書き方は配布元ごとに少しずつ違う。
func parseLine(line string) (domain string, allow bool, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", false, false
	}
	switch s[0] {
	case '!', '#', '[', ';':
		return "", false, false
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if strings.HasPrefix(s, "@@") {
		allow = true
		s = strings.TrimSpace(s[2:])
	}
	if s == "" {
		return "", false, false
	}
	if strings.HasPrefix(s, "||") {
		return hostFromRule(s[2:]), allow, hostFromRule(s[2:]) != ""
	}
	// hosts 形式（0.0.0.0 name / 127.0.0.1 name / ::1 name）
	if fields := strings.Fields(s); len(fields) >= 2 {
		first := fields[0]
		if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::" {
			d := validDomain(fields[1])
			return d, allow, d != ""
		}
		// 住所の列が付いただけの形は読まない。名前だけの行として扱わない。
		return "", false, false
	}
	if strings.HasPrefix(s, "*.") {
		d := validDomain(s[2:])
		return d, allow, d != ""
	}
	if strings.HasPrefix(s, "|") || strings.HasPrefix(s, "/") {
		return "", false, false
	}
	d := validDomain(s)
	return d, allow, d != ""
}

// hostFromRule は「example.com^」「example.com^$third-party」から名前を取り出す。
// 道筋（/ads.js のような書き方）や言い換え（$domain=...）は名前だけを見る。
func hostFromRule(body string) string {
	if i := strings.IndexAny(body, "^$"); i >= 0 {
		body = body[:i]
	}
	if i := strings.IndexByte(body, '/'); i >= 0 {
		// 道筋まで指定された規則は、名前だけにすると広すぎるので使わない。
		return ""
	}
	body = strings.TrimPrefix(body, "*.")
	return validDomain(body)
}

// validDomain は、名前として扱ってよい形かを見る。
func validDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return ""
	}
	if strings.ContainsAny(d, "*/\\?#@=[]:% ") {
		return ""
	}
	if net.ParseIP(d) != nil {
		return ""
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return ""
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return ""
	}
	if strings.HasPrefix(tld, "xn--") {
		return d
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return ""
		}
	}
	return d
}
