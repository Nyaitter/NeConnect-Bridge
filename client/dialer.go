package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"neconnectbridge/internal/covert"
)

// altPorts は、ブリッジのホストへ届く代替の HTTPS ポート。
// 実績のある 8443 から順に試す。
var altPorts = []string{"8443", "2053", "2083", "2087", "2096"}

// 一つの接続方法にかける待ち時間の上限。
const methodBudget = 7 * time.Second

const (
	// つなぐ準備として張っておく流れの数と、張り足す目安。
	poolSize       = 12
	poolLowWater   = 10
	poolWarmBudget = 6 * time.Second
)

// dialStage は、ブリッジのホストへ届くまでの一つの道筋。
type dialStage struct {
	port string // 代替の HTTPS ポート
	frag bool   // TLS の記録を分けて送る
	any  bool   // 名前解決を避けて近い住所へつなぐ
	ip   string // つなぐ先を決め打ちするときの住所
}

func (s dialStage) label() string {
	switch {
	case s.any && s.ip != "":
		return "anycast:" + s.ip
	case s.any:
		return "anycast"
	case s.port != "" && s.frag:
		return "altfrag:" + s.port
	case s.port != "":
		return "alt:" + s.port
	case s.frag:
		return "frag"
	default:
		return "direct"
	}
}

// stageFromLabel は、保存した手がかりから道筋を戻す。
func stageFromLabel(label string) (dialStage, bool) {
	label = strings.TrimSpace(label)
	head, tail := label, ""
	if i := strings.Index(label, ":"); i >= 0 {
		head, tail = label[:i], label[i+1:]
	}
	switch head {
	case "direct":
		return dialStage{}, true
	case "frag":
		return dialStage{frag: true}, true
	case "alt":
		if tail == "" {
			return dialStage{}, false
		}
		return dialStage{port: tail}, true
	case "altfrag":
		if tail == "" {
			return dialStage{}, false
		}
		return dialStage{port: tail, frag: true}, true
	case "anycast":
		return dialStage{any: true, ip: tail}, true
	}
	return dialStage{}, false
}

// stagesForParam は、保存した手がかりを試す順に直す。
// 前の版が残した「8443」や住所だけの形も読む。
func stagesForParam(param string) []dialStage {
	p := strings.TrimSpace(param)
	if p == "" {
		return nil
	}
	if _, err := strconv.Atoi(p); err == nil {
		return []dialStage{{port: p}}
	}
	if net.ParseIP(p) != nil {
		return []dialStage{{any: true, ip: p}}
	}
	if st, ok := stageFromLabel(p); ok {
		return []dialStage{st}
	}
	return nil
}

// standardStages は、速い順に並べた道筋。
// そのままの接続、代替ポート、記録の分割、住所の決め打ちの順に試す。
func standardStages() []dialStage {
	out := []dialStage{{}}
	for _, p := range altPorts {
		out = append(out, dialStage{port: p})
	}
	out = append(out, dialStage{frag: true}, dialStage{any: true})
	return out
}

// altFragStages は、代替ポートと記録の分割を重ねた道筋。
func altFragStages() []dialStage {
	out := make([]dialStage, 0, len(altPorts))
	for _, p := range altPorts {
		out = append(out, dialStage{port: p, frag: true})
	}
	return out
}

// noRouteErr は、試した道筋と結果を一つにまとめる。
func noRouteErr(errs []string) error {
	if len(errs) == 0 {
		return errors.New("no route is left to try")
	}
	return errors.New(strings.Join(errs, "\n"))
}

// routeLabelText は、保存した経路を表示用の短い文字列にする。
func routeLabelText(route *routeCache) string {
	if route == nil {
		return "auto"
	}
	if route.Param != "" {
		return route.Method + ":" + route.Param
	}
	return route.Method
}

// transportDialer は、道筋を順に試し、通った道筋を覚えておく。
// 一度も通らないと分かった道筋は、この接続の間は飛ばす。
type transportDialer struct {
	host string

	mu   sync.Mutex
	dead map[string]bool
	good string
}

func newTransportDialer(host string) *transportDialer {
	return &transportDialer{host: host, dead: map[string]bool{}}
}

// order は、通った道筋を先頭に、使えないと分かっている道筋を外して並べる。
func (d *transportDialer) order(preferred []dialStage) []dialStage {
	seen := map[string]bool{}
	var all []dialStage
	add := func(st dialStage) {
		label := st.label()
		if seen[label] {
			return
		}
		seen[label] = true
		all = append(all, st)
	}
	d.mu.Lock()
	good := d.good
	dead := make(map[string]bool, len(d.dead))
	for key, value := range d.dead {
		dead[key] = value
	}
	d.mu.Unlock()

	if good != "" {
		if st, ok := stageFromLabel(good); ok {
			add(st)
		}
	}
	for _, st := range preferred {
		add(st)
	}
	for _, st := range standardStages() {
		add(st)
	}

	out := make([]dialStage, 0, len(all))
	for _, st := range all {
		if dead[st.label()] {
			continue
		}
		out = append(out, st)
	}
	return out
}

func (d *transportDialer) isDead(label string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dead[label]
}

func (d *transportDialer) markDead(label string) {
	d.mu.Lock()
	d.dead[label] = true
	d.mu.Unlock()
}

func (d *transportDialer) markGood(label string) {
	d.mu.Lock()
	d.good = label
	d.dead[label] = false
	d.mu.Unlock()
}

// goodStage は、この接続で通った道筋を返す。
func (d *transportDialer) goodStage() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.good
}

// dialConn は、一つの道筋でつなぎ、必要なら TLS を張る。
func (d *transportDialer) dialConn(ctx context.Context, st dialStage, port string, useTLS bool, alpns []string) (net.Conn, error) {
	if d.isDead(st.label()) {
		return nil, fmt.Errorf("%s is not reachable", st.label())
	}
	raw, err := d.dialRaw(ctx, st, port)
	if err != nil {
		d.markDead(st.label())
		return nil, err
	}
	if !useTLS {
		d.markGood(st.label())
		return raw, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: alpns}
	if host := d.host; net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	conn := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		d.markDead(st.label())
		return nil, fmt.Errorf("%s: %w", st.label(), err)
	}
	d.markGood(st.label())
	return conn, nil
}

// dialRaw は、一つの道筋で TCP をつなぐ。
func (d *transportDialer) dialRaw(ctx context.Context, st dialStage, port string) (net.Conn, error) {
	host := d.host
	if st.port != "" {
		port = st.port
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	var err error
	if st.any {
		addresses := d.anycastAddresses(st.ip)
		if len(addresses) == 0 {
			return nil, errors.New("no address is known for the bridge")
		}
		for _, ip := range addresses {
			conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
			if err == nil {
				break
			}
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if st.frag {
		return covert.NewFragConn(conn), nil
	}
	return conn, nil
}

// anycastAddresses は、名前解決を避けてつなぐ先を返す。
func (d *transportDialer) anycastAddresses(pinned string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	add(pinned)
	if ip, err := resolveDoH(d.host); err == nil {
		add(ip)
	}
	for _, ip := range cfAnycastIPs {
		add(ip)
	}
	return out
}

// httpClient は、一つの道筋に結び付けた HTTP のやり取りを返す。
// h2 を立てるときは、TLS の次の約束に h2 を添える。
func (d *transportDialer) httpClient(st dialStage, timeout time.Duration, h2 bool) *http.Client {
	alpns := []string{"http/1.1"}
	if h2 {
		alpns = []string{"h2", "http/1.1"}
	}
	tr := &http.Transport{
		// 自分自身の通信はまわりの設定に左右されないよう、そのままつなぐ。
		Proxy:               nil,
		ForceAttemptHTTP2:   h2,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "80"
			}
			return d.dialConn(ctx, st, port, false, nil)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			return d.dialConn(ctx, st, port, true, alpns)
		},
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
