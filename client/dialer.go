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
	"time"

	"neconnectbridge/internal/covert"
	"neconnectbridge/internal/endpoint"
	"neconnectbridge/internal/routepick"
)

// altPorts は、ブリッジのホストへ届く代替の HTTPS ポート。
// 実績のある 8443 から順に試す。
var altPorts = []string{"8443", "2053", "2083", "2087", "2096"}

// 通らなかった道筋を候補から外しておく時間。
const stageCooldown = 8 * time.Second

// 一つの接続方法にかける待ち時間の上限。
const methodBudget = 7 * time.Second

// 道筋を並べて試すときは、次の道筋を始めるまでの間を空ける。
// 前の道筋が通るまでの待ちを、そのまま空費にしない。
// 道筋が多いときでも最後の一つまで予算の内に始められる間隔にする。
const (
	raceStagger = 400 * time.Millisecond
	raceWidth   = 6
)

// 一本の道筋で TCP と TLS を張るまでの上限。
const (
	dialTimeout      = 5 * time.Second
	tlsHandshakeWait = 4 * time.Second
)

const (
	// つなぐ準備として張っておく流れの数と、張り足す目安。
	// 使っていない間は寝ているだけなので、厚めに持っておく。
	poolSize       = 24
	poolLowWater   = 20
	poolWarmBudget = 6 * time.Second
	poolRefillMax  = 8
)

const (
	// 同時に張り出す流れの本数と、その手前で待たせる本数。
	// 流れが尽きたときに、来た接続の数だけ一斉に張り出さないための上限。
	dialSlots = 12
	dialQueue = 16
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
// 通らなかった道筋はしばらく休ませるが、その記憶は方法ごとに分ける。
// 通るかどうかは通信の形によって変わるため、別の方法の失敗を引きずらない。
type transportDialer struct {
	host   string
	scope  string
	shared *routepick.Shared
	set    *routepick.Set
}

func newTransportDialer(host string) *transportDialer {
	shared := routepick.NewShared()
	return &transportDialer{host: host, scope: "base", shared: shared, set: routepick.New(shared, stageCooldown)}
}

// forMethod は、一つの方法だけの休みを持つ見方を返す。
// 通った道筋の手がかりは、接続全体で共有する。
func (d *transportDialer) forMethod(name string) *transportDialer {
	return &transportDialer{host: d.host, scope: name, shared: d.shared, set: routepick.New(d.shared, stageCooldown)}
}

// order は、通った道筋を先頭に、休んでいる道筋を外して並べる。
func (d *transportDialer) order(preferred []dialStage) []dialStage {
	all := []dialStage{}
	if st, ok := stageFromLabel(d.goodStage()); ok {
		all = append(all, st)
	}
	all = append(all, preferred...)
	all = append(all, standardStages()...)
	return d.only(all)
}

// only は、渡された道筋だけを使える形に整える。
func (d *transportDialer) only(stages []dialStage) []dialStage {
	seen := map[string]bool{}
	var all []dialStage
	for _, st := range stages {
		label := st.label()
		if seen[label] {
			continue
		}
		seen[label] = true
		all = append(all, st)
	}
	labels := make([]string, 0, len(all))
	keep := map[string]dialStage{}
	for _, st := range all {
		labels = append(labels, st.label())
		keep[st.label()] = st
	}
	out := make([]dialStage, 0, len(all))
	for _, label := range d.set.Filter(labels) {
		out = append(out, keep[label])
	}
	return out
}

func (d *transportDialer) isDead(label string) bool {
	return d.set.Resting(label)
}

// markDead は、道筋をしばらく休ませる。通った道筋は休ませない。
func (d *transportDialer) markDead(label string) {
	d.set.Rest(label)
}

func (d *transportDialer) markGood(label string) {
	d.set.Wake(label)
}

// goodStage は、この接続で通った道筋を返す。
func (d *transportDialer) goodStage() string {
	return d.shared.Good()
}

// dialConn は、一つの道筋でつなぎ、必要なら TLS を張る。
func (d *transportDialer) dialConn(ctx context.Context, st dialStage, port string, useTLS bool, alpns []string) (net.Conn, error) {
	if d.isDead(st.label()) {
		return nil, fmt.Errorf("%s is not reachable", st.label())
	}
	raw, err := d.dialRaw(ctx, st, port)
	if err != nil {
		// 打ち切っただけの道筋は、使えないと決めつけない。
		if ctx.Err() == nil {
			d.markDead(st.label())
		}
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
	hctx, cancel := context.WithTimeout(ctx, tlsHandshakeWait)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		if ctx.Err() == nil {
			d.markDead(st.label())
		}
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
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
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
// 待たずに分かる住所を先に使い、照会はそれでも足りないときだけ行う。
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
	if ip, ok := dohLookup.Cached(d.host); ok {
		add(ip)
	}
	for _, ip := range cfAnycastIPs {
		add(ip)
	}
	if len(out) > 0 {
		return out
	}
	// 候補が一つも無いときだけ、実際に引く。
	if ip, err := resolveDoH(d.host); err == nil {
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

// raceStages は、道筋を少しずつずらして並べ、最初に通ったものを採る。
// 打ち切った道筋の接続は残さず、試していない道筋はそのまま残す。
func raceStages[T interface{ Close() error }](parent context.Context, budget time.Duration, stages []dialStage, attempt func(context.Context, dialStage) (T, error)) (T, dialStage, error) {
	var zero T
	if len(stages) == 0 {
		return zero, dialStage{}, noRouteErr(nil)
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()

	type outcome struct {
		value T
		stage dialStage
		err   error
	}
	results := make(chan outcome, len(stages))
	launched, active := 0, 0
	var errs []string
	var stopErr error
	nextLaunch := time.Now()

	// 道筋の試行で異常が出ても、本体を道連れにしない。
	runAttempt := func(st dialStage) (v T, err error) {
		defer func() {
			if r := recover(); r != nil {
				var zero T
				v = zero
				err = fmt.Errorf("%s: unexpected failure: %v", st.label(), r)
				logf("route attempt stopped: %v", r)
				writeCrashReport("route attempt", r)
			}
		}()
		return attempt(ctx, st)
	}
	launch := func(st dialStage) {
		launched++
		active++
		go func() {
			v, err := runAttempt(st)
			if ctx.Err() != nil {
				// 負けた道筋は、開いた接続ごと片付ける。
				if err == nil {
					_ = v.Close()
				}
				results <- outcome{stage: st, err: ctx.Err()}
				return
			}
			results <- outcome{value: v, stage: st, err: err}
		}()
	}
	settle := func(r outcome) (T, dialStage, bool) {
		active--
		if r.err == nil {
			cancel()
			return r.value, r.stage, true
		}
		// 道筋の名前を二度繰り返さない。
		if label := r.stage.label(); strings.HasPrefix(r.err.Error(), label) {
			errs = append(errs, r.err.Error())
		} else {
			errs = append(errs, label+": "+r.err.Error())
		}
		if errors.Is(r.err, endpoint.ErrUnavailable) {
			// 道筋を変えても答えは変わらないので、ここで打ち切る。
			cancel()
			stopErr = noRouteErr(errs)
		}
		return zero, dialStage{}, false
	}

	for {
		// 試している道筋がもう無いなら、次はすぐ始める。
		if active == 0 {
			nextLaunch = time.Time{}
		}
		for launched < len(stages) && active < raceWidth && !time.Now().Before(nextLaunch) {
			launch(stages[launched])
			nextLaunch = time.Now().Add(raceStagger)
		}
		if active == 0 && launched >= len(stages) {
			return zero, dialStage{}, noRouteErr(errs)
		}
		wait := time.Until(nextLaunch)
		if stopErr != nil {
			return zero, dialStage{}, stopErr
		}
		if wait <= 0 || launched >= len(stages) || active >= raceWidth {
			select {
			case r := <-results:
				if v, st, ok := settle(r); ok {
					return v, st, nil
				}
				if stopErr != nil {
					return zero, dialStage{}, stopErr
				}
			case <-ctx.Done():
				return zero, dialStage{}, noRouteErr(append(errs, "time budget spent"))
			}
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case r := <-results:
			timer.Stop()
			if v, st, ok := settle(r); ok {
				return v, st, nil
			}
			if stopErr != nil {
				return zero, dialStage{}, stopErr
			}
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return zero, dialStage{}, noRouteErr(append(errs, "time budget spent"))
		}
	}
}
