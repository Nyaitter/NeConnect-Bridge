// Package dohres は、名前を DoH で引くときの重複と連打をまとめる。
//
// 同時に同じ名前を引きにいっても照会は一度だけ行い、
// 失敗した名前はしばらく引き直さずに即座に諦める。
package dohres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrSkipped は、直前に失敗した名前を引き直さなかったことを表す。
var ErrSkipped = errors.New("lookup skipped after a recent failure")

const (
	defaultTTL     = 10 * time.Minute
	defaultFailTTL = 30 * time.Second
	defaultTimeout = 4 * time.Second
	maxParallel    = 2
)

// DefaultEndpoints は、名前を引く先。
var DefaultEndpoints = []string{
	"https://1.1.1.1/dns-query?name=%s&type=A",
	"https://8.8.8.8/resolve?name=%s&type=A",
}

// Options は Resolver の動きを決める。
type Options struct {
	TTL       time.Duration
	FailTTL   time.Duration
	Timeout   time.Duration
	Endpoints []string
	Log       func(format string, args ...any)
}

type entry struct {
	ip  string
	exp time.Time
}

type call struct {
	done chan struct{}
	ip   string
	err  error
}

// Resolver は、名前ごとの結果と照会中の呼び出しをまとめて持つ。
type Resolver struct {
	ttl       time.Duration
	failTTL   time.Duration
	timeout   time.Duration
	endpoints []string
	log       func(format string, args ...any)
	client    *http.Client

	mu       sync.Mutex
	cache    map[string]entry
	failed   map[string]time.Time
	inflight map[string]*call
	sem      chan struct{}
}

// New は Resolver を作る。
func New(opt Options) *Resolver {
	r := &Resolver{
		ttl:       opt.TTL,
		failTTL:   opt.FailTTL,
		timeout:   opt.Timeout,
		endpoints: opt.Endpoints,
		log:       opt.Log,
		cache:     map[string]entry{},
		failed:    map[string]time.Time{},
		inflight:  map[string]*call{},
		sem:       make(chan struct{}, maxParallel),
	}
	if r.ttl <= 0 {
		r.ttl = defaultTTL
	}
	if r.failTTL <= 0 {
		r.failTTL = defaultFailTTL
	}
	if r.timeout <= 0 {
		r.timeout = defaultTimeout
	}
	if len(r.endpoints) == 0 {
		r.endpoints = DefaultEndpoints
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
	r.client = &http.Client{
		Timeout: r.timeout,
		Transport: &http.Transport{
			// 自分の通信はまわりの設定に左右されないよう、そのままつなぐ。
			Proxy:               nil,
			MaxIdleConns:        4,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 4 * time.Second,
			DialContext:         dialer.DialContext,
		},
	}
	return r
}

func (r *Resolver) logf(format string, args ...any) {
	if r.log != nil {
		r.log(format, args...)
	}
}

// Resolve は名前から住所を返す。
// 同じ名前の照会が同時に来たときは、一度の照会の結果を全員で分ける。
func (r *Resolver) Resolve(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	now := time.Now()

	r.mu.Lock()
	if ent, ok := r.cache[host]; ok && now.Before(ent.exp) {
		r.mu.Unlock()
		return ent.ip, nil
	}
	if until, ok := r.failed[host]; ok && now.Before(until) {
		r.mu.Unlock()
		return "", fmt.Errorf("%s: %w", host, ErrSkipped)
	}
	if c, ok := r.inflight[host]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.ip, c.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[host] = c
	r.mu.Unlock()

	ip, err := r.lookup(ctx, host)

	r.mu.Lock()
	delete(r.inflight, host)
	if err == nil {
		r.cache[host] = entry{ip: ip, exp: time.Now().Add(r.ttl)}
		delete(r.failed, host)
	} else if !errors.Is(err, context.Canceled) {
		r.failed[host] = time.Now().Add(r.failTTL)
	}
	r.mu.Unlock()

	c.ip, c.err = ip, err
	close(c.done)
	return ip, err
}

// lookup は、実際に照会を行う。
func (r *Resolver) lookup(ctx context.Context, host string) (string, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	q := url.QueryEscape(host)
	var lastErr error
	for _, ep := range r.endpoints {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		ip, err := r.query(ctx, strings.Replace(ep, "%s", q, 1))
		if err != nil {
			lastErr = err
			continue
		}
		r.logf("DoH resolved %s -> %s", host, ip)
		return ip, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no endpoint answered")
	}
	// 何度も同じ失敗を並べないよう、記録は一度だけにする。
	r.logf("DoH lookup failed (%s): %v; skipping for %s", host, lastErr, r.failTTL)
	return "", lastErr
}

func (r *Resolver) query(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH answered HTTP %d", resp.StatusCode)
	}
	var res struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	for _, ans := range res.Answer {
		if ans.Type == 1 && net.ParseIP(ans.Data) != nil {
			return ans.Data, nil
		}
	}
	return "", errors.New("no address in the answer")
}

// Cached は、いま持っている結果だけを返す。照会はしない。
func (r *Resolver) Cached(host string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ent, ok := r.cache[host]
	if !ok || !time.Now().Before(ent.exp) {
		return "", false
	}
	return ent.ip, true
}

// Forget は、覚えている結果を捨てる。
func (r *Resolver) Forget(host string) {
	r.mu.Lock()
	delete(r.cache, host)
	delete(r.failed, host)
	r.mu.Unlock()
}
