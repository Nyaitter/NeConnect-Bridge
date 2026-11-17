package rangetunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"neconnectbridge/internal/endpoint"
)

// maxPart は、一部分として取り出す量の上限。
const maxPart = 2 * 1024 * 1024

// 続きが無いときに次を聞くまでの間。空振りが続くほど間を広げる。
const (
	idleWaitMin = 4 * time.Millisecond
	idleWaitMax = 120 * time.Millisecond
)

type Conn struct {
	base   string
	sid    string
	client *http.Client

	pending     []byte
	readOffset  int64
	writeOffset int64
	idleWait    time.Duration
	rMu         sync.Mutex
	wMu         sync.Mutex

	done   chan struct{}
	closer sync.Once
	mu     sync.Mutex
	err    error
}

// Dial は、続きを取りに行く形で中継を開く。
func Dial(ctx context.Context, baseURL string, client *http.Client) (net.Conn, error) {
	if client == nil {
		return nil, errors.New("http client is required")
	}
	if baseURL == "" {
		return nil, errors.New("stream url is empty")
	}
	sid := endpoint.NewSessionID()
	if err := endpoint.Open(ctx, client, baseURL, "range", sid); err != nil {
		return nil, err
	}
	return &Conn{base: baseURL, sid: sid, client: client, done: make(chan struct{})}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	for len(c.pending) == 0 {
		select {
		case <-c.done:
			return 0, io.EOF
		default:
		}
		chunk, err := c.fetch()
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			if c.idleWait == 0 {
				c.idleWait = idleWaitMin
			} else if c.idleWait < idleWaitMax {
				c.idleWait *= 2
				if c.idleWait > idleWaitMax {
					c.idleWait = idleWaitMax
				}
			}
			time.Sleep(c.idleWait)
			continue
		}
		c.idleWait = 0
		c.pending = chunk
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// fetch は、続きを一部分として取りに行く。
func (c *Conn) fetch() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.partURL(c.readOffset), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", endpoint.UserAgent)
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", c.readOffset))
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusGone:
		return nil, io.EOF
	case http.StatusNoContent:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, nil
	case http.StatusPartialContent, http.StatusOK:
	default:
		return nil, fmt.Errorf("range read failed: %d", resp.StatusCode)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPart))
	if rerr != nil {
		return nil, rerr
	}
	c.readOffset += int64(len(body))
	return body, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	c.wMu.Lock()
	defer c.wMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.partURL(c.writeOffset), bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", endpoint.UserAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/*", c.writeOffset, c.writeOffset+int64(len(p))-1))
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("range write failed: %d", resp.StatusCode)
	}
	c.writeOffset += int64(len(p))
	return len(p), nil
}

// partURL は、位置を添えた受け口のURLを返す。
func (c *Conn) partURL(offset int64) string {
	sep := "?"
	if strings.Contains(c.base, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%ssid=%s&offset=%d", c.base, sep, url.QueryEscape(c.sid), offset)
}

func (c *Conn) Close() error {
	c.closeOnce()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, rerr := endpoint.Request(ctx, "POST", c.base, c.sid, "close", nil)
		if rerr != nil {
			return
		}
		if resp, err := c.client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	return nil
}

func (c *Conn) closeOnce() {
	c.mu.Lock()
	if c.err == nil {
		c.err = io.EOF
	}
	c.mu.Unlock()
	c.closer.Do(func() { close(c.done) })
}

func (c *Conn) LocalAddr() net.Addr                { return tunnelAddr("range") }
func (c *Conn) RemoteAddr() net.Addr               { return tunnelAddr(c.base) }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "https" }
func (a tunnelAddr) String() string  { return string(a) }
