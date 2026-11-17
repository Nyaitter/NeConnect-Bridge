package h2tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"neconnectbridge/internal/endpoint"
)

// maxBatch は、1回の送信にまとめる量の上限。
const maxBatch = 256 * 1024

// 小さい書き込みが続くときは、少しだけ待って同じ送信にまとめる。
const (
	coalesceWait = time.Millisecond
	coalesceMin  = 16 * 1024
)

// uploadWait は、1回の送信にかける待ち時間の上限。
const uploadWait = 30 * time.Second

type Conn struct {
	base   string
	sid    string
	client *http.Client

	down    chan []byte
	pending []byte
	writes  chan []byte
	done    chan struct{}

	mu     sync.Mutex
	err    error
	closer sync.Once
}

// Dial は、下りは一続きの受信、上りはその横に並べた送信で中継を開く。
// どちらも同じ HTTP/2 の接続の上に置く。
func Dial(ctx context.Context, baseURL string, client *http.Client) (net.Conn, error) {
	if client == nil {
		return nil, errors.New("http client is required")
	}
	if baseURL == "" {
		return nil, errors.New("stream url is empty")
	}
	sid := endpoint.NewSessionID()
	if err := endpoint.Open(ctx, client, baseURL, "h2", sid); err != nil {
		return nil, err
	}
	c := &Conn{
		base:   baseURL,
		sid:    sid,
		client: client,
		down:   make(chan []byte, 64),
		writes: make(chan []byte, 64),
		done:   make(chan struct{}),
	}
	if err := c.startDown(); err != nil {
		c.shutdown(nil)
		return nil, err
	}
	go c.upLoop()
	return c, nil
}

// startDown は、下りを一続きの受信として開く。
func (c *Conn) startDown() error {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.done
		cancel()
	}()
	req, err := endpoint.Request(ctx, "GET", c.base, c.sid, "down", nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := c.client.Do(req)
	if err != nil {
		cancel()
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return fmt.Errorf("%w (http %d)", endpoint.ErrUnavailable, resp.StatusCode)
	}
	go func() {
		defer cancel()
		defer close(c.down)
		defer resp.Body.Close()
		buf := make([]byte, 64*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case c.down <- chunk:
				case <-c.done:
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	return nil
}

// upLoop は、送る分をまとめてから順に届ける。
func (c *Conn) upLoop() {
	for {
		var batch []byte
		select {
		case <-c.done:
			return
		case first := <-c.writes:
			batch = first
		}
		// 続けて届いている分は、同じ送信にまとめる。
	collect:
		for len(batch) < maxBatch {
			select {
			case more := <-c.writes:
				batch = append(batch, more...)
			default:
				break collect
			}
		}
		// まだ小さいうちは、少しだけ続きを待つ。
		if len(batch) < coalesceMin {
			timer := time.NewTimer(coalesceWait)
		wait:
			for len(batch) < maxBatch {
				select {
				case more := <-c.writes:
					batch = append(batch, more...)
				case <-timer.C:
					break wait
				case <-c.done:
					timer.Stop()
					return
				}
			}
			timer.Stop()
		}
		if err := c.upload(batch); err != nil {
			// 送り始めを断られたときは、この形を受け付けない相手とみなす。
			c.shutdown(fmt.Errorf("%w (%v)", endpoint.ErrUnavailable, err))
			return
		}
	}
}

func (c *Conn) upload(body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), uploadWait)
	defer cancel()
	req, err := endpoint.Request(ctx, "POST", c.base, c.sid, "up", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		select {
		case chunk, ok := <-c.down:
			if !ok {
				if err := c.reason(); err != nil {
					return 0, err
				}
				return 0, io.EOF
			}
			c.pending = chunk
		case <-c.done:
			if err := c.reason(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.writes <- buf:
		return len(p), nil
	case <-c.done:
		if err := c.reason(); err != nil {
			return 0, err
		}
		return 0, io.ErrClosedPipe
	}
}

func (c *Conn) Close() error {
	c.shutdown(nil)
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

func (c *Conn) reason() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) shutdown(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.closer.Do(func() { close(c.done) })
}

func (c *Conn) LocalAddr() net.Addr                { return tunnelAddr("h2") }
func (c *Conn) RemoteAddr() net.Addr               { return tunnelAddr(c.base) }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "https" }
func (a tunnelAddr) String() string  { return string(a) }
