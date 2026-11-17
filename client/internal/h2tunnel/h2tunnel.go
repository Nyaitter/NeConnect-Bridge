package h2tunnel

import (
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

// rotateAfter は、1本のアップロードを張り直す間隔。
// 受け口が待ち続けないよう、待ち時間の上限より短くしておく。
const rotateAfter = 60 * time.Second

var errUpDone = errors.New("upload stream closed")

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

// Dial は、HTTP/2 の流れを二本使う中継を開く。
// 上りは一続きの送信、下りは一続きの受信で、同じ接続の上に並べる。
func Dial(baseURL string, client *http.Client) (net.Conn, error) {
	if client == nil {
		return nil, errors.New("http client is required")
	}
	if baseURL == "" {
		return nil, errors.New("stream url is empty")
	}
	sid := endpoint.NewSessionID()
	if err := endpoint.Open(client, baseURL, "h2", sid); err != nil {
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

// upLoop は、途切れたら次のアップロードを張り直す。
func (c *Conn) upLoop() {
	for {
		select {
		case <-c.done:
			return
		default:
		}
		if err := c.upSession(); err != nil {
			if errors.Is(err, errUpDone) {
				return
			}
			c.shutdown(err)
			return
		}
	}
}

// upSession は、上りを一本張って、切り替えの時まで送る。
func (c *Conn) upSession() error {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := endpoint.Request(ctx, "POST", c.base, c.sid, "up", pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1

	finished := make(chan error, 1)
	go func() {
		resp, derr := c.client.Do(req)
		if derr != nil {
			finished <- derr
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		finished <- nil
	}()

	timer := time.NewTimer(rotateAfter)
	defer timer.Stop()
	for {
		select {
		case <-c.done:
			_ = pw.Close()
			<-finished
			return errUpDone
		case <-timer.C:
			_ = pw.Close()
			<-finished
			return nil
		case err := <-finished:
			_ = pw.Close()
			return err
		case chunk := <-c.writes:
			if _, werr := pw.Write(chunk); werr != nil {
				_ = pw.CloseWithError(werr)
				<-finished
				return werr
			}
		}
	}
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
