package httptunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

type ClientConn struct {
	baseURL string
	sid     string
	client  *http.Client
	rBuf    bytes.Buffer
	rMu     sync.Mutex
	wMu     sync.Mutex
	closed  bool
	closeMu sync.Mutex
}

func Dial(baseURL string, client *http.Client) (*ClientConn, error) {
	var b [12]byte
	_, _ = rand.Read(b[:])
	sid := hex.EncodeToString(b[:])

	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	req, err := http.NewRequest("POST", baseURL+"?sid="+sid+"&op=open", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("http tunnel open failed: " + resp.Status)
	}

	return &ClientConn{
		baseURL: baseURL,
		sid:     sid,
		client:  client,
	}, nil
}

func (c *ClientConn) isClosed() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closed
}

func (c *ClientConn) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()

	for c.rBuf.Len() == 0 {
		if c.isClosed() {
			return 0, io.EOF
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"?sid="+c.sid, nil)
		if err != nil {
			cancel()
			return 0, err
		}
		req.Header.Set("User-Agent", ua)
		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			if c.isClosed() {
				return 0, io.EOF
			}
			return 0, err
		}
		data, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusGone {
			return 0, io.EOF
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			return 0, errors.New("http tunnel read failed: " + resp.Status)
		}
		if rerr != nil {
			return 0, rerr
		}
		if len(data) > 0 {
			c.rBuf.Write(data)
		}
	}
	return c.rBuf.Read(p)
}

func (c *ClientConn) Write(p []byte) (int, error) {
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}
	c.wMu.Lock()
	defer c.wMu.Unlock()

	req, err := http.NewRequest("POST", c.baseURL+"?sid="+c.sid, bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("http tunnel write failed: " + resp.Status)
	}
	return len(p), nil
}

func (c *ClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()

	go func() {
		req, err := http.NewRequest("POST", c.baseURL+"?sid="+c.sid+"&op=close", nil)
		if err == nil {
			req.Header.Set("User-Agent", ua)
			if resp, err := c.client.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}()
	return nil
}

func (c *ClientConn) LocalAddr() net.Addr                { return dummyAddr("http-tunnel") }
func (c *ClientConn) RemoteAddr() net.Addr               { return dummyAddr(c.baseURL) }
func (c *ClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ClientConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "http" }
func (d dummyAddr) String() string  { return string(d) }
