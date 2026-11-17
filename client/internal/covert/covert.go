package covert

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// FragConn は、最初の書き込みを細かく分けて送る接続。
// 一続きの ClientHello として読まれないよう、TLS の記録ごとに二つへ割る。
type FragConn struct {
	net.Conn
	once sync.Once
}

func NewFragConn(c net.Conn) *FragConn {
	return &FragConn{Conn: c}
}

func (c *FragConn) Write(p []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first {
		return c.Conn.Write(p)
	}
	total := 0
	for _, part := range splitRecords(p) {
		n, err := c.Conn.Write(part)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// splitRecords は、TLS の記録を境目で二つに割る。
// 記録として読めないデータは、同じくらいの三つに分ける。
func splitRecords(p []byte) [][]byte {
	var out [][]byte
	rest := p
	for len(rest) > 0 {
		if len(rest) < 5 {
			out = append(out, rest)
			break
		}
		length := int(rest[3])<<8 | int(rest[4])
		readable := rest[0] >= 20 && rest[0] <= 24 && rest[1] == 0x03 && length > 0 && length+5 <= len(rest)
		if !readable {
			out = append(out, splitEven(rest)...)
			break
		}
		rec := rest[:5+length]
		cut := 5 + randomOffset(length-1)
		out = append(out, rec[:cut], rec[cut:])
		rest = rest[5+length:]
	}
	if len(out) == 0 {
		out = append(out, p)
	}
	return out
}

// randomOffset は、1 以上 span 以下の位置を返す。
func randomOffset(span int) int {
	if span <= 1 {
		return span
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return span / 2
	}
	return 1 + int(b[0])%span
}

// splitEven は、データを同じくらいの三つに分ける。
func splitEven(p []byte) [][]byte {
	if len(p) < 3 {
		return [][]byte{p}
	}
	third := len(p) / 3
	return [][]byte{p[:third], p[third : 2*third], p[2*third:]}
}

// DialFakeTLS は接続の先頭に TLS のやり取りを装ったやり取りを挟む。
func DialFakeTLS(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if err := fakeHandshake(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func fakeHandshake(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	defer conn.SetDeadline(time.Time{})

	body := make([]byte, 240)
	if _, err := rand.Read(body); err != nil {
		return err
	}
	body[0] = 0x03
	body[1] = 0x03
	header := []byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}
	if _, err := conn.Write(append(header, body...)); err != nil {
		return err
	}

	var reply [5]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x16 {
		return errors.New("unexpected reply")
	}
	length := int(reply[3])<<8 | int(reply[4])
	if length <= 0 || length > 8192 {
		return errors.New("invalid reply length")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(length)); err != nil {
		return err
	}
	return nil
}

func newSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sseConn はイベント配信の受信とフォーム送信の組み合わせで通信する。
type sseConn struct {
	streamURL string
	uploadURL string
	client    *http.Client
	chunks    chan []byte
	pending   []byte
	closeOnce sync.Once
	cancel    chan struct{}
	writeMu   sync.Mutex
}

func DialSSE(origin string, client *http.Client) (net.Conn, error) {
	sid := newSessionID()
	conn := &sseConn{
		streamURL: origin + "/bridge/stream?sid=" + sid,
		uploadURL: origin + "/bridge/upload?sid=" + sid,
		client:    client,
		chunks:    make(chan []byte, 64),
		cancel:    make(chan struct{}),
	}
	req, err := http.NewRequest("GET", conn.streamURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("stream unavailable: %d", resp.StatusCode)
	}
	go conn.readLoop(resp)
	return conn, nil
}

func (c *sseConn) readLoop(resp *http.Response) {
	defer close(c.chunks)
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[6:]))
		if err != nil || len(raw) == 0 {
			continue
		}
		select {
		case c.chunks <- raw:
		case <-c.cancel:
			return
		}
	}
}

func (c *sseConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		chunk, ok := <-c.chunks
		if !ok {
			return 0, io.EOF
		}
		c.pending = chunk
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *sseConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "blob.bin")
	if err != nil {
		return 0, err
	}
	if _, err := part.Write(p); err != nil {
		return 0, err
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", c.uploadURL, &body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("upload failed: %d", resp.StatusCode)
	}
	return len(p), nil
}

func (c *sseConn) Close() error {
	c.closeOnce.Do(func() { close(c.cancel) })
	return nil
}

func (c *sseConn) LocalAddr() net.Addr                { return tunnelAddr("sse") }
func (c *sseConn) RemoteAddr() net.Addr               { return tunnelAddr(c.streamURL) }
func (c *sseConn) SetDeadline(t time.Time) error      { return nil }
func (c *sseConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sseConn) SetWriteDeadline(t time.Time) error { return nil }

// assetConn は画像取得とクッキー送信の組み合わせで通信する。
type assetConn struct {
	assetURL  string
	client    *http.Client
	mu        sync.Mutex
	pending   []byte
	closeOnce sync.Once
	closed    bool
	writeMu   sync.Mutex
}

const assetChunk = 1200

func DialAsset(origin string, client *http.Client) (net.Conn, error) {
	conn := &assetConn{
		assetURL: origin + "/bridge/assets/logo.png?sid=" + newSessionID(),
		client:   client,
	}
	data, err := conn.fetch(nil)
	if err != nil {
		return nil, err
	}
	conn.pending = data
	return conn, nil
}

func (c *assetConn) fetch(payload []byte) ([]byte, error) {
	req, err := http.NewRequest("GET", c.assetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if len(payload) > 0 {
		req.Header.Set("Cookie", "nctb="+base64.RawURLEncoding.EncodeToString(payload))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asset unavailable: %d", resp.StatusCode)
	}
	if len(body) < 8+25+12 {
		return nil, errors.New("short response")
	}
	return body[8+25 : len(body)-12], nil
}

func (c *assetConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		data, err := c.fetch(nil)
		if err != nil {
			return 0, err
		}
		if len(data) == 0 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		c.mu.Lock()
		c.pending = append(c.pending, data...)
		c.mu.Unlock()
	}
}

func (c *assetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	rest := p
	for len(rest) > 0 {
		size := assetChunk
		if len(rest) < size {
			size = len(rest)
		}
		data, err := c.fetch(rest[:size])
		if err != nil {
			return total, err
		}
		if len(data) > 0 {
			c.mu.Lock()
			c.pending = append(c.pending, data...)
			c.mu.Unlock()
		}
		total += size
		rest = rest[size:]
	}
	return total, nil
}

func (c *assetConn) Close() error {
	c.closeOnce.Do(func() { c.closed = true })
	return nil
}

func (c *assetConn) LocalAddr() net.Addr                { return tunnelAddr("asset") }
func (c *assetConn) RemoteAddr() net.Addr               { return tunnelAddr(c.assetURL) }
func (c *assetConn) SetDeadline(t time.Time) error      { return nil }
func (c *assetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *assetConn) SetWriteDeadline(t time.Time) error { return nil }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "https" }
func (a tunnelAddr) String() string  { return string(a) }

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// AltPortURL は同じホストの別ポートを指す URL を返す。
func AltPortURL(raw string, port string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("host is empty")
	}
	u.Host = net.JoinHostPort(host, port)
	return u.String(), nil
}
