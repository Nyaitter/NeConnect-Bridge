package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"neconnectbridge/internal/relaylog"
)

// 手元の入口。SOCKS5・SOCKS4・HTTP のどれで来ても同じ中継へ流す。
func serveLocalProxy(ln net.Listener, dialTarget func(string) (net.Conn, error), pool *sync.Pool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					logf("local connection stopped: %v", r)
				}
			}()
			handleLocalConn(c, dialTarget, pool)
		}(conn)
	}
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite は、送り終えたことを相手に伝える。
func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// handleLocalConn は先頭の1バイトで種類を見分ける。
func handleLocalConn(c net.Conn, dialTarget func(string) (net.Conn, error), pool *sync.Pool) {
	defer c.Close()
	// 何も送ってこない相手につながったままにしない。
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReaderSize(c, 32*1024)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	wrapped := &bufferedConn{Conn: c, r: br}
	switch first[0] {
	case 0x05:
		handleSOCKS5(wrapped, dialTarget, pool)
	case 0x04:
		handleSOCKS4(wrapped, dialTarget, pool)
	default:
		handleHTTPProxy(wrapped, br, dialTarget, pool)
	}
}

// relay は両方向を中継する。片方が終わっても、もう片方の続きを打ち切らない。
// 手元の側が自分から切っただけのときは記録に残さず、中継先の失敗だけを知らせる。
func relay(label string, browser, remote net.Conn, pool *sync.Pool) {
	relaylog.Relay(label, browser, remote, pool, logf)
}

func handleSOCKS5(c net.Conn, dialTarget func(string) (net.Conn, error), pool *sync.Pool) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		buf := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 広告の配信元なら、中継へ流さずここで断る。
	if shouldBlockHost(host) {
		noteAdBlockHit(host)
		_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	remote, err := dialTarget(target)
	if err != nil {
		logf("SOCKS5 dialTarget %s failed: %v", target, err)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay("SOCKS5 "+target, c, remote, pool)
}

// handleSOCKS4 は SOCKS4 と SOCKS4a を受ける。
// 古いソフトや、システム設定の socks を SOCKS4 として扱うアプリからの接続に備える。
func handleSOCKS4(c net.Conn, dialTarget func(string) (net.Conn, error), pool *sync.Pool) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x04 {
		return
	}
	if head[1] != 0x01 {
		_, _ = c.Write([]byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}
	port := binary.BigEndian.Uint16(head[2:4])
	ip := net.IP(head[4:8])
	if _, err := readUntilNUL(c); err != nil {
		return
	}
	host := ip.String()
	// 0.0.0.x は SOCKS4a の合図で、続けてホスト名が来る。
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		name, err := readUntilNUL(c)
		if err != nil {
			return
		}
		host = name
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if shouldBlockHost(host) {
		noteAdBlockHit(host)
		_, _ = c.Write([]byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}

	remote, err := dialTarget(target)
	if err != nil {
		logf("SOCKS4 dialTarget %s failed: %v", target, err)
		_, _ = c.Write([]byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	if _, err := c.Write([]byte{0x00, 0x5A, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay("SOCKS4 "+target, c, remote, pool)
}

func readUntilNUL(c io.Reader) (string, error) {
	var b strings.Builder
	one := make([]byte, 1)
	for i := 0; i < 1024; i++ {
		if _, err := io.ReadFull(c, one); err != nil {
			return "", err
		}
		if one[0] == 0 {
			return b.String(), nil
		}
		b.WriteByte(one[0])
	}
	return "", errors.New("user name too long")
}

// handleHTTPProxy は通常の HTTP プロキシとしても動く。
func handleHTTPProxy(c *bufferedConn, br *bufio.Reader, dialTarget func(string) (net.Conn, error), pool *sync.Pool) {
	requestLine, headerText, err := readHTTPHead(br)
	if err != nil {
		return
	}
	fields := strings.Fields(requestLine)
	if len(fields) < 3 {
		writeHTTPError(c, 400, "Bad Request")
		return
	}
	method, target := fields[0], fields[1]

	if strings.EqualFold(method, "CONNECT") {
		addr := target
		if _, _, serr := net.SplitHostPort(addr); serr != nil {
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
		}
		if shouldBlockHost(addr) {
			noteAdBlockHit(addr)
			writeHTTPError(c, 403, "Forbidden")
			return
		}
		remote, derr := dialTarget(addr)
		if derr != nil {
			logf("HTTP CONNECT %s failed: %v", addr, derr)
			writeHTTPError(c, 502, "Bad Gateway")
			return
		}
		defer remote.Close()
		_ = c.SetDeadline(time.Time{})
		if _, werr := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); werr != nil {
			return
		}
		relay("HTTP CONNECT "+addr, c, remote, pool)
		return
	}

	u, perr := url.Parse(target)
	if perr != nil {
		writeHTTPError(c, 400, "Bad Request")
		return
	}
	host := u.Host
	path := u.RequestURI()
	if !u.IsAbs() || host == "" {
		// 絶対URLでないときは Host から宛先を決める。
		host = headerValue(headerText, "Host")
		if host == "" {
			writeHTTPError(c, 400, "Bad Request")
			return
		}
		path = target
	}
	port := "80"
	if strings.EqualFold(u.Scheme, "https") {
		port = "443"
	}
	addr := host
	if _, _, serr := net.SplitHostPort(addr); serr != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), port)
	}

	if shouldBlockHost(host) {
		noteAdBlockHit(host)
		writeHTTPError(c, 403, "Forbidden")
		return
	}

	remote, derr := dialTarget(addr)
	if derr != nil {
		logf("HTTP %s %s failed: %v", method, addr, derr)
		writeHTTPError(c, 502, "Bad Gateway")
		return
	}
	defer remote.Close()

	version := fields[2]
	head := method + " " + path + " " + version + "\r\n" + headerText + "\r\n"
	_ = c.SetDeadline(time.Time{})
	if _, werr := remote.Write([]byte(head)); werr != nil {
		return
	}
	relay("HTTP "+addr, c, remote, pool)
}

func writeHTTPError(c net.Conn, code int, text string) {
	body := text + "\n"
	_, _ = c.Write([]byte(fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, text, len(body), body)))
}

func readHTTPHead(br *bufio.Reader) (string, string, error) {
	requestLine, err := readHTTPLine(br)
	if err != nil {
		return "", "", err
	}
	var b strings.Builder
	for {
		line, lerr := readHTTPLine(br)
		if lerr != nil {
			return "", "", lerr
		}
		if line == "" {
			break
		}
		b.WriteString(line)
		b.WriteString("\r\n")
		if b.Len() > 64*1024 {
			return "", "", errors.New("header too large")
		}
	}
	return requestLine, b.String(), nil
}

func readHTTPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 8*1024 {
		return "", errors.New("line too long")
	}
	line = strings.TrimRight(line, "\r\n")
	return line, nil
}

func headerValue(headers, name string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), name) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}
