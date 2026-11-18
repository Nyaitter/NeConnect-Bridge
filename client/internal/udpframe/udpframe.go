// Package udpframe は、中継の上で UDP のまとまりを運ぶ形を扱う。
//
// 一つのまとまりの中で宛先は固定しない。まとまりごとに相手を添えて送るので、
// 一つの入口から複数の相手へ投げる通信も、そのまま通る。
package udpframe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	typeIPv4   byte = 0x01
	typeDomain byte = 0x03
	typeIPv6   byte = 0x04

	// MaxPayload は一度に運ぶ量の上限。
	MaxPayload = 65000

	// Request は、UDP のまとまりを開く合図。
	// 通常の宛先の長さは 1024 までなので、その値とは重ならない。
	Request uint16 = 0x8000
)

// Addr は、まとまりの行き先。
type Addr struct {
	Host string
	Port uint16
}

func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// ParseAddr は「host:port」の形を読む。
func ParseAddr(value string) (Addr, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return Addr{}, err
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return Addr{}, errors.New("invalid port")
	}
	return Addr{Host: host, Port: uint16(number)}, nil
}

// MarshalAddr は、行き先を送れる形にする。
func MarshalAddr(a Addr) ([]byte, error) {
	if a.Host == "" {
		return nil, errors.New("empty destination")
	}
	if ip := net.ParseIP(a.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = typeIPv4
			copy(out[1:5], v4)
			binary.BigEndian.PutUint16(out[5:7], a.Port)
			return out, nil
		}
		if v6 := ip.To16(); v6 != nil {
			out := make([]byte, 1+16+2)
			out[0] = typeIPv6
			copy(out[1:17], v6)
			binary.BigEndian.PutUint16(out[17:19], a.Port)
			return out, nil
		}
	}
	name := []byte(a.Host)
	if len(name) == 0 || len(name) > 255 {
		return nil, errors.New("invalid destination")
	}
	out := make([]byte, 1+1+len(name)+2)
	out[0] = typeDomain
	out[1] = byte(len(name))
	copy(out[2:], name)
	binary.BigEndian.PutUint16(out[2+len(name):], a.Port)
	return out, nil
}

// UnmarshalAddr は、届いた行き先を読む。読んだ長さも返す。
func UnmarshalAddr(buf []byte) (Addr, int, error) {
	if len(buf) < 1 {
		return Addr{}, 0, io.ErrUnexpectedEOF
	}
	p := 1
	var host string
	switch buf[0] {
	case typeIPv4:
		if len(buf) < p+4 {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(buf[p : p+4]).String()
		p += 4
	case typeIPv6:
		if len(buf) < p+16 {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(buf[p : p+16]).String()
		p += 16
	case typeDomain:
		if len(buf) < p+1 {
			return Addr{}, 0, io.ErrUnexpectedEOF
		}
		length := int(buf[p])
		p++
		if length == 0 || len(buf) < p+length {
			return Addr{}, 0, errors.New("invalid destination name")
		}
		host = string(buf[p : p+length])
		p += length
	default:
		return Addr{}, 0, errors.New("unknown destination type")
	}
	if len(buf) < p+2 {
		return Addr{}, 0, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(buf[p : p+2])
	p += 2
	return Addr{Host: host, Port: port}, p, nil
}

// WriteFrame は、行き先と中身を一つにまとめて送る。
func WriteFrame(w io.Writer, a Addr, payload []byte) error {
	if len(payload) > MaxPayload {
		payload = payload[:MaxPayload]
	}
	addr, err := MarshalAddr(a)
	if err != nil {
		return err
	}
	total := len(addr) + len(payload)
	if total > 65535 {
		return errors.New("frame too large")
	}
	frame := make([]byte, 2, 2+total)
	binary.BigEndian.PutUint16(frame, uint16(total))
	frame = append(frame, addr...)
	frame = append(frame, payload...)
	_, err = w.Write(frame)
	return err
}

// ReadFrame は、次に届いたまとまりを読む。
// 途中で切れていても、続きが届くまで待ってつなぐ。
func ReadFrame(r *bufio.Reader) (Addr, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Addr{}, nil, err
	}
	total := int(binary.BigEndian.Uint16(head[:]))
	if total < 3 || total > 65535 {
		return Addr{}, nil, errors.New("invalid frame length")
	}
	body := make([]byte, total)
	if _, err := io.ReadFull(r, body); err != nil {
		return Addr{}, nil, err
	}
	addr, size, err := UnmarshalAddr(body)
	if err != nil {
		return Addr{}, nil, err
	}
	payload := make([]byte, len(body)-size)
	copy(payload, body[size:])
	return addr, payload, nil
}

// UnmarshalSocksUDP は、SOCKS5 の入口に届いた一つ分を読む。
// 分かれたまとまりは扱わない。
func UnmarshalSocksUDP(buf []byte) (Addr, []byte, error) {
	if len(buf) < 4 {
		return Addr{}, nil, io.ErrUnexpectedEOF
	}
	if buf[2] != 0 {
		return Addr{}, nil, errors.New("fragmented datagram is not supported")
	}
	addr, size, err := UnmarshalAddr(buf[3:])
	if err != nil {
		return Addr{}, nil, err
	}
	payload := make([]byte, len(buf)-3-size)
	copy(payload, buf[3+size:])
	return addr, payload, nil
}

// MarshalSocksUDP は、SOCKS5 の入口へ返す一つ分を組み立てる。
func MarshalSocksUDP(a Addr, payload []byte) ([]byte, error) {
	addr, err := MarshalAddr(a)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 3, 3+len(addr)+len(payload))
	out[0], out[1], out[2] = 0, 0, 0
	out = append(out, addr...)
	out = append(out, payload...)
	return out, nil
}
