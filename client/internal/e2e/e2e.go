package e2e

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const serverPubB64 = ""

func deriveAEADs(shared, clientPub []byte) (cipher.AEAD, cipher.AEAD, error) {
	k1 := sha256.Sum256(append(append([]byte("c2s:"), shared...), clientPub...))
	k2 := sha256.Sum256(append(append([]byte("s2c:"), shared...), clientPub...))
	a1, err := chacha20poly1305.New(k1[:])
	if err != nil {
		return nil, nil, err
	}
	a2, err := chacha20poly1305.New(k2[:])
	if err != nil {
		return nil, nil, err
	}
	return a2, a1, nil
}

func WrapClient(c net.Conn) (net.Conn, error) {
	curve := ecdh.X25519()
	sPubBytes, _ := base64.StdEncoding.DecodeString(serverPubB64)
	sPub, err := curve.NewPublicKey(sPubBytes)
	if err != nil {
		return nil, err
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cPub := cPriv.PublicKey().Bytes()
	shared, err := cPriv.ECDH(sPub)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(cPub); err != nil {
		return nil, err
	}
	rAEAD, wAEAD, err := deriveAEADs(shared, cPub)
	if err != nil {
		return nil, err
	}
	return &aeadConn{Conn: c, rAEAD: rAEAD, wAEAD: wAEAD}, nil
}

type aeadConn struct {
	net.Conn
	rMu    sync.Mutex
	wMu    sync.Mutex
	rAEAD  cipher.AEAD
	wAEAD  cipher.AEAD
	rSeq   uint64
	wSeq   uint64
	rPlain []byte
}

func makeNonce(seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

func (a *aeadConn) Read(p []byte) (int, error) {
	a.rMu.Lock()
	defer a.rMu.Unlock()
	for len(a.rPlain) == 0 {
		var lb [4]byte
		if _, err := io.ReadFull(a.Conn, lb[:]); err != nil {
			return 0, err
		}
		clen := int(binary.BigEndian.Uint32(lb[:]))
		if clen <= 0 || clen > 512*1024 {
			return 0, errors.New("invalid e2e frame length")
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(a.Conn, ct); err != nil {
			return 0, err
		}
		a.rSeq++
		plain, err := a.rAEAD.Open(nil, makeNonce(a.rSeq), ct, nil)
		if err != nil {
			return 0, errors.New("e2e authentication failed")
		}
		a.rPlain = plain
	}
	n := copy(p, a.rPlain)
	a.rPlain = a.rPlain[n:]
	return n, nil
}

func (a *aeadConn) Write(p []byte) (int, error) {
	a.wMu.Lock()
	defer a.wMu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 64*1024 {
			chunk = p[:64*1024]
		}
		a.wSeq++
		ct := a.wAEAD.Seal(nil, makeNonce(a.wSeq), chunk, nil)
		pkt := make([]byte, 4+len(ct))
		binary.BigEndian.PutUint32(pkt[:4], uint32(len(ct)))
		copy(pkt[4:], ct)
		if _, err := a.Conn.Write(pkt); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}
