package obfs

import (
	"crypto/rand"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
)

func Wrap(c net.Conn, key [32]byte) (net.Conn, error) {
	var sendNonce [24]byte
	if _, err := rand.Read(sendNonce[:]); err != nil {
		return nil, err
	}
	var padLenByte [1]byte
	if _, err := rand.Read(padLenByte[:]); err != nil {
		return nil, err
	}
	padLen := int(padLenByte[0] & 0x3F)
	pad := make([]byte, padLen)
	if padLen > 0 {
		_, _ = rand.Read(pad)
	}

	wCipher, err := chacha20.NewUnauthenticatedCipher(key[:], sendNonce[:])
	if err != nil {
		return nil, err
	}
	var encPadLen [1]byte
	wCipher.XORKeyStream(encPadLen[:], []byte{byte(padLen)})

	hdr := make([]byte, 25+padLen)
	copy(hdr[:24], sendNonce[:])
	hdr[24] = encPadLen[0]
	copy(hdr[25:], pad)

	errCh := make(chan error, 1)
	go func() {
		_, werr := c.Write(hdr)
		errCh <- werr
	}()

	var recvHdr [25]byte
	if _, err := io.ReadFull(c, recvHdr[:]); err != nil {
		return nil, err
	}
	if werr := <-errCh; werr != nil {
		return nil, werr
	}

	rCipher, err := chacha20.NewUnauthenticatedCipher(key[:], recvHdr[:24])
	if err != nil {
		return nil, err
	}
	var decPadLen [1]byte
	rCipher.XORKeyStream(decPadLen[:], recvHdr[24:25])
	rPadLen := int(decPadLen[0] & 0x3F)
	if rPadLen > 0 {
		discard := make([]byte, rPadLen)
		if _, err := io.ReadFull(c, discard); err != nil {
			return nil, err
		}
	}

	return &obfsConn{
		Conn:    c,
		rCipher: rCipher,
		wCipher: wCipher,
	}, nil
}

type obfsConn struct {
	net.Conn
	rMu     sync.Mutex
	wMu     sync.Mutex
	rCipher *chacha20.Cipher
	wCipher *chacha20.Cipher
}

func (o *obfsConn) Read(p []byte) (int, error) {
	o.rMu.Lock()
	defer o.rMu.Unlock()
	n, err := o.Conn.Read(p)
	if n > 0 {
		o.rCipher.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (o *obfsConn) Write(p []byte) (int, error) {
	o.wMu.Lock()
	defer o.wMu.Unlock()
	buf := make([]byte, len(p))
	o.wCipher.XORKeyStream(buf, p)
	return o.Conn.Write(buf)
}
