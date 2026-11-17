package endpoint

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnavailable は、そのブリッジがこの受け口を持っていないことを表す。
// 道筋を変えても答えは変わらないので、この先の試行を打ち切る目印になる。
var ErrUnavailable = errors.New("this bridge does not offer this stream")

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// NewSessionID は、この接続だけの目印を作る。
func NewSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Open は受け口を開き、このブリッジで使えるかを短く確かめる。
func Open(client *http.Client, base, transport, sid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := Request(ctx, "POST", base, sid, "open", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (http %d)", ErrUnavailable, resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return fmt.Errorf("%w (unexpected answer)", ErrUnavailable)
	}
	var out struct {
		OK        bool   `json:"ok"`
		Transport string `json:"transport"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("%w (unexpected answer)", ErrUnavailable)
	}
	if !out.OK || (out.Transport != "" && out.Transport != transport) {
		return fmt.Errorf("%w (unexpected answer)", ErrUnavailable)
	}
	return nil
}

// Request は、受け口へのやり取りを一つ組み立てる。
func Request(ctx context.Context, method, base, sid, op string, body io.Reader) (*http.Request, error) {
	query := "sid=" + url.QueryEscape(sid)
	if op != "" {
		query += "&op=" + url.QueryEscape(op)
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, method, base+sep+query, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	return req, nil
}
