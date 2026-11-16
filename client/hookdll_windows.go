package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed nctb_hook64.dll
var embeddedHookDLL []byte

// ensureHookDLL は同梱の補助モジュールを runtime フォルダへ書き出す。
func ensureHookDLL(dir string) (string, error) {
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return "", err
	}
	p := filepath.Join(runtimeDir, "nctb_hook64.dll")
	if st, err := os.Stat(p); err == nil && st.Size() == int64(len(embeddedHookDLL)) {
		return p, nil
	}
	if err := os.WriteFile(p, embeddedHookDLL, 0644); err != nil {
		return "", err
	}
	logf("hook module written: %s (%d bytes)", p, len(embeddedHookDLL))
	return p, nil
}
