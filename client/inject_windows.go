package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const (
	createSuspended         = 0x00000004
	createNewConsole        = 0x00000010
	createUnicodeEnv        = 0x00000400
	createNoWindow          = 0x08000000
	memCommit               = 0x00001000
	memReserve              = 0x00002000
	memRelease              = 0x00008000
	pageReadWrite           = 0x00000004
	waitTimeout             = 0x00000102
	processQueryInformation = 0x0400
	synchronizeAccess       = 0x00100000
)

var (
	procVirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx       = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess  = kernel32.NewProc("GetExitCodeProcess")
	procResumeThread        = kernel32.NewProc("ResumeThread")
	procOpenProcess         = kernel32.NewProc("OpenProcess")
	procCreateProcessW      = kernel32.NewProc("CreateProcessW")
	procLoadLibraryW        = kernel32.NewProc("LoadLibraryW")
)

type startupInfoW struct {
	cb            uint32
	lpReserved    *uint16
	lpDesktop     *uint16
	lpTitle       *uint16
	dwX           uint32
	dwY           uint32
	dwXSize       uint32
	dwYSize       uint32
	dwXCountChars uint32
	dwYCountChars uint32
	dwFillAttr    uint32
	dwFlags       uint32
	wShowWindow   uint16
	cbReserved2   uint16
	lpReserved2   *byte
	hStdInput     syscall.Handle
	hStdOutput    syscall.Handle
	hStdError     syscall.Handle
}

type processInfoW struct {
	hProcess    syscall.Handle
	hThread     syscall.Handle
	dwProcessID uint32
	dwThreadID  uint32
}

type launchedProcess struct {
	pid     uint32
	hProcess syscall.Handle
	hThread  syscall.Handle
}

// buildEnvBlock は現在の環境変数と追加分をまとめた UTF-16 の環境ブロックを作る。
func buildEnvBlock(extra []string) []uint16 {
	values := map[string]string{}
	keys := []string{}
	set := func(kv string) {
		if kv == "" {
			return
		}
		if i := strings.Index(kv, "="); i > 0 {
			k := kv[:i]
			up := strings.ToUpper(k)
			if _, ok := values[up]; !ok {
				keys = append(keys, up)
			}
			values[up] = kv
		}
	}
	for _, kv := range os.Environ() {
		set(kv)
	}
	for _, kv := range extra {
		set(kv)
	}
	sort.Strings(keys)

	var out []uint16
	for _, k := range keys {
		u, err := syscall.UTF16FromString(values[k])
		if err != nil {
			continue
		}
		out = append(out, u...)
	}
	out = append(out, 0)
	return out
}

func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

func injectDLL(hProcess syscall.Handle, dllPath string) error {
	pathUTF16, err := syscall.UTF16FromString(dllPath)
	if err != nil {
		return err
	}
	size := uintptr(len(pathUTF16) * 2)
	addr, _, _ := procVirtualAllocEx.Call(uintptr(hProcess), 0, size, memCommit|memReserve, pageReadWrite)
	if addr == 0 {
		return fmt.Errorf("メモリの確保に失敗しました")
	}
	defer procVirtualFreeEx.Call(uintptr(hProcess), addr, 0, memRelease)

	var written uintptr
	r, _, _ := procWriteProcessMemory.Call(uintptr(hProcess), addr, uintptr(unsafe.Pointer(&pathUTF16[0])), size, uintptr(unsafe.Pointer(&written)))
	if r == 0 {
		return fmt.Errorf("書き込みに失敗しました")
	}
	th, _, _ := procCreateRemoteThread.Call(uintptr(hProcess), 0, 0, procLoadLibraryW.Addr(), addr, 0, 0)
	if th == 0 {
		return fmt.Errorf("開始に失敗しました")
	}
	procWaitForSingleObject.Call(th, 15000)
	procCloseHandle.Call(th)
	return nil
}

// startProcess は指定の実行ファイルを起動し、必要なら補助モジュールを読み込ませる。
func startProcess(exe string, args []string, workDir string, extraEnv []string, hookDLL string, newConsole bool) (*launchedProcess, error) {
	if _, err := os.Stat(exe); err != nil {
		return nil, fmt.Errorf("アプリが見つかりません: %s", exe)
	}

	cmdline := quoteArg(exe)
	for _, a := range args {
		cmdline += " " + quoteArg(a)
	}
	cmdUTF16, err := syscall.UTF16FromString(cmdline)
	if err != nil {
		return nil, err
	}
	exeUTF16, err := syscall.UTF16FromString(exe)
	if err != nil {
		return nil, err
	}
	var dirUTF16 *uint16
	if workDir != "" {
		dirUTF16, _ = syscall.UTF16PtrFromString(workDir)
	}

	env := buildEnvBlock(extraEnv)

	flags := uint32(createUnicodeEnv)
	if newConsole {
		flags |= createNewConsole
	} else {
		flags |= createNoWindow
	}
	if hookDLL != "" {
		flags |= createSuspended
	}

	var si startupInfoW
	si.cb = uint32(unsafe.Sizeof(si))
	var pi processInfoW

	r, _, errno := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(&exeUTF16[0])),
		uintptr(unsafe.Pointer(&cmdUTF16[0])),
		0, 0, 0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&env[0])),
		uintptr(unsafe.Pointer(dirUTF16)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return nil, fmt.Errorf("起動できませんでした: %v", errno)
	}

	if hookDLL != "" {
		if ierr := injectDLL(pi.hProcess, hookDLL); ierr != nil {
			logf("hook load failed (%s): %v", hookDLL, ierr)
		}
		procResumeThread.Call(uintptr(pi.hThread))
	}
	return &launchedProcess{pid: pi.dwProcessID, hProcess: pi.hProcess, hThread: pi.hThread}, nil
}

// wait はプロセスの終了まで待つ。
func (p *launchedProcess) wait() {
	if p == nil {
		return
	}
	if p.hProcess != 0 {
		procWaitForSingleObject.Call(uintptr(p.hProcess), 0xFFFFFFFF)
		var code uint32
		procGetExitCodeProcess.Call(uintptr(p.hProcess), uintptr(unsafe.Pointer(&code)))
		procCloseHandle.Call(uintptr(p.hProcess))
		p.hProcess = 0
	}
	if p.hThread != 0 {
		procCloseHandle.Call(uintptr(p.hThread))
		p.hThread = 0
	}
}

func isPIDAlive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	h, _, _ := procOpenProcess.Call(synchronizeAccess, 0, uintptr(pid))
	if h == 0 {
		return false
	}
	defer procCloseHandle.Call(h)
	r, _, _ := procWaitForSingleObject.Call(h, 0)
	return uint32(r) == waitTimeout
}
