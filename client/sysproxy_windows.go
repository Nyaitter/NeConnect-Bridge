package main

import (
	"net/url"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	wininet                   = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW    = wininet.NewProc("InternetSetOptionW")
	procCreateToolhelp32Snap  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW       = kernel32.NewProc("Process32FirstW")
	procProcess32NextW        = kernel32.NewProc("Process32NextW")
	procCloseHandle           = kernel32.NewProc("CloseHandle")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	th32csSnapProcess             = 0x00000002
	regInternetSettings           = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

type processEntry32W struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func countProcesses(exePath string) int {
	target := strings.ToLower(filepath.Base(exePath))
	if target == "" {
		return 0
	}
	snap, _, _ := procCreateToolhelp32Snap.Call(th32csSnapProcess, 0)
	if snap == uintptr(syscall.InvalidHandle) || snap == 0 {
		return 0
	}
	defer procCloseHandle.Call(snap)

	count := 0
	var pe processEntry32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))
	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		name := strings.ToLower(syscall.UTF16ToString(pe.szExeFile[:]))
		if name == target {
			count++
		}
		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	}
	return count
}

type sysProxyBackup struct {
	hadEnable bool
	enableVal uint64
	hadServer bool
	serverVal string
	active    bool
}

func getSystemHTTPProxy() *url.URL {
	k, err := registry.OpenKey(registry.CURRENT_USER, regInternetSettings, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	en, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || en == 0 {
		return nil
	}
	srv, _, err := k.GetStringValue("ProxyServer")
	if err != nil || strings.TrimSpace(srv) == "" {
		return nil
	}
	if strings.Contains(srv, "127.0.0.1:") {
		return nil
	}
	// Parse "http=host:port;https=host:port" or "host:port"
	cand := srv
	if strings.Contains(srv, "=") {
		for _, part := range strings.Split(srv, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && (strings.EqualFold(kv[0], "https") || strings.EqualFold(kv[0], "http")) {
				cand = kv[1]
				break
			}
		}
	}
	if !strings.Contains(cand, "://") {
		cand = "http://" + cand
	}
	u, err := url.Parse(cand)
	if err != nil {
		return nil
	}
	return u
}

func refreshWinINET() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}

func setSystemSOCKSProxy(addr string) (*sysProxyBackup, error) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, regInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	bk := &sysProxyBackup{active: true}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		bk.hadEnable = true
		bk.enableVal = v
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		bk.hadServer = true
		bk.serverVal = v
	}

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return nil, err
	}
	if err := k.SetStringValue("ProxyServer", "socks="+addr); err != nil {
		return nil, err
	}
	refreshWinINET()
	logf("System SOCKS proxy enabled: socks=%s", addr)
	return bk, nil
}

func (bk *sysProxyBackup) restore() {
	if bk == nil || !bk.active {
		return
	}
	bk.active = false
	k, err := registry.OpenKey(registry.CURRENT_USER, regInternetSettings, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if bk.hadEnable {
		_ = k.SetDWordValue("ProxyEnable", uint32(bk.enableVal))
	} else {
		_ = k.DeleteValue("ProxyEnable")
	}
	if bk.hadServer {
		_ = k.SetStringValue("ProxyServer", bk.serverVal)
	} else {
		_ = k.DeleteValue("ProxyServer")
	}
	refreshWinINET()
	logf("System proxy restored")
}
