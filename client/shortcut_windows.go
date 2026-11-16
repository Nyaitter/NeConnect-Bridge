package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ole32   = syscall.NewLazyDLL("ole32.dll")
	shell32 = syscall.NewLazyDLL("shell32.dll")
	comdlg  = syscall.NewLazyDLL("comdlg32.dll")

	procCoInitializeEx       = ole32.NewProc("CoInitializeEx")
	procCoUninitialize       = ole32.NewProc("CoUninitialize")
	procCoCreateInstance     = ole32.NewProc("CoCreateInstance")
	procSHGetFolderPathW     = shell32.NewProc("SHGetFolderPathW")
	procDragAcceptFiles      = shell32.NewProc("DragAcceptFiles")
	procDragQueryFileW       = shell32.NewProc("DragQueryFileW")
	procDragFinish           = shell32.NewProc("DragFinish")
	procGetSaveFileNameW     = comdlg.NewProc("GetSaveFileNameW")
	procGetOpenFileNameW     = comdlg.NewProc("GetOpenFileNameW")
	procSHGetFileInfoW       = shell32.NewProc("SHGetFileInfoW")
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	clsidShellLink = guid{0x00021401, 0, 0, [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidShellLinkW  = guid{0x000214F9, 0, 0, [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidPersistFile = guid{0x0000010B, 0, 0, [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
)

const (
	clsctxInprocServer = 0x1
	coinitApartment    = 0x2
	csidlDesktopDir    = 0x0010
	stgmRead           = 0x00000000
	stgmReadWrite      = 0x00000002
	maxPath            = 260

	ofnOverwritePrompt = 0x00000002
	ofnNoChangeDir     = 0x00000008
	ofnPathMustExist   = 0x00000800
	ofnExplorer        = 0x00080000
	ofnFileMustExist   = 0x00001000

	swHide = 0
)

// comCall は COM インターフェースの仮想関数を呼ぶ。
func comCall(this uintptr, index int, args ...uintptr) uintptr {
	if this == 0 {
		return 0x80004003 // E_POINTER
	}
	vtbl := *(*uintptr)(unsafe.Pointer(this))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, 12)
	all = append(all, this)
	all = append(all, args...)
	var r uintptr
	switch len(all) {
	case 1:
		r, _, _ = syscall.Syscall(fn, 1, all[0], 0, 0)
	case 2:
		r, _, _ = syscall.Syscall(fn, 2, all[0], all[1], 0)
	case 3:
		r, _, _ = syscall.Syscall(fn, 3, all[0], all[1], all[2])
	case 4:
		r, _, _ = syscall.Syscall6(fn, 4, all[0], all[1], all[2], all[3], 0, 0)
	case 5:
		r, _, _ = syscall.Syscall6(fn, 5, all[0], all[1], all[2], all[3], all[4], 0)
	case 6:
		r, _, _ = syscall.Syscall6(fn, 6, all[0], all[1], all[2], all[3], all[4], all[5])
	default:
		if len(all) == 7 {
			r, _, _ = syscall.Syscall6(fn, 6, all[0], all[1], all[2], all[3], all[4], all[5])
		}
	}
	return r
}

func hresultErr(what string, hr uintptr) error {
	if int32(hr) >= 0 {
		return nil
	}
	return fmt.Errorf("%s に失敗しました (0x%08X)", what, uint32(hr))
}

// withCOM は COM を初期化したスレッドで fn を実行する。
func withCOM(fn func() error) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		procCoInitializeEx.Call(0, coinitApartment)
		defer procCoUninitialize.Call()
		var res result
		func() {
			defer func() {
				if r := recover(); r != nil {
					res.err = fmt.Errorf("%v", r)
				}
			}()
			res.err = fn()
		}()
		ch <- res
	}()
	return (<-ch).err
}

func comString(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// createShortcut はショートカットファイルを作る。
func createShortcut(lnkPath, target, args, workDir, desc, iconExe string) error {
	ext := strings.ToLower(filepath.Ext(lnkPath))
	if ext != ".lnk" {
		lnkPath += ".lnk"
	}
	if err := os.MkdirAll(filepath.Dir(lnkPath), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Dir(lnkPath)); err != nil {
		return fmt.Errorf("保存先が見つかりません")
	}

	return withCOM(func() error {
		var link uintptr
		hr, _, _ := procCoCreateInstance.Call(
			uintptr(unsafe.Pointer(&clsidShellLink)),
			0,
			clsctxInprocServer,
			uintptr(unsafe.Pointer(&iidShellLinkW)),
			uintptr(unsafe.Pointer(&link)),
		)
		if err := hresultErr("ショートカットの準備", hr); err != nil {
			return err
		}
		if link == 0 {
			return fmt.Errorf("ショートカットの準備に失敗しました")
		}
		defer comCall(link, 2) // Release

		tp := comString(target)
		comCall(link, 20, uintptr(unsafe.Pointer(tp))) // SetPath
		runtime.KeepAlive(tp)

		if args != "" {
			ap := comString(args)
			comCall(link, 11, uintptr(unsafe.Pointer(ap))) // SetArguments
			runtime.KeepAlive(ap)
		}
		if workDir != "" {
			wp := comString(workDir)
			comCall(link, 9, uintptr(unsafe.Pointer(wp))) // SetWorkingDirectory
			runtime.KeepAlive(wp)
		}
		if desc != "" {
			dp := comString(desc)
			comCall(link, 7, uintptr(unsafe.Pointer(dp))) // SetDescription
			runtime.KeepAlive(dp)
		}
		icon := iconExe
		if icon == "" {
			icon = target
		}
		ip := comString(icon)
		comCall(link, 17, uintptr(unsafe.Pointer(ip)), 0) // SetIconLocation
		runtime.KeepAlive(ip)

		comCall(link, 15, 1) // SetShowCmd(SW_SHOWNORMAL)

		var pf uintptr
		comCall(link, 0, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&pf)))
		if pf == 0 {
			return fmt.Errorf("ショートカットの保存に失敗しました")
		}
		defer comCall(pf, 2)

		lp := comString(lnkPath)
		defer runtime.KeepAlive(lp)
		hres := comCall(pf, 6, uintptr(unsafe.Pointer(lp)), 1)
		if err := hresultErr("ショートカットの保存", hres); err != nil {
			return err
		}
		logf("Shortcut created: %s -> %s (args=%q)", lnkPath, target, args)
		return nil
	})
}

// shortcutTarget はショートカットのリンク先と引数を返す。
func shortcutTarget(lnkPath string) (target, args string, err error) {
	err = withCOM(func() error {
		var link uintptr
		hr, _, _ := procCoCreateInstance.Call(
			uintptr(unsafe.Pointer(&clsidShellLink)),
			0,
			clsctxInprocServer,
			uintptr(unsafe.Pointer(&iidShellLinkW)),
			uintptr(unsafe.Pointer(&link)),
		)
		if e := hresultErr("ショートカットの読み込み", hr); e != nil {
			return e
		}
		if link == 0 {
			return fmt.Errorf("ショートカットの読み込みに失敗しました")
		}
		defer comCall(link, 2)

		var pf uintptr
		comCall(link, 0, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&pf)))
		if pf == 0 {
			return fmt.Errorf("ショートカットの読み込みに失敗しました")
		}
		defer comCall(pf, 2)

		lp := comString(lnkPath)
		defer runtime.KeepAlive(lp)
		hres := comCall(pf, 5, uintptr(unsafe.Pointer(lp)), stgmRead)
		if e := hresultErr("ショートカットの読み込み", hres); e != nil {
			return e
		}

		buf := make([]uint16, maxPath)
		comCall(link, 3, uintptr(unsafe.Pointer(&buf[0])), maxPath, 0, 4) // GetPath(SLGP_RAWPATH)
		target = syscall.UTF16ToString(buf)

		abuf := make([]uint16, 1024)
		comCall(link, 10, uintptr(unsafe.Pointer(&abuf[0])), 1024) // GetArguments
		args = syscall.UTF16ToString(abuf)
		return nil
	})
	return target, args, err
}

// desktopPath はデスクトップのフォルダを返す。
func desktopPath() string {
	buf := make([]uint16, maxPath)
	hr, _, _ := procSHGetFolderPathW.Call(0, csidlDesktopDir, 0, 0, uintptr(unsafe.Pointer(&buf[0])))
	if int32(hr) >= 0 {
		p := syscall.UTF16ToString(buf)
		if p != "" {
			return p
		}
	}
	if up := os.Getenv("USERPROFILE"); up != "" {
		cand := filepath.Join(up, "Desktop")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	Flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        unsafe.Pointer
	dwReserved        uint32
	FlagsEx           uint32
}

// pickShortcutPath は保存先を選ぶダイアログを開き、選ばれたパスを返す。
func pickShortcutPath(owner uintptr, defaultName string) (string, bool) {
	buf := make([]uint16, 1024)
	def, _ := syscall.UTF16FromString(defaultName)
	copy(buf, def)
	filter := syscall.StringToUTF16Ptr("ショートカット (*.lnk)\x00*.lnk\x00すべてのファイル (*.*)\x00*.*\x00\x00")
	title := syscall.StringToUTF16Ptr("ショートカットの保存先")
	initial := syscall.StringToUTF16Ptr(desktopPath())
	defExt := syscall.StringToUTF16Ptr("lnk")

	var ofn openFileNameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.hwndOwner = owner
	ofn.lpstrFilter = filter
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	ofn.lpstrInitialDir = initial
	ofn.lpstrTitle = title
	ofn.lpstrDefExt = defExt
	ofn.Flags = ofnOverwritePrompt | ofnPathMustExist | ofnNoChangeDir | ofnExplorer

	r, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}

// resolveDroppedPath はドロップされたパスから実行ファイルを取り出す。
func resolveDroppedPath(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".lnk") {
		if t, _, err := shortcutTarget(path); err == nil && t != "" {
			return t
		}
	}
	return path
}

// openFileDialog はアプリを選ぶダイアログを開く。
func openFileDialog(owner uintptr) (string, bool) {
	buf := make([]uint16, 1024)
	filter := syscall.StringToUTF16Ptr("アプリ (*.exe;*.lnk)\x00*.exe;*.lnk\x00すべてのファイル (*.*)\x00*.*\x00\x00")
	title := syscall.StringToUTF16Ptr("起動するアプリを選択")
	initial := syscall.StringToUTF16Ptr(desktopPath())
	defExt := syscall.StringToUTF16Ptr("exe")

	var ofn openFileNameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.hwndOwner = owner
	ofn.lpstrFilter = filter
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	ofn.lpstrInitialDir = initial
	ofn.lpstrTitle = title
	ofn.lpstrDefExt = defExt
	ofn.Flags = ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir | ofnExplorer

	r, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}
