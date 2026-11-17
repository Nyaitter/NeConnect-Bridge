package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	gdi32                = syscall.NewLazyDLL("gdi32.dll")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procIsDialogMessageW = user32.NewProc("IsDialogMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen = user32.NewProc("GetWindowTextLengthW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procSetFocus         = user32.NewProc("SetFocus")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procRegisterMsgW     = user32.NewProc("RegisterWindowMessageW")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW  = user32.NewProc("CallWindowProcW")
	procGetKeyState      = user32.NewProc("GetKeyState")
	procGetScrollInfo    = user32.NewProc("GetScrollInfo")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsVisible      = 0x10000000
	wsChild        = 0x40000000
	wsTabStop      = 0x00010000
	wsBorder       = 0x00800000
	wsVScroll      = 0x00200000
	wsHScroll      = 0x00100000
	wsClipSibling  = 0x04000000
	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esAutoHScroll  = 0x0080
	esReadOnly     = 0x0800
	esWantReturn   = 0x1000
	bsPushBtn      = 0x0000
	bsDefPushBtn   = 0x0001
	cbsDropDownLst = 0x0003
	cbsHasStrings  = 0x0200
	wsExClientEdge = 0x00000200
	wmDestroy      = 0x0002
	wmSize         = 0x0005
	wmClose        = 0x0010
	wmSetFont      = 0x0030
	wmCommand      = 0x0111
	wmApp          = 0x8000
	wmDropFiles    = 0x0233
	cbAddString    = 0x0143
	cbSetCurSel    = 0x014E
	cbGetCurSel    = 0x0147
	cbnSelChange   = 1
	emSetSel       = 0x00B1
	emReplaceSel   = 0x00C2
	emSetReadOnly  = 0x00CF
	emGetLineCount = 0x00BA
	emLinesScroll  = 0x00B6
	wmVScroll      = 0x0115
	sbBottom       = 7
	defaultGuiFnt  = 17
	swShow         = 5
	fwNormal       = 400
	fixedPitch     = 0x01
	ffModern       = 0x30
	fwDonTCare     = 0

	idServerEdit    = 105
	idGenBtn        = 106
	idStatusLbl     = 108
	idConnectBtn    = 109
	idDisconnectBtn = 110
	idTargetCombo   = 111
	idAppPath       = 112
	idBrowseBtn     = 113
	idLaunchBtn     = 114
	idShortcutBtn   = 115
	idLogBtn        = 116
	idCacheBtn      = 117

	wmAppStatus    = wmApp + 1
	wmAppState     = wmApp + 2
	wmAppAppendURL = wmApp + 3
	wmAppError     = wmApp + 4
	wmAppWake      = wmApp + 5
	wmAppQuit      = wmApp + 6
	wmAppShowLog   = wmApp + 7
	wmAppTray      = wmApp + 8
	wmAppMinimize  = wmApp + 9
	wmAppRestore   = wmApp + 10

	// ログ欄の選択とスクロールを扱うための値
	emGetSel       = 0x00B0
	emLineIndex    = 0x00BB
	emScrollCaret  = 0x00B7
	emGetScrollPos = 0x045D
	emSetScrollPos = 0x045E

	// 通知領域
	wmSysCommand    = 0x0112
	scMinimize      = 0xF020
	scRestore       = 0xF120
	wmKeyDown       = 0x0100
	wmKeyUp         = 0x0101
	wmChar          = 0x0102
	wmSysKeyDown    = 0x0104
	wmContextMenu   = 0x007B
	wmLeftButtonUp  = 0x0202
	wmLeftDblClk    = 0x0203
	wmRightButtonUp = 0x0205
	wmNull          = 0x0000
	wmGetMinMaxInfo = 0x0024
	tpmRightButton  = 0x0002
	tpmReturnCmd    = 0x0100
	tpmNoNotify     = 0x0080
	mfString        = 0x0000
	mfSeparator     = 0x0800
	cmdTrayOpen     = 0xE001
	cmdTrayExit     = 0xE002
	nimAdd          = 0
	nimModify       = 1
	nimDelete       = 2
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004
	idiApplication  = 32512
	swRestore       = 9
	swShowNormal    = 1
	gwlpWndProc     = ^uintptr(3) // -4
	vkA             = 0x41
	vkControl       = 0x11
	sbVert          = 1
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type msgStruct struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
}

type uiHooks struct {
	onConnect        func(serverURLs string)
	onDisconnect     func()
	onLaunch         func(targetIdx int, appPath, serverURLs string)
	onCreateShortcut func(targetIdx int, appPath string)
	onClearCache     func()
	onOpenLog        func()
}

type uiMessage struct {
	title string
	text  string
}

type mainUI struct {
	mu           sync.Mutex
	statusText   string
	statusSet    bool
	runState     int
	pendingURLs  []string
	pendingErrs  []uiMessage
	pendingLogs  []string
	pendingPaths []string
	logLines     []string
	logShown     int
	wakePending  bool

	hwnd          uintptr
	serverEdit    uintptr
	genBtn        uintptr
	statusLbl     uintptr
	connectBtn    uintptr
	disconnectBtn uintptr
	targetCombo   uintptr
	appPathEdit   uintptr
	browseBtn     uintptr
	launchBtn     uintptr
	shortcutBtn   uintptr
	logBtn        uintptr
	cacheBtn      uintptr

	logHwnd uintptr
	logEdit uintptr
	logProc uintptr

	trayAdded  bool
	trayWanted bool
	trayID     uint32

	connected  bool
	connecting bool
	closing    bool

	hooks uiHooks
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uTimeoutOrVer    uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type pointStruct struct {
	x int32
	y int32
}

type scrollInfo struct {
	cbSize    uint32
	fMask     uint32
	nMin      int32
	nMax      int32
	nPage     uint32
	nPos      int32
	nTrackPos int32
}

const sifAll = 0x00000017

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func getText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	n, _, _ := procGetWindowTextLen.Call(hwnd)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+2)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func setText(hwnd uintptr, s string) {
	if hwnd == 0 {
		return
	}
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(u16(s))))
}

func showError(title, text string) {
	ui := globalUI
	if ui == nil {
		procMessageBoxW.Call(0, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), 0x10)
		return
	}
	ui.postError(title, text)
}

func (u *mainUI) wake() {
	if u.hwnd != 0 {
		procPostMessageW.Call(u.hwnd, wmAppWake, 0, 0)
	}
}

// wakeLater は、続けて起きた変化をまとめて1回だけ画面に伝える。
func (u *mainUI) wakeLater() {
	u.mu.Lock()
	if u.wakePending {
		u.mu.Unlock()
		return
	}
	u.wakePending = true
	u.mu.Unlock()
	go func() {
		time.Sleep(150 * time.Millisecond)
		u.mu.Lock()
		u.wakePending = false
		u.mu.Unlock()
		u.wake()
	}()
}

func (u *mainUI) windowHandle() uintptr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hwnd
}

func (u *mainUI) setStatus(text string) {
	u.mu.Lock()
	u.statusText = text
	u.statusSet = true
	u.mu.Unlock()
	u.wake()
}

func (u *mainUI) setRunState(connecting, connected bool) {
	code := 0
	if connecting {
		code = 1
	} else if connected {
		code = 2
	}
	u.mu.Lock()
	u.runState = code
	u.mu.Unlock()
	u.wake()
}

func (u *mainUI) appendGeneratedURL(newURL string) {
	u.mu.Lock()
	u.pendingURLs = append(u.pendingURLs, newURL)
	u.mu.Unlock()
	u.wake()
}

func (u *mainUI) postError(title, text string) {
	u.mu.Lock()
	if len(u.pendingErrs) < 8 {
		u.pendingErrs = append(u.pendingErrs, uiMessage{title: title, text: text})
	}
	u.mu.Unlock()
	u.wake()
}

func (u *mainUI) showLogWindow() {
	if u.hwnd == 0 {
		return
	}
	procPostMessageW.Call(u.hwnd, wmAppShowLog, 0, 0)
}

func (u *mainUI) takeStatus() (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.statusSet {
		return "", false
	}
	text := u.statusText
	u.statusSet = false
	return text, true
}

func (u *mainUI) takeRunState() (int, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	state := u.runState
	if state < 0 {
		return 0, false
	}
	u.runState = -1
	return state, true
}

func (u *mainUI) takeURLs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingURLs) == 0 {
		return nil
	}
	urls := u.pendingURLs
	u.pendingURLs = nil
	return urls
}

func (u *mainUI) takeErrors() []uiMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingErrs) == 0 {
		return nil
	}
	errs := u.pendingErrs
	u.pendingErrs = nil
	return errs
}

func (u *mainUI) takeLogs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingLogs) == 0 {
		return nil
	}
	logs := u.pendingLogs
	u.pendingLogs = nil
	return logs
}

// uiAppendLog はログをファイルと画面の両方へ流す。
func uiAppendLog(line string) {
	ui := globalUI
	if ui == nil {
		return
	}
	ui.mu.Lock()
	if len(ui.pendingLogs) < 4000 {
		ui.pendingLogs = append(ui.pendingLogs, line)
	}
	ui.mu.Unlock()
	ui.wakeLater()
}

func mkLabel(parent uintptr, text string, px, py, pw, ph int, hFont uintptr, hInst uintptr) uintptr {
	h, _, _ := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(u16("STATIC"))),
		uintptr(unsafe.Pointer(u16(text))),
		wsChild|wsVisible,
		uintptr(px), uintptr(py), uintptr(pw), uintptr(ph),
		parent, 0, hInst, 0)
	procSendMessageW.Call(h, wmSetFont, hFont, 1)
	return h
}

func mkButton(parent uintptr, text string, px, py, pw, ph int, id int, hFont uintptr, hInst uintptr) uintptr {
	h, _, _ := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(u16("BUTTON"))),
		uintptr(unsafe.Pointer(u16(text))),
		wsChild|wsVisible|wsTabStop|bsPushBtn,
		uintptr(px), uintptr(py), uintptr(pw), uintptr(ph),
		parent, uintptr(id), hInst, 0)
	procSendMessageW.Call(h, wmSetFont, hFont, 1)
	return h
}

func runMainWindow(cfg Config, hooks uiHooks, onQuit func()) {
	runtime.LockOSThread()
	hInst, _, _ := procGetModuleHandleW.Call(0)
	className := u16("NeConnectBridgeWnd")
	logClass := u16("NeConnectBridgeLogWnd")

	ui := &mainUI{runState: -1, hooks: hooks}
	globalUI = ui

	loadLogTail := func(limit int) {
		path := filepath.Join(exeDir(), "nctb.log")
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		text := string(b)
		if len(text) > 120*1024 {
			text = text[len(text)-120*1024:]
			if i := strings.Index(text, "\n"); i >= 0 {
				text = text[i+1:]
			}
		}
		lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
		start := 0
		if len(lines) > limit {
			start = len(lines) - limit
		}
		ui.logLines = append(ui.logLines, lines[start:]...)
	}

	logAtBottom := func() bool {
		if ui.logEdit == 0 {
			return true
		}
		var si scrollInfo
		si.cbSize = uint32(unsafe.Sizeof(si))
		si.fMask = sifAll
		r, _, _ := procGetScrollInfo.Call(ui.logEdit, sbVert, uintptr(unsafe.Pointer(&si)))
		if r == 0 {
			return true
		}
		return int(si.nPos)+int(si.nPage) >= int(si.nMax)-2
	}

	saveScroll := func() (pointStruct, bool) {
		var pt pointStruct
		if ui.logEdit == 0 {
			return pt, false
		}
		r, _, _ := procSendMessageW.Call(ui.logEdit, emGetScrollPos, 0, uintptr(unsafe.Pointer(&pt)))
		return pt, r != 0
	}

	// syncLog は、覚えている行とログ欄の中身を合わせる。
	syncLog := func(force bool) {
		if ui.logEdit == 0 {
			return
		}
		total := len(ui.logLines)
		if !force && ui.logShown == total {
			return
		}
		if force || ui.logShown < 0 || ui.logShown > total {
			setText(ui.logEdit, strings.Join(ui.logLines, "\r\n"))
			ui.logShown = total
			procSendMessageW.Call(ui.logEdit, emSetSel, ^uintptr(0), ^uintptr(0))
			procSendMessageW.Call(ui.logEdit, wmVScroll, sbBottom, 0)
			return
		}
		lines := ui.logLines[ui.logShown:]
		if len(lines) == 0 {
			return
		}

		atBottom := logAtBottom()
		pos, hadPos := saveScroll()

		// 選んでいる範囲があれば、追記のあとに戻す。
		var selStart, selEnd uint32
		procSendMessageW.Call(ui.logEdit, emGetSel,
			uintptr(unsafe.Pointer(&selStart)), uintptr(unsafe.Pointer(&selEnd)))

		procSendMessageW.Call(ui.logEdit, emSetSel, ^uintptr(0), ^uintptr(0))
		chunk := strings.Join(lines, "\r\n") + "\r\n"
		procSendMessageW.Call(ui.logEdit, emReplaceSel, 0, uintptr(unsafe.Pointer(u16(chunk))))
		ui.logShown = total

		if selEnd > selStart {
			procSendMessageW.Call(ui.logEdit, emSetSel, uintptr(selStart), uintptr(selEnd))
		}
		if atBottom {
			procSendMessageW.Call(ui.logEdit, wmVScroll, sbBottom, 0)
		} else if hadPos {
			procSendMessageW.Call(ui.logEdit, emSetScrollPos, 0, uintptr(unsafe.Pointer(&pos)))
		}
	}

	appendLogLines := func(lines []string) {
		if len(lines) == 0 {
			return
		}
		ui.logLines = append(ui.logLines, lines...)
		dropped := 0
		if len(ui.logLines) > 2000 {
			dropped = len(ui.logLines) - 1200
			ui.logLines = append([]string{}, ui.logLines[dropped:]...)
		}
		if ui.logEdit == 0 {
			return
		}
		if !isWindowVisible(ui.logHwnd) {
			// 閉じている間は触らず、開いたときにまとめて追いつかせる。
			ui.logShown = -1
			return
		}
		if dropped > 0 {
			syncLog(true)
			return
		}
		syncLog(false)
	}

	logProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
		switch msg {
		case wmClose:
			procShowWindow.Call(hwnd, swHide)
			return 0
		case wmSize:
			if ui.logEdit != 0 {
				w := int(lParam & 0xffff)
				h := int((lParam >> 16) & 0xffff)
				moveWindow(ui.logEdit, 4, 4, w-8, h-8)
			}
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	})

	wcLog := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   logProc,
		hInstance:     hInst,
		hbrBackground: 6,
		lpszClassName: logClass,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcLog)))

	// ログ欄の中で Ctrl+A を効かせるための受け渡し。
	editProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
		switch msg {
		case wmChar:
			if wParam == 1 {
				procSendMessageW.Call(hwnd, emSetSel, 0, ^uintptr(0))
				return 0
			}
		case wmKeyDown, wmSysKeyDown:
			if wParam == vkA {
				state, _, _ := procGetKeyState.Call(vkControl)
				if int16(state) < 0 {
					procSendMessageW.Call(hwnd, emSetSel, 0, ^uintptr(0))
					return 0
				}
			}
		}
		ret, _, _ := procCallWindowProcW.Call(ui.logProc, hwnd, uintptr(msg), wParam, lParam)
		return ret
	})
	taskbarCreatedMsg, _, _ := procRegisterMsgW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))

	syncTarget := func() {
		sel, _, _ := procSendMessageW.Call(ui.targetCombo, cbGetCurSel, 0, 0)
		isApp := int(sel) == targetApp
		procEnableWindow.Call(ui.appPathEdit, boolFlag(isApp))
		procEnableWindow.Call(ui.browseBtn, boolFlag(isApp))
	}

	syncButtons := func() {
		busy := ui.connected || ui.connecting
		procEnableWindow.Call(ui.connectBtn, boolFlag(!busy))
		procEnableWindow.Call(ui.disconnectBtn, boolFlag(busy))
		procEnableWindow.Call(ui.serverEdit, boolFlag(!busy))
		procEnableWindow.Call(ui.genBtn, boolFlag(!busy))
		syncTarget()
	}

	// ---- 通知領域 --------------------------------------------------

	addTray := func() {
		if ui.hwnd == 0 {
			return
		}
		ui.trayWanted = true
		if ui.trayAdded {
			return
		}
		var nid notifyIconDataW
		nid.cbSize = uint32(unsafe.Sizeof(nid))
		nid.hWnd = ui.hwnd
		nid.uID = 1
		nid.uFlags = nifMessage | nifIcon | nifTip
		nid.uCallbackMessage = wmAppTray
		nid.hIcon, _, _ = procLoadIconW.Call(0, idiApplication)
		tip, _ := syscall.UTF16FromString("NeConnect Bridge")
		copy(nid.szTip[:], tip)
		r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		if r != 0 {
			ui.trayAdded = true
		}
	}

	removeTray := func() {
		ui.trayWanted = false
		if !ui.trayAdded || ui.hwnd == 0 {
			return
		}
		var nid notifyIconDataW
		nid.cbSize = uint32(unsafe.Sizeof(nid))
		nid.hWnd = ui.hwnd
		nid.uID = 1
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		ui.trayAdded = false
	}

	restoreFromTray := func() {
		removeTray()
		procShowWindow.Call(ui.hwnd, swShowNormal)
		procShowWindow.Call(ui.hwnd, swRestore)
		procSetForeground.Call(ui.hwnd)
	}

	trayMenu := func() {
		menu, _, _ := procCreatePopupMenu.Call()
		if menu == 0 {
			return
		}
		procAppendMenuW.Call(menu, mfString, cmdTrayOpen, uintptr(unsafe.Pointer(u16("開く"))))
		procAppendMenuW.Call(menu, mfSeparator, 0, 0)
		procAppendMenuW.Call(menu, mfString, cmdTrayExit, uintptr(unsafe.Pointer(u16("終了"))))
		var pt pointStruct
		procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
		procSetForeground.Call(ui.hwnd)
		cmd, _, _ := procTrackPopupMenu.Call(menu,
			tpmRightButton|tpmReturnCmd|tpmNoNotify,
			uintptr(uint32(pt.x)), uintptr(uint32(pt.y)), 0, ui.hwnd, 0)
		procDestroyMenu.Call(menu)
		procPostMessageW.Call(ui.hwnd, wmNull, 0, 0)
		switch cmd {
		case cmdTrayOpen:
			restoreFromTray()
		case cmdTrayExit:
			procPostMessageW.Call(ui.hwnd, wmClose, 0, 0)
		}
	}

	applyRunState := func(state int) {
		switch state {
		case 0:
			ui.connecting = false
			ui.connected = false
		case 1:
			ui.connecting = true
			ui.connected = false
		case 2:
			ui.connecting = false
			ui.connected = true
		}
		syncButtons()
	}

	openLogWindow := func() {
		if ui.logHwnd == 0 {
			sw, _, _ := procGetSystemMetrics.Call(0)
			sh, _, _ := procGetSystemMetrics.Call(1)
			w, h := uintptr(760), uintptr(460)
			x := (sw - w) / 2
			y := (sh - h) / 2
			ui.logHwnd, _, _ = procCreateWindowExW.Call(
				0,
				uintptr(unsafe.Pointer(logClass)),
				uintptr(unsafe.Pointer(u16("ログ"))),
				wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox|wsVisible,
				x, y, w, h,
				0, 0, hInst, 0,
			)
			if len(ui.logLines) == 0 {
				loadLogTail(800)
			}
			ui.logEdit, _, _ = procCreateWindowExW.Call(
				wsExClientEdge,
				uintptr(unsafe.Pointer(u16("EDIT"))),
				0,
				wsChild|wsVisible|wsTabStop|wsBorder|wsVScroll|wsHScroll|esMultiline|esReadOnly|esAutoVScroll|esAutoHScroll,
				4, 4, w-16, h-40,
				ui.logHwnd, 0, hInst, 0,
			)
			fixedFont, _, _ := procCreateFontW.Call(
				uintptr(0xFFFFFFF2), // -14
				0, 0, 0, fwNormal, 0, 0, 0, 0, 0, 0, 0, fixedPitch|ffModern,
				uintptr(unsafe.Pointer(u16("Consolas"))),
			)
			procSendMessageW.Call(ui.logEdit, wmSetFont, fixedFont, 1)
			ui.logProc, _, _ = procSetWindowLongPtr.Call(ui.logEdit, gwlpWndProc, editProc)
			ui.logShown = -1
			procSendMessageW.Call(ui.logHwnd, wmSize, 0, uintptr(uint32(w)<<16|uint32(h)))
		}
		procShowWindow.Call(ui.logHwnd, swShow)
		procUpdateWindow.Call(ui.logHwnd)
		syncLog(ui.logShown < 0)
		procSetFocus.Call(ui.logEdit)
	}

	wndProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
		if taskbarCreatedMsg != 0 && msg == uint32(taskbarCreatedMsg) {
			if ui.trayWanted {
				ui.trayAdded = false
				addTray()
			}
			return 0
		}
		switch msg {
		case wmAppMinimize:
			addTray()
			if ui.logHwnd != 0 {
				procShowWindow.Call(ui.logHwnd, swHide)
			}
			procShowWindow.Call(hwnd, swHide)
			return 0
		case wmAppRestore:
			restoreFromTray()
			return 0
		case wmAppTray:
			switch uint32(lParam) & 0xffff {
			case wmLeftButtonUp, wmLeftDblClk:
				restoreFromTray()
			case wmRightButtonUp, wmContextMenu:
				trayMenu()
			}
			return 0
		case wmAppWake, wmAppStatus, wmAppState, wmAppAppendURL, wmAppError:
			if text, ok := ui.takeStatus(); ok {
				setText(ui.statusLbl, text)
			}
			for _, newURL := range ui.takeURLs() {
				current := strings.TrimSpace(getText(ui.serverEdit))
				if current == "" {
					setText(ui.serverEdit, newURL)
				} else {
					setText(ui.serverEdit, newURL+"\r\n"+current)
				}
			}
			for _, p := range ui.takePaths() {
				setText(ui.appPathEdit, p)
				procSendMessageW.Call(ui.targetCombo, cbSetCurSel, targetApp, 0)
				syncTarget()
			}
			if state, ok := ui.takeRunState(); ok {
				applyRunState(state)
			}
			for _, message := range ui.takeErrors() {
				procMessageBoxW.Call(ui.hwnd, uintptr(unsafe.Pointer(u16(message.text))), uintptr(unsafe.Pointer(u16(message.title))), 0x10)
			}
			appendLogLines(ui.takeLogs())
			return 0
		case wmAppShowLog:
			appendLogLines(ui.takeLogs())
			openLogWindow()
			return 0
		case wmDropFiles:
			count, _, _ := procDragQueryFileW.Call(wParam, 0xFFFFFFFF, 0, 0)
			if count > 0 {
				buf := make([]uint16, 1024)
				n, _, _ := procDragQueryFileW.Call(wParam, 0, uintptr(unsafe.Pointer(&buf[0])), 1024)
				if n > 0 {
					dropped := syscall.UTF16ToString(buf[:n])
					resolved := resolveDroppedPath(dropped)
					procSendMessageW.Call(ui.targetCombo, cbSetCurSel, targetApp, 0)
					syncTarget()
					setText(ui.appPathEdit, resolved)
					// すぐ書き換えられるよう、入れたパスを選択して焦点を移す。
					procSendMessageW.Call(ui.appPathEdit, emSetSel, 0, ^uintptr(0))
					procSetFocus.Call(ui.appPathEdit)
					if count > 1 {
						setText(ui.statusLbl, "1つ目のアプリを指定しました")
					} else {
						setText(ui.statusLbl, "ドロップされたアプリを指定しました")
					}
					logf("dropped: %s", resolved)
				}
			}
			procDragFinish.Call(wParam)
			return 0
		case wmCommand:
			id := int(uint16(wParam & 0xffff))
			notif := int(uint16((wParam >> 16) & 0xffff))
			switch id {
			case idTargetCombo:
				if notif == cbnSelChange {
					syncTarget()
				}
				return 0
			case idGenBtn:
				if !ui.connecting && !ui.connected {
					cur := getText(ui.serverEdit)
					go generateURL(cur)
				}
				return 0
			case idConnectBtn:
				if !ui.connecting && !ui.connected && ui.hooks.onConnect != nil {
					urls := getText(ui.serverEdit)
					go ui.hooks.onConnect(urls)
				}
				return 0
			case idDisconnectBtn:
				if ui.hooks.onDisconnect != nil {
					go ui.hooks.onDisconnect()
				}
				return 0
			case idLaunchBtn:
				if ui.hooks.onLaunch != nil {
					tIdx, _, _ := procSendMessageW.Call(ui.targetCombo, cbGetCurSel, 0, 0)
					path := getText(ui.appPathEdit)
					urls := getText(ui.serverEdit)
					go ui.hooks.onLaunch(int(tIdx), path, urls)
				}
				return 0
			case idShortcutBtn:
				if ui.hooks.onCreateShortcut != nil {
					tIdx, _, _ := procSendMessageW.Call(ui.targetCombo, cbGetCurSel, 0, 0)
					path := getText(ui.appPathEdit)
					go ui.hooks.onCreateShortcut(int(tIdx), path)
				}
				return 0
			case idBrowseBtn:
				// ファイル選択は簡易にエクスプローラ風ダイアログを使う
				go func() {
					picked, ok := pickAppFile(ui.windowHandle())
					if ok && picked != "" {
						procSendMessageW.Call(ui.targetCombo, cbSetCurSel, targetApp, 0)
						ui.postPickedPath(picked)
					}
				}()
				return 0
			case idLogBtn:
				if ui.hooks.onOpenLog != nil {
					ui.hooks.onOpenLog()
				}
				return 0
			case idCacheBtn:
				if !ui.connecting && !ui.connected && ui.hooks.onClearCache != nil {
					go ui.hooks.onClearCache()
				}
				return 0
			}
			return 0
		case wmSysCommand:
			if wParam&0xFFF0 == scMinimize {
				procPostMessageW.Call(hwnd, wmAppMinimize, 0, 0)
				return 0
			}
		case wmSize:
			if wParam&0xffff == 1 {
				procPostMessageW.Call(hwnd, wmAppMinimize, 0, 0)
				return 0
			}
		case wmClose:
			if ui.closing {
				return 0
			}
			ui.closing = true
			removeTray()
			go func() {
				done := make(chan struct{})
				go func() {
					defer func() {
						recover()
						close(done)
					}()
					onQuit()
				}()
				select {
				case <-done:
				case <-time.After(1500 * time.Millisecond):
				}
				procPostMessageW.Call(hwnd, wmAppQuit, 0, 0)
			}()
			return 0
		case wmAppQuit:
			procDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			removeTray()
			procPostQuitMessage.Call(0)
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return ret
	})

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   wndProc,
		hInstance:     hInst,
		hbrBackground: 6,
		lpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	sw, _, _ := procGetSystemMetrics.Call(0)
	sh, _, _ := procGetSystemMetrics.Call(1)
	w, h := uintptr(470), uintptr(380)
	x := (sw - w) / 2
	y := (sh - h) / 2

	ui.hwnd, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16("NeConnect Bridge"))),
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox,
		x, y, w, h,
		0, 0, hInst, 0,
	)

	hFont, _, _ := procGetStockObject.Call(defaultGuiFnt)

	mkLabel(ui.hwnd, "ブリッジURL", 20, 10, 200, 16, hFont, hInst)
	ui.genBtn = mkButton(ui.hwnd, "ブリッジURLをリクエスト", 285, 6, 150, 26, idGenBtn, hFont, hInst)
	editText := strings.ReplaceAll(cfg.ServerURL, "\n", "\r\n")
	editText = strings.ReplaceAll(editText, "\r\r\n", "\r\n")
	ui.serverEdit, _, _ = procCreateWindowExW.Call(
		wsExClientEdge,
		uintptr(unsafe.Pointer(u16("EDIT"))),
		uintptr(unsafe.Pointer(u16(editText))),
		wsChild|wsVisible|wsTabStop|wsBorder|wsVScroll|esMultiline|esAutoVScroll|esWantReturn,
		20, 34, 415, 84,
		ui.hwnd, idServerEdit, hInst, 0,
	)
	procSendMessageW.Call(ui.serverEdit, wmSetFont, hFont, 1)

	ui.connectBtn = mkButton(ui.hwnd, "Connect", 20, 128, 95, 28, idConnectBtn, hFont, hInst)
	ui.disconnectBtn = mkButton(ui.hwnd, "Disconnect", 123, 128, 105, 28, idDisconnectBtn, hFont, hInst)
	ui.cacheBtn = mkButton(ui.hwnd, "接続キャッシュをクリア", 236, 128, 199, 28, idCacheBtn, hFont, hInst)

	mkLabel(ui.hwnd, "起動対象", 20, 168, 100, 16, hFont, hInst)
	ui.targetCombo, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(u16("COMBOBOX"))), 0,
		wsChild|wsVisible|wsTabStop|cbsDropDownLst|cbsHasStrings,
		20, 186, 190, 200, ui.hwnd, idTargetCombo, hInst, 0,
	)
	procSendMessageW.Call(ui.targetCombo, wmSetFont, hFont, 1)
	for _, label := range targetLabels {
		procSendMessageW.Call(ui.targetCombo, cbAddString, 0, uintptr(unsafe.Pointer(u16(label))))
	}
	procSendMessageW.Call(ui.targetCombo, cbSetCurSel, uintptr(cfg.TargetIdx), 0)

	ui.appPathEdit, _, _ = procCreateWindowExW.Call(
		wsExClientEdge,
		uintptr(unsafe.Pointer(u16("EDIT"))),
		uintptr(unsafe.Pointer(u16(cfg.AppPath))),
		wsChild|wsVisible|wsTabStop|wsBorder|esAutoHScroll,
		225, 186, 155, 25,
		ui.hwnd, idAppPath, hInst, 0,
	)
	procSendMessageW.Call(ui.appPathEdit, wmSetFont, hFont, 1)
	ui.browseBtn = mkButton(ui.hwnd, "参照", 385, 186, 50, 25, idBrowseBtn, hFont, hInst)

	ui.launchBtn = mkButton(ui.hwnd, "Launch", 20, 223, 120, 32, idLaunchBtn, hFont, hInst)
	ui.shortcutBtn = mkButton(ui.hwnd, "ショートカットを作成", 150, 223, 190, 32, idShortcutBtn, hFont, hInst)
	ui.logBtn = mkButton(ui.hwnd, "ログ", 350, 223, 85, 32, idLogBtn, hFont, hInst)

	ui.statusLbl = mkLabel(ui.hwnd, "待機中", 20, 266, 415, 60, hFont, hInst)

	procDragAcceptFiles.Call(ui.hwnd, 1)

	syncButtons()
	procShowWindow.Call(ui.hwnd, swShow)
	procUpdateWindow.Call(ui.hwnd)

	var m msgStruct
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		handled, _, _ := procIsDialogMessageW.Call(ui.hwnd, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}
}

func boolFlag(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func isWindowVisible(h uintptr) bool {
	if h == 0 {
		return false
	}
	r, _, _ := procIsWindowVisible.Call(h)
	return r != 0
}

var procIsWindowVisible = user32.NewProc("IsWindowVisible")

func moveWindow(h uintptr, x, y, w, hgt int) {
	procMoveWindow.Call(h, uintptr(x), uintptr(y), uintptr(w), uintptr(hgt), 1)
}

var procMoveWindow = user32.NewProc("MoveWindow")

// postPickedPath は参照ボタンで選ばれたパスを画面へ反映する。
func (u *mainUI) postPickedPath(path string) {
	u.mu.Lock()
	u.pendingPaths = append(u.pendingPaths, path)
	u.mu.Unlock()
	u.wake()
}

func (u *mainUI) takePaths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingPaths) == 0 {
		return nil
	}
	p := u.pendingPaths
	u.pendingPaths = nil
	return p
}

// pickAppFile は起動するアプリを選ぶダイアログを開く。
func pickAppFile(owner uintptr) (string, bool) {
	var picked string
	_ = withCOM(func() error {
		p, ok := openFileDialog(owner)
		if ok {
			picked = p
		}
		return nil
	})
	_ = owner
	return picked, picked != ""
}
