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

	"neconnectbridge/internal/logqueue"
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
	wsThickFrame   = 0x00040000
	wsMinimizeBox  = 0x00020000
	wsMaximizeBox  = 0x00010000
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
	wmCreate       = 0x0001
	wmSize         = 0x0005
	wmSetRedraw    = 0x000B
	wmGetTextLen   = 0x000E
	wmMouseWheel   = 0x020A
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
	emSetLimitText = 0x00C5
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
	idAdBlock       = 118
	bsAutoCheckbox  = 0x0003
	bmSetCheck      = 0x00F1
	bmGetCheck      = 0x00F0
	bnClicked       = 0
	idYes           = 6
	mbYesNo         = 0x00000004
	mbIconQuestion  = 0x00000020
	mbSetForeground = 0x00010000

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
	emLineScroll   = 0x00C9
	emFirstVisible = 0x00CE

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

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type point struct {
	x int32
	y int32
}

// minMaxInfo は、窓の大きさの上限と下限を渡すための形。
type minMaxInfo struct {
	reserved     point
	maxSize      point
	maxPosition  point
	minTrackSize point
	maxTrackSize point
}

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
	onToggleAdBlock  func(enabled bool)
}

type uiMessage struct {
	title string
	text  string
}

// uiConfirm は、画面に出す確認と、その答えの返し口。
type uiConfirm struct {
	title string
	text  string
	reply chan bool
}

type mainUI struct {
	mu           sync.Mutex
	statusText   string
	statusSet    bool
	runState     int
	pendingURLs  []string
	pendingErrs  []uiMessage
	pendingAsk   []uiConfirm
	logs         *logqueue.Queue
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
	adblockBtn    uintptr

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

// mainWindowClass は、本体の窓の種類の名前。
// 二重起動したときに、先に開いている窓を探すのにも使う。
const mainWindowClass = "NeConnectBridgeWnd"

// u16 は、文字列を Windows の文字列に直す。
// 途中に入れられない文字が混ざっていても、落とさずに置き換えて渡す。
func u16(s string) *uint16 {
	if p, err := syscall.UTF16PtrFromString(s); err == nil {
		return p
	}
	buf := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r == 0 {
			r = ' '
		}
		buf = append(buf, uint16(r))
		if r > 0xFFFF {
			// 面の外の文字は、そのままでは入れられないので置き換える。
			buf = buf[:len(buf)-1]
			buf = append(buf, 0xFFFD)
		}
	}
	buf = append(buf, 0)
	return &buf[0]
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
	if h := u.windowHandle(); h != 0 {
		procPostMessageW.Call(h, wmAppWake, 0, 0)
	}
}

// setWindowHandle は、窓を作ったときに控える。
func (u *mainUI) setWindowHandle(h uintptr) {
	u.mu.Lock()
	u.hwnd = h
	u.mu.Unlock()
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
	goSafe("ui wake", func() {
		time.Sleep(150 * time.Millisecond)
		u.mu.Lock()
		u.wakePending = false
		u.mu.Unlock()
		u.wake()
	})
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

// askConfirm は、画面に「はい／いいえ」を出して答えを待つ。
// 画面の流れが止まるのは待っている間だけで、接続はそのまま続く。
func (u *mainUI) askConfirm(title, text string) bool {
	reply := make(chan bool, 1)
	u.mu.Lock()
	if len(u.pendingAsk) < 4 {
		u.pendingAsk = append(u.pendingAsk, uiConfirm{title: title, text: text, reply: reply})
	}
	u.mu.Unlock()
	if u.windowHandle() == 0 {
		return false
	}
	u.wake()
	select {
	case yes := <-reply:
		return yes
	case <-time.After(10 * time.Minute):
		// 返事が無いまま止めない。次に起動したときから新しい版を使う。
		return false
	}
}

func (u *mainUI) takeConfirm() (uiConfirm, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pendingAsk) == 0 {
		return uiConfirm{}, false
	}
	c := u.pendingAsk[0]
	u.pendingAsk = u.pendingAsk[1:]
	return c, true
}

func (u *mainUI) takeLogs() []string {
	u.mu.Lock()
	q := u.logs
	u.mu.Unlock()
	if q == nil {
		return nil
	}
	return q.Take()
}

// uiAppendLog はログをファイルと画面の両方へ流す。
func uiAppendLog(line string) {
	ui := globalUI
	if ui == nil {
		return
	}
	ui.mu.Lock()
	q := ui.logs
	ui.mu.Unlock()
	if q == nil {
		return
	}
	q.Push(line)
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
	className := u16(mainWindowClass)
	logClass := u16("NeConnectBridgeLogWnd")

	ui := &mainUI{runState: -1, hooks: hooks, logs: logqueue.New(4000)}
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

	// firstVisibleLine は、いま一番上に見えている行を返す。
	firstVisibleLine := func() int {
		if ui.logEdit == 0 {
			return 0
		}
		r, _, _ := procSendMessageW.Call(ui.logEdit, emFirstVisible, 0, 0)
		return int(uint16(r))
	}

	// logFollowState は、末尾を見ているかどうかと、先頭の表示行を返す。
	logFollowState := func() (bool, int) {
		if ui.logEdit == 0 {
			return true, 0
		}
		var si scrollInfo
		si.cbSize = uint32(unsafe.Sizeof(si))
		si.fMask = sifAll
		r, _, _ := procGetScrollInfo.Call(ui.logEdit, sbVert, uintptr(unsafe.Pointer(&si)))
		if r == 0 {
			return true, firstVisibleLine()
		}
		atBottom := int(si.nPos)+int(si.nPage) >= int(si.nMax)-1
		return atBottom, firstVisibleLine()
	}

	scrollToBottom := func() {
		if ui.logEdit != 0 {
			procSendMessageW.Call(ui.logEdit, wmVScroll, sbBottom, 0)
		}
	}

	scrollLines := func(delta int) {
		if ui.logEdit == 0 || delta == 0 {
			return
		}
		procSendMessageW.Call(ui.logEdit, emLineScroll, 0, uintptr(uint32(int32(delta))))
	}

	// syncLog は、増えた行だけを末尾へ書き足す。
	// 読んでいる位置は、書き足す前の行に合わせて戻す。
	syncLog := func(force bool, trimmed int) {
		if ui.logEdit == 0 {
			return
		}
		total := len(ui.logLines)
		if !force && ui.logShown >= 0 && total-ui.logShown > 400 {
			// まとめて増えたときは、書き足すより今の内容で作り直すほうが軽い。
			force = true
		}
		if !force && ui.logShown == total {
			return
		}
		atBottom, firstLine := logFollowState()
		procSendMessageW.Call(ui.logEdit, wmSetRedraw, 0, 0)
		if force || ui.logShown < 0 || ui.logShown > total {
			setText(ui.logEdit, strings.Join(ui.logLines, "\r\n"))
			ui.logShown = total
			if atBottom {
				scrollToBottom()
			} else {
				// 先頭が削られた分だけ手前へずらして、同じ場所を見せる。
				keep := firstLine - trimmed
				if keep < 0 {
					keep = 0
				}
				scrollLines(keep)
			}
		} else {
			lines := ui.logLines[ui.logShown:]
			if len(lines) == 0 {
				procSendMessageW.Call(ui.logEdit, wmSetRedraw, 1, 0)
				return
			}
			// 書き足す前に、必ずいまの末尾へ位置を移す。
			endLen, _, _ := procSendMessageW.Call(ui.logEdit, wmGetTextLen, 0, 0)
			end := int(endLen)
			procSendMessageW.Call(ui.logEdit, emSetSel, uintptr(end), uintptr(end))
			chunk := strings.Join(lines, "\r\n")
			if end > 0 {
				chunk = "\r\n" + chunk
			}
			procSendMessageW.Call(ui.logEdit, emReplaceSel, 0, uintptr(unsafe.Pointer(u16(chunk))))
			ui.logShown = total
			if atBottom {
				scrollToBottom()
			} else {
				// 末尾へ動いた表示を、書き足す前の行まで戻す。
				scrollLines(firstLine - firstVisibleLine())
			}
		}
		procSendMessageW.Call(ui.logEdit, wmSetRedraw, 1, 0)
		procInvalidateRect.Call(ui.logEdit, 0, 1)
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
			syncLog(true, dropped)
			return
		}
		syncLog(false, 0)
	}

	// ログ欄は、窓の大きさが変わるたびに中身の広さへ合わせ直す。
	layoutLogWindow := func() {
		if ui.logHwnd == 0 || ui.logEdit == 0 {
			return
		}
		rc := rect{}
		ok, _, _ := procGetClientRect.Call(ui.logHwnd, uintptr(unsafe.Pointer(&rc)))
		if ok == 0 {
			return
		}
		w := int(rc.right - rc.left)
		h := int(rc.bottom - rc.top)
		if w <= 0 || h <= 0 {
			return
		}
		const margin = 8
		moveWindow(ui.logEdit, margin, margin, w-margin*2, h-margin*2)
	}

	logProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (result uintptr) {
		defer func() {
			if r := recover(); r != nil {
				logf("log window stopped: %v", r)
				writeCrashReport("log window", r)
				result = 0
			}
		}()
		switch msg {
		case wmClose:
			procShowWindow.Call(hwnd, swHide)
			return 0
		case wmCreate:
			layoutLogWindow()
			return 0
		case wmSize:
			layoutLogWindow()
			return 0
		case wmMouseWheel:
			if ui.logEdit != 0 {
				procSendMessageW.Call(ui.logEdit, wmMouseWheel, wParam, lParam)
			}
			return 0
		case wmGetMinMaxInfo:
			if lParam != 0 {
				mm := (*minMaxInfo)(unsafe.Pointer(lParam))
				mm.minTrackSize.x = 360
				mm.minTrackSize.y = 240
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
	editProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (result uintptr) {
		defer func() {
			if r := recover(); r != nil {
				logf("log view stopped: %v", r)
				writeCrashReport("log view", r)
				result = 0
			}
		}()
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
	showMsg := showWindowMessage()

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
		// ブリッジURLの取得は、つないだままでも使える。
		procEnableWindow.Call(ui.genBtn, boolFlag(!ui.connecting))
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
			hLog, _, _ := procCreateWindowExW.Call(
				0,
				uintptr(unsafe.Pointer(logClass)),
				uintptr(unsafe.Pointer(u16("ログ"))),
				wsOverlapped|wsCaption|wsSysMenu|wsThickFrame|wsMinimizeBox|wsMaximizeBox|wsVisible,
				x, y, w, h,
				0, 0, hInst, 0,
			)
			ui.logHwnd = hLog
			if len(ui.logLines) == 0 {
				loadLogTail(800)
			}
			ui.logEdit, _, _ = procCreateWindowExW.Call(
				wsExClientEdge,
				uintptr(unsafe.Pointer(u16("EDIT"))),
				0,
				wsChild|wsVisible|wsTabStop|wsBorder|wsVScroll|esMultiline|esReadOnly|esAutoVScroll,
				0, 0, 0, 0,
				ui.logHwnd, 0, hInst, 0,
			)
			fixedFont, _, _ := procCreateFontW.Call(
				uintptr(0xFFFFFFF2), // -14
				0, 0, 0, fwNormal, 0, 0, 0, 0, 0, 0, 0, fixedPitch|ffModern,
				uintptr(unsafe.Pointer(u16("Consolas"))),
			)
			procSendMessageW.Call(ui.logEdit, wmSetFont, fixedFont, 1)
			// 既定の文字数上限に達すると末尾で切れるため、余裕を持たせる。
			procSendMessageW.Call(ui.logEdit, emSetLimitText, 0x7FFFFFFE, 0)
			ui.logProc, _, _ = procSetWindowLongPtr.Call(ui.logEdit, gwlpWndProc, editProc)
			ui.logShown = -1
			layoutLogWindow()
		}
		procShowWindow.Call(ui.logHwnd, swShow)
		procUpdateWindow.Call(ui.logHwnd)
		syncLog(ui.logShown < 0, 0)
		procSetFocus.Call(ui.logEdit)
	}

	wndProc := syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (result uintptr) {
		defer func() {
			if r := recover(); r != nil {
				logf("window stopped: %v", r)
				writeCrashReport("window", r)
				result = 0
			}
		}()
		if taskbarCreatedMsg != 0 && msg == uint32(taskbarCreatedMsg) {
			if ui.trayWanted {
				ui.trayAdded = false
				addTray()
			}
			return 0
		}
		if showMsg != 0 && msg == showMsg {
			// 二重に起動されたときは、通知領域から通常表示へ戻す。
			restoreFromTray()
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
			for {
				ask, ok := ui.takeConfirm()
				if !ok {
					break
				}
				if !isWindowVisible(ui.hwnd) {
					restoreFromTray()
				}
				answer, _, _ := procMessageBoxW.Call(
					ui.hwnd,
					uintptr(unsafe.Pointer(u16(ask.text))),
					uintptr(unsafe.Pointer(u16(ask.title))),
					uintptr(mbYesNo|mbIconQuestion|mbSetForeground),
				)
				select {
				case ask.reply <- int(answer) == idYes:
				default:
				}
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
				if !ui.connecting {
					cur := getText(ui.serverEdit)
					goSafe("url request", func() { generateURL(cur) })
				}
				return 0
			case idConnectBtn:
				if !ui.connecting && !ui.connected && ui.hooks.onConnect != nil {
					urls := getText(ui.serverEdit)
					goSafe("connect", func() { ui.hooks.onConnect(urls) })
				}
				return 0
			case idDisconnectBtn:
				if ui.hooks.onDisconnect != nil {
					goSafe("disconnect", func() { ui.hooks.onDisconnect() })
				}
				return 0
			case idLaunchBtn:
				if ui.hooks.onLaunch != nil {
					tIdx, _, _ := procSendMessageW.Call(ui.targetCombo, cbGetCurSel, 0, 0)
					path := getText(ui.appPathEdit)
					urls := getText(ui.serverEdit)
					goSafe("launch", func() { ui.hooks.onLaunch(int(tIdx), path, urls) })
				}
				return 0
			case idShortcutBtn:
				if ui.hooks.onCreateShortcut != nil {
					tIdx, _, _ := procSendMessageW.Call(ui.targetCombo, cbGetCurSel, 0, 0)
					path := getText(ui.appPathEdit)
					goSafe("shortcut", func() { ui.hooks.onCreateShortcut(int(tIdx), path) })
				}
				return 0
			case idBrowseBtn:
				// ファイル選択は簡易にエクスプローラ風ダイアログを使う
				goSafe("pick file", func() {
					picked, ok := pickAppFile(ui.windowHandle())
					if ok && picked != "" {
						procSendMessageW.Call(ui.targetCombo, cbSetCurSel, targetApp, 0)
						ui.postPickedPath(picked)
					}
				})
				return 0
			case idLogBtn:
				if ui.hooks.onOpenLog != nil {
					ui.hooks.onOpenLog()
				}
				return 0
			case idCacheBtn:
				if !ui.connecting && !ui.connected && ui.hooks.onClearCache != nil {
					goSafe("clear cache", func() { ui.hooks.onClearCache() })
				}
				return 0
			case idAdBlock:
				if notif == bnClicked {
					checked, _, _ := procSendMessageW.Call(ui.adblockBtn, bmGetCheck, 0, 0)
					if ui.hooks.onToggleAdBlock != nil {
						ui.hooks.onToggleAdBlock(checked == 1)
					}
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
	w, h := uintptr(470), uintptr(422)
	x := (sw - w) / 2
	y := (sh - h) / 2

	hMain, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16("NeConnect Bridge"))),
		wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox,
		x, y, w, h,
		0, 0, hInst, 0,
	)
	ui.setWindowHandle(hMain)

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
	procSendMessageW.Call(ui.serverEdit, emSetLimitText, 1<<20, 0)

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

	ui.adblockBtn, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(u16("BUTTON"))),
		uintptr(unsafe.Pointer(u16("広告ブロック"))),
		wsChild|wsVisible|wsTabStop|bsAutoCheckbox,
		20, 264, 200, 22,
		ui.hwnd, idAdBlock, hInst, 0,
	)
	procSendMessageW.Call(ui.adblockBtn, wmSetFont, hFont, 1)
	if cfg.AdBlock {
		procSendMessageW.Call(ui.adblockBtn, bmSetCheck, 1, 0)
	}

	ui.statusLbl = mkLabel(ui.hwnd, "待機中", 20, 292, 415, 70, hFont, hInst)

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
var procGetClientRect = user32.NewProc("GetClientRect")
var procInvalidateRect = user32.NewProc("InvalidateRect")

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
	if err := withCOM(func() error {
		p, ok := openFileDialog(owner)
		if ok {
			picked = p
		}
		return nil
	}); err != nil {
		logf("アプリを選ぶ画面を開けませんでした: %v", err)
		showError("NeConnect Bridge", "アプリを選ぶ画面を開けませんでした。")
		return "", false
	}
	_ = owner
	return picked, picked != ""
}
