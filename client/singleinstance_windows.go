//go:build windows

package main

import (
	"sync"
	"syscall"
	"time"
	"unsafe"

	"neconnectbridge/internal/singleinst"
)

// 先に起動している画面を探すときの待ち方。
// 起動直後は窓がまだ無いので、少しの間だけ待つ。
const (
	windowWaitAttempts = 20
	windowWaitInterval = 150 * time.Millisecond
	asfwAny            = ^uintptr(0)
)

const errAlreadyExists = syscall.Errno(183)

var (
	procCreateMutexW        = kernel32.NewProc("CreateMutexW")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procAllowSetForegroundW = user32.NewProc("AllowSetForegroundWindow")

	// singleInstance は、起動している間ずっと持っておく。
	// 手放すと、次の起動が自分を二重起動と見なせなくなる。
	singleInstance   uintptr
	showMessageOnce  sync.Once
	showMessageValue uint32
)

// takeInstance は、画面を出している側の席が空いていれば取る。
func takeInstance() bool {
	handle, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(u16(singleinst.MutexName()))))
	if handle == 0 {
		// 目印を作れない環境でも、これまでどおり起動は止めない。
		logf("二重起動の確認ができませんでした: %v", callErr)
		return true
	}
	if errno, _ := callErr.(syscall.Errno); errno == errAlreadyExists {
		procCloseHandle.Call(handle)
		return false
	}
	singleInstance = handle
	return true
}

// claimWindowInstance は、このプロセスが画面を出してよいかを返す。
// 既に画面を出している側があれば、そちらを通常表示へ戻して false を返す。
func claimWindowInstance() bool {
	if takeInstance() {
		return true
	}
	if wakeExistingWindow() {
		logf("既に起動しているため、開いている窓を戻しました")
		return false
	}
	// 目印だけが残っていて窓が無いときは、そのまま開く。
	logf("起動中の窓が見つからないため、このまま開きます")
	takeInstance()
	return true
}

// releaseWindowInstance は、次に起動する自分へ席を譲る。
// 差し替えたあとの起動が、二重起動として閉じられないようにするために使う。
func releaseWindowInstance() {
	if singleInstance == 0 {
		return
	}
	procCloseHandle.Call(singleInstance)
	singleInstance = 0
}

// showWindowMessage は、窓を通常表示へ戻す合図の値を返す。
func showWindowMessage() uint32 {
	showMessageOnce.Do(func() {
		v, _, _ := procRegisterMsgW.Call(uintptr(unsafe.Pointer(u16(singleinst.ShowMessageName()))))
		showMessageValue = uint32(v)
	})
	return showMessageValue
}

// wakeExistingWindow は、先に起動している窓を探して手前へ戻す。
func wakeExistingWindow() bool {
	var target uintptr
	found := singleinst.WaitFor(func() bool {
		h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(u16(mainWindowClass))), 0)
		if h == 0 {
			return false
		}
		target = h
		return true
	}, windowWaitAttempts, windowWaitInterval, time.Sleep)
	if !found {
		return false
	}

	// 手前へ出してよいと、いま動いている側へ伝える。
	procAllowSetForegroundW.Call(asfwAny)
	if msg := showWindowMessage(); msg != 0 {
		if ok, _, _ := procPostMessageW.Call(target, uintptr(msg), 0, 0); ok != 0 {
			return true
		}
	}
	// 合図が届かない相手には、そのまま表示へ切り替える。
	procShowWindow.Call(target, swRestore)
	procSetForeground.Call(target)
	return true
}
