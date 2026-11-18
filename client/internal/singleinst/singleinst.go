// Package singleinst は、二重に起動されたときに、先に開いている画面へ戻すための目印を扱う。
// Windows の呼び出しは、この目印を使って行う。
package singleinst

import "time"

const (
	// mutexName は、画面を出している側を1つに保つための名前。
	// Local は同じ PC の同じ利用者の中でだけ通用するので、別の利用者の起動には影響しない。
	mutexName = `Local\NeConnectBridge_SingleInstance`

	// ShowMessageName は、窓を通常表示へ戻してほしいと伝える合図の名前。
	showMessageName = "NeConnectBridge_ShowMainWindow"
)

// launchFlags は、画面を出さずに起動役として走る指定。
// 起動役は、画面が開いていても並んで動く必要がある。
var launchFlags = []string{"--launch", "/launch"}

// MutexName は、二重起動を見分けるための名前を返す。
func MutexName() string {
	return mutexName
}

// ShowMessageName は、窓を戻す合図の名前を返す。
func ShowMessageName() string {
	return showMessageName
}

// LaunchFlagIndex は、args の中で起動役の指定がある位置を返す。無ければ -1。
func LaunchFlagIndex(args []string) int {
	for i, arg := range args {
		for _, flag := range launchFlags {
			if arg == flag {
				return i
			}
		}
	}
	return -1
}

// IsLauncherInvocation は、画面を出さない起動役として走る呼び出しかを返す。
func IsLauncherInvocation(args []string) bool {
	return LaunchFlagIndex(args) >= 0
}

// WaitFor は、find が true を返すまで interval ごとに待つ。
// 最初の1回は待たずに確かめ、待つのは attempts-1 回まで。
func WaitFor(find func() bool, attempts int, interval time.Duration, sleep func(time.Duration)) bool {
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 && sleep != nil {
			sleep(interval)
		}
		if find() {
			return true
		}
	}
	return false
}
