package singleinst

import (
	"strings"
	"testing"
	"time"
)

func TestLaunchFlagIndex(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"起動役と対象", []string{"--launch", "chrome"}, 0},
		{"起動役だけ", []string{"--launch"}, 0},
		{"スラッシュ形", []string{"/launch", "edge"}, 0},
		{"後ろに別の指定", []string{"--x", "--launch", "browser"}, 1},
		{"指定なし", []string{"C:\\Users\\me\\NeConnectBridge.exe"}, -1},
		{"空", nil, -1},
		{"似た名前", []string{"--launching"}, -1},
		{"大文字", []string{"--LAUNCH"}, -1},
		{"等号つき", []string{"--launch=browser"}, -1},
		{"語の途中", []string{"--no-launch"}, -1},
	}
	for _, c := range cases {
		if got := LaunchFlagIndex(c.args); got != c.want {
			t.Fatalf("%s: LaunchFlagIndex(%q) = %d, want %d", c.name, c.args, got, c.want)
		}
	}
}

func TestIsLauncherInvocation(t *testing.T) {
	if !IsLauncherInvocation([]string{"--launch", "chrome"}) {
		t.Fatal("launcher invocation not recognized")
	}
	if IsLauncherInvocation([]string{"chrome"}) {
		t.Fatal("plain argument treated as launcher invocation")
	}
}

func TestNamesAreStableAndLocal(t *testing.T) {
	if MutexName() != MutexName() {
		t.Fatal("mutex name changes between calls")
	}
	if !strings.HasPrefix(MutexName(), `Local\`) {
		t.Fatalf("mutex name %q is not in the Local namespace", MutexName())
	}
	if ShowMessageName() == "" || MutexName() == ShowMessageName() {
		t.Fatalf("names collide: mutex=%q message=%q", MutexName(), ShowMessageName())
	}
	// Windows の名前は 260 文字までなので、余裕を持って収める。
	if len(MutexName()) >= 200 || len(ShowMessageName()) >= 200 {
		t.Fatalf("names are too long: %q / %q", MutexName(), ShowMessageName())
	}
	// 名前に実行ファイルの場所などを混ぜないので、同じ PC の同じ利用者では常に同じになる。
	if strings.Contains(MutexName(), " ") {
		t.Fatalf("mutex name contains a space: %q", MutexName())
	}
}

func TestWaitFor(t *testing.T) {
	const interval = 10 * time.Millisecond

	t.Run("すぐ見つかる", func(t *testing.T) {
		sleeps := 0
		ok := WaitFor(func() bool { return true }, 5, interval, func(time.Duration) { sleeps++ })
		if !ok {
			t.Fatal("WaitFor returned false")
		}
		if sleeps != 0 {
			t.Fatalf("slept %d times before the first look", sleeps)
		}
	})

	t.Run("途中で見つかる", func(t *testing.T) {
		sleeps := 0
		tries := 0
		ok := WaitFor(func() bool {
			tries++
			return tries == 3
		}, 5, interval, func(d time.Duration) {
			if d != interval {
				t.Fatalf("sleep interval = %s, want %s", d, interval)
			}
			sleeps++
		})
		if !ok {
			t.Fatal("WaitFor returned false")
		}
		if sleeps != 2 || tries != 3 {
			t.Fatalf("sleeps=%d tries=%d, want 2 and 3", sleeps, tries)
		}
	})

	t.Run("見つからない", func(t *testing.T) {
		sleeps := 0
		tries := 0
		ok := WaitFor(func() bool {
			tries++
			return false
		}, 4, interval, func(time.Duration) { sleeps++ })
		if ok {
			t.Fatal("WaitFor returned true")
		}
		if sleeps != 3 || tries != 4 {
			t.Fatalf("sleeps=%d tries=%d, want 3 and 4", sleeps, tries)
		}
	})

	t.Run("回数が0でも1回は確かめる", func(t *testing.T) {
		tries := 0
		ok := WaitFor(func() bool {
			tries++
			return true
		}, 0, interval, func(time.Duration) {})
		if !ok || tries != 1 {
			t.Fatalf("ok=%v tries=%d, want true and 1", ok, tries)
		}
	})
}
