package wintext

import "testing"

func TestUnitsKeepsTheSeparatorsAndEndsWithZero(t *testing.T) {
	got := Units("ショートカット (*.lnk)\x00*.lnk\x00すべてのファイル (*.*)\x00*.*\x00\x00")
	if len(got) == 0 || got[len(got)-1] != 0 {
		t.Fatalf("the list does not end with a terminator: %v", got)
	}
	// 区切りの数は変わらない。
	zeros := 0
	for _, unit := range got {
		if unit == 0 {
			zeros++
		}
	}
	if zeros != 5 {
		t.Fatalf("separators = %d, want 5 (%v)", zeros, got)
	}
}

func TestUnitsAddsTheTerminatorOnlyOnce(t *testing.T) {
	got := Units("lnk")
	if len(got) != 4 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0] != 'l' || got[1] != 'n' || got[2] != 'k' || got[3] != 0 {
		t.Fatalf("units = %v", got)
	}
}

func TestUnitsHandlesEmptyText(t *testing.T) {
	got := Units("")
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("units = %v", got)
	}
}

func TestMultiStringPointsAtTheTerminator(t *testing.T) {
	units := Units("*.exe\x00*.lnk\x00\x00")
	got := MultiString("*.exe\x00*.lnk\x00\x00")
	if got == nil {
		t.Fatal("nil pointer")
	}
	if *got != units[0] {
		t.Fatalf("first unit = %d", *got)
	}
}

func TestUnitsHandlesTextOutsideTheBasicPlane(t *testing.T) {
	got := Units("🐾")
	if len(got) != 3 {
		t.Fatalf("len = %d", len(got))
	}
	if got[2] != 0 {
		t.Fatalf("units = %v", got)
	}
}
