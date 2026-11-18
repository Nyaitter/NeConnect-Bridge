// Package wintext は、Windows に渡す文字列を作る。
package wintext

import "unicode/utf16"

// Units は、終端の 0 まで含めた形を返す。
// 途中の 0 もそのまま残すので、NUL で区切った一覧にも使える。
func Units(s string) []uint16 {
	units := utf16.Encode([]rune(s))
	if len(units) == 0 || units[len(units)-1] != 0 {
		units = append(units, 0)
	}
	return units
}

// MultiString は、NUL で区切った一連の文字列を、終端付きの形にする。
// syscall.StringToUTF16Ptr は NUL を含む文字列を受け取れないため、こちらで作る。
func MultiString(s string) *uint16 {
	units := Units(s)
	return &units[0]
}
