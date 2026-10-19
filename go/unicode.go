package main

// Unicode 16.0.0 tables are generated from the immutable Unicode UCD release.
// Hashing never normalizes names; these functions are exclusively validators.
func unicode16Control(r rune) bool {
	lo, hi := 0, len(unicode16Controls)
	for lo < hi {
		mid := (lo + hi) / 2
		if unicode16Controls[mid][1] < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(unicode16Controls) && unicode16Controls[lo][0] <= r
}
func decompose16(r rune, out *[]rune) {
	const sBase, lBase, vBase, tBase rune = 0xac00, 0x1100, 0x1161, 0x11a7
	if r >= sBase && r < sBase+11172 {
		n := r - sBase
		*out = append(*out, lBase+n/588, vBase+(n%588)/28)
		if n%28 != 0 {
			*out = append(*out, tBase+n%28)
		}
		return
	}
	if d, ok := unicode16Decompositions[r]; ok {
		for _, c := range d {
			decompose16(c, out)
		}
		return
	}
	*out = append(*out, r)
}
func compose16(a, b rune) rune {
	if a >= 0x1100 && a < 0x1113 && b >= 0x1161 && b < 0x1176 {
		return 0xac00 + (a-0x1100)*588 + (b-0x1161)*28
	}
	if a >= 0xac00 && a < 0xd7a4 && (a-0xac00)%28 == 0 && b > 0x11a7 && b < 0x11c3 {
		return a + b - 0x11a7
	}
	return unicode16Compositions[[2]rune{a, b}]
}
func nfc16(s string) string {
	var d []rune
	for _, r := range s {
		decompose16(r, &d)
	}
	for i := 1; i < len(d); i++ {
		c := unicode16Combining[d[i]]
		if c == 0 {
			continue
		}
		j := i
		for j > 0 && unicode16Combining[d[j-1]] > c {
			d[j], d[j-1] = d[j-1], d[j]
			j--
		}
	}
	out := make([]rune, 0, len(d))
	starter := -1
	last := uint8(0)
	for _, r := range d {
		c := unicode16Combining[r]
		if starter >= 0 && (last < c || last == 0) {
			if composed := compose16(out[starter], r); composed != 0 {
				out[starter] = composed
				continue
			}
		}
		if c == 0 {
			starter = len(out)
		}
		out = append(out, r)
		last = c
	}
	return string(out)
}
func unicode16Fold(s string) string {
	s = nfc16(s)
	var folded []rune
	for _, r := range s {
		if f, ok := unicode16Folds[r]; ok {
			folded = append(folded, []rune(f)...)
		} else {
			folded = append(folded, r)
		}
	}
	return nfc16(string(folded))
}
