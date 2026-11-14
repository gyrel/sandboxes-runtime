package bundle

import "unicode"

// foldKey mirrors encoding/json's case-folding for field-name matching. The
// standard library prefers an exact field-name match, then falls back to this
// fold when decoding structs. We use the same identity when rejecting aliases
// so differently-cased keys cannot overwrite the same typed field.
func foldKey(value string) string {
	folded := make([]rune, 0, len(value))
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		} else if r >= unicode.MaxASCII {
			r = foldRune(r)
		}
		folded = append(folded, r)
	}
	return string(folded)
}

func foldRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}
