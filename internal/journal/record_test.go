package journal

import (
	"strings"
	"testing"
)

const validRecord = `{"schema":1,"id":"create-1","token":"0123456789abcdef0123456789abcdef","phase":"run","resources":[{"kind":"fifo","native_id":"id","rel_path":"run/fifo","marked":true}],"started_at_unix":1730000000}`

func TestParse(t *testing.T) {
	tests := []struct {
		name, input string
		valid       bool
	}{
		{"valid", validRecord, true},
		{"unknown", strings.Replace(validRecord, `"schema":1`, `"schema":1,"unknown":1`, 1), false},
		{"duplicate", strings.Replace(validRecord, `"schema":1`, `"schema":1,"schema":1`, 1), false},
		{"traversal", strings.Replace(validRecord, `run/fifo`, `../fifo`, 1), false},
		{"absolute", strings.Replace(validRecord, `run/fifo`, `/run/fifo`, 1), false},
		{"token", strings.Replace(validRecord, `0123456789abcdef0123456789abcdef`, `0123`, 1), false},
		{"truncated", validRecord[:len(validRecord)-1], false},
		{"trailing", validRecord + `{}`, false},
		{"large", strings.Repeat(" ", MaxRecordSize+1), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("Parse error = %v, valid = %v", err, tc.valid)
			}
		})
	}
}

func FuzzJournalParse(f *testing.F) {
	f.Add([]byte(validRecord))
	f.Add([]byte(`{"schema":1`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Parse(data) })
}
