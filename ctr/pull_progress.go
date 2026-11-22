package ctr

import (
	"bytes"
	"strings"
)

// Progress is the ctr-adapter view of an in-flight image pull. Phase is a
// machine-readable label ("pulling"), Completed/Total count distinct image
// layers whose ctr status reached "complete"/seen. It is advisory display
// data and never a lifecycle signal.
type Progress struct {
	Phase     string
	Completed int64
	Total     int64
}

// pullTrackerMaxFrame bounds the unterminated-frame buffer. ctr redraws
// progress frames with \r and \n separators; a runaway frame without any
// separator is dropped head-first rather than growing memory.
const pullTrackerMaxFrame = 16 * 1024

// pullTracker folds the redraw-heavy `ctr images pull` progress tree into
// distinct-layer counters. Tree lines look like:
//
//	├──layer (b7777c923ed2)           downloading |++++------| 9.2 MiB/38.9 MiB
//	  ├──manifest (37793cfc622c)       complete   |++++++++++|
//
// Only layer entries count toward Total. A layer stays complete once any
// frame reported it complete; frames may arrive split across read chunks.
type pullTracker struct {
	layers  map[string]bool
	buf     []byte
	emit    func(Progress)
	last    Progress
	hasEmit bool
}

func newPullTracker(emit func(Progress)) *pullTracker {
	return &pullTracker{layers: map[string]bool{}, emit: emit}
}

// observe feeds one raw output chunk and processes every completed frame.
func (t *pullTracker) observe(chunk []byte) {
	t.buf = append(t.buf, chunk...)
	for {
		i := bytes.IndexAny(t.buf, "\r\n")
		if i < 0 {
			break
		}
		t.frame(string(t.buf[:i]))
		t.buf = t.buf[i+1:]
	}
	if len(t.buf) > pullTrackerMaxFrame {
		t.buf = t.buf[len(t.buf)-pullTrackerMaxFrame:]
	}
}

// finish processes the trailing unterminated frame.
func (t *pullTracker) finish() {
	if len(t.buf) > 0 {
		t.frame(string(t.buf))
		t.buf = nil
	}
}

func (t *pullTracker) frame(line string) {
	idx := strings.Index(line, "layer (")
	if idx < 0 {
		return
	}
	rest := line[idx+len("layer ("):]
	id, after, found := strings.Cut(rest, ")")
	if !found || id == "" {
		return
	}
	status := ""
	if fields := strings.Fields(after); len(fields) > 0 {
		status = fields[0]
	}
	if _, seen := t.layers[id]; !seen {
		t.layers[id] = false
	}
	if status == "complete" {
		t.layers[id] = true
	}
	t.publish()
}

func (t *pullTracker) publish() {
	p := Progress{Phase: "pulling", Total: int64(len(t.layers))}
	for _, done := range t.layers {
		if done {
			p.Completed++
		}
	}
	if t.hasEmit && p == t.last {
		return
	}
	t.last = p
	t.hasEmit = true
	if t.emit != nil {
		t.emit(p)
	}
}
