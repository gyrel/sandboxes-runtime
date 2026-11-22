package ctr

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const redactedValue = "<redacted>"

// hostPathPlaceholder replaces absolute host filesystem locations in errors
// returned from ctr. AGENTS.md §5 forbids surfacing user paths without
// redaction: pull/run failures travel through gRPC into CLI output and CI
// logs, so the socket, state and binary roots and the user home must not be
// embedded in those strings. The last path element stays visible because
// names like containerd.sock are actionable and carry no personal data.
const hostPathPlaceholder = "<host-path>"

// formatArgs renders argv for error and log messages with environment values
// masked. Flags and environment variable names stay readable; arguments that
// are not environment overrides are rendered unchanged.
func formatArgs(args []string) string {
	rendered := make([]string, len(args))
	copy(rendered, args)
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--env" || args[i] == "--env-file":
			if i+1 < len(args) {
				i++
				rendered[i] = redactedEnvValue(args[i])
			}
		case strings.HasPrefix(args[i], "--env="):
			rendered[i] = "--env=" + redactedEnvValue(strings.TrimPrefix(args[i], "--env="))
		case strings.HasPrefix(args[i], "--env-file="):
			rendered[i] = "--env-file=" + redactedEnvValue(strings.TrimPrefix(args[i], "--env-file="))
		}
	}
	return strings.Join(rendered, " ")
}

// redactedEnvValue keeps a valid KEY= prefix so failures remain actionable
// while hiding the value. Values without a recognizable KEY= prefix, such as
// environment file paths, are hidden entirely.
func redactedEnvValue(value string) string {
	key, _, ok := strings.Cut(value, "=")
	if !ok || !validEnvName(key) {
		return redactedValue
	}
	return key + "=" + redactedValue
}

// redactionRoots lists the host filesystem prefixes whose concrete location
// must never reach a returned error: the socket and its directory, the ctr
// binary and its directory, and the user home. Home is resolved best-effort;
// a failure only removes one layer, the configured roots are still masked.
func (c *Client) redactionRoots() []string {
	roots := make([]string, 0, 6)
	add := func(root string) {
		for _, variant := range pathVariants(root) {
			if variant != "" && variant != "." && variant != "/" && !strings.Contains(variant, " ") {
				roots = append(roots, variant)
			}
		}
	}
	add(c.cfg.Socket)
	add(c.cfg.CTR)
	if abs, err := filepath.Abs(c.cfg.CTR); err == nil {
		add(abs)
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(home)
	}
	// Longest first so a nested root (home inside a parent) is masked
	// completely before the shorter prefix would fragment it.
	sort.Slice(roots, func(i, j int) bool { return len(roots[i]) > len(roots[j]) })
	return roots
}

// pathVariants expands one filesystem path into the shapes host output can
// take regardless of the OS running us: the raw value, both separator
// spellings (ctr logs on a Windows host can mix forward and backslashes, and
// a POSIX-spelled socket configured on Windows must still mask backslashed
// output and vice versa), and the parent directory under each spelling.
// Redaction roots are a fail-closed superset: extra variants can only widen
// masking, never weaken it.
func pathVariants(p string) []string {
	if p == "" {
		return nil
	}
	out := []string{p}
	if slashed := filepath.ToSlash(p); slashed != p {
		out = append(out, slashed)
	}
	if slashed := filepath.FromSlash(p); slashed != p {
		out = append(out, slashed)
	}
	for _, v := range append([]string(nil), out...) {
		if idx := strings.LastIndexAny(v, `/\`); idx > 0 {
			out = append(out, v[:idx])
		}
	}
	return out
}

// redactHostPaths replaces every configured host root inside s with the
// placeholder plus only the final element of the path token, so intermediate
// host directories (user name, state layout) never survive while the file
// name keeps the message actionable.
func redactHostPaths(s string, roots []string) string {
	for _, root := range roots {
		var b strings.Builder
		b.Grow(len(s))
		pos := 0
		for pos < len(s) {
			rel := strings.Index(s[pos:], root)
			if rel < 0 {
				b.WriteString(s[pos:])
				break
			}
			start := pos + rel
			end := start + len(root)
			for end < len(s) && !isPathBreak(s[end]) {
				end++
			}
			path := s[start:end]
			replacement := hostPathPlaceholder
			if base := path[strings.LastIndexAny(path, `/\`)+1:]; base != "" {
				replacement += "/" + base
			}
			b.WriteString(s[pos:start])
			b.WriteString(replacement)
			// Resume after the original token; the replacement is never
			// rescanned, so a basename equal to the root cannot loop.
			pos = end
		}
		s = b.String()
	}
	return s
}

// isPathBreak reports whether b ends a filesystem path token inside ctr
// output and argv renderings.
func isPathBreak(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ',', ';', '"', '\'', '(', ')', '=', ':':
		return true
	}
	return false
}

// redactedError carries an API-safe message while keeping the underlying
// execution error available for errors.Is/errors.As classification: exit
// status inspection (exec.go) must not depend on message text.
type redactedError struct {
	message string
	cause   error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

// outputTail keeps the last meaningful lines of ctr output for the returned
// error. The ctr pull/run progress logs are hundreds of lines and repeat the
// command line verbatim; the actionable failure reason is the final line.
func outputTail(out string) string {
	lines := make([]string, 0, 4)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	const maxLines = 3
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	tail := strings.Join(lines, " | ")
	tailRunes := []rune(tail)
	const maxRunes = 320
	if len(tailRunes) > maxRunes {
		tail = string(tailRunes[len(tailRunes)-maxRunes:])
	}
	return tail
}
