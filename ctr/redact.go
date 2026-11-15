package ctr

import "strings"

const redactedValue = "<redacted>"

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
