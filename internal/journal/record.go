// Package journal defines the durable representation of a create attempt.
package journal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/gyrel/sandboxes-core/ids"
)

const (
	// MaxRecordSize bounds memory used while parsing untrusted journal files.
	MaxRecordSize = 1 << 20
	maxResources  = 4096
)

// Record is a versioned create attempt. Resource paths are relative to a
// runtime-owned root, never absolute host paths.
type Record struct {
	Schema        int        `json:"schema"`
	ID            string     `json:"id"`
	OpID          string     `json:"op_id,omitempty"`
	Token         string     `json:"token"`
	Phase         string     `json:"phase"`
	Resources     []Resource `json:"resources"`
	StartedAtUnix int64      `json:"started_at_unix"`
}

// Resource describes an external object created by an attempt.
type Resource struct {
	Kind     string `json:"kind"`
	NativeID string `json:"native_id"`
	RelPath  string `json:"rel_path"`
	Marked   bool   `json:"marked"`
}

// Parse rejects malformed, oversized, ambiguous, or unsupported records.
func Parse(data []byte) (Record, error) {
	var record Record
	if len(data) > MaxRecordSize {
		return record, errors.New("journal exceeds size limit")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return record, fmt.Errorf("invalid journal: %w", err)
	}
	if err := validateFields(data); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode journal: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("journal has trailing data")
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// validateFields requires the exact schema, including false-valued fields.
func validateFields(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("invalid journal object")
	}
	if value, ok := fields["op_id"]; ok {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null journal op_id")
		}
		delete(fields, "op_id")
	}
	if err := exactFields(fields, "schema", "id", "token", "phase", "resources", "started_at_unix"); err != nil {
		return err
	}
	var resources []json.RawMessage
	if err := json.Unmarshal(fields["resources"], &resources); err != nil || resources == nil || len(resources) > maxResources {
		return errors.New("invalid journal resources")
	}
	for _, raw := range resources {
		var resource map[string]json.RawMessage
		if err := json.Unmarshal(raw, &resource); err != nil {
			return errors.New("invalid journal resource")
		}
		if err := exactFields(resource, "kind", "native_id", "rel_path", "marked"); err != nil {
			return err
		}
	}
	return nil
}

func exactFields(fields map[string]json.RawMessage, names ...string) error {
	if len(fields) != len(names) {
		return errors.New("invalid journal fields")
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("missing or null journal field")
		}
	}
	return nil
}

// Validate checks structural invariants without trusting paths as ownership proof.
func (r Record) Validate() error {
	if !validHeader(r) {
		return errors.New("invalid journal header")
	}
	if !validOpID(r.Schema, r.OpID) {
		return errors.New("invalid journal op_id")
	}
	token, err := hex.DecodeString(r.Token)
	if err != nil || len(token) != 16 || r.Token != strings.ToLower(r.Token) {
		return errors.New("invalid journal token")
	}
	switch r.Phase {
	case "pending", "network", "run", "done":
	default:
		return errors.New("invalid journal phase")
	}
	if r.Resources == nil || len(r.Resources) > maxResources {
		return errors.New("invalid journal resources")
	}
	seen := make(map[string]struct{}, len(r.Resources))
	for _, resource := range r.Resources {
		if !validResource(resource) {
			return errors.New("invalid journal resource")
		}
		key := resource.Kind + "\x00" + resource.NativeID + "\x00" + resource.RelPath
		if _, ok := seen[key]; ok {
			return errors.New("duplicate journal resource")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validResource(resource Resource) bool {
	return validName(resource.Kind) && len(resource.NativeID) <= 1024 && !strings.ContainsRune(resource.NativeID, 0) && validRelativePath(resource.RelPath)
}

func validName(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !nameCharacter(c) {
			return false
		}
	}
	return true
}

func nameCharacter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

func validRelativePath(value string) bool {
	if value == "" { // Non-filesystem resources need no path.
		return true
	}
	return len(value) <= 4096 && !strings.ContainsAny(value, "\\\x00") && !strings.HasPrefix(value, "/") && value != "." && value != ".." && path.Clean(value) == value && !strings.HasPrefix(value, "../")
}

// rejectDuplicateKeys avoids different interpretations of the same JSON by
// parsers that use first- or last-key-wins semantics.
func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func consumeValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObject(decoder, depth)
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeObject(decoder *json.Decoder, depth int) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid object key")
		}
		if _, exists := keys[key]; exists {
			return errors.New("duplicate object key")
		}
		keys[key] = struct{}{}
		if err := consumeValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func validHeader(r Record) bool {
	return (r.Schema == 1 || r.Schema == 2) && validName(r.ID) && r.StartedAtUnix > 0
}

func validOpID(schema int, id string) bool {
	return id == "" || (schema == 2 && strings.HasPrefix(id, "op_") && ids.Validate(id) == nil)
}
