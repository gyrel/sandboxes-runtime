package journal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"
)

// Reason identifies a recovery decision without exposing host paths.
//
//nolint:errname // Reason doubles as the finding's stable identifier, not a sentinel error type.
type Reason string

//nolint:errname // These constants identify findings; Error() existence is incidental.
const (
	MarkerMissing  Reason = "markerMissing"
	MarkerMismatch Reason = "markerMismatch"
	SymlinkRefused Reason = "symlinkRefused"
	OutsideRoot    Reason = "outsideRoot"
	ParseFailed    Reason = "parseFailed"
	TempOrphan     Reason = "tempOrphan"
	// ForeignResource marks a non-filesystem resource another owner controls
	// (generation or token mismatch): recovery leaves it intact.
	ForeignResource Reason = "foreign"
	// UnsupportedOwnership marks a resource the recovery backend cannot attest
	// (no NetworkAttester or backend refusal); recovery never guesses.
	UnsupportedOwnership Reason = "unsupportedOwnership"
)

// ExternalResolver reconciles a non-filesystem resource of a journal record
// (network attachments, containers). handled=true means the resource is
// removed or provably absent; otherwise reason names the LEAVE decision.
type ExternalResolver func(rec Record, res Resource) (handled bool, reason Reason, err error)

// Finding describes an object left for inspection. Resource is a relative path.
type Finding struct {
	ID       string
	Resource string
	Reason   Reason
}

func (f Finding) String() string { return fmt.Sprintf("journal %s: %s", f.ID, f.Reason) }

// Error implements the error interface with the stable reason text.
func (r Reason) Error() string { return string(r) }

// Err returns a stable typed error for this finding.
func (f Finding) Err() error { return f.Reason }

// RecoverDir removes only marker-owned filesystem resources below stateDir.
// It never follows symlinks (os.Root refuses every symlink component), verifies
// the token marker content before each removal, and deletes the journal only
// after every tracked resource resolved to either removed or provably absent.
// now is reserved for future retention policy; recovery makes no age decisions.
func RecoverDir(stateDir string, now func() time.Time) ([]Finding, error) {
	return RecoverWith(stateDir, now, nil)
}

// RecoverWith runs filesystem recovery and, when external is non-nil, hands
// non-filesystem resources (empty rel_path kinds such as network/container)
// to the resolver. Journals are removed only when every resource — filesystem
// or external — resolved to removed-or-absent.
//
//nolint:gocognit // Recovery keeps each journal decision explicit; per-resource work lives in reconcile helpers.
func RecoverWith(stateDir string, now func() time.Time, external ExternalResolver) ([]Finding, error) {
	_ = now
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, fmt.Errorf("open recovery root: %w", err)
	}
	defer func() { _ = root.Close() }()
	jd, err := root.OpenRoot("journal")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open journal directory: %w", err)
	}
	defer func() { _ = jd.Close() }()
	dirFile, err := jd.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open journal directory: %w", err)
	}
	entries, err := dirFile.ReadDir(-1)
	err = errors.Join(err, dirFile.Close())
	if err != nil {
		return nil, fmt.Errorf("read journal directory: %w", err)
	}
	var findings []Finding
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".create-") {
			findings = append(findings, Finding{ID: name, Reason: TempOrphan})
			continue
		}
		if !strings.HasPrefix(name, "create-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "create-"), ".json")
		if entry.Type()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{ID: id, Reason: SymlinkRefused})
			continue
		}
		rec, ok := readJournal(jd, name, id)
		if !ok {
			findings = append(findings, Finding{ID: id, Reason: ParseFailed})
			continue
		}
		clean, recFindings, recErrs := reconcileRecord(root, id, rec, external)
		findings = append(findings, recFindings...)
		errs = append(errs, recErrs...)
		if clean {
			if err := jd.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("journal %s: unlink: %w", id, err))
			}
		}
	}
	return findings, errors.Join(errs...)
}

func readJournal(jd *os.Root, name, id string) (Record, bool) {
	f, err := jd.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Record{}, false
		}
		return Record{}, false
	}
	info, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, MaxRecordSize+1))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() {
		return Record{}, false
	}
	rec, parseErr := Parse(data)
	if parseErr != nil || rec.ID != id {
		return Record{}, false
	}
	return rec, true
}

// recoverResource resolves rel under root and removes the resource (then its
// marker) only when the marker proves ownership. Reasons are returned for
// every LEAVE decision; absent-and-consistent pairs count as completed.
//
//nolint:gocognit,gocyclo,cyclop // Ownership checks are intentionally explicit.
func recoverResource(root *os.Root, rel, token string) (Reason, error) {
	if rel == "" || !validRelativePath(rel) {
		return OutsideRoot, nil
	}
	parts := strings.Split(rel, "/")
	parent, cleanup, reason, err := descend(root, parts[:len(parts)-1])
	defer cleanup()
	if err != nil || reason != "" || parent == nil {
		return reason, err
	}
	name := parts[len(parts)-1]
	marker := name + ".gyrel-token"
	resourceInfo, resourceErr := parent.Lstat(name)
	if resourceErr != nil && !errors.Is(resourceErr, fs.ErrNotExist) {
		return "", resourceErr
	}
	if resourceErr == nil && resourceInfo.Mode()&os.ModeSymlink != 0 {
		return SymlinkRefused, nil
	}
	markerInfo, markerErr := parent.Lstat(marker)
	switch {
	case errors.Is(markerErr, fs.ErrNotExist):
		if errors.Is(resourceErr, fs.ErrNotExist) {
			return "", nil // both entries absent: cleanup already completed
		}
		return MarkerMissing, nil
	case markerErr != nil:
		return "", markerErr
	}
	if markerInfo.Mode()&os.ModeSymlink != 0 {
		return SymlinkRefused, nil
	}
	if !markerInfo.Mode().IsRegular() || !markerModeTrusted(markerInfo) {
		return MarkerMismatch, nil
	}
	if reason, err := verifyMarkerToken(parent, marker, token); err != nil || reason != "" {
		return reason, err
	}
	// Remove the resource first, then the marker: a crash between the two
	// leaves a marker without a resource, which reads as completed.
	if resourceErr == nil {
		if err := removeEntry(parent, name); err != nil {
			return "", err
		}
	}
	if err := parent.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return "", nil
}

// descend opens each intermediate directory with symlink refusal and returns
// the deepest handle plus a cleanup closing every intermediate it opened. A
// missing intermediate proves all deeper entries absent.
func descend(root *os.Root, dirs []string) (*os.Root, func(), Reason, error) {
	var opened []*os.Root
	cleanup := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			_ = opened[i].Close()
		}
	}
	current := root
	for _, dir := range dirs {
		next, err := current.OpenRoot(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, cleanup, "", nil
			}
			if isSymlinkError(current, dir, err) {
				return nil, cleanup, SymlinkRefused, nil
			}
			return nil, cleanup, "", err
		}
		opened = append(opened, next)
		current = next
	}
	return current, cleanup, "", nil
}

func isSymlinkError(parent *os.Root, name string, err error) bool {
	if !errors.Is(err, fs.ErrInvalid) && !errors.Is(err, os.ErrInvalid) {
		return false
	}
	info, statErr := parent.Lstat(name)
	return statErr == nil && info.Mode()&os.ModeSymlink != 0
}

// markerModeTrusted enforces 0600 where Unix permission bits exist; Windows
// ACLs are evaluated by the token-content check instead.
func markerModeTrusted(info fs.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm() == 0o600
}

func verifyMarkerToken(parent *os.Root, marker, token string) (Reason, error) {
	f, err := parent.Open(marker)
	if err != nil {
		if isSymlinkError(parent, marker, err) {
			return SymlinkRefused, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return MarkerMissing, nil
		}
		return "", err
	}
	reopened, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, 33))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil {
		return "", errors.Join(statErr, readErr, closeErr)
	}
	if !reopened.Mode().IsRegular() || !markerModeTrusted(reopened) || string(data) != token {
		return MarkerMismatch, nil
	}
	// Recheck that the name still refers to the marker we verified.
	final, err := parent.Lstat(marker)
	if err != nil || !os.SameFile(reopened, final) {
		return MarkerMismatch, nil
	}
	return "", nil
}

// removeEntry deletes one owned entry; directories are emptied recursively.
func removeEntry(parent *os.Root, name string) error {
	info, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		dir, err := parent.Open(name)
		if err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(-1)
		closeErr := dir.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, entry := range entries {
			if err := removeEntry(parent, name+"/"+entry.Name()); err != nil {
				return err
			}
		}
	}
	return parent.Remove(name)
}

// reconcileResource resolves one journal resource: non-filesystem entries
// (empty rel_path) go to the external resolver when provided; everything
// else gets marker-proven filesystem recovery.
func reconcileResource(root *os.Root, id string, rec Record, res Resource, external ExternalResolver) ([]Finding, []error, bool) {
	if res.RelPath == "" && external != nil {
		handled, reason, extErr := external(rec, res)
		if extErr != nil {
			return nil, []error{fmt.Errorf("journal %s: external cleanup failed: %w", id, extErr)}, false
		}
		if handled {
			return nil, nil, true
		}
		if reason == "" {
			reason = ForeignResource
		}
		return []Finding{{ID: id, Resource: res.NativeID, Reason: reason}}, nil, false
	}
	reason, cleanupErr := recoverResource(root, res.RelPath, rec.Token)
	var findings []Finding
	var errs []error
	clean := true
	if reason != "" {
		findings = append(findings, Finding{ID: id, Resource: res.RelPath, Reason: reason})
		clean = false
	}
	if cleanupErr != nil {
		errs = append(errs, fmt.Errorf("journal %s: cleanup failed: %w", id, cleanupErr))
		clean = false
	}
	return findings, errs, clean
}

// reconcileRecord applies reconcileResource across a record's resources.
func reconcileRecord(root *os.Root, id string, rec Record, external ExternalResolver) (bool, []Finding, []error) {
	clean := true
	var findings []Finding
	var errs []error
	for _, res := range rec.Resources {
		f, e, ok := reconcileResource(root, id, rec, res, external)
		findings = append(findings, f...)
		errs = append(errs, e...)
		if !ok {
			clean = false
		}
	}
	return clean, findings, errs
}
