// Package bundle validates the contents and declared platform of a Rheic
// runtime bundle. It does not authenticate bundle.json; callers must verify
// the enclosing archive's provenance before trusting this manifest.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ManifestName  = "bundle.json"
	SchemaV1      = 1
	Partial       = "partial"
	RequiredRoles = "required-roles"
	maxManifest   = 1 << 20
)

var requiredComponents = []string{"containerd", "ctr", "nerdbox-shim", "gvproxy", "libkrun", "kernel", "guest-rootfs"}

var openBundleRootTestHook func()

// Manifest is a content inventory, not a provenance statement.
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Platform      string     `json:"platform"`
	Completeness  string     `json:"completeness"`
	Files         []FileItem `json:"files"`
}

// FileItem identifies one regular file relative to the bundle root.
type FileItem struct {
	Component string `json:"component"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

// Options defines the target platform and whether experimental partial bundles
// may be verified by this caller.
type Options struct {
	ExpectedPlatform string
	AllowPartial     bool
}

// WriteManifest creates bundle.json from the declared artifact paths. It
// refuses to overwrite an existing manifest and validates the complete
// inventory before returning. The resulting manifest remains unauthenticated.
func WriteManifest(root, platform, completeness string, declarations []FileItem) (resultErr error) {
	if err := validateManifestHeader(platform, completeness, len(declarations)); err != nil {
		return err
	}
	rootDir, err := openBundleRoot(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rootDir.Close()) }()
	if _, err := rootDir.Lstat(ManifestName); err == nil {
		return errors.New("bundle manifest already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect existing bundle manifest: %w", err)
	}
	manifest, err := createManifest(rootDir, platform, completeness, declarations)
	if err != nil {
		return err
	}
	if err := installManifest(rootDir, manifest); err != nil {
		return err
	}
	if err := verifyInventory(rootDir, manifest); err != nil {
		_ = rootDir.Remove(ManifestName)
		return err
	}
	return nil
}

// Verify checks manifest structure, platform, completeness, exact file
// inventory, lengths, and SHA-256 digests. It does not authenticate the
// manifest. Verify the enclosing archive with GitHub artifact attestations
// before treating these results as supply-chain evidence.
func Verify(root string, options Options) (manifest Manifest, resultErr error) {
	if !validPlatform(options.ExpectedPlatform) {
		return Manifest{}, fmt.Errorf("unsupported expected platform %q", options.ExpectedPlatform)
	}
	rootDir, err := openBundleRoot(root)
	if err != nil {
		return Manifest{}, fmt.Errorf("open bundle root: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, rootDir.Close()) }()
	manifest, err = readManifest(rootDir)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.SchemaVersion != SchemaV1 {
		return Manifest{}, fmt.Errorf("unsupported bundle schema version %d", manifest.SchemaVersion)
	}
	if manifest.Platform != options.ExpectedPlatform {
		return Manifest{}, fmt.Errorf("bundle platform %q does not match required %q", manifest.Platform, options.ExpectedPlatform)
	}
	if manifest.Completeness == Partial && !options.AllowPartial {
		return Manifest{}, errors.New("partial runtime bundle is experimental and not accepted by this verification policy")
	}
	if err := validateCompleteness(manifest); err != nil {
		return Manifest{}, err
	}
	if err := verifyInventory(rootDir, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func openBundleRoot(root string) (*os.Root, error) {
	info, err := captureBundleRootIdentity(root)
	if err != nil {
		return nil, fmt.Errorf("inspect bundle root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("bundle root must be a real directory")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle root: %w", err)
	}
	if openBundleRootTestHook != nil {
		openBundleRootTestHook()
	}
	rootDir, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("open bundle root: %w", err)
	}
	openedInfo, err := rootDir.Stat(".")
	if err != nil {
		_ = rootDir.Close()
		return nil, fmt.Errorf("inspect opened bundle root: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		_ = rootDir.Close()
		return nil, errors.New("bundle root changed while opening")
	}
	return rootDir, nil
}

func validateManifestHeader(platform, completeness string, fileCount int) error {
	if !validPlatform(platform) {
		return fmt.Errorf("unsupported bundle platform %q", platform)
	}
	if completeness != Partial && completeness != RequiredRoles {
		return fmt.Errorf("invalid bundle completeness %q", completeness)
	}
	if fileCount == 0 {
		return errors.New("bundle manifest must contain at least one file")
	}
	return nil
}

func createManifest(rootDir *os.Root, platform, completeness string, declarations []FileItem) (Manifest, error) {
	manifest := Manifest{SchemaVersion: SchemaV1, Platform: platform, Completeness: completeness}
	components := make(map[string]struct{}, len(declarations))
	paths := make(map[string]struct{}, len(declarations))
	for _, item := range declarations {
		if err := validateItemPath(item.Path); err != nil {
			return Manifest{}, err
		}
		if strings.TrimSpace(item.Component) == "" {
			return Manifest{}, errors.New("bundle component must not be empty")
		}
		pathKey := foldKey(item.Path)
		if _, ok := components[item.Component]; ok {
			return Manifest{}, fmt.Errorf("duplicate bundle component %q", item.Component)
		}
		if _, ok := paths[pathKey]; ok {
			return Manifest{}, fmt.Errorf("duplicate bundle path %q", item.Path)
		}
		components[item.Component] = struct{}{}
		paths[pathKey] = struct{}{}
		digested, err := digestArtifact(rootDir, item)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, digested)
	}
	if err := validateCompleteness(manifest); err != nil {
		return Manifest{}, err
	}
	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return manifest, nil
}

func digestArtifact(rootDir *os.Root, item FileItem) (FileItem, error) {
	info, err := rootDir.Lstat(filepath.FromSlash(item.Path))
	if err != nil {
		return FileItem{}, fmt.Errorf("inspect bundle artifact %q: %w", item.Path, err)
	}
	if !info.Mode().IsRegular() {
		return FileItem{}, fmt.Errorf("bundle artifact %q must be a regular file", item.Path)
	}
	file, err := rootDir.Open(filepath.FromSlash(item.Path))
	if err != nil {
		return FileItem{}, fmt.Errorf("open bundle artifact %q: %w", item.Path, err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return FileItem{}, fmt.Errorf("hash bundle artifact %q: %w", item.Path, err)
	}
	item.SHA256 = hex.EncodeToString(hash.Sum(nil))
	item.Size = size
	return item, nil
}

func installManifest(rootDir *os.Root, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bundle manifest: %w", err)
	}
	data = append(data, '\n')
	const tmpName = ".bundle-manifest.tmp"
	tmp, err := rootDir.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create bundle manifest: %w", err)
	}
	defer func() { _ = rootDir.Remove(tmpName) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set bundle manifest permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write bundle manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close bundle manifest: %w", err)
	}
	if err := rootDir.Link(tmpName, ManifestName); err != nil {
		return fmt.Errorf("install bundle manifest: %w", err)
	}
	if err := rootDir.Remove(tmpName); err != nil {
		_ = rootDir.Remove(ManifestName)
		return fmt.Errorf("remove temporary bundle manifest: %w", err)
	}
	return nil
}

func readManifest(rootDir *os.Root) (Manifest, error) {
	info, err := rootDir.Lstat(ManifestName)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect bundle manifest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, errors.New("bundle manifest must be a regular file")
	}
	manifestFile, err := rootDir.Open(ManifestName)
	if err != nil {
		return Manifest{}, fmt.Errorf("open bundle manifest: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(manifestFile, maxManifest+1))
	closeErr := manifestFile.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return Manifest{}, fmt.Errorf("read bundle manifest: %w", err)
	}
	if len(data) > maxManifest {
		return Manifest{}, errors.New("bundle manifest exceeds 1 MiB limit")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Manifest{}, fmt.Errorf("decode bundle manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode bundle manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("bundle manifest has trailing JSON data")
		}
		return Manifest{}, fmt.Errorf("decode bundle manifest trailing data: %w", err)
	}
	return manifest, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("bundle manifest has trailing JSON data")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		return expectJSONDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func consumeJSONObject(decoder *json.Decoder) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("JSON object key is not a string")
		}
		originalKey := key
		key = foldKey(key)
		if _, ok := keys[key]; ok {
			return fmt.Errorf("duplicate JSON object key %q", originalKey)
		}
		keys[key] = struct{}{}
		if err := consumeJSONValue(decoder); err != nil {
			return err
		}
	}
	return expectJSONDelimiter(decoder, '}')
}

func expectJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return fmt.Errorf("unexpected JSON delimiter %v; expected %q", token, expected)
	}
	return nil
}

func verifyInventory(rootDir *os.Root, manifest Manifest) error {
	listed, err := validateInventoryEntries(manifest.Files)
	if err != nil {
		return err
	}
	if err := validateParentDirectories(rootDir, listed); err != nil {
		return err
	}
	seen, err := scanBundleInventory(rootDir, listed)
	if err != nil {
		return err
	}
	for name, item := range listed {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("bundle artifact %q is missing", name)
		}
		if err := verifyArtifact(rootDir, name, item); err != nil {
			return err
		}
	}
	return nil
}

func validateInventoryEntries(items []FileItem) (map[string]FileItem, error) {
	listed := make(map[string]FileItem, len(items))
	components := make(map[string]struct{}, len(items))
	pathKeys := make(map[string]struct{}, len(items))
	for _, item := range items {
		if err := addInventoryEntry(listed, components, pathKeys, item); err != nil {
			return nil, err
		}
	}
	return listed, nil
}

func addInventoryEntry(listed map[string]FileItem, components, pathKeys map[string]struct{}, item FileItem) error {
	if err := validateItemPath(item.Path); err != nil {
		return err
	}
	if strings.TrimSpace(item.Component) == "" {
		return errors.New("bundle component must not be empty")
	}
	if _, ok := components[item.Component]; ok {
		return fmt.Errorf("duplicate bundle component %q", item.Component)
	}
	if err := validateDigest(item); err != nil {
		return err
	}
	if err := validateUniqueBundlePath(pathKeys, item.Path); err != nil {
		return err
	}
	components[item.Component] = struct{}{}
	pathKeys[foldKey(item.Path)] = struct{}{}
	listed[item.Path] = item
	return nil
}

func validateDigest(item FileItem) error {
	if len(item.SHA256) != sha256.Size*2 {
		return fmt.Errorf("invalid SHA-256 digest for %q", item.Path)
	}
	if _, err := hex.DecodeString(item.SHA256); err != nil || strings.ToLower(item.SHA256) != item.SHA256 {
		return fmt.Errorf("invalid SHA-256 digest for %q", item.Path)
	}
	if item.Size < 0 {
		return fmt.Errorf("negative file size for %q", item.Path)
	}
	return nil
}

func validateUniqueBundlePath(pathKeys map[string]struct{}, name string) error {
	if _, ok := pathKeys[foldKey(name)]; ok {
		return fmt.Errorf("case-insensitive duplicate bundle path %q", name)
	}
	return nil
}

func validateParentDirectories(rootDir *os.Root, listed map[string]FileItem) error {
	checked := make(map[string]struct{})
	for name := range listed {
		current := path.Dir(name)
		for current != "." {
			if _, ok := checked[current]; ok {
				current = path.Dir(current)
				continue
			}
			info, err := rootDir.Lstat(filepath.FromSlash(current))
			if err != nil {
				return fmt.Errorf("inspect bundle directory %q: %w", current, err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("bundle path component %q is not a real directory", current)
			}
			checked[current] = struct{}{}
			current = path.Dir(current)
		}
	}
	return nil
}

func scanBundleInventory(rootDir *os.Root, listed map[string]FileItem) (map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(listed)+1)
	directories := listedDirectoryIndex(listed)
	seen[ManifestName] = struct{}{}
	err := fs.WalkDir(rootDir.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains symlink %q", relative)
		}
		if entry.IsDir() {
			if _, ok := directories[relative]; !ok {
				return fmt.Errorf("bundle contains undeclared directory %q", relative)
			}
			return nil
		}
		if relative == ManifestName {
			return nil
		}
		if _, ok := listed[relative]; !ok {
			return fmt.Errorf("bundle contains undeclared file %q", relative)
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inspect bundle inventory: %w", err)
	}
	return seen, nil
}

func verifyArtifact(rootDir *os.Root, name string, item FileItem) error {
	info, err := rootDir.Lstat(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("inspect bundle artifact %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("bundle artifact %q must be a regular file", name)
	}
	file, err := rootDir.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("open bundle artifact %q: %w", name, err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("hash bundle artifact %q: %w", name, err)
	}
	if size != item.Size || hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		return fmt.Errorf("bundle artifact %q does not match its manifest", name)
	}
	return nil
}

func validateCompleteness(manifest Manifest) error {
	if manifest.Completeness != Partial && manifest.Completeness != RequiredRoles {
		return fmt.Errorf("invalid bundle completeness %q", manifest.Completeness)
	}
	if len(manifest.Files) == 0 {
		return errors.New("bundle manifest must contain at least one file")
	}
	if manifest.Completeness == Partial {
		return nil
	}
	components := make(map[string]struct{}, len(manifest.Files))
	for _, item := range manifest.Files {
		components[item.Component] = struct{}{}
	}
	for _, required := range requiredComponents {
		if _, ok := components[required]; !ok {
			return fmt.Errorf("required-role inventory is missing component %q", required)
		}
	}
	return nil
}

func validateItemPath(name string) error {
	if name == "" || strings.ContainsAny(name, "\\:") || path.IsAbs(name) || path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") || strings.EqualFold(name, ManifestName) {
		return fmt.Errorf("invalid bundle artifact path %q", name)
	}
	return nil
}

func validPlatform(platform string) bool {
	return platform == "darwin/arm64" || platform == "linux/arm64"
}
