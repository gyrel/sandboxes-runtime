package ctr

import (
	"context"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	runtime "github.com/gyrel/sandboxes-runtime"
)

func TestSkillsMountRejectsUnsupportedModesBeforeRuntimeActivity(t *testing.T) {
	backend := &Backend{}
	store := t.TempDir()
	cases := []struct {
		name   string
		skills *runtime.SkillsMount
		want   string
	}{
		{name: "readwrite", skills: &runtime.SkillsMount{StorePath: store, HelperPath: "/synthetic/helper", ReadOnly: false}, want: "read-write mode is not supported"},
		{name: "agent-path", skills: &runtime.SkillsMount{StorePath: store, HelperPath: "/synthetic/helper", AgentPath: "/home/agent/.agents/skills", ReadOnly: true}, want: "must not set an agent path"},
		{name: "relative-store", skills: &runtime.SkillsMount{StorePath: "skills", HelperPath: "/synthetic/helper", ReadOnly: true}, want: "clean absolute"},
		{name: "relative-helper", skills: &runtime.SkillsMount{StorePath: store, HelperPath: "helper", ReadOnly: true}, want: "helper must be a clean absolute"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := backend.Create(context.Background(), runtime.Config{Skills: tc.skills})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStageSkillsHelperUsesPrivateDirectory(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix executable permission bits")
	}
	source := filepath.Join(t.TempDir(), "sandbox-guest")
	if err := os.WriteFile(source, []byte("synthetic-helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir, staged, err := stageSkillsHelper(source)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "sandbox-guest" {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	data, err := os.ReadFile(staged)
	if err != nil || string(data) != "synthetic-helper" {
		t.Fatalf("content=%q err=%v", data, err)
	}
	pin := &skillsPin{helperDir: dir}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging directory not removed: %v", err)
	}
}

func TestStageSkillsHelperRejectsSymlink(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix executable permission bits")
	}
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, _, err := stageSkillsHelper(link); err == nil {
		t.Fatal("symlinked helper was accepted")
	}
}

func TestApplySkillsMountsRejectsWorkspaceOverlap(t *testing.T) {
	spec := &RunSpec{}
	workspaces := []Mount{{Source: "/host", Destination: "/run"}}
	skills := []Mount{{Source: "/proc/1/fd/3", Destination: runtime.SkillsStoreGuestPath, ReadOnly: true, RecursiveReadOnly: true}}
	err := applySkillsMounts(spec, workspaces, skills, []string{skillsLabel + "=readonly"})
	if err == nil || !strings.Contains(err.Error(), "overlaps runtime mount") {
		t.Fatalf("got %v", err)
	}
	if len(spec.Mounts) != 0 || len(spec.Labels) != 0 {
		t.Fatalf("spec mutated on error: %+v", spec)
	}
}

func TestApplySkillsMountsAddsReadOnlyMountsAndLabel(t *testing.T) {
	spec := &RunSpec{}
	skills := []Mount{
		{Source: "/proc/1/fd/3", Destination: runtime.SkillsStoreGuestPath, ReadOnly: true, RecursiveReadOnly: true},
		{Source: "/tmp/private/sandbox-guest", Destination: runtime.SkillsHelperGuestPath, ReadOnly: true},
	}
	if err := applySkillsMounts(spec, nil, skills, []string{skillsLabel + "=readonly"}); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 2 || spec.Mounts[0].Destination != runtime.SkillsStoreGuestPath || len(spec.Labels) != 1 {
		t.Fatalf("spec=%+v", spec)
	}
}

func TestPinSkillsStoreSnapshotIsPrivateAndStable(t *testing.T) {
	if goruntime.GOOS == "linux" {
		t.Skip("Linux uses fd pinning instead of a snapshot")
	}
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "SKILL.md"), []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := pinSkillsStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if pin.snapshotDir == "" || pin.storeSource == "" {
		t.Fatalf("pin=%+v", pin)
	}
	if data, err := os.ReadFile(filepath.Join(pin.storeSource, "SKILL.md")); err != nil || string(data) != "snapshot" {
		t.Fatalf("snapshot content=%q err=%v", data, err)
	}
	if err := os.Rename(store, store+"-moved"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(pin.storeSource, "SKILL.md")); err != nil || string(data) != "snapshot" {
		t.Fatalf("snapshot followed rename: %q %v", data, err)
	}
	dir := pin.snapshotDir
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("snapshot directory not removed: %v", err)
	}
}

func TestPinSkillsStoreSnapshotRejectsSymlink(t *testing.T) {
	if goruntime.GOOS == "linux" {
		t.Skip("Linux uses fd pinning instead of a snapshot")
	}
	store := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(store, "escape")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := pinSkillsStore(store); err == nil {
		t.Fatal("snapshot accepted a symlink")
	}
}

func TestValidSkillsPinPath(t *testing.T) {
	valid := filepath.Join(os.TempDir(), "gyrel-skills-pin-test", "store")
	if !validSkillsPinPath(valid) {
		t.Fatalf("valid pin path rejected: %s", valid)
	}
	for _, path := range []string{
		"", "relative/store", "/", filepath.Join(os.TempDir(), "other", "store"),
		filepath.Join(os.TempDir(), "gyrel-skills-pin-test", "..", "store"),
	} {
		if validSkillsPinPath(path) {
			t.Fatalf("unsafe pin path accepted: %q", path)
		}
	}
}

func TestAdoptSkillsPinRejectsMissingMetadata(t *testing.T) {
	backend := &Backend{}
	if err := backend.adoptSkillsPin("gyrel-dev", map[string]string{}); err == nil {
		t.Fatal("empty pin metadata accepted")
	}
}

func TestAdoptSnapshotPinOnNonLinux(t *testing.T) {
	if goruntime.GOOS == "linux" {
		t.Skip("Linux uses the bind-mount path")
	}
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "SKILL.md"), []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := pinSkillsStore(store)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(pin.storeSource)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{
		skillsLabel:              "readonly",
		skillsStoreIdentityLabel: skillsIdentity(info),
		skillsPinPathLabel:       pin.storeSource,
	}
	backend := &Backend{}
	if err := backend.adoptSkillsPin("gyrel-dev", labels); err != nil {
		t.Fatal(err)
	}
	if backend.skillsPin("gyrel-dev") == nil {
		t.Fatal("snapshot pin was not adopted")
	}
	if err := backend.forgetSkillsPath("gyrel-dev", pin.storeSource); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pin.storeSource); !os.IsNotExist(err) {
		t.Fatalf("snapshot not removed: %v", err)
	}
}
