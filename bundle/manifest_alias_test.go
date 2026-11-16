package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRejectsCaseFoldedDuplicateFieldNames(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "top-level platform",
			json: `{"schema_version":1,"platform":"darwin/arm64","Platform":"linux/arm64","completeness":"partial","files":[{"component":"shim","path":"bin/shim","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0}]}`,
		},
		{
			name: "nested file item",
			json: `{"schema_version":1,"platform":"linux/arm64","completeness":"partial","files":[{"component":"shim","Component":"other","path":"bin/shim","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil || !strings.Contains(err.Error(), "duplicate JSON") {
				t.Fatalf("Verify() error = %v, want case-folded duplicate JSON key rejection", err)
			}
		})
	}
}
