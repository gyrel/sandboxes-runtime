//go:build !windows

package bundle

import (
	"fmt"
	"os"
)

func captureBundleRootIdentity(root string) (os.FileInfo, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect bundle root: %w", err)
	}
	return info, nil
}
