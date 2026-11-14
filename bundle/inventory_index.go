package bundle

import "path"

// listedDirectoryIndex contains every ancestor directory needed by at least
// one inventory entry. Building it costs O(total path bytes), so the directory
// walk can test descendants without scanning all files for every directory.
func listedDirectoryIndex(listed map[string]FileItem) map[string]struct{} {
	directories := make(map[string]struct{})
	for name := range listed {
		current := path.Dir(name)
		for current != "." {
			directories[current] = struct{}{}
			current = path.Dir(current)
		}
	}
	return directories
}
