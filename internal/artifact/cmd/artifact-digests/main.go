// Command artifact-digests regenerates build/digests.yaml from a verified
// artifact set. It is invoked by scripts/update-artifact-digests.sh.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rheic/sandboxes-runtime/internal/artifact"
)

func main() {
	manifestPath := flag.String("manifest", "build/manifest.yaml", "path to the build manifest")
	digestsPath := flag.String("out", "build/digests.yaml", "path of the digest file to write")
	var artifactFlags artifactList
	flag.Var(&artifactFlags, "artifact", "name=path of a runtime artifact; repeat for each binary")
	flag.Parse()
	for _, value := range flag.Args() {
		if err := artifactFlags.Set(value); err != nil {
			fail(err)
		}
	}
	if err := artifact.Generate(*manifestPath, *digestsPath, artifactFlags); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s (%d runtime artifact(s) recorded)\n", *digestsPath, len(artifactFlags))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "artifact-digests: %v\n", err)
	os.Exit(1)
}

type artifactList map[string]string

func (l *artifactList) String() string {
	entries := make([]string, 0, len(*l))
	for name, path := range *l {
		entries = append(entries, name+"="+path)
	}
	return strings.Join(entries, ",")
}

func (l *artifactList) Set(value string) error {
	name, path, ok := strings.Cut(value, "=")
	if !ok || name == "" || path == "" {
		return fmt.Errorf("artifact must be name=/absolute/path, got %q", value)
	}
	if *l == nil {
		*l = artifactList{}
	}
	if _, exists := (*l)[name]; exists {
		return fmt.Errorf("artifact %q is listed more than once", name)
	}
	(*l)[name] = path
	return nil
}
