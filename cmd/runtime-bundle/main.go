// Command runtime-bundle creates or checks a content inventory for a staged
// Rheic runtime bundle. It does not verify GitHub artifact attestations.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rheic/sandboxes-runtime/bundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: runtime-bundle <manifest|verify> [flags]")
	}
	switch args[0] {
	case "manifest":
		return createManifest(args[1:])
	case "verify":
		return verifyBundle(args[1:])
	default:
		return fmt.Errorf("unknown runtime-bundle command %q", args[0])
	}
}

func createManifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	root := flags.String("root", "", "staged bundle directory")
	platform := flags.String("platform", "", "bundle target platform (darwin/arm64 or linux/arm64)")
	completeness := flags.String("completeness", bundle.Partial, "partial or required-roles")
	var declarations fileDeclarations
	flags.Var(&declarations, "file", "component=relative/path (repeat for each artifact)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *root == "" || *platform == "" || len(declarations) == 0 {
		return errors.New("manifest requires --root, --platform, and at least one --file")
	}
	if err := bundle.WriteManifest(*root, *platform, *completeness, declarations); err != nil {
		return err
	}
	fmt.Println("bundle manifest written; provenance is not verified")
	return nil
}

func verifyBundle(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := flags.String("root", "", "staged bundle directory")
	platform := flags.String("platform", "", "required target platform")
	allowPartial := flags.Bool("allow-partial", false, "allow experimental partial bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *root == "" || *platform == "" {
		return errors.New("verify requires --root and --platform")
	}
	manifest, err := bundle.Verify(*root, bundle.Options{
		ExpectedPlatform: *platform,
		AllowPartial:     *allowPartial,
	})
	if err != nil {
		return err
	}
	fmt.Printf("bundle inventory valid: platform=%s completeness=%s files=%d; runtime behavior and provenance are not verified\n",
		manifest.Platform, manifest.Completeness, len(manifest.Files))
	return nil
}

type fileDeclarations []bundle.FileItem

func (declarations *fileDeclarations) String() string {
	return fmt.Sprint([]bundle.FileItem(*declarations))
}

func (declarations *fileDeclarations) Set(value string) error {
	component, name, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(component) == "" || strings.TrimSpace(name) == "" {
		return errors.New("--file must use component=relative/path")
	}
	*declarations = append(*declarations, bundle.FileItem{Component: component, Path: name})
	return nil
}
