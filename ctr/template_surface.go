package ctr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	runtime "github.com/rheic/sandboxes-runtime"
)

// SaveTemplate implements runtime.TemplateBackend.
func (b *Backend) SaveTemplate(ctx context.Context, h runtime.Handle, spec runtime.TemplateSaveSpec) (runtime.TemplateInfo, error) {
	summary, err := SaveTemplate(ctx, b, h, TemplateSaveOptions{
		Tag: spec.Tag, BaseImage: spec.BaseImage, Excludes: spec.Excludes, OutputPath: spec.OutputPath,
	})
	if err != nil {
		return runtime.TemplateInfo{}, err
	}
	return runtime.TemplateInfo{
		Name: summary.Name, Digest: summary.Digest, SizeBytes: summary.SizeBytes,
		Layers: summary.Layers, Notice: summary.Notice,
	}, nil
}

// LoadTemplate implements runtime.TemplateBackend.
func (b *Backend) LoadTemplate(ctx context.Context, spec runtime.TemplateLoadSpec) (runtime.TemplateInfo, error) {
	summary, err := LoadTemplate(ctx, b, spec.TarPath, spec.Name)
	if err != nil {
		return runtime.TemplateInfo{}, err
	}
	return runtime.TemplateInfo{Name: summary.Name, Digest: summary.Digest, SizeBytes: summary.SizeBytes, Layers: summary.Layers, Notice: summary.Notice}, nil
}

// RemoveTemplate implements runtime.TemplateBackend. Reference safety is a
// daemon responsibility enforced before this call.
func (b *Backend) RemoveTemplate(ctx context.Context, name string) error {
	return b.RemoveTemplateImage(ctx, name)
}

// ExportTemplate implements runtime.TemplateBackend.
func (b *Backend) ExportTemplate(ctx context.Context, name, tarPath string) error {
	return b.ExportTemplateArchive(ctx, name, tarPath)
}

// TemplateBootDocument implements runtime.TemplateBackend by reading the
// image config. Environment values never leave this function: only names
// are returned (presence-only contract).
func (b *Backend) TemplateBootDocument(ctx context.Context, name string) (runtime.TemplateBootDocument, error) {
	_, _, configBytes, err := b.ImageLayerDescriptors(ctx, name)
	if err != nil {
		return runtime.TemplateBootDocument{}, err
	}
	var doc struct {
		Config struct {
			Env        []string `json:"Env"`
			WorkingDir string   `json:"WorkingDir"`
			User       string   `json:"User"`
		} `json:"config"`
	}
	if err := json.Unmarshal(configBytes, &doc); err != nil {
		return runtime.TemplateBootDocument{}, fmt.Errorf("parse template boot document: %w", err)
	}
	names := make([]string, 0, len(doc.Config.Env))
	for _, entry := range doc.Config.Env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "" {
			continue
		}
		names = append(names, key)
	}
	return runtime.TemplateBootDocument{EnvNames: names, WorkingDir: doc.Config.WorkingDir, User: doc.Config.User}, nil
}

var _ runtime.TemplateBackend = (*Backend)(nil)
