package runtime

import "context"

// TemplateSaveSpec describes one template capture request. Excludes are
// guest absolute paths that must never be captured (sandbox mounts); the
// backend additionally always excludes the nested Docker data directory.
type TemplateSaveSpec struct {
	Tag        string
	BaseImage  string
	Excludes   []string
	OutputPath string
}

// TemplateInfo reports a recorded template. Digest addresses the assembled
// manifest; Notice is stable operator-facing guidance without secrets.
type TemplateInfo struct {
	Name      string
	Digest    string
	SizeBytes int64
	Layers    int
	Notice    string
}

// TemplateLoadSpec names an archive to import and an optional reference
// override.
type TemplateLoadSpec struct {
	TarPath string
	Name    string
}

// TemplateBootDocument is the reconstructed boot configuration of a
// template image. Environment is presence-only: names never carry values.
type TemplateBootDocument struct {
	EnvNames   []string
	WorkingDir string
	User       string
}

// TemplateBackend is implemented by runtimes that can capture, import,
// remove and inspect template images (ADR-0008). Save requires a running
// task handle owned by the caller; the daemon guarantees sandbox state
// restoration around the call.
type TemplateBackend interface {
	SaveTemplate(ctx context.Context, h Handle, spec TemplateSaveSpec) (TemplateInfo, error)
	LoadTemplate(ctx context.Context, spec TemplateLoadSpec) (TemplateInfo, error)
	RemoveTemplate(ctx context.Context, name string) error
	ExportTemplate(ctx context.Context, name, tarPath string) error
	TemplateBootDocument(ctx context.Context, name string) (TemplateBootDocument, error)
}
