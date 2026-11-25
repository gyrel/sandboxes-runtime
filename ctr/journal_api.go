package ctr

import (
	"context"

	"github.com/gyrel/sandboxes-runtime/internal/journal"
)

// JournalFinding re-exports the journal finding type so module consumers
// (e.g. the daemon) can name it without importing the internal package.
type JournalFinding = journal.Finding

// JournalRecoverer is implemented by backends that reconcile create
// journals (ADR-0009); assert Backend to it optionally.
type JournalRecoverer interface {
	Recover(ctx context.Context) ([]JournalFinding, error)
}

var _ JournalRecoverer = (*Backend)(nil)
