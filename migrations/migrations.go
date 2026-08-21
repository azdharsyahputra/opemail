package migrations

import "embed"

// FS embeds SQL migration files for run-time migration execution.
//go:embed *.sql
var FS embed.FS
