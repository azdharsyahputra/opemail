package backup

import "time"

type Manifest struct {
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	Database     bool              `json:"database"`
	Maildir      bool              `json:"maildir"`
	DKIM         bool              `json:"dkim"`
	TLS          bool              `json:"tls"`
	Configs      bool              `json:"configs"`
	Checksums    map[string]string `json:"checksums"`
	Encrypted    bool              `json:"encrypted"`
	TotalFiles   int               `json:"total_files"`
	ArchiveBytes int64             `json:"archive_bytes"`
}

type VerificationReport struct {
	Valid     bool     `json:"valid"`
	Manifest  Manifest `json:"manifest"`
	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	FileCount int      `json:"file_count"`
}
