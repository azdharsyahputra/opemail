package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)


type BackupConfig struct {
	DBURL      string
	DB         *sql.DB
	VmailDir   string
	DKIMDir    string
	TLSDir     string
	ConfigDir  string
	Passphrase string
	OutputPath string
}

// CreateBackup archives PostgreSQL data, Maildir, TLS/DKIM keys, and configuration into an encrypted tarball.
func CreateBackup(ctx context.Context, cfg BackupConfig) (*Manifest, string, error) {
	manifest := &Manifest{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Checksums: make(map[string]string),
		Encrypted: cfg.Passphrase != "",
	}

	var tarBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&tarBuf)
	tarWriter := tar.NewWriter(gzWriter)

	addFileToTar := func(name string, content []byte, mode int64) error {
		hasher := sha256.New()
		hasher.Write(content)
		manifest.Checksums[name] = hex.EncodeToString(hasher.Sum(nil))
		manifest.TotalFiles++

		hdr := &tar.Header{
			Name:    name,
			Mode:    mode,
			Size:    int64(len(content)),
			ModTime: time.Now().UTC(),
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tarWriter.Write(content)
		return err
	}

	addDirToTar := func(baseDir, targetPrefix string) error {
		if _, err := os.Stat(baseDir); err != nil {
			return nil // directory does not exist, skip
		}
		return filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(baseDir, path)
			tarPath := filepath.Join(targetPrefix, rel)
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return addFileToTar(tarPath, content, int64(info.Mode()))
		})
	}

	// 1. Export PostgreSQL schema & tables if DB is provided
	if cfg.DB != nil {
		sqlDump, err := exportDatabaseTables(ctx, cfg.DB)
		if err == nil && len(sqlDump) > 0 {
			_ = addFileToTar("postgres/dump.sql", sqlDump, 0600)
			manifest.Database = true
		}
	}

	// 2. Maildir storage
	if cfg.VmailDir != "" {
		if err := addDirToTar(cfg.VmailDir, "maildir"); err == nil {
			manifest.Maildir = true
		}
	}

	// 3. DKIM keys
	if cfg.DKIMDir != "" {
		if err := addDirToTar(cfg.DKIMDir, "dkim"); err == nil {
			manifest.DKIM = true
		}
	}

	// 4. TLS keys & certs
	if cfg.TLSDir != "" {
		if err := addDirToTar(cfg.TLSDir, "tls"); err == nil {
			manifest.TLS = true
		}
	}

	// 5. Configs
	if cfg.ConfigDir != "" {
		if err := addDirToTar(cfg.ConfigDir, "configs"); err == nil {
			manifest.Configs = true
		}
	}

	// 6. Write manifest.json
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = addFileToTar("manifest.json", manifestBytes, 0600)

	_ = tarWriter.Close()
	_ = gzWriter.Close()

	rawTarGz := tarBuf.Bytes()

	// 7. Encrypt if passphrase given
	finalPayload, err := EncryptData(rawTarGz, cfg.Passphrase)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt backup: %w", err)
	}

	outPath := cfg.OutputPath
	if outPath == "" {
		ext := ".tar.gz"
		if cfg.Passphrase != "" {
			ext = ".tar.gz.enc"
		}
		outPath = fmt.Sprintf("mailopen-backup-%s%s", time.Now().Format("20060102-150405"), ext)
	}

	if err := os.WriteFile(outPath, finalPayload, 0600); err != nil {
		return nil, "", fmt.Errorf("write backup file: %w", err)
	}

	manifest.ArchiveBytes = int64(len(finalPayload))
	return manifest, outPath, nil
}

func exportDatabaseTables(ctx context.Context, db *sql.DB) ([]byte, error) {
	tables := []string{"domains", "mailboxes", "aliases", "domain_dkim", "domain_mail_policy", "mailbox_limits", "audit_logs", "message_events"}
	var sb bytes.Buffer

	sb.WriteString("-- MailOpen Database Backup Dump\n")
	sb.WriteString(fmt.Sprintf("-- Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	for _, table := range tables {
		rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s", table))
		if err != nil {
			continue // table might not exist
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]interface{}, len(cols))
			scanArgs := make([]interface{}, len(cols))
			for i := range values {
				scanArgs[i] = &values[i]
			}
			if err := rows.Scan(scanArgs...); err != nil {
				continue
			}

			sb.WriteString(fmt.Sprintf("-- Row for %s: %v\n", table, values))
		}
		rows.Close()
	}

	return sb.Bytes(), nil
}
