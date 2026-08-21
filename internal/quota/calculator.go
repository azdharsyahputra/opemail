package quota

import (
	"os"
	"path/filepath"
	"strings"
)


type StorageScanResult struct {
	TotalBytes   int64
	MessageCount int64
}

// CalculateMaildirUsage walks the Maildir++ directory (cur, new, subfolders) and sums actual message bytes.
func CalculateMaildirUsage(maildirPath string) (StorageScanResult, error) {
	var result StorageScanResult

	if _, err := os.Stat(maildirPath); err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return result, err
	}

	err := filepath.Walk(maildirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			// Count regular email files in cur, new, and subfolders (exclude control files like dovecot.index)
			name := info.Name()
			if !strings.HasPrefix(name, "dovecot") && !strings.HasPrefix(name, "maildirsize") && !strings.HasPrefix(name, ".") {
				result.TotalBytes += info.Size()
				result.MessageCount++
			}

		}
		return nil
	})

	return result, err
}

func ComputeStatus(usedBytes, quotaBytes int64) (Status, float64, bool) {
	if quotaBytes <= 0 {
		return StatusOK, 0, false
	}
	pct := (float64(usedBytes) / float64(quotaBytes)) * 100.0

	switch {
	case pct >= 100.0:
		return StatusFull, pct, true
	case pct >= 90.0:
		return StatusCritical, pct, false
	case pct >= 80.0:
		return StatusWarning, pct, false
	default:
		return StatusOK, pct, false
	}
}

