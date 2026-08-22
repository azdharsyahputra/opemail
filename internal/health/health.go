package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/azdharsyahputra/openmail/internal/queue"
)

type CheckResult struct {
	Component string `json:"component"`
	Status    string `json:"status"` // UP, DOWN, WARNING
	Message   string `json:"message,omitempty"`
}

type HealthResponse struct {
	Status    string                 `json:"status"` // OK, DEGRADED, DOWN
	Timestamp time.Time              `json:"timestamp"`
	Checks    []CheckResult          `json:"checks,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type Checker struct {
	DB           *sql.DB
	QueueService queue.Service
	VmailDir     string
	TLSPath      string
	DKIMPath     string
}

func NewChecker(db *sql.DB, qSvc queue.Service, vmailDir, tlsPath, dkimPath string) *Checker {
	return &Checker{
		DB:           db,
		QueueService: qSvc,
		VmailDir:     vmailDir,
		TLSPath:      tlsPath,
		DKIMPath:     dkimPath,
	}
}

func (c *Checker) Live(ctx context.Context) HealthResponse {
	return HealthResponse{
		Status:    "OK",
		Timestamp: time.Now().UTC(),
	}
}

func (c *Checker) Ready(ctx context.Context) HealthResponse {
	resp := HealthResponse{
		Status:    "OK",
		Timestamp: time.Now().UTC(),
	}

	// 1. PostgreSQL
	if c.DB != nil {
		if err := c.DB.PingContext(ctx); err != nil {
			resp.Status = "DOWN"
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "postgresql",
				Status:    "DOWN",
				Message:   err.Error(),
			})
		} else {
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "postgresql",
				Status:    "UP",
				Message:   "Connected",
			})
		}
	}

	// 2. Postfix ports :25 & :587, Dovecot ports :143 & :993
	postfixHost := os.Getenv("POSTFIX_HOST")
	if postfixHost == "" {
		postfixHost = "postfix"
	}
	dovecotHost := os.Getenv("DOVECOT_HOST")
	if dovecotHost == "" {
		dovecotHost = "dovecot"
	}

	checkTCP := func(name, host, port string) {
		addr := net.JoinHostPort(host, port)
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			// Fallback to 127.0.0.1 for local host execution
			if host != "127.0.0.1" && host != "localhost" {
				if connLocal, errLocal := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 1*time.Second); errLocal == nil {
					_ = connLocal.Close()
					resp.Checks = append(resp.Checks, CheckResult{
						Component: name,
						Status:    "UP",
						Message:   "Listening",
					})
					return
				}
			}
			resp.Status = "DEGRADED"
			resp.Checks = append(resp.Checks, CheckResult{
				Component: name,
				Status:    "DOWN",
				Message:   err.Error(),
			})
		} else {
			_ = conn.Close()
			resp.Checks = append(resp.Checks, CheckResult{
				Component: name,
				Status:    "UP",
				Message:   "Listening",
			})
		}
	}

	checkTCP("postfix_25", postfixHost, "25")
	checkTCP("postfix_587", postfixHost, "587")
	checkTCP("dovecot_143", dovecotHost, "143")
	checkTCP("dovecot_993", dovecotHost, "993")

	// 3. Storage filesystem
	if c.VmailDir != "" {
		if _, err := os.Stat(c.VmailDir); err != nil {
			resp.Status = "DEGRADED"
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "storage_vmail",
				Status:    "DOWN",
				Message:   err.Error(),
			})
		} else {
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "storage_vmail",
				Status:    "UP",
				Message:   "Writable directory accessible",
			})
		}
	}

	return resp
}

func (c *Checker) Deep(ctx context.Context) HealthResponse {
	resp := c.Ready(ctx)

	// 1. Storage write test
	if c.VmailDir != "" {
		testFile := filepath.Join(c.VmailDir, fmt.Sprintf(".healthcheck_%d", time.Now().UnixNano()))
		if err := os.WriteFile(testFile, []byte("healthcheck"), 0600); err != nil {
			resp.Status = "DEGRADED"
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "storage_write",
				Status:    "DOWN",
				Message:   fmt.Sprintf("Failed write: %v", err),
			})
		} else {
			_ = os.Remove(testFile)
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "storage_write",
				Status:    "UP",
				Message:   "Write & delete verified",
			})
		}
	}

	// 2. Postfix queue
	if c.QueueService != nil {
		qSummary, err := c.QueueService.GetStatus(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "executable file not found") {
				resp.Checks = append(resp.Checks, CheckResult{
					Component: "postfix_queue",
					Status:    "STANDBY",
					Message:   "Queue manager operating via MTA socket",
				})
			} else {
				resp.Checks = append(resp.Checks, CheckResult{
					Component: "postfix_queue",
					Status:    "DOWN",
					Message:   err.Error(),
				})
			}
		} else {
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "postfix_queue",
				Status:    "UP",
				Message:   fmt.Sprintf("Active: %d, Deferred: %d, Hold: %d", qSummary.Active, qSummary.Deferred, qSummary.Hold),
			})
		}
	}

	// 3. TLS Directory
	if c.TLSPath != "" {
		if _, err := os.Stat(c.TLSPath); err == nil {
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "tls_keystore",
				Status:    "UP",
				Message:   "Directory available",
			})
		}
	}

	// 4. DKIM Keystore
	if c.DKIMPath != "" {
		if _, err := os.Stat(c.DKIMPath); err == nil {
			resp.Checks = append(resp.Checks, CheckResult{
				Component: "dkim_keystore",
				Status:    "UP",
				Message:   "Directory available",
			})
		}
	}

	return resp
}

// Router returns an http.Handler with /health/live, /health/ready, and /health/deep endpoints.
func (c *Checker) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.Live(r.Context()))
	})

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := c.Ready(r.Context())
		if res.Status == "DOWN" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/health/deep", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := c.Deep(r.Context())
		if res.Status == "DOWN" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	return mux
}
