package cli

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/azdharsyahputra/openmail/internal/health"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Run or serve health checks (live, ready, deep)",
}

var healthLiveCmd = &cobra.Command{
	Use:   "live",
	Short: "Liveness probe (fast, lightweight)",
	RunE: func(cmd *cobra.Command, args []string) error {
		checker := health.NewChecker(nil, nil, "", "", "")
		res := checker.Live(cmd.Context())
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

var healthReadyCmd = &cobra.Command{
	Use:   "ready",
	Short: "Readiness probe (PostgreSQL, Postfix, Dovecot, Storage)",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}
		cfg, _ := loadAppConfig()
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		checker := health.NewChecker(db, qSvc, cfg.VmailRoot, cfg.TLSBaseDir, cfg.DKIMBaseDir)

		res := checker.Ready(cmd.Context())
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

var healthDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Deep diagnostics probe (DB write, Storage write, Queue, Keys)",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}
		cfg, _ := loadAppConfig()
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		checker := health.NewChecker(db, qSvc, cfg.VmailRoot, cfg.TLSBaseDir, cfg.DKIMBaseDir)

		res := checker.Deep(cmd.Context())
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return nil
	},
}

var healthServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP server for /health/live, /health/ready, /health/deep, and /metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, _ := getDB()
		if db != nil {
			defer db.Close()
		}
		cfg, _ := loadAppConfig()
		qSvc := queue.NewService(queue.NewSystemDriver("mailopen_postfix"))
		checker := health.NewChecker(db, qSvc, cfg.VmailRoot, cfg.TLSBaseDir, cfg.DKIMBaseDir)


		port, _ := cmd.Flags().GetString("port")
		if port == "" {
			port = "8080"
		}

		mux := http.NewServeMux()
		mux.Handle("/health/", checker.Router())
		mux.HandleFunc("/metrics", metrics.Handler())

		fmt.Printf("Health & Metrics server listening on :%s ...\n", port)
		return http.ListenAndServe(":"+port, mux)
	},
}

func init() {
	healthServeCmd.Flags().String("port", "8080", "HTTP server port")

	healthCmd.AddCommand(healthLiveCmd)
	healthCmd.AddCommand(healthReadyCmd)
	healthCmd.AddCommand(healthDeepCmd)
	healthCmd.AddCommand(healthServeCmd)
}
