package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/azdharsyahputra/openmail/internal/api/handler"
	"github.com/azdharsyahputra/openmail/internal/api/middleware"
	"github.com/azdharsyahputra/openmail/internal/api/token"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/dkim"
	"github.com/azdharsyahputra/openmail/internal/domain"
	"github.com/azdharsyahputra/openmail/internal/identity"
	"github.com/azdharsyahputra/openmail/internal/mailbox"
	"github.com/azdharsyahputra/openmail/internal/metrics"
	"github.com/azdharsyahputra/openmail/internal/queue"
	"github.com/azdharsyahputra/openmail/internal/quota"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/go-chi/chi/v5"
)


type RouterDependencies struct {
	Logger          *slog.Logger
	TokenManager    token.Manager
	IdentityService identity.Service
	DomainService   domain.Service
	MailboxService  mailbox.Service
	AliasRepo       mailbox.AliasRepository
	MailboxRepo     mailbox.Repository
	DomainRepo      domain.Repository
	DKIMService     dkim.Service
	TLSService      *openmailtls.Service
	QueueService    queue.Service
	QuotaService    quota.Service
	AuditService    audit.Service
	HealthHandler   *handler.HealthHandler
	MetricsRegistry *metrics.Registry
}

func NewRouter(deps RouterDependencies) http.Handler {
	r := chi.NewRouter()

	// Global Middlewares
	r.Use(middleware.CORS)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logging(deps.Logger))
	r.Use(middleware.Recovery(deps.Logger))
	r.Use(middleware.BodyLimit(1 << 20)) // 1MB payload limit
	r.Use(middleware.NewRateLimiter(200, time.Minute))



	// Instantiate Handlers
	authH := handler.NewAuthHandler(deps.IdentityService, deps.TokenManager)
	domH := handler.NewDomainHandler(deps.DomainService, deps.DKIMService, deps.TLSService, deps.AuditService)
	mbH := handler.NewMailboxHandler(deps.MailboxService, deps.AuditService)
	quotaH := handler.NewQuotaHandler(deps.QuotaService)

	aliasH := handler.NewAliasHandler(deps.AliasRepo, deps.MailboxRepo, deps.DomainRepo)
	dkimH := handler.NewDKIMHandler(deps.DKIMService)
	tlsH := handler.NewTLSHandler(deps.TLSService)
	polH := handler.NewPolicyHandler(deps.DKIMService)
	identH := handler.NewIdentityHandler(deps.IdentityService)
	qH := handler.NewQueueHandler(deps.QueueService)
	auditH := handler.NewAuditHandler(deps.AuditService)
	metricsH := handler.NewMetricsHandler(deps.MetricsRegistry)


	// Public Observability Endpoints
	r.Get("/health/live", deps.HealthHandler.Live)
	r.Get("/health/ready", deps.HealthHandler.Ready)
	r.Get("/health/deep", deps.HealthHandler.Deep)
	r.Get("/metrics", metricsH.Metrics)

	// Public Auth Endpoints
	r.Post("/api/v1/auth/login", authH.Login)
	r.Post("/api/v1/auth/refresh", authH.Refresh)

	// Authenticated API Scope
	r.Group(func(apiGroup chi.Router) {
		apiGroup.Use(middleware.Authenticate(deps.TokenManager))

		// Auth & Profile
		apiGroup.Post("/api/v1/auth/logout", authH.Logout)
		apiGroup.Get("/api/v1/auth/me", authH.Me)

		// Domains
		apiGroup.Route("/api/v1/domains", func(dr chi.Router) {
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/", domH.List)
			dr.With(middleware.RequireRole("admin")).Post("/", domH.Create)
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}", domH.Get)
			dr.With(middleware.RequireRole("admin")).Delete("/{domain}", domH.Delete)
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}/doctor", domH.Doctor)
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}/dns", domH.DNS)

			// DKIM
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}/dkim", dkimH.List)
			dr.With(middleware.RequireRole("admin", "operator")).Post("/{domain}/dkim", dkimH.Generate)
			dr.With(middleware.RequireRole("admin", "operator")).Post("/{domain}/dkim/{selector}/verify", dkimH.Verify)
			dr.With(middleware.RequireRole("admin", "operator")).Post("/{domain}/dkim/{selector}/activate", dkimH.Activate)
			dr.With(middleware.RequireRole("admin")).Post("/{domain}/dkim/{selector}/revoke", dkimH.Revoke)

			// TLS
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}/tls", tlsH.Get)
			dr.With(middleware.RequireRole("admin")).Post("/{domain}/tls", tlsH.Install)

			// Policy
			dr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{domain}/policy", polH.Get)
			dr.With(middleware.RequireRole("admin", "operator")).Put("/{domain}/policy", polH.Update)
		})

		// Mailboxes
		apiGroup.Route("/api/v1/mailboxes", func(mr chi.Router) {
			mr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/", mbH.List)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/", mbH.Create)
			mr.With(middleware.RequireRole("admin", "operator", "auditor", "user"), middleware.RequireMailboxOwnership()).Get("/{email}", mbH.Get)
			mr.With(middleware.RequireRole("admin")).Delete("/{email}", mbH.Delete)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/{email}/suspend", mbH.Suspend)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/{email}/resume", mbH.Resume)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/{email}/provision", mbH.Provision)
			mr.With(middleware.RequireRole("admin", "operator", "user"), middleware.RequireMailboxOwnership()).Post("/{email}/password", mbH.SetPassword)

			// Aliases
			mr.With(middleware.RequireRole("admin", "operator", "auditor", "user"), middleware.RequireMailboxOwnership()).Get("/{email}/aliases", aliasH.List)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/{email}/aliases", aliasH.Create)
			mr.With(middleware.RequireRole("admin", "operator")).Delete("/{email}/aliases/{alias}", aliasH.Delete)

			// Quota
			mr.With(middleware.RequireRole("admin", "operator", "auditor", "user"), middleware.RequireMailboxOwnership()).Get("/{email}/quota", quotaH.Get)
			mr.With(middleware.RequireRole("admin", "operator")).Put("/{email}/quota", quotaH.Update)
			mr.With(middleware.RequireRole("admin", "operator")).Post("/{email}/quota/reconcile", quotaH.Reconcile)
		})

		// Identity & LDAP
		apiGroup.Route("/api/v1/identity", func(ir chi.Router) {
			ir.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/providers", identH.ListProviders)
		})
		apiGroup.Route("/api/v1/ldap", func(lr chi.Router) {
			lr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/status", identH.LDAPDoctor)
			lr.With(middleware.RequireRole("admin", "operator", "auditor")).Post("/doctor", identH.LDAPDoctor)
			lr.With(middleware.RequireRole("admin")).Post("/sync", identH.LDAPSync)
		})

		// Mail Queue
		apiGroup.Route("/api/v1/queue", func(qr chi.Router) {
			qr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/", qrStatusOrList(qH))
			qr.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/{id}", qH.Inspect)
			qr.With(middleware.RequireRole("admin", "operator")).Post("/{id}/retry", qH.Retry)
			qr.With(middleware.RequireRole("admin", "operator")).Post("/{id}/hold", qH.Hold)
			qr.With(middleware.RequireRole("admin", "operator")).Post("/{id}/release", qH.Release)
			qr.With(middleware.RequireRole("admin")).Delete("/{id}", qH.Delete)
			qr.With(middleware.RequireRole("admin")).Post("/flush", qH.Flush)
		})


		// Audit
		apiGroup.With(middleware.RequireRole("admin", "auditor")).Get("/api/v1/audit", auditH.List)

		// System
		apiGroup.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/api/v1/system/status", deps.HealthHandler.Ready)
		apiGroup.With(middleware.RequireRole("admin", "operator", "auditor")).Get("/api/v1/system/doctor", deps.HealthHandler.SystemDoctor)
	})

	return r
}

func qrStatusOrList(h *handler.QueueHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("summary") == "true" {
			h.Status(w, r)
		} else {
			h.List(w, r)
		}
	}
}
