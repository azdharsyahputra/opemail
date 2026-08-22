package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/azdharsyahputra/openmail/internal/api/response"
	"github.com/azdharsyahputra/openmail/internal/audit"
	"github.com/azdharsyahputra/openmail/internal/dkim"

	"github.com/azdharsyahputra/openmail/internal/dns"
	"github.com/azdharsyahputra/openmail/internal/domain"
	openmailtls "github.com/azdharsyahputra/openmail/internal/tls"
	"github.com/go-chi/chi/v5"
)

type DomainHandler struct {
	domainService domain.Service
	dkimService   dkim.Service
	tlsService    *openmailtls.Service
	auditService  audit.Service
}

func NewDomainHandler(domSvc domain.Service, dkimSvc dkim.Service, tlsSvc *openmailtls.Service, auditSvc audit.Service) *DomainHandler {
	return &DomainHandler{
		domainService: domSvc,
		dkimService:   dkimSvc,
		tlsService:    tlsSvc,
		auditService:  auditSvc,
	}
}

type CreateDomainRequest struct {
	Name string `json:"name"`
}

func (h *DomainHandler) List(w http.ResponseWriter, r *http.Request) {
	domains, err := h.domainService.List(r.Context())
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to list domains", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, response.DataListResponse{
		Data: domains,
		Pagination: response.PaginationResponse{
			Total: len(domains),
			Limit: len(domains),
		},
	})
}

func (h *DomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "malformed request payload", err.Error())
		return
	}

	req.Name = strings.TrimSpace(strings.ToLower(req.Name))
	if req.Name == "" {
		response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "domain name is required", nil)
		return
	}

	d, err := h.domainService.Create(r.Context(), req.Name)
	if err != nil {
		if err == domain.ErrDomainExists {
			response.Error(w, r, http.StatusConflict, response.ErrCodeDomainAlreadyExists, "domain already exists", nil)
			return
		}
		if err == domain.ErrInvalidDomain {
			response.Error(w, r, http.StatusBadRequest, response.ErrCodeValidationError, "invalid domain name format", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to create domain", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "domain.create", "domain", &d.ID, map[string]string{"domain": d.Name})
	}

	response.JSON(w, http.StatusCreated, d)
}

func (h *DomainHandler) Get(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	d, err := h.domainService.GetByName(r.Context(), domName)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.ErrCodeDomainNotFound, "domain not found", nil)
		return
	}

	response.JSON(w, http.StatusOK, d)
}

func (h *DomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	err := h.domainService.Delete(r.Context(), domName)
	if err != nil {
		if err == domain.ErrDomainNotFound {
			response.Error(w, r, http.StatusNotFound, response.ErrCodeDomainNotFound, "domain not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, response.ErrCodeInternal, "failed to delete domain", err.Error())
		return
	}

	if h.auditService != nil {
		_ = h.auditService.RecordAudit(r.Context(), "api", nil, "domain.delete", "domain", nil, map[string]string{"domain": domName})
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "domain deleted successfully"})
}


func (h *DomainHandler) Doctor(w http.ResponseWriter, r *http.Request) {
	domName := chi.URLParam(r, "domain")
	var tlsProv openmailtls.CertificateProvider
	if h.tlsService != nil {
		tlsProv = h.tlsService.Provider()
	}

	report := dns.RunDomainDoctor(r.Context(), dns.DoctorOptions{
		DomainName:    domName,
		DomainService: h.domainService,
		DKIMService:   h.dkimService,
		TLSProvider:   tlsProv,
	})

	response.JSON(w, http.StatusOK, report)
}

var (
	cachedPublicIP     string
	cachedPublicIPTime time.Time
	publicIPMutex      sync.Mutex
)

func getPublicServerIP() string {
	if ip := os.Getenv("SERVER_IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if ip := os.Getenv("MAIL_SERVER_IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	publicIPMutex.Lock()
	defer publicIPMutex.Unlock()

	// Return cached IP if checked within last 1 hour
	if cachedPublicIP != "" && time.Since(cachedPublicIPTime) < time.Hour {
		return cachedPublicIP
	}

	// Fetch from fast public IP providers with 1.5s timeout
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err == nil && resp.StatusCode == http.StatusOK {
			buf := make([]byte, 64)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			ipStr := strings.TrimSpace(string(buf[:n]))
			if parsedIP := net.ParseIP(ipStr); parsedIP != nil && parsedIP.To4() != nil {
				cachedPublicIP = ipStr
				cachedPublicIPTime = time.Now()
				return ipStr
			}
		}
	}

	// Fallback to local non-loopback outbound socket
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr.IP != nil && !localAddr.IP.IsLoopback() {
			cachedPublicIP = localAddr.IP.String()
			cachedPublicIPTime = time.Now()
			return cachedPublicIP
		}
	}

	return ""
}

func (h *DomainHandler) DNS(w http.ResponseWriter, r *http.Request) {
	domName := parseEmailParam(r, "domain")
	pol, _ := h.dkimService.GetPolicy(r.Context(), domName)
	dkimRec, _ := h.dkimService.GetDNSRecord(r.Context(), domName, "default")

	serverIP := getPublicServerIP()

	spfVal := "v=spf1 a mx ~all"
	if serverIP != "" {
		spfVal = fmt.Sprintf("v=spf1 a mx ip4:%s ~all", serverIP)
	}

	dmarcVal := fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s", domName)
	if pol != nil {
		if pol.SPFPolicy != "" && pol.SPFPolicy != "v=spf1 mx ~all" {
			spfVal = pol.SPFPolicy
		}
		if pol.DMARCPolicy != "" && pol.DMARCPolicy != "v=DMARC1; p=none" {
			dmarcVal = pol.DMARCPolicy
		}
	}

	aValue := serverIP
	if aValue == "" {
		aValue = "<YOUR_SERVER_IPV4>"
	}

	recs := map[string]interface{}{
		"domain":    domName,
		"server_ip": serverIP,
		"a": map[string]interface{}{
			"type":  "A",
			"host":  "mail",
			"value": aValue,
		},
		"mx": map[string]interface{}{
			"type":     "MX",
			"host":     "@",
			"value":    "mail." + domName,
			"priority": 10,
		},
		"spf": map[string]string{
			"type":  "TXT",
			"host":  "@",
			"value": spfVal,
		},
		"dmarc": map[string]string{
			"type":  "TXT",
			"host":  "_dmarc",
			"value": dmarcVal,
		},
		"dkim": dkimRec,
	}

	response.JSON(w, http.StatusOK, recs)
}
