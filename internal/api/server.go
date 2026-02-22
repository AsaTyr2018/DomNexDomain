package api

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/domnexdomain/domnexdomain/internal/app"
	"github.com/domnexdomain/domnexdomain/internal/auth"
	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/metrics"
	"github.com/domnexdomain/domnexdomain/internal/model"
)

//go:embed all:dist
var assets embed.FS

type Server struct {
	app     *app.Service
	auth    *auth.Service
	log     *logx.Logger
	metrics *metrics.Collector
}

func New(appSvc *app.Service, authSvc *auth.Service, log *logx.Logger, m *metrics.Collector) *Server {
	return &Server{app: appSvc, auth: authSvc, log: log, metrics: m}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(s.metricsMiddleware("admin_api"))
	r.Use(s.setupGateMiddleware)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"ok": true}) })
	r.Get("/api/v1/style", s.handlePublicStyle)
	r.Get("/api/v1/csrf", s.handleCSRF)
	r.Get("/api/v1/setup/status", s.handleSetupStatus)
	r.Post("/api/v1/setup/unlock", s.handleSetupUnlock)
	r.Post("/api/v1/setup/restore/upload", s.handleSetupRestoreUpload)
	r.Post("/api/v1/setup/restore/analyze", s.handleSetupRestoreAnalyze)
	r.Post("/api/v1/setup/apply", s.handleSetupApply)
	r.Post("/api/v1/login", s.handleLogin)
	r.Post("/api/v1/password-reset/consume", s.handleConsumePasswordReset)

	r.Group(func(pr chi.Router) {
		pr.Use(s.requireAuth(model.RoleReadOnly, ""))
		pr.Get("/api/v1/me", s.handleMe)
		pr.Get("/api/v1/me/profile", s.handleMeProfileGet)
		pr.Post("/api/v1/logout", s.handleLogout)
		pr.Get("/api/v1/domains", s.handleListDomains)
		pr.Get("/api/v1/domains/{id}/live-check", s.handleDomainLiveCheck)
		pr.Get("/api/v1/hosts", s.handleListHosts)
		pr.Get("/api/v1/hosts/diagnostics", s.handleHostsDiagnostics)
		pr.Get("/api/v1/traffic/overview", s.handleTrafficOverview)
		pr.Get("/api/v1/traffic/hosts/{id}", s.handleHostTraffic)
		pr.Get("/api/v1/traffic/countries", s.handleTrafficCountries)
		pr.Get("/api/v1/audit", s.handleListAudit)
		pr.Get("/api/v1/security/ip-blocks", s.handleListBlockedIPs)
		pr.Get("/api/v1/threat-intel/config", s.handleThreatIntelConfigGet)
		pr.Get("/api/v1/threat-intel/feeds", s.handleThreatIntelFeedsList)
		pr.Get("/api/v1/threat-intel/matches", s.handleThreatIntelMatchesList)
		pr.Get("/api/v1/threat-intel/matches/{ip}/targets", s.handleThreatIntelTargetsByIP)
		pr.Get("/api/v1/threat-intel/offenders", s.handleThreatIntelOffendersList)
		pr.Get("/api/v1/threat-intel/blocked", s.handleThreatIntelBlockedList)
		pr.Get("/api/v1/threat-intel/allowlist", s.handleThreatIntelAllowlistList)
		pr.Get("/api/v1/settings", s.handleGetSettings)
		pr.Get("/api/v1/time-sync", s.handleGetTimeSyncStatus)
		pr.Get("/api/v1/system/health", s.handleGetSystemHealth)
		pr.Get("/api/v1/backup/settings", s.handleBackupSettingsGet)
		pr.Get("/api/v1/backup/archives", s.handleBackupArchivesList)
		pr.Get("/api/v1/users", s.handleListUsers)
		pr.Get("/api/v1/tokens", s.handleListTokens)
		pr.Get("/api/v1/ssh/routes", s.handleListSSHBastionRoutes)
		pr.Get("/api/v1/ssh/keys", s.handleListSSHBastionKeys)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(s.requireAuth(model.RoleReadOnly, ""))
		pr.Use(s.requireCSRF)
		pr.Post("/api/v1/me/password", s.handleChangeOwnPassword)
		pr.Post("/api/v1/me/profile", s.handleMeProfileSet)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(s.requireAuth(model.RoleOperator, "hosts:write"))
		pr.Use(s.requireCSRF)
		pr.Post("/api/v1/hosts/preflight", s.handleHostPreflight)
		pr.Post("/api/v1/hosts", s.handleCreateHost)
		pr.Put("/api/v1/hosts/{id}", s.handleUpdateHostRouting)
		pr.Put("/api/v1/hosts/{id}/auth", s.handleSetHostAuth)
		pr.Put("/api/v1/hosts/{id}/geo", s.handleSetHostGeoPolicy)
		pr.Post("/api/v1/hosts/{id}/disable", s.handleSetHostDisabled)
		pr.Post("/api/v1/hosts/{id}/maintenance", s.handleSetHostMaintenance)
		pr.Post("/api/v1/hosts/{id}/retry", s.handleRetryHost)
		pr.Delete("/api/v1/hosts/{id}", s.handleDeleteHost)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(s.requireAuth(model.RoleAdmin, ""))
		pr.Use(s.requireCSRF)
		pr.Post("/api/v1/domains/preflight", s.handleDomainPreflight)
		pr.Post("/api/v1/domains", s.handleUpsertDomain)
		pr.Post("/api/v1/domains/{id}/deactivate", s.handleDeactivateDomain)
		pr.Delete("/api/v1/domains/{id}", s.handleDeleteDomain)
		pr.Post("/api/v1/dyndns", s.handleDynDNSUpdate)
		pr.Post("/api/v1/secrets/cloudflare", s.handleSetCloudflareToken)
		pr.Post("/api/v1/tokens", s.handleCreateToken)
		pr.Get("/api/v1/tokens", s.handleListTokens)
		pr.Delete("/api/v1/tokens/{id}", s.handleRevokeToken)
		pr.Post("/api/v1/password-reset/create", s.handleCreatePasswordReset)
		pr.Post("/api/v1/settings", s.handleSetSettings)
		pr.Post("/api/v1/reload", s.handleReloadService)
		pr.Post("/api/v1/backup/settings", s.handleBackupSettingsSet)
		pr.Post("/api/v1/backup/schedule/run", s.handleBackupScheduleRunNow)
		pr.Post("/api/v1/backup/create", s.handleBackupCreate)
		pr.Post("/api/v1/backup/analyze", s.handleBackupAnalyze)
		pr.Post("/api/v1/backup/restore", s.handleBackupRestore)
		pr.Post("/api/v1/backup/post-restore-check", s.handleBackupPostRestoreCheck)
		pr.Post("/api/v1/backup/archives/{id}/restore", s.handleBackupArchiveRestore)
		pr.Delete("/api/v1/backup/archives/{id}", s.handleBackupArchiveDelete)
		pr.Post("/api/v1/users", s.handleCreateUser)
		pr.Put("/api/v1/users/{id}", s.handleUpdateUserAccess)
		pr.Put("/api/v1/users/{id}/domains", s.handleSetUserDomains)
		pr.Put("/api/v1/users/{id}/password", s.handleSetUserPassword)
		pr.Delete("/api/v1/users/{id}", s.handleDeleteUser)
		pr.Post("/api/v1/logout-all", s.handleLogoutAll)
		pr.Post("/api/v1/security/ip-blocks", s.handleAddBlockedIP)
		pr.Post("/api/v1/security/ip-blocks/remove", s.handleRemoveBlockedIP)
		pr.Post("/api/v1/ssh/routes", s.handleUpsertSSHBastionRoute)
		pr.Delete("/api/v1/ssh/routes/{id}", s.handleDeleteSSHBastionRoute)
		pr.Post("/api/v1/ssh/keys/import", s.handleImportSSHBastionKey)
		pr.Post("/api/v1/ssh/keys/generate", s.handleGenerateSSHBastionKey)
		pr.Delete("/api/v1/ssh/keys/{id}", s.handleDeleteSSHBastionKey)
		pr.Post("/api/v1/threat-intel/config", s.handleThreatIntelConfigSet)
		pr.Post("/api/v1/threat-intel/feeds", s.handleThreatIntelFeedUpsert)
		pr.Delete("/api/v1/threat-intel/feeds/{id}", s.handleThreatIntelFeedDelete)
		pr.Post("/api/v1/threat-intel/sync", s.handleThreatIntelSync)
		pr.Post("/api/v1/threat-intel/actions/block", s.handleThreatIntelActionBlock)
		pr.Post("/api/v1/threat-intel/actions/allow", s.handleThreatIntelActionAllow)
		pr.Post("/api/v1/threat-intel/actions/unallow", s.handleThreatIntelActionUnallow)
	})

	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		clean := strings.TrimPrefix(path.Clean(req.URL.Path), "/")
		if clean == "." || clean == "" {
			clean = "index.html"
		}
		p := path.Join("dist", clean)
		if b, err := fs.ReadFile(assets, p); err == nil {
			w.Header().Set("Content-Type", contentTypeFor(p))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
			return
		}
		b, err := fs.ReadFile(assets, "dist/index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})

	return r
}

func (s *Server) setupGateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		st, err := s.app.GetSetupStatus(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if st.Initialized {
			next.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/v1/style", "/api/v1/csrf", "/api/v1/setup/status", "/api/v1/setup/unlock", "/api/v1/setup/restore/upload", "/api/v1/setup/restore/analyze", "/api/v1/setup/apply":
			next.ServeHTTP(w, r)
			return
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "setup required",
				"code":  "setup_required",
			})
			return
		}
	})
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.app.GetSetupStatus(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSetupUnlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OTS string `json:"ots"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	st, err := s.app.UnlockSetup(r.Context(), in.OTS)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSetupRestoreAnalyze(w http.ResponseWriter, r *http.Request) {
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(ct, "multipart/form-data") {
		fileName, raw, passphrase, err := readBackupUpload(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		meta, err := s.app.UploadSetupBackup(r.Context(), fileName, raw, passphrase)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, meta)
		return
	}
	var in struct {
		FileName string `json:"fileName"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeErr(w, http.StatusBadRequest, "send multipart form-data with fields: backup (file), passphrase")
}

func (s *Server) handleSetupRestoreUpload(w http.ResponseWriter, r *http.Request) {
	fileName, raw, passphrase, err := readBackupUpload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, err := s.app.UploadSetupBackup(r.Context(), fileName, raw, passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleBackupSettingsGet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	cfg, err := s.app.GetBackupScheduleSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleBackupSettingsSet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Enabled        bool                    `json:"enabled"`
		IntervalHours  int                     `json:"intervalHours"`
		RetentionCount int                     `json:"retentionCount"`
		Passphrase     string                  `json:"passphrase"`
		Local          app.BackupLocalSettings `json:"local"`
		FTP            app.BackupFTPSettings   `json:"ftp"`
		FTPPassword    string                  `json:"ftpPassword"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetBackupScheduleSettings(r.Context(), app.BackupScheduleSettings{
		Enabled:        in.Enabled,
		IntervalHours:  in.IntervalHours,
		RetentionCount: in.RetentionCount,
		Local:          in.Local,
		FTP:            in.FTP,
	}, in.Passphrase, in.FTPPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleBackupArchivesList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.app.ListBackupArchives(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats, err := s.app.GetBackupGeneralStats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "stats": stats})
}

func (s *Server) handleBackupScheduleRunNow(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	if err := s.app.RunScheduledBackupNow(r.Context()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, meta, err := s.app.CreateBackupPackage(r.Context(), in.Passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fileName := "domnex-backup-" + time.Now().UTC().Format("20060102-150405") + ".dnxbak"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
	w.Header().Set("X-Domnex-Backup-Meta", toCompactJSON(meta))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleBackupAnalyze(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	fileName, raw, passphrase, err := readBackupUpload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, err := s.app.AnalyzeBackupPackage(r.Context(), fileName, raw, passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != "RESTORE" {
		writeErr(w, http.StatusBadRequest, "confirm must equal RESTORE")
		return
	}
	fileName, raw, passphrase, err := readBackupUpload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, err := s.app.RestoreFromBackupPackage(r.Context(), fileName, raw, passphrase)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	checkCtx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	post, postErr := s.app.RunPostRestoreCheck(checkCtx)
	cancel()
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "backup.restore.apply", Target: meta.FileName, Meta: "done"})
	if postErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "meta": meta, "postCheckError": postErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "meta": meta, "postCheck": post})
}

func (s *Server) handleBackupPostRestoreCheck(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	checkCtx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	out, err := s.app.RunPostRestoreCheck(checkCtx)
	cancel()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBackupArchiveRestore(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	archiveID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, post, err := s.app.RestoreBackupArchive(r.Context(), archiveID, in.Confirm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "meta": meta, "postCheck": post})
}

func (s *Server) handleBackupArchiveDelete(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	archiveID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := s.app.DeleteBackupArchive(r.Context(), archiveID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func readBackupUpload(r *http.Request) (string, []byte, string, error) {
	if err := r.ParseMultipartForm(96 << 20); err != nil {
		return "", nil, "", fmt.Errorf("invalid multipart payload")
	}
	passphrase := strings.TrimSpace(r.FormValue("passphrase"))
	if len(passphrase) < 12 {
		return "", nil, "", fmt.Errorf("passphrase must be at least 12 characters")
	}
	f, fh, err := r.FormFile("backup")
	if err != nil {
		return "", nil, "", fmt.Errorf("backup file is required")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 96<<20))
	if err != nil {
		return "", nil, "", err
	}
	if len(raw) == 0 {
		return "", nil, "", fmt.Errorf("backup file is empty")
	}
	name := ""
	if fh != nil {
		name = strings.TrimSpace(fh.Filename)
	}
	return name, raw, passphrase, nil
}

func toCompactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (s *Server) handleSetupApply(w http.ResponseWriter, r *http.Request) {
	var in app.SetupApplyInput
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.ApplyInitialSetup(r.Context(), in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": true})
}

func (s *Server) handleDomainPreflight(w http.ResponseWriter, r *http.Request) {
	if !isGlobalAdmin(identityFrom(r.Context())) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Name     string `json:"name"`
		DNSMode  string `json:"dnsMode"`
		Provider string `json:"provider"`
		ZoneID   string `json:"zoneId"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.RunDomainPreflight(r.Context(), in.Name, in.DNSMode, in.Provider, in.ZoneID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) metricsMiddleware(component string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			s.metrics.Requests.WithLabelValues(component, strconv.Itoa(ww.Status())).Inc()
		})
	}
}

func (s *Server) requireAuth(role model.Role, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := s.auth.ResolveIdentity(r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !auth.RoleAllows(id.Role, role) {
				writeErr(w, http.StatusForbidden, "insufficient role")
				return
			}
			if scope != "" && !auth.ScopeAllows(id.Scopes, scope) {
				writeErr(w, http.StatusForbidden, "missing token scope")
				return
			}
			ctx := context.WithValue(r.Context(), ctxIdentity{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r.Context())
		if id.Type == "token" {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("domnex_csrf")
		if err != nil {
			writeErr(w, http.StatusForbidden, "missing csrf cookie")
			return
		}
		header := r.Header.Get("X-CSRF-Token")
		if cookie.Value == "" || header == "" || cookie.Value != header {
			writeErr(w, http.StatusForbidden, "invalid csrf token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	token, _ := randomHex(32)
	http.SetCookie(w, &http.Cookie{Name: "domnex_csrf", Value: token, Path: "/", HttpOnly: false, Secure: isSecureRequest(r), SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]any{"csrfToken": token})
}

func (s *Server) handlePublicStyle(w http.ResponseWriter, r *http.Request) {
	profile, custom, err := s.app.GetStyleSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"styleProfile": profile,
		"styleCustom":  custom,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	source := clientIP(r)
	sid, user, err := s.auth.AuthenticatePassword(r.Context(), in.Username, in.Password, source)
	if err != nil {
		s.metrics.Failures.WithLabelValues("auth").Inc()
		writeErr(w, http.StatusUnauthorized, "login failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "domnex_session", Value: sid, Path: "/", HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if id.Type != "token" {
		cookie, err := r.Cookie("domnex_csrf")
		if err != nil || cookie.Value == "" || cookie.Value != r.Header.Get("X-CSRF-Token") {
			writeErr(w, http.StatusForbidden, "invalid csrf token")
			return
		}
	}
	c, err := r.Cookie("domnex_session")
	if err == nil && c.Value != "" {
		_ = s.auth.Logout(r.Context(), c.Value, id.Username)
	}
	http.SetCookie(w, &http.Cookie{Name: "domnex_session", Value: "", Path: "/", HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if id.UserID == 0 {
		writeErr(w, http.StatusBadRequest, "session identity required")
		return
	}
	if err := s.auth.LogoutAll(r.Context(), id.UserID, id.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"identity": identityFrom(r.Context())})
}

func profileEmailSettingKey(username string) string {
	return "profile.email." + strings.ToLower(strings.TrimSpace(username))
}

func profileDashboardLayoutSettingKey(username string) string {
	return "profile.dashboard_layout." + strings.ToLower(strings.TrimSpace(username))
}

func (s *Server) handleMeProfileGet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	email := ""
	if v, err := s.app.Store().GetSetting(r.Context(), profileEmailSettingKey(id.Username)); err == nil {
		email = strings.TrimSpace(v)
	}
	out := map[string]any{"email": email}
	if v, err := s.app.Store().GetSetting(r.Context(), profileDashboardLayoutSettingKey(id.Username)); err == nil {
		raw := strings.TrimSpace(v)
		if raw != "" && json.Valid([]byte(raw)) {
			var obj any
			if err := json.Unmarshal([]byte(raw), &obj); err == nil {
				out["dashboardLayout"] = obj
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMeProfileSet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	var in struct {
		Email           *string         `json:"email"`
		DashboardLayout json.RawMessage `json:"dashboardLayout"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Email != nil {
		email := strings.TrimSpace(*in.Email)
		if len(email) > 254 {
			writeErr(w, http.StatusBadRequest, "email too long")
			return
		}
		if email != "" && (!strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n")) {
			writeErr(w, http.StatusBadRequest, "invalid email")
			return
		}
		if err := s.app.Store().SetSetting(r.Context(), profileEmailSettingKey(id.Username), email); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "profile.email.update", Target: id.Username, Meta: ""})
	}
	if len(in.DashboardLayout) > 0 {
		raw := strings.TrimSpace(string(in.DashboardLayout))
		if len(raw) > 128*1024 {
			writeErr(w, http.StatusBadRequest, "dashboard layout too large")
			return
		}
		if raw == "" || raw == "null" {
			raw = ""
		} else if !json.Valid([]byte(raw)) {
			writeErr(w, http.StatusBadRequest, "invalid dashboard layout")
			return
		}
		if err := s.app.Store().SetSetting(r.Context(), profileDashboardLayoutSettingKey(id.Username), raw); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "profile.dashboard_layout.update", Target: id.Username, Meta: ""})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "domains:read") {
		return
	}
	items, err := s.app.ListDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		items = filterDomainsByIDs(items, id.DomainIDs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleUpsertDomain(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "domains:write") {
		return
	}
	if id.Type == "token" && !auth.ScopeAllows(id.Scopes, "global:write") {
		writeErr(w, http.StatusForbidden, "global:write required for domain upsert")
		return
	}
	var in struct {
		Name     string `json:"name"`
		DNSMode  string `json:"dnsMode"`
		CertMode string `json:"certMode"`
		Provider string `json:"provider"`
		ZoneID   string `json:"zoneId"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.DNSMode == "" {
		in.DNSMode = "cloudflare"
	}
	if in.CertMode == "" {
		in.CertMode = "letsencrypt"
	}
	if in.Provider == "" {
		in.Provider = "cloudflare"
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	d, err := s.app.UpsertDomain(r.Context(), in.Name, in.DNSMode, in.CertMode, in.Provider, in.ZoneID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "domain.upsert", Target: d.Name, Meta: d.Provider})
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "domains:write") {
		return
	}
	if id.Type == "token" && !auth.ScopeAllows(id.Scopes, "global:write") {
		writeErr(w, http.StatusForbidden, "global:write required for domain delete")
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	domainID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := s.app.RemoveDomain(r.Context(), domainID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := identityFrom(r.Context()).Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "domain.delete", Target: strconv.FormatInt(domainID, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeactivateDomain(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "domains:write") {
		return
	}
	if id.Type == "token" && !auth.ScopeAllows(id.Scopes, "global:write") {
		writeErr(w, http.StatusForbidden, "global:write required for domain deactivate")
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	domainID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := s.app.DeactivateDomain(r.Context(), domainID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "domain.deactivate",
		Target: strconv.FormatInt(domainID, 10),
		Meta:   "cascade_hosts=disabled",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:read") {
		return
	}
	h, err := s.app.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		h = filterHostsByDomainIDs(h, id.DomainIDs)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": h})
}

func (s *Server) handleDomainLiveCheck(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "domains:read") {
		return
	}
	domainID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if (id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id)) && !containsInt64(id.DomainIDs, domainID) {
		writeErr(w, http.StatusForbidden, "domain not assigned to this admin")
		return
	}
	check, err := s.app.RunDomainLiveCheck(r.Context(), domainID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, check)
}

func (s *Server) handleHostsDiagnostics(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:read") {
		return
	}
	items, err := s.app.GetHostsDiagnostics(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		allowedHosts, err := s.app.ListHosts(r.Context())
		if err == nil {
			allowedHosts = filterHostsByDomainIDs(allowedHosts, id.DomainIDs)
			set := map[string]bool{}
			for _, h := range allowedHosts {
				set[h.FQDN] = true
			}
			filtered := make([]app.HostDiagnostic, 0, len(items))
			for _, it := range items {
				if set[it.FQDN] {
					filtered = append(filtered, it)
				}
			}
			items = filtered
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleTrafficOverview(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	overview, err := s.app.GetTrafficOverview(r.Context(), hours)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		allowedHosts, err := s.app.ListHosts(r.Context())
		if err == nil {
			allowed := map[int64]bool{}
			for _, h := range filterHostsByDomainIDs(allowedHosts, id.DomainIDs) {
				allowed[h.ID] = true
			}
			filtered := make([]app.HostTrafficSummary, 0, len(overview.Hosts))
			var req, bin, bout, blk, uv int64
			for _, h := range overview.Hosts {
				if !allowed[h.HostID] {
					continue
				}
				filtered = append(filtered, h)
				req += h.Requests
				bin += h.BytesIn
				bout += h.BytesOut
				blk += h.Blocked
				uv += h.UniqueVisitors
			}
			overview.Hosts = filtered
			overview.TotalRequests = req
			overview.TotalBytesIn = bin
			overview.TotalBytesOut = bout
			overview.TotalBlocked = blk
			overview.UniqueVisitors = uv
		}
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleHostTraffic(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:read") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	out, err := s.app.GetHostTraffic(r.Context(), hostID, hours)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTrafficCountries(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	hostID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("hostId")), 10, 64)
	class := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("class")))
	switch class {
	case "", "all", "crawler", "human", "unknown":
	default:
		class = "all"
	}
	if hours <= 0 {
		hours = 24
	}

	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		allowedHosts, err := s.app.ListHosts(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		allowedHosts = filterHostsByDomainIDs(allowedHosts, id.DomainIDs)
		allowed := map[int64]app.TrafficCountryOverview{}
		if hostID > 0 {
			ok := false
			for _, h := range allowedHosts {
				if h.ID == hostID {
					ok = true
					break
				}
			}
			if !ok {
				writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
				return
			}
			out, err := s.app.GetTrafficCountries(r.Context(), hostID, hours, class)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		for _, h := range allowedHosts {
			out, err := s.app.GetTrafficCountries(r.Context(), h.ID, hours, class)
			if err != nil {
				continue
			}
			allowed[h.ID] = out
		}
		merged := app.TrafficCountryOverview{
			Hours:            hours,
			GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
			RequestClass:     class,
			Countries:        []app.CountryTraffic{},
			UnknownBreakdown: []app.HostCountryTraffic{},
		}
		byCountry := map[string]app.CountryTraffic{}
		byUnknownHost := map[int64]app.HostCountryTraffic{}
		for _, ov := range allowed {
			merged.TotalRequests += ov.TotalRequests
			merged.TotalBlocked += ov.TotalBlocked
			merged.TotalBytesOut += ov.TotalBytesOut
			for _, c := range ov.Countries {
				curr := byCountry[c.Country]
				curr.Country = c.Country
				curr.Requests += c.Requests
				curr.Blocked += c.Blocked
				curr.Status2xx += c.Status2xx
				curr.Status3xx += c.Status3xx
				curr.Status4xx += c.Status4xx
				curr.Status5xx += c.Status5xx
				curr.BytesOut += c.BytesOut
				byCountry[c.Country] = curr
			}
			for _, h := range ov.UnknownBreakdown {
				curr := byUnknownHost[h.HostID]
				curr.HostID = h.HostID
				curr.FQDN = h.FQDN
				curr.Requests += h.Requests
				curr.Blocked += h.Blocked
				curr.Status2xx += h.Status2xx
				curr.Status3xx += h.Status3xx
				curr.Status4xx += h.Status4xx
				curr.Status5xx += h.Status5xx
				curr.BytesOut += h.BytesOut
				byUnknownHost[h.HostID] = curr
			}
		}
		for _, c := range byCountry {
			merged.Countries = append(merged.Countries, c)
		}
		for _, h := range byUnknownHost {
			merged.UnknownBreakdown = append(merged.UnknownBreakdown, h)
		}
		sort.Slice(merged.Countries, func(i, j int) bool { return merged.Countries[i].Requests > merged.Countries[j].Requests })
		sort.Slice(merged.UnknownBreakdown, func(i, j int) bool { return merged.UnknownBreakdown[i].Requests > merged.UnknownBreakdown[j].Requests })
		writeJSON(w, http.StatusOK, merged)
		return
	}

	out, err := s.app.GetTrafficCountries(r.Context(), hostID, hours, class)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	var in struct {
		Domain      string            `json:"domain"`
		Sub         string            `json:"subdomain"`
		Upstream    string            `json:"upstream"`
		InsecureTLS bool              `json:"insecureTls"`
		HAEnabled   bool              `json:"haEnabled"`
		HAMode      string            `json:"haMode"`
		HABackends  []model.HABackend `json:"haBackends"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		d, err := s.app.Store().GetDomainByName(r.Context(), strings.ToLower(strings.TrimSpace(in.Domain)))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unknown domain")
			return
		}
		if !containsInt64(id.DomainIDs, d.ID) {
			writeErr(w, http.StatusForbidden, "domain not assigned to this admin")
			return
		}
	}
	h, err := s.app.CreateHost(r.Context(), in.Domain, in.Sub, in.Upstream, in.InsecureTLS, in.HAEnabled, in.HAMode, in.HABackends)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "host.create", Target: h.FQDN, Meta: h.UpstreamURL})
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) handleHostPreflight(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	var in struct {
		Domain      string            `json:"domain"`
		Sub         string            `json:"subdomain"`
		Upstream    string            `json:"upstream"`
		InsecureTLS bool              `json:"insecureTls"`
		HAEnabled   bool              `json:"haEnabled"`
		HAMode      string            `json:"haMode"`
		HABackends  []model.HABackend `json:"haBackends"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		d, err := s.app.Store().GetDomainByName(r.Context(), strings.ToLower(strings.TrimSpace(in.Domain)))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unknown domain")
			return
		}
		if !containsInt64(id.DomainIDs, d.ID) {
			writeErr(w, http.StatusForbidden, "domain not assigned to this admin")
			return
		}
	}
	out, err := s.app.RunHostPreflight(r.Context(), in.Domain, in.Sub, in.Upstream, in.InsecureTLS, in.HAEnabled, in.HAMode, in.HABackends)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateHostRouting(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	var in struct {
		Upstream    string            `json:"upstream"`
		InsecureTLS bool              `json:"insecureTls"`
		HAEnabled   bool              `json:"haEnabled"`
		HAMode      string            `json:"haMode"`
		HABackends  []model.HABackend `json:"haBackends"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.app.UpdateHostRouting(r.Context(), hostID, in.Upstream, in.InsecureTLS, in.HAEnabled, in.HAMode, in.HABackends)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "host.update",
		Target: updated.FQDN,
		Meta:   updated.UpstreamURL,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleSetHostAuth(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	var in struct {
		Enabled  bool   `json:"enabled"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.app.SetHostAuth(r.Context(), hostID, in.Enabled, in.Username, in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "host.auth.update",
		Target: updated.FQDN,
		Meta:   strconv.FormatBool(updated.AuthEnabled),
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleSetHostGeoPolicy(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	var in struct {
		Mode      string   `json:"mode"`
		Countries []string `json:"countries"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.app.SetHostGeoPolicy(r.Context(), hostID, in.Mode, in.Countries)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "host.geo.update",
		Target: updated.FQDN,
		Meta:   updated.GeoMode + ":" + strings.Join(updated.GeoCountries, ","),
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleRetryHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		h, err := s.app.Store().GetHostByID(r.Context(), hostID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	if err := s.app.RetryHost(r.Context(), hostID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := id.Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "host.retry", Target: strconv.FormatInt(hostID, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetHostDisabled(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.app.SetHostDisabled(r.Context(), hostID, in.Disabled)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	action := "host.enable"
	if in.Disabled {
		action = "host.disable"
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: action,
		Target: updated.FQDN,
		Meta:   updated.State,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleSetHostMaintenance(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	h, err := s.app.Store().GetHostByID(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.app.SetHostMaintenance(r.Context(), hostID, in.Enabled)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	action := "host.maintenance.off"
	if in.Enabled {
		action = "host.maintenance.on"
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: action,
		Target: updated.FQDN,
		Meta:   updated.State,
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "hosts:write") {
		return
	}
	hostID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id.Role == model.RoleDomainAdmin || tokenHasDomainRestriction(id) {
		h, err := s.app.Store().GetHostByID(r.Context(), hostID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !containsInt64(id.DomainIDs, h.DomainID) {
			writeErr(w, http.StatusForbidden, "host domain not assigned to this admin")
			return
		}
	}
	if err := s.app.RemoveHost(r.Context(), hostID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := id.Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "host.delete", Target: strconv.FormatInt(hostID, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetCloudflareToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(in.Token) == "" {
		writeErr(w, http.StatusBadRequest, "token required")
		return
	}
	if err := s.app.SetCloudflareToken(r.Context(), in.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDynDNSUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IPv4 string `json:"ipv4"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.UpdatePublicIP(r.Context(), in.IPv4); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "tokens:write") {
		return
	}
	var in struct {
		Name        string   `json:"name"`
		Role        string   `json:"role"`
		Scopes      []string `json:"scopes"`
		DomainIDs   []int64  `json:"domainIds"`
		Permissions struct {
			GlobalRead  bool `json:"globalRead"`
			GlobalWrite bool `json:"globalWrite"`
			DomainRead  bool `json:"domainRead"`
			DomainWrite bool `json:"domainWrite"`
			SystemRead  bool `json:"systemRead"`
			SystemWrite bool `json:"systemWrite"`
		} `json:"permissions"`
		ExpiresIn string `json:"expiresIn"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	dur, err := time.ParseDuration(in.ExpiresIn)
	if err != nil || dur <= 0 {
		dur = 30 * 24 * time.Hour
	}
	role := model.Role(in.Role)
	if role == "" {
		role = model.RoleOperator
	}
	scopeSet := map[string]bool{}
	for _, sc := range in.Scopes {
		sc = strings.TrimSpace(sc)
		if sc != "" {
			scopeSet[sc] = true
		}
	}
	if in.Permissions.DomainRead {
		scopeSet["domains:read"] = true
		scopeSet["hosts:read"] = true
	}
	if in.Permissions.DomainWrite {
		scopeSet["domains:write"] = true
		scopeSet["domains:read"] = true
		scopeSet["hosts:write"] = true
		scopeSet["hosts:read"] = true
		scopeSet["dns:write"] = true
		scopeSet["cert:write"] = true
	}
	if in.Permissions.SystemRead {
		scopeSet["system:read"] = true
		scopeSet["settings:read"] = true
		scopeSet["audit:read"] = true
		scopeSet["users:read"] = true
		scopeSet["tokens:read"] = true
	}
	if in.Permissions.SystemWrite {
		scopeSet["system:write"] = true
		scopeSet["settings:write"] = true
		scopeSet["reload:write"] = true
		scopeSet["users:write"] = true
		scopeSet["tokens:write"] = true
	}
	if in.Permissions.GlobalRead {
		scopeSet["global:read"] = true
		scopeSet["domains:read"] = true
		scopeSet["hosts:read"] = true
		scopeSet["system:read"] = true
	}
	if in.Permissions.GlobalWrite {
		scopeSet["global:write"] = true
		scopeSet["domains:write"] = true
		scopeSet["hosts:write"] = true
		scopeSet["system:write"] = true
		scopeSet["settings:write"] = true
		scopeSet["reload:write"] = true
		scopeSet["users:write"] = true
		scopeSet["tokens:write"] = true
		scopeSet["dns:write"] = true
		scopeSet["cert:write"] = true
	}
	scopeList := make([]string, 0, len(scopeSet))
	for sc := range scopeSet {
		scopeList = append(scopeList, sc)
	}
	if len(scopeList) == 0 {
		scopeList = []string{"domains:read", "hosts:read"}
	}
	tokenDomainIDs := in.DomainIDs
	if scopeSet["global:read"] || scopeSet["global:write"] {
		tokenDomainIDs = nil
	}
	tok, raw, err := s.app.Store().CreateAPIToken(r.Context(), in.Name, role, strings.Join(scopeList, ","), tokenDomainIDs, time.Now().UTC().Add(dur))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	actor := id.Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "token.create", Target: in.Name, Meta: string(role)})
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "meta": tok})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "tokens:read") {
		return
	}
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "admin or read-only required")
		return
	}
	items, err := s.app.ListAPITokens(r.Context(), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "tokens:write") {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := s.app.RevokeAPIToken(r.Context(), id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := identityFrom(r.Context()).Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "token.revoke", Target: strconv.FormatInt(id, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCreatePasswordReset(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "users:write") {
		return
	}
	var in struct {
		Username  string `json:"username"`
		ExpiresIn string `json:"expiresIn"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(in.ExpiresIn))
	if err != nil || ttl <= 0 {
		ttl = 30 * time.Minute
	}
	token, err := s.app.CreatePasswordResetToken(r.Context(), in.Username, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := identityFrom(r.Context())
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "auth.password_reset.token_created", Target: in.Username, Meta: ttl.String()})
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresIn": ttl.String()})
}

func (s *Server) handleConsumePasswordReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.ConsumePasswordResetToken(r.Context(), in.Token, in.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: "password_reset", Action: "auth.password_reset.consumed", Target: "user", Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "audit:read") {
		return
	}
	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.app.Store().ListAuditEvents(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ipFilter := strings.TrimSpace(r.URL.Query().Get("ip"))
	actionFilter := strings.TrimSpace(r.URL.Query().Get("action"))
	actorFilter := strings.TrimSpace(r.URL.Query().Get("actor"))
	if ipFilter != "" || actionFilter != "" || actorFilter != "" {
		filtered := make([]model.AuditEvent, 0, len(items))
		for _, it := range items {
			if ipFilter != "" && !strings.EqualFold(strings.TrimSpace(it.SourceIP), ipFilter) {
				continue
			}
			if actionFilter != "" && !strings.EqualFold(strings.TrimSpace(it.Action), actionFilter) {
				continue
			}
			if actorFilter != "" && !strings.EqualFold(strings.TrimSpace(it.Actor), actorFilter) {
				continue
			}
			filtered = append(filtered, it)
		}
		items = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleListBlockedIPs(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "audit:read") {
		return
	}
	items, err := s.app.Store().ListBlockedIPs(r.Context(), 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAddBlockedIP(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	var in struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := net.ParseIP(strings.TrimSpace(in.IP))
	if ip == nil {
		writeErr(w, http.StatusBadRequest, "invalid ip")
		return
	}
	if err := s.app.Store().UpsertBlockedIP(r.Context(), ip.String(), strings.TrimSpace(in.Reason)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "security.ip_block.add",
		Target: ip.String(),
		Meta:   strings.TrimSpace(in.Reason),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRemoveBlockedIP(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := net.ParseIP(strings.TrimSpace(in.IP))
	if ip == nil {
		writeErr(w, http.StatusBadRequest, "invalid ip")
		return
	}
	if err := s.app.Store().RemoveBlockedIP(r.Context(), ip.String()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "security.ip_block.remove",
		Target: ip.String(),
		Meta:   "",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "settings:read") {
		return
	}
	settings, err := s.app.GetRuntimeSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(identityFrom(r.Context())) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		ACMEEmail          string                `json:"acmeEmail"`
		ACMEStaging        bool                  `json:"acmeStaging"`
		CFToken            string                `json:"cfToken"`
		PublicIPv4         string                `json:"publicIpv4"`
		BaseDomain         string                `json:"baseDomain"`
		StyleProfile       string                `json:"styleProfile"`
		StyleCustom        string                `json:"styleCustom"`
		TimeSyncMode       string                `json:"timeSyncMode"`
		TimeSyncLANServers string                `json:"timeSyncLANServers"`
		LogServers         app.LogServerSettings `json:"logServers"`
		LogHTTPBearer      string                `json:"logHttpBearer"`
		Retention          app.RetentionPolicy   `json:"retention"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetRuntimeSettings(r.Context(), in.ACMEEmail, in.ACMEStaging, in.CFToken, in.PublicIPv4, in.BaseDomain, in.StyleProfile, in.StyleCustom, in.TimeSyncMode, in.TimeSyncLANServers, in.LogServers, in.LogHTTPBearer, in.Retention); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := id.Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "settings.update", Target: "runtime", Meta: "acme/cloudflare/base-domain/time-sync/logservers/retention"})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"restartNeeded": true,
		"message":       "Settings saved. Please restart the service so ACME and DNS runtime pick them up safely.",
	})
}

func (s *Server) handleGetTimeSyncStatus(w http.ResponseWriter, r *http.Request) {
	if !requireTokenScope(w, identityFrom(r.Context()), "settings:read") {
		return
	}
	out, err := s.app.GetTimeSyncStatus(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSystemHealth(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "system:read") {
		return
	}
	out, err := s.app.GetSystemHealth(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleThreatIntelConfigGet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:read") {
		return
	}
	cfg, err := s.app.GetThreatIntelConfig(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleThreatIntelConfigSet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in model.ThreatIntelConfig
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetThreatIntelConfig(r.Context(), in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.config.update",
		Target: "threat-intel",
		Meta:   "mode=" + strings.ToLower(strings.TrimSpace(in.Mode)),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleThreatIntelFeedsList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:read") {
		return
	}
	items, err := s.app.ListThreatIntelFeeds(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleThreatIntelFeedUpsert(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in model.ThreatIntelFeed
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.UpsertThreatIntelFeed(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.feed.upsert",
		Target: out.Name,
		Meta:   out.URL,
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleThreatIntelFeedDelete(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	feedID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if feedID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid feed id")
		return
	}
	if err := s.app.DeleteThreatIntelFeed(r.Context(), feedID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.feed.delete",
		Target: strconv.FormatInt(feedID, 10),
		Meta:   "",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleThreatIntelSync(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	out, err := s.app.SyncThreatIntelFeeds(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.sync.manual",
		Target: "threat-intel",
		Meta:   "manual",
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleThreatIntelMatchesList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "audit:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	pageSize, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("pageSize")))
	items, err := s.app.ListThreatIntelMatches(r.Context(), hours, decision, q, page, pageSize)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleThreatIntelOffendersList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "audit:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	page, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	pageSize, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("pageSize")))
	items, err := s.app.ListThreatIntelOffenders(r.Context(), hours, page, pageSize)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleThreatIntelBlockedList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "audit:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	pageSize, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("pageSize")))
	items, err := s.app.ListThreatIntelBlocked(r.Context(), hours, q, page, pageSize)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleThreatIntelTargetsByIP(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "audit:read") {
		return
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("hours")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	ip := strings.TrimSpace(chi.URLParam(r, "ip"))
	items, err := s.app.ListThreatIntelTargetsByIP(r.Context(), hours, ip, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleThreatIntelAllowlistList(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:read") {
		return
	}
	items, err := s.app.ListThreatIntelAllowlist(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleThreatIntelActionBlock(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.UpsertBlockedIP(r.Context(), strings.TrimSpace(in.IP), "threat_intel_manual:"+strings.TrimSpace(in.Reason)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.action.block",
		Target: strings.TrimSpace(in.IP),
		Meta:   strings.TrimSpace(in.Reason),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleThreatIntelActionAllow(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := strings.TrimSpace(in.IP)
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "ip required")
		return
	}
	_ = s.app.Store().RemoveBlockedIP(r.Context(), ip)
	if err := s.app.AddThreatIntelAllowIP(r.Context(), ip, strings.TrimSpace(in.Reason)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.action.allow",
		Target: ip,
		Meta:   strings.TrimSpace(in.Reason),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleThreatIntelActionUnallow(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "settings:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.RemoveThreatIntelAllowIP(r.Context(), strings.TrimSpace(in.IP)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "threatintel.action.unallow",
		Target: strings.TrimSpace(in.IP),
		Meta:   "",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReloadService(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "reload:write") {
		return
	}
	if !isGlobalAdmin(identityFrom(r.Context())) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	actor := id.Username
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: actor, Action: "service.reload", Target: "domnexdomain", Meta: "ui"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Service restart initiated"})
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:read") {
		return
	}
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "admin or read-only required")
		return
	}
	users, err := s.app.ListManagedUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Username        string  `json:"username"`
		Password        string  `json:"password"`
		Role            string  `json:"role"`
		DomainIDs       []int64 `json:"domainIds"`
		AllowedCIDRs    string  `json:"allowedCidrs"`
		IPCheckDisabled bool    `json:"ipCheckDisabled"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.app.CreateManagedUser(r.Context(), in.Username, in.Password, model.Role(in.Role), in.DomainIDs, in.AllowedCIDRs, in.IPCheckDisabled)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "user.create", Target: u.Username, Meta: string(u.Role)})
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleSetUserDomains(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	userID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var in struct {
		DomainIDs []int64 `json:"domainIds"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetManagedUserDomains(r.Context(), userID, in.DomainIDs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "user.update_domains", Target: strconv.FormatInt(userID, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUpdateUserAccess(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	userID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if userID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if userID == id.UserID {
		writeErr(w, http.StatusBadRequest, "cannot change own role via this endpoint")
		return
	}
	var in struct {
		Role            string  `json:"role"`
		DomainIDs       []int64 `json:"domainIds"`
		AllowedCIDRs    string  `json:"allowedCidrs"`
		IPCheckDisabled bool    `json:"ipCheckDisabled"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetManagedUserAccess(r.Context(), userID, model.Role(in.Role), in.DomainIDs, in.AllowedCIDRs, in.IPCheckDisabled); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "user.update_access",
		Target: strconv.FormatInt(userID, 10),
		Meta:   strings.TrimSpace(in.Role),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	userID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if userID == id.UserID {
		writeErr(w, http.StatusBadRequest, "use /api/v1/me/password for own account")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetManagedUserPassword(r.Context(), userID, in.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "user.password.reset",
		Target: strconv.FormatInt(userID, 10),
		Meta:   "admin-reset",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if id.Type != "session" || id.UserID <= 0 {
		writeErr(w, http.StatusForbidden, "session auth required")
		return
	}
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.ChangeOwnPassword(r.Context(), id.UserID, in.CurrentPassword, in.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "auth.password.changed",
		Target: id.Username,
		Meta:   "self-service",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !requireTokenScope(w, id, "users:write") {
		return
	}
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	userID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if userID == id.UserID {
		writeErr(w, http.StatusBadRequest, "cannot delete current user")
		return
	}
	if err := s.app.DeleteManagedUser(r.Context(), userID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{Actor: id.Username, Action: "user.delete", Target: strconv.FormatInt(userID, 10), Meta: ""})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListSSHBastionRoutes(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "admin or read-only required")
		return
	}
	items, err := s.app.ListSSHBastionRoutes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleUpsertSSHBastionRoute(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		ID         int64  `json:"id"`
		FQDN       string `json:"fqdn"`
		TargetHost string `json:"targetHost"`
		TargetPort int    `json:"targetPort"`
		Enabled    bool   `json:"enabled"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.UpsertSSHBastionRoute(r.Context(), model.SSHBastionRoute{
		ID:         in.ID,
		FQDN:       in.FQDN,
		TargetHost: in.TargetHost,
		TargetPort: in.TargetPort,
		Enabled:    in.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "ssh.bastion.route.upsert",
		Target: out.FQDN,
		Meta:   out.TargetHost + ":" + strconv.Itoa(out.TargetPort),
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteSSHBastionRoute(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	routeID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if routeID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid route id")
		return
	}
	if err := s.app.DeleteSSHBastionRoute(r.Context(), routeID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "ssh.bastion.route.delete",
		Target: strconv.FormatInt(routeID, 10),
		Meta:   "",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleListSSHBastionKeys(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) && id.Role != model.RoleReadOnly {
		writeErr(w, http.StatusForbidden, "admin or read-only required")
		return
	}
	items, err := s.app.ListSSHBastionKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if id.Role == model.RoleReadOnly {
		for i := range items {
			items[i].PublicKey = "REDACTED"
			items[i].Fingerprint = "REDACTED"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleImportSSHBastionKey(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Name      string  `json:"name"`
		PublicKey string  `json:"publicKey"`
		RouteIDs  []int64 `json:"routeIds"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := s.app.CreateSSHBastionKeyFromPublic(r.Context(), in.Name, in.PublicKey, in.RouteIDs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "ssh.bastion.key.import",
		Target: key.Name,
		Meta:   key.Fingerprint,
	})
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) handleGenerateSSHBastionKey(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	var in struct {
		Name     string  `json:"name"`
		RouteIDs []int64 `json:"routeIds"`
	}
	if err := decodeJSON(r.Body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.GenerateSSHBastionKey(r.Context(), in.Name, in.RouteIDs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "ssh.bastion.key.generate",
		Target: out.Key.Name,
		Meta:   out.Key.Fingerprint,
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteSSHBastionKey(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !isGlobalAdmin(id) {
		writeErr(w, http.StatusForbidden, "global admin required")
		return
	}
	keyID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if keyID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid key id")
		return
	}
	if err := s.app.DeleteSSHBastionKey(r.Context(), keyID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.app.Store().AddAuditEvent(r.Context(), model.AuditEvent{
		Actor:  id.Username,
		Action: "ssh.bastion.key.delete",
		Target: strconv.FormatInt(keyID, 10),
		Meta:   "",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type ctxIdentity struct{}

func identityFrom(ctx context.Context) auth.Identity {
	id, _ := ctx.Value(ctxIdentity{}).(auth.Identity)
	return id
}

func decodeJSON(body io.ReadCloser, out any) error {
	defer body.Close()
	dec := json.NewDecoder(io.LimitReader(body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func contentTypeFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	default:
		return "application/octet-stream"
	}
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if p := strings.TrimSpace(strings.Split(xff, ",")[0]); p != "" {
			return p
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func isGlobalAdmin(id auth.Identity) bool {
	return id.Role == model.RoleAdmin
}

func requireTokenScope(w http.ResponseWriter, id auth.Identity, scope string) bool {
	if id.Type != "token" {
		return true
	}
	if auth.ScopeAllows(id.Scopes, "global:write") {
		return true
	}
	if scope == "" || auth.ScopeAllows(id.Scopes, scope) {
		return true
	}
	writeErr(w, http.StatusForbidden, "missing token scope: "+scope)
	return false
}

func tokenHasDomainRestriction(id auth.Identity) bool {
	if id.Type != "token" {
		return false
	}
	if len(id.DomainIDs) == 0 {
		return false
	}
	if auth.ScopeAllows(id.Scopes, "global:read") || auth.ScopeAllows(id.Scopes, "global:write") {
		return false
	}
	return true
}

func containsInt64(items []int64, v int64) bool {
	for _, i := range items {
		if i == v {
			return true
		}
	}
	return false
}

func filterDomainsByIDs(items []model.Domain, allowed []int64) []model.Domain {
	if len(allowed) == 0 {
		return []model.Domain{}
	}
	out := make([]model.Domain, 0, len(items))
	for _, it := range items {
		if containsInt64(allowed, it.ID) {
			out = append(out, it)
		}
	}
	return out
}

func filterHostsByDomainIDs(items []model.Host, allowed []int64) []model.Host {
	if len(allowed) == 0 {
		return []model.Host{}
	}
	out := make([]model.Host, 0, len(items))
	for _, it := range items {
		if containsInt64(allowed, it.DomainID) {
			out = append(out, it)
		}
	}
	return out
}
