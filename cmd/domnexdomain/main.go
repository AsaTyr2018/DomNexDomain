package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/acme"
	"github.com/domnexdomain/domnexdomain/internal/api"
	"github.com/domnexdomain/domnexdomain/internal/app"
	"github.com/domnexdomain/domnexdomain/internal/auth"
	"github.com/domnexdomain/domnexdomain/internal/bastion"
	"github.com/domnexdomain/domnexdomain/internal/config"
	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/dns"
	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/metrics"
	"github.com/domnexdomain/domnexdomain/internal/proxy"
	"github.com/domnexdomain/domnexdomain/internal/store"
	"github.com/domnexdomain/domnexdomain/internal/traffic"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log, err := logx.New(cfg.EnableFileLogs, cfg.LogDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger error: %v\n", err)
		os.Exit(1)
	}
	log.Info("starting domnexdomain", map[string]any{"domain": cfg.Domain})

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("store open failed", map[string]any{"err": err.Error()})
		os.Exit(1)
	}
	defer st.Close()

	ks, err := crypto.LoadOrCreateKey(cfg.SecretKeyPath)
	if err != nil {
		log.Error("keystore init failed", map[string]any{"err": err.Error()})
		os.Exit(1)
	}

	if v, err := st.GetSetting(context.Background(), "acme.email"); err == nil && strings.TrimSpace(v) != "" {
		cfg.ACMEEmail = strings.TrimSpace(v)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Warn("acme.email setting read failed", map[string]any{"err": err.Error()})
	}
	if v, err := st.GetSetting(context.Background(), "acme.staging"); err == nil && strings.TrimSpace(v) != "" {
		cfg.ACMEStaging = strings.EqualFold(strings.TrimSpace(v), "true")
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Warn("acme.staging setting read failed", map[string]any{"err": err.Error()})
	}
	if v, err := st.GetSetting(context.Background(), "cloudflare.zone_id"); err == nil && strings.TrimSpace(v) != "" {
		cfg.CFZoneID = strings.TrimSpace(v)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Warn("cloudflare.zone_id setting read failed", map[string]any{"err": err.Error()})
	}

	cfToken := cfg.CFAPIToken
	if cfToken == "" {
		if enc, err := st.GetSecret(context.Background(), "cloudflare.api_token"); err == nil {
			if dec, err := ks.Decrypt(enc); err == nil {
				cfToken = dec
			}
		}
	}

	var dnsProvider dns.Provider
	if cfToken != "" {
		dnsProvider = dns.NewCloudflare(cfToken)
	}

	appSvc := app.New(cfg, st, ks, dnsProvider, log)
	appSvc.InitializePublicIPv4(context.Background())
	if err := appSvc.Bootstrap(context.Background(), cfg.BootstrapUser, cfg.BootstrapPass); err != nil {
		log.Error("bootstrap failed", map[string]any{"err": err.Error()})
		os.Exit(1)
	}

	authSvc, err := auth.New(st, cfg.SessionTTL, cfg.AllowedCIDRs)
	if err != nil {
		log.Error("auth init failed", map[string]any{"err": err.Error()})
		os.Exit(1)
	}
	m := metrics.New()
	tr := traffic.NewRecorder(st, log)

	apiSrv := api.New(appSvc, authSvc, log, m)
	adminServer := &http.Server{
		Addr:              cfg.AdminBindAddr,
		Handler:           apiSrv.Router(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logx.StdLogger(log),
	}

	px := proxy.New(appSvc, log, m, tr)
	if err := px.Refresh(context.Background()); err != nil {
		log.Warn("initial proxy refresh failed", map[string]any{"err": err.Error()})
	}

	acmeManager := acme.New(cfg.ACMECacheDir, cfg.ACMEEmail, cfg.ACMEStaging, appSvc)
	redirectOrACME := acmeManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           redirectOrACME,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logx.StdLogger(log),
	}

	httpsServer := &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           px.Handler(),
		TLSConfig:         acmeManager.TLSConfig(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logx.StdLogger(log),
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler())
	metricsServer := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("admin API listening", map[string]any{"addr": cfg.AdminBindAddr})
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin server failed", map[string]any{"err": err.Error()})
			stop()
		}
	}()

	go func() {
		log.Info("metrics listening", map[string]any{"addr": cfg.MetricsAddr})
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server failed", map[string]any{"err": err.Error()})
		}
	}()

	go func() {
		log.Info("HTTP listening", map[string]any{"addr": cfg.HTTPAddr})
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server failed", map[string]any{"err": err.Error()})
			stop()
		}
	}()

	go func() {
		log.Info("HTTPS listening", map[string]any{"addr": cfg.HTTPSAddr})
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTPS server failed", map[string]any{"err": err.Error()})
			stop()
		}
	}()

	go px.StartRefresher(ctx, 10*time.Second)
	go pruneSessions(ctx, st, log)
	go tr.Start(ctx)

	if cfg.SSHBastionOn {
		sshBastion := bastion.New(cfg.SSHBastionAddr, cfg.SSHBastionKey, appSvc, log)
		go func() {
			if err := sshBastion.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("ssh bastion failed", map[string]any{"err": err.Error()})
				stop()
			}
		}()
	}

	<-ctx.Done()
	log.Info("shutdown requested", nil)

	sdCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = adminServer.Shutdown(sdCtx)
	_ = httpServer.Shutdown(sdCtx)
	_ = httpsServer.Shutdown(sdCtx)
	_ = metricsServer.Shutdown(sdCtx)
	log.Info("shutdown complete", nil)
}

func pruneSessions(ctx context.Context, st *store.Store, log *logx.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.PruneExpiredSessions(ctx); err != nil {
				log.Warn("session prune failed", map[string]any{"err": err.Error()})
			}
		}
	}
}
