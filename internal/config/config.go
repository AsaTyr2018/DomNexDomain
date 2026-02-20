package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Domain         string
	HTTPAddr       string
	HTTPSAddr      string
	AdminBindAddr  string
	DataDir        string
	LogDir         string
	DBPath         string
	SecretKeyPath  string
	ACMECacheDir   string
	ACMEEmail      string
	ACMEStaging    bool
	CFAPIToken     string
	CFZoneID       string
	MetricsAddr    string
	SessionTTL     time.Duration
	TokenTTL       time.Duration
	BootstrapUser  string
	BootstrapPass  string
	AllowedCIDRs   []string
	EnableFileLogs bool
}

func Load() (Config, error) {
	cfg := Config{
		Domain:         getenv("DOMNEX_DOMAIN", ""),
		HTTPAddr:       getenv("DOMNEX_HTTP_ADDR", ":80"),
		HTTPSAddr:      getenv("DOMNEX_HTTPS_ADDR", ":443"),
		AdminBindAddr:  getenv("DOMNEX_ADMIN_BIND", "127.0.0.1:8443"),
		DataDir:        getenv("DOMNEX_DATA_DIR", "/var/lib/domnexdomain"),
		LogDir:         getenv("DOMNEX_LOG_DIR", "/var/log/domnexdomain"),
		ACMEEmail:      getenv("DOMNEX_ACME_EMAIL", ""),
		ACMEStaging:    getenv("DOMNEX_ACME_STAGING", "false") == "true",
		CFAPIToken:     getenv("DOMNEX_CF_API_TOKEN", ""),
		CFZoneID:       getenv("DOMNEX_CF_ZONE_ID", ""),
		MetricsAddr:    getenv("DOMNEX_METRICS_ADDR", "127.0.0.1:9108"),
		SessionTTL:     parseDuration(getenv("DOMNEX_SESSION_TTL", "12h"), 12*time.Hour),
		TokenTTL:       parseDuration(getenv("DOMNEX_TOKEN_TTL", "720h"), 30*24*time.Hour),
		BootstrapUser:  getenv("DOMNEX_BOOTSTRAP_USER", "admin"),
		BootstrapPass:  getenv("DOMNEX_BOOTSTRAP_PASSWORD", ""),
		EnableFileLogs: getenv("DOMNEX_FILE_LOGS", "false") == "true",
	}

	cfg.DBPath = getenv("DOMNEX_DB_PATH", filepath.Join(cfg.DataDir, "domnex.sqlite3"))
	cfg.SecretKeyPath = getenv("DOMNEX_SECRET_KEY", filepath.Join(cfg.DataDir, "keystore.key"))
	cfg.ACMECacheDir = getenv("DOMNEX_ACME_CACHE", filepath.Join(cfg.DataDir, "acme"))
	cfg.AllowedCIDRs = splitCSV(getenv("DOMNEX_ADMIN_ALLOWED_CIDRS", "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))

	if cfg.BootstrapPass == "" {
		return Config{}, errors.New("DOMNEX_BOOTSTRAP_PASSWORD is required")
	}
	if cfg.Domain != "" && strings.Count(cfg.Domain, ".") < 1 {
		return Config{}, errors.New("DOMNEX_DOMAIN must be an apex domain (e.g. example.com) or empty")
	}
	if err := validateCIDRs(cfg.AllowedCIDRs); err != nil {
		return Config{}, fmt.Errorf("invalid DOMNEX_ADMIN_ALLOWED_CIDRS: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return Config{}, err
	}
	if err := os.MkdirAll(cfg.ACMECacheDir, 0o750); err != nil {
		return Config{}, err
	}
	if cfg.EnableFileLogs {
		if err := os.MkdirAll(cfg.LogDir, 0o750); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func getenv(k, fallback string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	return v
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDuration(v string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func validateCIDRs(cidrs []string) error {
	for _, c := range cidrs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return err
		}
	}
	return nil
}
