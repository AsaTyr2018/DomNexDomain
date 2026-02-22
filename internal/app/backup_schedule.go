package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/jlaffaye/ftp"
)

const (
	settingBackupEnabled      = "runtime.backup.enabled"
	settingBackupInterval     = "runtime.backup.interval_hours"
	settingBackupLastRun      = "runtime.backup.last_run_at"
	settingBackupLastResult   = "runtime.backup.last_result"
	settingBackupFTPEnabled   = "runtime.backup.ftp.enabled"
	settingBackupFTPHost      = "runtime.backup.ftp.host"
	settingBackupFTPPort      = "runtime.backup.ftp.port"
	settingBackupFTPUser      = "runtime.backup.ftp.user"
	settingBackupFTPRemoteDir = "runtime.backup.ftp.remote_dir"
	settingBackupFTPTLSMode   = "runtime.backup.ftp.tls_mode"

	secretBackupPassphrase = "backup.schedule_passphrase"
	secretBackupFTPPass    = "backup.ftp_password"
)

type BackupFTPSettings struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	RemoteDir      string `json:"remoteDir"`
	TLSMode        string `json:"tlsMode"`
	HasPassword    bool   `json:"hasPassword"`
	PasswordMasked bool   `json:"passwordMasked"`
}

type BackupScheduleSettings struct {
	Enabled          bool              `json:"enabled"`
	IntervalHours    int               `json:"intervalHours"`
	HasPassphrase    bool              `json:"hasPassphrase"`
	PassphraseMasked bool              `json:"passphraseMasked"`
	LastRunAt        string            `json:"lastRunAt,omitempty"`
	LastResult       string            `json:"lastResult,omitempty"`
	FTP              BackupFTPSettings `json:"ftp"`
}

func defaultBackupScheduleSettings() BackupScheduleSettings {
	return BackupScheduleSettings{
		Enabled:       false,
		IntervalHours: 24,
		FTP: BackupFTPSettings{
			Enabled:   false,
			Port:      21,
			RemoteDir: "/",
			TLSMode:   "explicit",
		},
	}
}

func normalizeBackupScheduleSettings(in BackupScheduleSettings) (BackupScheduleSettings, error) {
	out := defaultBackupScheduleSettings()
	out.Enabled = in.Enabled
	out.IntervalHours = in.IntervalHours
	if out.IntervalHours < 1 {
		out.IntervalHours = 1
	}
	if out.IntervalHours > 168 {
		out.IntervalHours = 168
	}
	out.FTP.Enabled = in.FTP.Enabled
	out.FTP.Host = strings.TrimSpace(in.FTP.Host)
	out.FTP.Port = in.FTP.Port
	if out.FTP.Port <= 0 {
		out.FTP.Port = 21
	}
	if out.FTP.Port > 65535 {
		return out, fmt.Errorf("ftp port must be 1-65535")
	}
	out.FTP.Username = strings.TrimSpace(in.FTP.Username)
	out.FTP.RemoteDir = strings.TrimSpace(in.FTP.RemoteDir)
	if out.FTP.RemoteDir == "" {
		out.FTP.RemoteDir = "/"
	}
	if !strings.HasPrefix(out.FTP.RemoteDir, "/") {
		out.FTP.RemoteDir = "/" + out.FTP.RemoteDir
	}
	switch strings.ToLower(strings.TrimSpace(in.FTP.TLSMode)) {
	case "off", "explicit", "implicit":
		out.FTP.TLSMode = strings.ToLower(strings.TrimSpace(in.FTP.TLSMode))
	default:
		out.FTP.TLSMode = "explicit"
	}
	if out.FTP.Enabled {
		if out.FTP.Host == "" {
			return out, fmt.Errorf("ftp host is required")
		}
		if out.FTP.Username == "" {
			return out, fmt.Errorf("ftp username is required")
		}
	}
	return out, nil
}

func (s *Service) SetBackupScheduleSettings(ctx context.Context, in BackupScheduleSettings, passphrase, ftpPassword string) error {
	cfg, err := normalizeBackupScheduleSettings(in)
	if err != nil {
		return err
	}
	passphrase = strings.TrimSpace(passphrase)
	if passphrase != "" {
		if len(passphrase) < 12 {
			return fmt.Errorf("backup passphrase must be at least 12 characters")
		}
		enc, err := s.keystore.Encrypt(passphrase)
		if err != nil {
			return err
		}
		if err := s.store.StoreSecret(ctx, secretBackupPassphrase, enc); err != nil {
			return err
		}
	}
	if cfg.Enabled {
		if _, err := s.getBackupSchedulePassphrase(ctx); err != nil {
			return fmt.Errorf("scheduled backup enabled but no backup passphrase stored")
		}
	}
	ftpPassword = strings.TrimSpace(ftpPassword)
	if ftpPassword != "" {
		enc, err := s.keystore.Encrypt(ftpPassword)
		if err != nil {
			return err
		}
		if err := s.store.StoreSecret(ctx, secretBackupFTPPass, enc); err != nil {
			return err
		}
	}
	if cfg.FTP.Enabled {
		if _, err := s.getBackupFTPPassword(ctx); err != nil {
			return fmt.Errorf("ftp upload enabled but no ftp password stored")
		}
	}
	if err := s.store.SetSetting(ctx, settingBackupEnabled, strconv.FormatBool(cfg.Enabled)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupInterval, strconv.Itoa(cfg.IntervalHours)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPEnabled, strconv.FormatBool(cfg.FTP.Enabled)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPHost, cfg.FTP.Host); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPPort, strconv.Itoa(cfg.FTP.Port)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPUser, cfg.FTP.Username); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPRemoteDir, cfg.FTP.RemoteDir); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupFTPTLSMode, cfg.FTP.TLSMode); err != nil {
		return err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.settings.update", Target: "schedule", Meta: "enabled=" + strconv.FormatBool(cfg.Enabled)})
	return nil
}

func (s *Service) GetBackupScheduleSettings(ctx context.Context) (BackupScheduleSettings, error) {
	out := defaultBackupScheduleSettings()
	if v, err := s.store.GetSetting(ctx, settingBackupEnabled); err == nil {
		out.Enabled = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.store.GetSetting(ctx, settingBackupInterval); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.IntervalHours = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLastRun); err == nil {
		out.LastRunAt = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLastResult); err == nil {
		out.LastResult = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPEnabled); err == nil {
		out.FTP.Enabled = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPHost); err == nil {
		out.FTP.Host = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPPort); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.FTP.Port = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPUser); err == nil {
		out.FTP.Username = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPRemoteDir); err == nil {
		out.FTP.RemoteDir = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupFTPTLSMode); err == nil {
		out.FTP.TLSMode = strings.TrimSpace(v)
	}
	if _, err := s.getBackupSchedulePassphrase(ctx); err == nil {
		out.HasPassphrase = true
		out.PassphraseMasked = true
	}
	if _, err := s.getBackupFTPPassword(ctx); err == nil {
		out.FTP.HasPassword = true
		out.FTP.PasswordMasked = true
	}
	return normalizeBackupScheduleSettings(out)
}

func (s *Service) getBackupSchedulePassphrase(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, secretBackupPassphrase)
	if err != nil {
		return "", err
	}
	return s.keystore.Decrypt(enc)
}

func (s *Service) getBackupFTPPassword(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, secretBackupFTPPass)
	if err != nil {
		return "", err
	}
	return s.keystore.Decrypt(enc)
}

func (s *Service) StartBackupScheduler(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScheduledBackupTick(ctx)
		}
	}
}

func (s *Service) runScheduledBackupTick(ctx context.Context) {
	s.backupRunMu.Lock()
	defer s.backupRunMu.Unlock()
	cfg, err := s.GetBackupScheduleSettings(ctx)
	if err != nil || !cfg.Enabled {
		return
	}
	lastRun := time.Time{}
	if strings.TrimSpace(cfg.LastRunAt) != "" {
		if t, perr := time.Parse(time.RFC3339Nano, strings.TrimSpace(cfg.LastRunAt)); perr == nil {
			lastRun = t
		}
	}
	interval := time.Duration(cfg.IntervalHours) * time.Hour
	if !lastRun.IsZero() && time.Since(lastRun) < interval {
		return
	}
	passphrase, err := s.getBackupSchedulePassphrase(ctx)
	if err != nil || strings.TrimSpace(passphrase) == "" {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule skipped: missing passphrase")
		return
	}
	raw, _, err := s.CreateBackupPackage(ctx, passphrase)
	if err != nil {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: "+err.Error())
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.failed", Target: "create", Meta: err.Error()})
		return
	}
	fileName := "domnex-backup-" + time.Now().UTC().Format("20060102-150405") + ".dnxbak"
	if cfg.FTP.Enabled {
		ftpPass, err := s.getBackupFTPPassword(ctx)
		if err != nil || strings.TrimSpace(ftpPass) == "" {
			_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: ftp password missing")
			return
		}
		if err := uploadBackupViaFTP(cfg.FTP, ftpPass, fileName, raw); err != nil {
			_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: ftp upload: "+err.Error())
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.failed", Target: "ftp", Meta: err.Error()})
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_ = s.store.SetSetting(ctx, settingBackupLastRun, now)
	_ = s.store.SetSetting(ctx, settingBackupLastResult, "ok")
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.success", Target: fileName, Meta: "ftp=" + strconv.FormatBool(cfg.FTP.Enabled)})
}

func uploadBackupViaFTP(cfg BackupFTPSettings, password, fileName string, raw []byte) error {
	addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	dialOpts := []ftp.DialOption{ftp.DialWithTimeout(15 * time.Second)}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	switch cfg.TLSMode {
	case "explicit":
		dialOpts = append(dialOpts, ftp.DialWithExplicitTLS(tlsCfg))
	case "implicit":
		dialOpts = append(dialOpts, ftp.DialWithTLS(tlsCfg))
	}
	conn, err := ftp.Dial(addr, dialOpts...)
	if err != nil {
		return err
	}
	defer conn.Quit()
	if err := conn.Login(cfg.Username, password); err != nil {
		return err
	}
	remoteDir := strings.TrimSpace(cfg.RemoteDir)
	if remoteDir == "" {
		remoteDir = "/"
	}
	if err := ensureFTPDir(conn, remoteDir); err != nil {
		return err
	}
	remotePath := path.Join(remoteDir, fileName)
	return conn.Stor(remotePath, bytes.NewReader(raw))
}

func ensureFTPDir(conn *ftp.ServerConn, dir string) error {
	if dir == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	cur := ""
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cur = cur + "/" + p
		_ = conn.MakeDir(cur)
	}
	return nil
}
