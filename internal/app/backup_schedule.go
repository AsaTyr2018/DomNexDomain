package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/jlaffaye/ftp"
)

const (
	settingBackupEnabled        = "runtime.backup.enabled"
	settingBackupInterval       = "runtime.backup.interval_hours"
	settingBackupLastRun        = "runtime.backup.last_run_at"
	settingBackupLastResult     = "runtime.backup.last_result"
	settingBackupRetentionCount = "runtime.backup.retention_count"
	settingBackupLocalEnabled   = "runtime.backup.local.enabled"
	settingBackupLocalDir       = "runtime.backup.local.dir"
	settingBackupFTPEnabled     = "runtime.backup.ftp.enabled"
	settingBackupFTPHost        = "runtime.backup.ftp.host"
	settingBackupFTPPort        = "runtime.backup.ftp.port"
	settingBackupFTPUser        = "runtime.backup.ftp.user"
	settingBackupFTPRemoteDir   = "runtime.backup.ftp.remote_dir"
	settingBackupFTPTLSMode     = "runtime.backup.ftp.tls_mode"

	secretBackupPassphrase = "backup.schedule_passphrase"
	secretBackupFTPPass    = "backup.ftp_password"
)

type BackupLocalSettings struct {
	Enabled bool   `json:"enabled"`
	Dir     string `json:"dir"`
}

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
	Enabled          bool                `json:"enabled"`
	IntervalHours    int                 `json:"intervalHours"`
	RetentionCount   int                 `json:"retentionCount"`
	HasPassphrase    bool                `json:"hasPassphrase"`
	PassphraseMasked bool                `json:"passphraseMasked"`
	LastRunAt        string              `json:"lastRunAt,omitempty"`
	LastResult       string              `json:"lastResult,omitempty"`
	Local            BackupLocalSettings `json:"local"`
	FTP              BackupFTPSettings   `json:"ftp"`
}

type BackupGeneralStats struct {
	TotalArchives int64 `json:"totalArchives"`
	LocalArchives int64 `json:"localArchives"`
	FTPArchives   int64 `json:"ftpArchives"`
}

func defaultBackupScheduleSettings() BackupScheduleSettings {
	return BackupScheduleSettings{
		Enabled:        false,
		IntervalHours:  24,
		RetentionCount: 10,
		Local: BackupLocalSettings{
			Enabled: true,
			Dir:     "/var/lib/domnexdomain/backups",
		},
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
	out.RetentionCount = in.RetentionCount
	if out.RetentionCount < 1 {
		out.RetentionCount = 10
	}
	if out.RetentionCount > 1000 {
		out.RetentionCount = 1000
	}
	out.Local.Enabled = in.Local.Enabled
	out.Local.Dir = strings.TrimSpace(in.Local.Dir)
	if out.Local.Dir == "" {
		out.Local.Dir = "/var/lib/domnexdomain/backups"
	}
	if !filepath.IsAbs(out.Local.Dir) {
		return out, fmt.Errorf("local backup dir must be an absolute path")
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
	if !out.Local.Enabled && !out.FTP.Enabled {
		return out, fmt.Errorf("enable at least one backup target (local or ftp)")
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
	if err := s.store.SetSetting(ctx, settingBackupRetentionCount, strconv.Itoa(cfg.RetentionCount)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupLocalEnabled, strconv.FormatBool(cfg.Local.Enabled)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingBackupLocalDir, cfg.Local.Dir); err != nil {
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
	if v, err := s.store.GetSetting(ctx, settingBackupRetentionCount); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.RetentionCount = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLastRun); err == nil {
		out.LastRunAt = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLastResult); err == nil {
		out.LastResult = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLocalEnabled); err == nil {
		out.Local.Enabled = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.store.GetSetting(ctx, settingBackupLocalDir); err == nil {
		out.Local.Dir = strings.TrimSpace(v)
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

func (s *Service) GetBackupGeneralStats(ctx context.Context) (BackupGeneralStats, error) {
	items, err := s.store.ListBackupArchives(ctx, 5000)
	if err != nil {
		return BackupGeneralStats{}, err
	}
	out := BackupGeneralStats{TotalArchives: int64(len(items))}
	for _, it := range items {
		switch strings.ToLower(strings.TrimSpace(it.Storage)) {
		case "local":
			out.LocalArchives++
		case "ftp":
			out.FTPArchives++
		}
	}
	return out, nil
}

func (s *Service) ListBackupArchives(ctx context.Context, limit int) ([]model.BackupArchive, error) {
	return s.store.ListBackupArchives(ctx, limit)
}

func (s *Service) RestoreBackupArchive(ctx context.Context, id int64, confirm string) (BackupMeta, PostRestoreCheckResult, error) {
	if strings.TrimSpace(confirm) != "RESTORE" {
		return BackupMeta{}, PostRestoreCheckResult{}, fmt.Errorf("confirm must equal RESTORE")
	}
	rec, err := s.store.GetBackupArchiveByID(ctx, id)
	if err != nil {
		return BackupMeta{}, PostRestoreCheckResult{}, err
	}
	passphrase, err := s.getBackupSchedulePassphrase(ctx)
	if err != nil || strings.TrimSpace(passphrase) == "" {
		return BackupMeta{}, PostRestoreCheckResult{}, fmt.Errorf("scheduled backup passphrase missing")
	}
	raw, err := s.readArchiveRaw(ctx, rec)
	if err != nil {
		return BackupMeta{}, PostRestoreCheckResult{}, err
	}
	meta, err := s.RestoreFromBackupPackage(ctx, rec.FileName, raw, passphrase)
	if err != nil {
		return BackupMeta{}, PostRestoreCheckResult{}, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	post, postErr := s.RunPostRestoreCheck(checkCtx)
	cancel()
	if postErr != nil {
		return meta, PostRestoreCheckResult{}, postErr
	}
	return meta, post, nil
}

func (s *Service) DeleteBackupArchive(ctx context.Context, id int64) error {
	rec, err := s.store.GetBackupArchiveByID(ctx, id)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(rec.Storage)) {
	case "local":
		_ = os.Remove(strings.TrimSpace(rec.Location))
	case "ftp":
		cfg, err := s.GetBackupScheduleSettings(ctx)
		if err == nil {
			if ftpPass, perr := s.getBackupFTPPassword(ctx); perr == nil && strings.TrimSpace(ftpPass) != "" {
				_ = deleteBackupViaFTP(cfg.FTP, ftpPass, rec.Location)
			}
		}
	}
	return s.store.DeleteBackupArchiveByID(ctx, id)
}

func (s *Service) readArchiveRaw(ctx context.Context, rec model.BackupArchive) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(rec.Storage)) {
	case "local":
		return os.ReadFile(strings.TrimSpace(rec.Location))
	case "ftp":
		cfg, err := s.GetBackupScheduleSettings(ctx)
		if err != nil {
			return nil, err
		}
		ftpPass, err := s.getBackupFTPPassword(ctx)
		if err != nil || strings.TrimSpace(ftpPass) == "" {
			return nil, fmt.Errorf("ftp password missing")
		}
		return downloadBackupViaFTP(cfg.FTP, ftpPass, rec.Location)
	default:
		return nil, fmt.Errorf("unknown archive storage")
	}
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
	_ = s.runScheduledBackup(ctx, true, "auto")
}

func (s *Service) RunScheduledBackupNow(ctx context.Context) error {
	s.backupRunMu.Lock()
	defer s.backupRunMu.Unlock()
	return s.runScheduledBackup(ctx, false, "manual")
}

func (s *Service) runScheduledBackup(ctx context.Context, enforceInterval bool, trigger string) error {
	cfg, err := s.GetBackupScheduleSettings(ctx)
	if err != nil {
		return err
	}
	if enforceInterval && !cfg.Enabled {
		return nil
	}
	if !enforceInterval && !cfg.Enabled {
		return fmt.Errorf("scheduled backups are disabled")
	}
	lastRun := time.Time{}
	if strings.TrimSpace(cfg.LastRunAt) != "" {
		if t, perr := time.Parse(time.RFC3339Nano, strings.TrimSpace(cfg.LastRunAt)); perr == nil {
			lastRun = t
		}
	}
	// Fallback guard: if setting write failed previously, use latest archive timestamp
	// so interval enforcement still works and prevents minute-spam backups.
	if items, lerr := s.store.ListBackupArchives(ctx, 1); lerr == nil && len(items) > 0 {
		t := items[0].CreatedAt
		if !t.IsZero() && t.After(lastRun) {
			lastRun = t
		}
	}
	interval := time.Duration(cfg.IntervalHours) * time.Hour
	if enforceInterval && !lastRun.IsZero() && time.Since(lastRun) < interval {
		return nil
	}
	passphrase, err := s.getBackupSchedulePassphrase(ctx)
	if err != nil || strings.TrimSpace(passphrase) == "" {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule skipped: missing passphrase")
		return fmt.Errorf("missing backup passphrase")
	}
	raw, _, err := s.CreateBackupPackage(ctx, passphrase)
	if err != nil {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: "+err.Error())
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.failed", Target: "create", Meta: err.Error()})
		return err
	}
	fileName := "domnex-backup-" + time.Now().UTC().Format("20060102-150405") + ".dnxbak"
	localOK := false
	ftpOK := false
	if cfg.Local.Enabled {
		loc, err := persistLocalBackup(cfg.Local.Dir, fileName, raw)
		if err != nil {
			_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: local store: "+err.Error())
		} else {
			_, _ = s.store.InsertBackupArchive(ctx, model.BackupArchive{
				FileName:  fileName,
				Storage:   "local",
				Location:  loc,
				SizeBytes: int64(len(raw)),
				SHA256:    hashHex(raw),
				Status:    "ready",
			})
			localOK = true
		}
	}
	if cfg.FTP.Enabled {
		ftpPass, err := s.getBackupFTPPassword(ctx)
		if err != nil || strings.TrimSpace(ftpPass) == "" {
			_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: ftp password missing")
		} else {
			remotePath, err := uploadBackupViaFTP(cfg.FTP, ftpPass, fileName, raw)
			if err != nil {
				_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: ftp upload: "+err.Error())
			} else {
				_, _ = s.store.InsertBackupArchive(ctx, model.BackupArchive{
					FileName:  fileName,
					Storage:   "ftp",
					Location:  remotePath,
					SizeBytes: int64(len(raw)),
					SHA256:    hashHex(raw),
					Status:    "ready",
				})
				ftpOK = true
			}
		}
	}
	_ = s.enforceArchiveRetention(ctx, cfg)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_ = s.store.SetSetting(ctx, settingBackupLastRun, now)
	meta := "trigger=" + strings.TrimSpace(trigger) + ";local=" + strconv.FormatBool(localOK) + ";ftp=" + strconv.FormatBool(ftpOK)
	if localOK || ftpOK {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "ok")
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.success", Target: fileName, Meta: meta})
	} else {
		_ = s.store.SetSetting(ctx, settingBackupLastResult, "schedule failed: no backup target succeeded")
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.schedule.failed", Target: fileName, Meta: meta})
		return fmt.Errorf("no backup target succeeded")
	}
	return nil
}

func (s *Service) enforceArchiveRetention(ctx context.Context, cfg BackupScheduleSettings) error {
	keep := cfg.RetentionCount
	if keep < 1 {
		keep = 10
	}
	if cfg.Local.Enabled {
		items, err := s.store.ListBackupArchivesByStorageOldestFirst(ctx, "local")
		if err == nil && len(items) > keep {
			for _, it := range items[:len(items)-keep] {
				_ = os.Remove(strings.TrimSpace(it.Location))
				_ = s.store.DeleteBackupArchiveByID(ctx, it.ID)
			}
		}
	}
	if cfg.FTP.Enabled {
		ftpPass, err := s.getBackupFTPPassword(ctx)
		if err == nil && strings.TrimSpace(ftpPass) != "" {
			items, lerr := s.store.ListBackupArchivesByStorageOldestFirst(ctx, "ftp")
			if lerr == nil && len(items) > keep {
				for _, it := range items[:len(items)-keep] {
					_ = deleteBackupViaFTP(cfg.FTP, ftpPass, it.Location)
					_ = s.store.DeleteBackupArchiveByID(ctx, it.ID)
				}
			}
		}
	}
	return nil
}

func persistLocalBackup(dir, fileName string, raw []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	loc := filepath.Join(dir, fileName)
	if err := os.WriteFile(loc, raw, 0o600); err != nil {
		return "", err
	}
	return loc, nil
}

func connectFTP(cfg BackupFTPSettings, password string) (*ftp.ServerConn, error) {
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
		return nil, err
	}
	if err := conn.Login(cfg.Username, password); err != nil {
		_ = conn.Quit()
		return nil, err
	}
	return conn, nil
}

func uploadBackupViaFTP(cfg BackupFTPSettings, password, fileName string, raw []byte) (string, error) {
	conn, err := connectFTP(cfg, password)
	if err != nil {
		return "", err
	}
	defer conn.Quit()
	remoteDir := strings.TrimSpace(cfg.RemoteDir)
	if remoteDir == "" {
		remoteDir = "/"
	}
	if err := ensureFTPDir(conn, remoteDir); err != nil {
		return "", err
	}
	remotePath := path.Join(remoteDir, fileName)
	if err := conn.Stor(remotePath, bytes.NewReader(raw)); err != nil {
		return "", err
	}
	return remotePath, nil
}

func downloadBackupViaFTP(cfg BackupFTPSettings, password, remotePath string) ([]byte, error) {
	conn, err := connectFTP(cfg, password)
	if err != nil {
		return nil, err
	}
	defer conn.Quit()
	r, err := conn.Retr(strings.TrimSpace(remotePath))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 96<<20))
}

func deleteBackupViaFTP(cfg BackupFTPSettings, password, remotePath string) error {
	conn, err := connectFTP(cfg, password)
	if err != nil {
		return err
	}
	defer conn.Quit()
	return conn.Delete(strings.TrimSpace(remotePath))
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
