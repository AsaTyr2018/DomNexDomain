package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/model"
)

const (
	settingSetupCompletedAt = "setup.completed_at"
	setupOTSTTL             = 20 * time.Minute
	setupUnlockTTL          = 45 * time.Minute
	setupMaxAttempts        = 5
	setupCooldownTTL        = 5 * time.Minute
)

type SetupStatus struct {
	Initialized   bool      `json:"initialized"`
	Locked        bool      `json:"locked"`
	Unlocked      bool      `json:"unlocked"`
	RestoreReady  bool      `json:"restoreReady"`
	OTSExpiresAt  time.Time `json:"otsExpiresAt,omitempty"`
	UnlockUntil   time.Time `json:"unlockUntil,omitempty"`
	CooldownUntil time.Time `json:"cooldownUntil,omitempty"`
}

type SetupBackupMeta struct {
	FileName      string `json:"fileName"`
	Format        string `json:"format"`
	CreatedAt     string `json:"createdAt"`
	DomNexVersion string `json:"domnexVersion"`
	Domains       int    `json:"domains"`
	Subdomains    int    `json:"subdomains"`
	Users         int    `json:"users"`
}

type SetupApplyInput struct {
	Mode               string            `json:"mode"`
	AdminUsername      string            `json:"adminUsername"`
	AdminPassword      string            `json:"adminPassword"`
	ACMEEmail          string            `json:"acmeEmail"`
	ACMEStaging        bool              `json:"acmeStaging"`
	CFToken            string            `json:"cfToken"`
	PublicIPv4         string            `json:"publicIpv4"`
	BaseDomain         string            `json:"baseDomain"`
	TimeSyncMode       string            `json:"timeSyncMode"`
	TimeSyncLANServers string            `json:"timeSyncLanServers"`
	LogServers         LogServerSettings `json:"logServers"`
	LogHTTPBearer      string            `json:"logHttpBearer"`
	Retention          RetentionPolicy   `json:"retention"`
	DomainName         string            `json:"domainName"`
	DomainDNSMode      string            `json:"domainDnsMode"`
	DomainCertMode     string            `json:"domainCertMode"`
	DomainProvider     string            `json:"domainProvider"`
	DomainZoneID       string            `json:"domainZoneId"`
	FirstSubdomain     string            `json:"firstSubdomain"`
	FirstUpstream      string            `json:"firstUpstream"`
	FirstInsecureTLS   bool              `json:"firstInsecureTls"`
	BackupMeta         *SetupBackupMeta  `json:"backupMeta,omitempty"`
}

func (s *Service) ensureSetupState(ctx context.Context) error {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.ensureSetupStateLocked(ctx)
}

func (s *Service) ensureSetupStateLocked(ctx context.Context) error {
	if s.setupInitialized {
		return nil
	}
	if v, err := s.store.GetSetting(ctx, settingSetupCompletedAt); err == nil && strings.TrimSpace(v) != "" {
		s.setupInitialized = true
		return nil
	}
	count, err := s.store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		s.setupInitialized = true
		_ = s.store.SetSetting(ctx, settingSetupCompletedAt, time.Now().UTC().Format(time.RFC3339Nano))
		return nil
	}
	// first-run setup mode
	now := time.Now().UTC()
	if now.Before(s.setupOTSExpires) {
		return nil
	}
	return s.rotateOTSLocked(now)
}

func (s *Service) rotateOTSLocked(now time.Time) error {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	code := strings.ToUpper(base64.RawURLEncoding.EncodeToString(raw))
	s.setupOTSHash = sha256.Sum256([]byte(code))
	s.setupOTSExpires = now.Add(setupOTSTTL)
	s.setupUnlockUntil = time.Time{}
	s.setupAttempts = 0
	s.setupCooldown = time.Time{}
	s.log.Warn("initial setup locked: one-time setup code generated", map[string]any{
		"ots":       code,
		"expiresAt": s.setupOTSExpires.Format(time.RFC3339),
	})
	_ = s.writeOTSFile(code)
	return nil
}

func (s *Service) writeOTSFile(code string) error {
	bootDir := filepath.Join(s.cfg.DataDir, "bootstrap")
	if err := os.MkdirAll(bootDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(bootDir, "ots")
	body := []byte(code + "\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return nil
}

func (s *Service) GetSetupStatus(ctx context.Context) (SetupStatus, error) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.ensureSetupStateLocked(ctx); err != nil {
		return SetupStatus{}, err
	}
	now := time.Now().UTC()
	st := SetupStatus{Initialized: s.setupInitialized}
	if st.Initialized {
		st.Locked = false
		st.Unlocked = false
		st.RestoreReady = false
		return st, nil
	}
	st.OTSExpiresAt = s.setupOTSExpires
	st.CooldownUntil = s.setupCooldown
	st.Unlocked = now.Before(s.setupUnlockUntil)
	st.Locked = !st.Unlocked
	st.RestoreReady = s.setupRestore != nil
	if st.Unlocked {
		st.UnlockUntil = s.setupUnlockUntil
	}
	return st, nil
}

func (s *Service) UnlockSetup(ctx context.Context, code string) (SetupStatus, error) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.ensureSetupStateLocked(ctx); err != nil {
		return SetupStatus{}, err
	}
	if s.setupInitialized {
		return SetupStatus{Initialized: true}, nil
	}
	now := time.Now().UTC()
	if now.Before(s.setupCooldown) {
		return SetupStatus{}, fmt.Errorf("setup unlock temporarily blocked, retry after cooldown")
	}
	if now.After(s.setupOTSExpires) {
		if err := s.rotateOTSLocked(now); err != nil {
			return SetupStatus{}, err
		}
		return SetupStatus{}, fmt.Errorf("setup code expired; new code generated in service logs")
	}
	candidate := sha256.Sum256([]byte(strings.TrimSpace(code)))
	if subtle.ConstantTimeCompare(candidate[:], s.setupOTSHash[:]) != 1 {
		s.setupAttempts++
		if s.setupAttempts >= setupMaxAttempts {
			s.setupCooldown = now.Add(setupCooldownTTL)
			s.setupAttempts = 0
		}
		return SetupStatus{}, fmt.Errorf("invalid setup code")
	}
	s.setupUnlockUntil = now.Add(setupUnlockTTL)
	s.setupAttempts = 0
	s.setupCooldown = time.Time{}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "setup", Action: "setup.unlock.success", Target: "wizard", Meta: ""})
	st := SetupStatus{Initialized: false, Locked: false, Unlocked: true, RestoreReady: s.setupRestore != nil, OTSExpiresAt: s.setupOTSExpires, UnlockUntil: s.setupUnlockUntil}
	return st, nil
}

func (s *Service) ApplyInitialSetup(ctx context.Context, in SetupApplyInput) error {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.ensureSetupStateLocked(ctx); err != nil {
		return err
	}
	if s.setupInitialized {
		return fmt.Errorf("setup already completed")
	}
	if !time.Now().UTC().Before(s.setupUnlockUntil) {
		return fmt.Errorf("setup is locked; unlock with one-time setup code")
	}
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = "fresh"
	}
	if mode != "fresh" && mode != "restore" {
		return fmt.Errorf("invalid setup mode")
	}
	if mode == "fresh" {
		domainName := strings.ToLower(strings.TrimSpace(in.DomainName))
		dnsMode := strings.ToLower(strings.TrimSpace(in.DomainDNSMode))
		certMode := strings.ToLower(strings.TrimSpace(in.DomainCertMode))
		provider := strings.ToLower(strings.TrimSpace(in.DomainProvider))
		if dnsMode == "" {
			dnsMode = "manual"
		}
		if certMode == "" {
			certMode = "letsencrypt"
		}
		if provider == "" {
			provider = dnsMode
		}
		if domainName != "" {
			if _, err := s.UpsertDomain(ctx, domainName, dnsMode, certMode, provider, in.DomainZoneID); err != nil {
				return err
			}
			if strings.TrimSpace(in.BaseDomain) == "" {
				in.BaseDomain = domainName
			}
		}
		if err := s.SetRuntimeSettings(
			ctx,
			in.ACMEEmail,
			in.ACMEStaging,
			in.CFToken,
			in.PublicIPv4,
			in.BaseDomain,
			"cybermonolith",
			"",
			in.TimeSyncMode,
			in.TimeSyncLANServers,
			in.LogServers,
			in.LogHTTPBearer,
			in.Retention,
			MFAPolicy{},
			LDAPSettings{},
			"",
			OIDCSettings{},
			"",
		); err != nil {
			return err
		}
		firstSub := strings.ToLower(strings.TrimSpace(in.FirstSubdomain))
		firstUpstream := strings.TrimSpace(in.FirstUpstream)
		if domainName != "" && firstSub != "" && firstUpstream != "" {
			if _, err := s.CreateHost(ctx, domainName, firstSub, firstUpstream, in.FirstInsecureTLS, false, "", nil); err != nil {
				return err
			}
		}
	} else {
		if s.setupRestore == nil {
			return fmt.Errorf("restore package not uploaded")
		}
		if err := s.applyBackupSnapshot(ctx, s.setupRestore); err != nil {
			return err
		}
		s.setupRestore = nil
		checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		if res, err := s.RunPostRestoreCheck(checkCtx); err != nil {
			s.log.Warn("post-restore check failed during setup", map[string]any{"err": err.Error()})
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "setup", Action: "backup.post_restore_check.failed", Target: "setup_restore", Meta: err.Error()})
		} else {
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
				Actor:  "setup",
				Action: "backup.post_restore_check.completed",
				Target: "setup_restore",
				Meta:   "warmup=" + strconv.Itoa(res.CertWarmupSucceeded) + "/" + strconv.Itoa(res.CertWarmupAttempts),
			})
		}
		cancel()
	}

	username := strings.ToLower(strings.TrimSpace(in.AdminUsername))
	if username == "" {
		username = "admin"
	}
	if len(strings.TrimSpace(in.AdminPassword)) < 10 {
		return fmt.Errorf("admin password must be at least 10 characters")
	}
	hash, err := crypto.HashPassword(in.AdminPassword, crypto.DefaultArgonConfig())
	if err != nil {
		return err
	}
	userCount, err := s.store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if userCount == 0 {
		if _, err := s.store.CreateUser(ctx, username, model.RoleAdmin, "", false, hash); err != nil {
			return err
		}
	} else {
		u, err := s.store.FindUserByUsername(ctx, username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				if _, err := s.store.CreateUser(ctx, username, model.RoleAdmin, "", false, hash); err != nil {
					return err
				}
			} else {
				return err
			}
		} else if err := s.store.SetUserPasswordHashByID(ctx, u.ID, hash); err != nil {
			return err
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.store.SetSetting(ctx, settingSetupCompletedAt, now); err != nil {
		return err
	}
	s.setupInitialized = true
	s.setupUnlockUntil = time.Time{}
	s.setupOTSExpires = time.Time{}
	s.setupOTSHash = [32]byte{}
	s.setupAttempts = 0
	s.setupCooldown = time.Time{}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "setup", Action: "setup.completed", Target: mode, Meta: ""})
	return nil
}
