package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"golang.org/x/crypto/scrypt"
)

const (
	backupMagic  = "DNXBACKUP1"
	backupSaltSz = 16
	backupNonce  = 12
)

type BackupMeta struct {
	FileName      string `json:"fileName"`
	Format        string `json:"format"`
	CreatedAt     string `json:"createdAt"`
	DomNexVersion string `json:"domnexVersion"`
	Domains       int    `json:"domains"`
	Subdomains    int    `json:"subdomains"`
	Users         int    `json:"users"`
	DBSHA256      string `json:"dbSha256"`
	KeySHA256     string `json:"keySha256"`
}

type PostRestoreCheckResult struct {
	CheckedAt           string   `json:"checkedAt"`
	DomainsTotal        int      `json:"domainsTotal"`
	DomainsOK           int      `json:"domainsOk"`
	HostsTotal          int      `json:"hostsTotal"`
	HostsDNSOK          int      `json:"hostsDnsOk"`
	HostsHTTPSOK        int      `json:"hostsHttpsOk"`
	HostsTLSOK          int      `json:"hostsTlsOk"`
	HostsCertValid      int      `json:"hostsCertValid"`
	CertWarmupAttempts  int      `json:"certWarmupAttempts"`
	CertWarmupSucceeded int      `json:"certWarmupSucceeded"`
	Issues              []string `json:"issues"`
}

type backupManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	CreatedAt     string `json:"createdAt"`
	Host          string `json:"host"`
	Users         int    `json:"users"`
	Domains       int    `json:"domains"`
	Subdomains    int    `json:"subdomains"`
	DBSHA256      string `json:"dbSha256"`
	KeySHA256     string `json:"keySha256"`
}

type backupSnapshot struct {
	Manifest backupManifest
	DBBytes  []byte
	KeyBytes []byte
	FileName string
}

func (s *Service) CreateBackupPackage(ctx context.Context, passphrase string) ([]byte, BackupMeta, error) {
	if len(strings.TrimSpace(passphrase)) < 12 {
		return nil, BackupMeta{}, fmt.Errorf("backup passphrase must be at least 12 characters")
	}
	tmpDir, err := os.MkdirTemp("", "domnex-backup-*")
	if err != nil {
		return nil, BackupMeta{}, err
	}
	defer os.RemoveAll(tmpDir)
	snapPath := filepath.Join(tmpDir, "domnex.snapshot.sqlite3")
	if err := s.store.VacuumInto(ctx, snapPath); err != nil {
		return nil, BackupMeta{}, err
	}
	dbBytes, err := os.ReadFile(snapPath)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	keyBytes, err := os.ReadFile(s.cfg.SecretKeyPath)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	manifest := backupManifest{
		SchemaVersion: 1,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Host:          s.hostName,
		Users:         len(users),
		Domains:       len(domains),
		Subdomains:    len(hosts),
		DBSHA256:      hashHex(dbBytes),
		KeySHA256:     hashHex(keyBytes),
	}
	plain, err := buildBackupTarGZ(manifest, dbBytes, keyBytes)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	enc, err := encryptBackupBlob(plain, passphrase)
	if err != nil {
		return nil, BackupMeta{}, err
	}
	meta := BackupMeta{
		Format:        "dnxbak",
		CreatedAt:     manifest.CreatedAt,
		DomNexVersion: "v0.8.x",
		Domains:       manifest.Domains,
		Subdomains:    manifest.Subdomains,
		Users:         manifest.Users,
		DBSHA256:      manifest.DBSHA256,
		KeySHA256:     manifest.KeySHA256,
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.create", Target: "encrypted", Meta: "format=dnxbak"})
	return enc, meta, nil
}

func (s *Service) AnalyzeBackupPackage(ctx context.Context, fileName string, raw []byte, passphrase string) (BackupMeta, error) {
	snap, err := parseBackupPackage(raw, passphrase)
	if err != nil {
		return BackupMeta{}, err
	}
	name := strings.TrimSpace(fileName)
	if name == "" {
		name = "domnex-backup.dnxbak"
	}
	return BackupMeta{
		FileName:      name,
		Format:        "dnxbak",
		CreatedAt:     snap.Manifest.CreatedAt,
		DomNexVersion: "v0.8.x",
		Domains:       snap.Manifest.Domains,
		Subdomains:    snap.Manifest.Subdomains,
		Users:         snap.Manifest.Users,
		DBSHA256:      snap.Manifest.DBSHA256,
		KeySHA256:     snap.Manifest.KeySHA256,
	}, nil
}

func (s *Service) UploadSetupBackup(ctx context.Context, fileName string, raw []byte, passphrase string) (SetupBackupMeta, error) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := s.ensureSetupStateLocked(ctx); err != nil {
		return SetupBackupMeta{}, err
	}
	if s.setupInitialized {
		return SetupBackupMeta{}, fmt.Errorf("setup already completed")
	}
	if !time.Now().UTC().Before(s.setupUnlockUntil) {
		return SetupBackupMeta{}, fmt.Errorf("setup is locked; unlock with one-time setup code")
	}
	snap, err := parseBackupPackage(raw, passphrase)
	if err != nil {
		return SetupBackupMeta{}, err
	}
	snap.FileName = strings.TrimSpace(fileName)
	if snap.FileName == "" {
		snap.FileName = "domnex-backup.dnxbak"
	}
	s.setupRestore = snap
	meta := SetupBackupMeta{
		FileName:      snap.FileName,
		Format:        "dnxbak",
		CreatedAt:     snap.Manifest.CreatedAt,
		DomNexVersion: "v0.8.x",
		Domains:       snap.Manifest.Domains,
		Subdomains:    snap.Manifest.Subdomains,
		Users:         snap.Manifest.Users,
	}
	return meta, nil
}

func (s *Service) RestoreFromBackupPackage(ctx context.Context, fileName string, raw []byte, passphrase string) (BackupMeta, error) {
	snap, err := parseBackupPackage(raw, passphrase)
	if err != nil {
		return BackupMeta{}, err
	}
	if err := s.applyBackupSnapshot(ctx, snap); err != nil {
		return BackupMeta{}, err
	}
	meta := BackupMeta{
		FileName:      strings.TrimSpace(fileName),
		Format:        "dnxbak",
		CreatedAt:     snap.Manifest.CreatedAt,
		DomNexVersion: "v0.8.x",
		Domains:       snap.Manifest.Domains,
		Subdomains:    snap.Manifest.Subdomains,
		Users:         snap.Manifest.Users,
		DBSHA256:      snap.Manifest.DBSHA256,
		KeySHA256:     snap.Manifest.KeySHA256,
	}
	if meta.FileName == "" {
		meta.FileName = "domnex-backup.dnxbak"
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.restore", Target: meta.FileName, Meta: "format=dnxbak"})
	return meta, nil
}

func (s *Service) RunPostRestoreCheck(ctx context.Context) (PostRestoreCheckResult, error) {
	out := PostRestoreCheckResult{
		CheckedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Issues:    []string{},
	}
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return out, err
	}
	out.DomainsTotal = len(domains)
	for _, d := range domains {
		check, err := s.RunDomainLiveCheck(ctx, d.ID)
		if err != nil {
			out.Issues = append(out.Issues, d.Name+": live-check error: "+err.Error())
			continue
		}
		if check.OverallOK {
			out.DomainsOK++
		} else {
			out.Issues = append(out.Issues, d.Name+": domain live-check not fully green")
		}
		for _, h := range check.Hosts {
			out.HostsTotal++
			if h.DNSOK {
				out.HostsDNSOK++
			}
			if h.HTTPSReachable {
				out.HostsHTTPSOK++
			}
			if h.TLSOK {
				out.HostsTLSOK++
			}
			if h.TLSOK && h.CertDaysLeft > 0 {
				out.HostsCertValid++
				continue
			}
			// Cert warmup: perform a direct TLS probe with SNI to trigger/prime ACME retrieval when possible.
			wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, tlsOK, certDays := probeHTTPSAndCert(wctx, h.FQDN)
			cancel()
			out.CertWarmupAttempts++
			if tlsOK && certDays > 0 {
				out.CertWarmupSucceeded++
				out.HostsTLSOK++
				out.HostsCertValid++
				continue
			}
			out.Issues = append(out.Issues, h.FQDN+": tls/cert still not valid after warmup")
		}
	}
	meta := "domains_ok=" + strconv.Itoa(out.DomainsOK) +
		";domains_total=" + strconv.Itoa(out.DomainsTotal) +
		";hosts_total=" + strconv.Itoa(out.HostsTotal) +
		";warmup=" + strconv.Itoa(out.CertWarmupSucceeded) + "/" + strconv.Itoa(out.CertWarmupAttempts)
	_ = s.store.SetSetting(ctx, "runtime.backup.last_postcheck", out.CheckedAt)
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: "system", Action: "backup.post_restore_check", Target: "summary", Meta: meta})
	return out, nil
}

func (s *Service) applyBackupSnapshot(ctx context.Context, snap *backupSnapshot) error {
	tmpDir, err := os.MkdirTemp("", "domnex-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	snapPath := filepath.Join(tmpDir, "restore.sqlite3")
	if err := os.WriteFile(snapPath, snap.DBBytes, 0o600); err != nil {
		return err
	}
	if err := s.store.RestoreFromSnapshot(ctx, snapPath); err != nil {
		return err
	}
	if err := os.WriteFile(s.cfg.SecretKeyPath, snap.KeyBytes, 0o600); err != nil {
		return err
	}
	ks, err := crypto.LoadOrCreateKey(s.cfg.SecretKeyPath)
	if err != nil {
		return err
	}
	s.keystore = ks
	return nil
}

func buildBackupTarGZ(manifest backupManifest, dbBytes, keyBytes []byte) ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	files := []struct {
		Name string
		Data []byte
	}{
		{Name: "manifest.json", Data: manifestBytes},
		{Name: "domnex.sqlite3", Data: dbBytes},
		{Name: "keystore.key", Data: keyBytes},
	}
	for _, f := range files {
		h := &tar.Header{
			Name:    f.Name,
			Mode:    0o600,
			Size:    int64(len(f.Data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func parseBackupPackage(raw []byte, passphrase string) (*backupSnapshot, error) {
	plain, err := decryptBackupBlob(raw, passphrase)
	if err != nil {
		return nil, err
	}
	files, err := readBackupTarGZ(plain)
	if err != nil {
		return nil, err
	}
	manifestRaw, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("backup manifest missing")
	}
	dbRaw, ok := files["domnex.sqlite3"]
	if !ok {
		return nil, fmt.Errorf("backup sqlite payload missing")
	}
	keyRaw, ok := files["keystore.key"]
	if !ok {
		return nil, fmt.Errorf("backup keystore payload missing")
	}
	var mf backupManifest
	if err := json.Unmarshal(manifestRaw, &mf); err != nil {
		return nil, fmt.Errorf("invalid backup manifest: %w", err)
	}
	if mf.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported backup schema version")
	}
	if hashHex(dbRaw) != strings.ToLower(strings.TrimSpace(mf.DBSHA256)) {
		return nil, fmt.Errorf("backup db checksum mismatch")
	}
	if hashHex(keyRaw) != strings.ToLower(strings.TrimSpace(mf.KeySHA256)) {
		return nil, fmt.Errorf("backup key checksum mismatch")
	}
	return &backupSnapshot{Manifest: mf, DBBytes: dbRaw, KeyBytes: keyRaw}, nil
}

func readBackupTarGZ(raw []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h == nil || h.FileInfo().IsDir() {
			continue
		}
		if h.Size > 128*1024*1024 {
			return nil, fmt.Errorf("backup entry too large")
		}
		buf := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, err
		}
		out[pathBase(h.Name)] = buf
	}
	return out, nil
}

func pathBase(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func encryptBackupBlob(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, backupSaltSz)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, backupNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(backupMagic))
	buf := make([]byte, 0, len(backupMagic)+backupSaltSz+backupNonce+len(ct))
	buf = append(buf, []byte(backupMagic)...)
	buf = append(buf, salt...)
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return buf, nil
}

func decryptBackupBlob(raw []byte, passphrase string) ([]byte, error) {
	headerLen := len(backupMagic) + backupSaltSz + backupNonce
	if len(raw) <= headerLen {
		return nil, fmt.Errorf("invalid backup package")
	}
	if string(raw[:len(backupMagic)]) != backupMagic {
		return nil, fmt.Errorf("invalid backup package header")
	}
	off := len(backupMagic)
	salt := raw[off : off+backupSaltSz]
	off += backupSaltSz
	nonce := raw[off : off+backupNonce]
	off += backupNonce
	cipherText := raw[off:]
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, cipherText, []byte(backupMagic))
	if err != nil {
		return nil, fmt.Errorf("backup decrypt failed (wrong passphrase or corrupt package)")
	}
	return plain, nil
}

func hashHex(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}
