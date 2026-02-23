package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

type Store struct {
	db          *sql.DB
	hookMu      sync.RWMutex
	auditHookFn func(model.AuditEvent)
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SetAuditHook(fn func(model.AuditEvent)) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	s.auditHookFn = fn
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  allowed_cidrs TEXT NOT NULL DEFAULT '',
  ip_check_disabled INTEGER NOT NULL DEFAULT 0,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret_enc TEXT NOT NULL DEFAULT '',
  mfa_enrolled_at TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  role TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS api_token_domain_scopes (
  token_id INTEGER NOT NULL,
  domain_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(token_id, domain_id),
  FOREIGN KEY(token_id) REFERENCES api_tokens(id) ON DELETE CASCADE,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  dns_mode TEXT NOT NULL,
  cert_mode TEXT NOT NULL,
  provider TEXT NOT NULL,
  zone_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  subdomain TEXT NOT NULL,
  fqdn TEXT NOT NULL UNIQUE,
  upstream_url TEXT NOT NULL,
  insecure_tls INTEGER NOT NULL DEFAULT 0,
  ha_enabled INTEGER NOT NULL DEFAULT 0,
  ha_mode TEXT NOT NULL DEFAULT '',
  ha_backends TEXT NOT NULL DEFAULT '',
  auth_enabled INTEGER NOT NULL DEFAULT 0,
  auth_user TEXT NOT NULL DEFAULT '',
  auth_pass_hash TEXT NOT NULL DEFAULT '',
  geo_mode TEXT NOT NULL DEFAULT '',
  geo_countries TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  error_reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  UNIQUE(domain_id, subdomain)
);

CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_name TEXT NOT NULL UNIQUE,
  enc_value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  meta TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS state_transitions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_attempts (
  username TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  last_failed_at TEXT NOT NULL,
  lock_until TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_domain_scopes (
  user_id INTEGER NOT NULL,
  domain_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(user_id, domain_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  used_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  PRIMARY KEY(user_id, code_hash),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_traffic_minute (
  host_id INTEGER NOT NULL,
  fqdn TEXT NOT NULL,
  country TEXT NOT NULL,
  bucket_start TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  status_2xx INTEGER NOT NULL DEFAULT 0,
  status_3xx INTEGER NOT NULL DEFAULT 0,
  status_4xx INTEGER NOT NULL DEFAULT 0,
  status_5xx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host_id, country, bucket_start),
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_traffic_class_minute (
  host_id INTEGER NOT NULL,
  fqdn TEXT NOT NULL,
  country TEXT NOT NULL,
  class TEXT NOT NULL,
  bucket_start TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  status_2xx INTEGER NOT NULL DEFAULT 0,
  status_3xx INTEGER NOT NULL DEFAULT 0,
  status_4xx INTEGER NOT NULL DEFAULT 0,
  status_5xx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host_id, country, class, bucket_start),
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_visitors_daily (
  host_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  PRIMARY KEY(host_id, day, ip_hash),
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ssh_bastion_routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fqdn TEXT NOT NULL UNIQUE,
  target_host TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_bastion_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_bastion_key_routes (
  key_id INTEGER NOT NULL,
  route_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(key_id, route_id),
  FOREIGN KEY(key_id) REFERENCES ssh_bastion_keys(id) ON DELETE CASCADE,
  FOREIGN KEY(route_id) REFERENCES ssh_bastion_routes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_intel_feeds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  is_default INTEGER NOT NULL DEFAULT 0,
  entry_count INTEGER NOT NULL DEFAULT 0,
  last_sync_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  last_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_entries (
  feed_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(feed_id, ip),
  FOREIGN KEY(feed_id) REFERENCES threat_intel_feeds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_intel_allowlist (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  feed TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  country TEXT NOT NULL,
  mode TEXT NOT NULL,
  decision TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_trace_id TEXT NOT NULL DEFAULT '',
  source_scope TEXT NOT NULL DEFAULT '',
  xp_delta INTEGER NOT NULL DEFAULT 0,
  xp_after INTEGER NOT NULL DEFAULT 0,
  level_after INTEGER NOT NULL DEFAULT 0,
  tier_after TEXT NOT NULL DEFAULT 'tier0',
  UNIQUE(ip, feed, host, path, decision)
);

CREATE TABLE IF NOT EXISTS threat_intel_ip_state (
  ip TEXT PRIMARY KEY,
  xp INTEGER NOT NULL DEFAULT 0,
  level INTEGER NOT NULL DEFAULT 0,
  risk_state TEXT NOT NULL DEFAULT 'monitoring',
  ban_until TEXT NOT NULL DEFAULT '',
  perm_block INTEGER NOT NULL DEFAULT 0,
  temp_block_count INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT NOT NULL,
  top_signal TEXT NOT NULL DEFAULT '',
  signal_counts TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_archives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  storage TEXT NOT NULL,
  location TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ready',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_host_traffic_minute_bucket ON host_traffic_minute(bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_minute_host_bucket ON host_traffic_minute(host_id, bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_class_minute_bucket ON host_traffic_class_minute(bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_class_minute_host_bucket ON host_traffic_class_minute(host_id, bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_visitors_daily_day ON host_visitors_daily(day);
CREATE INDEX IF NOT EXISTS idx_ssh_bastion_key_fingerprint ON ssh_bastion_keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_ip ON threat_intel_entries(ip);
CREATE INDEX IF NOT EXISTS idx_threat_intel_matches_ip ON threat_intel_matches(ip);
CREATE INDEX IF NOT EXISTS idx_threat_intel_matches_last_seen ON threat_intel_matches(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_threat_intel_state_level ON threat_intel_ip_state(level);
CREATE INDEX IF NOT EXISTS idx_backup_archives_storage_created ON backup_archives(storage, created_at);
`
	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE domains ADD COLUMN zone_id TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN insecure_tls INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN auth_enabled INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN auth_user TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN auth_pass_hash TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN ha_enabled INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN ha_mode TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN ha_backends TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN geo_mode TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE hosts ADD COLUMN geo_countries TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE threat_intel_matches ADD COLUMN xp_delta INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE threat_intel_matches ADD COLUMN xp_after INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE threat_intel_matches ADD COLUMN level_after INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE threat_intel_matches ADD COLUMN tier_after TEXT NOT NULL DEFAULT 'tier0'`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN ip_check_disabled INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN mfa_secret_enc TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN mfa_enrolled_at TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}
	return nil
}

func (s *Store) EnsureBootstrapUser(ctx context.Context, username, role, passHash string) (bool, error) {
	var c int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&c); err != nil {
		return false, err
	}
	if c > 0 {
		return false, nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(username, role, allowed_cidrs, ip_check_disabled, password_hash, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`, username, role, "", 0, passHash, now, now)
	return true, err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var c int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (model.User, error) {
	var u model.User
	var created, updated, mfaEnrolledAt string
	var ipCheckDisabled, mfaEnabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, allowed_cidrs, ip_check_disabled, mfa_enabled, mfa_secret_enc, mfa_enrolled_at, password_hash, created_at, updated_at FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.AllowedCIDRs, &ipCheckDisabled, &mfaEnabled, &u.MFASecretEnc, &mfaEnrolledAt, &u.PasswordHash, &created, &updated)
	if err != nil {
		return u, err
	}
	u.IPCheckOff = ipCheckDisabled != 0
	u.MFAEnabled = mfaEnabled != 0
	u.MFAEnrolled = parseTimeOrZero(mfaEnrolledAt)
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (model.User, error) {
	var u model.User
	var created, updated, mfaEnrolledAt string
	var ipCheckDisabled, mfaEnabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, allowed_cidrs, ip_check_disabled, mfa_enabled, mfa_secret_enc, mfa_enrolled_at, password_hash, created_at, updated_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.AllowedCIDRs, &ipCheckDisabled, &mfaEnabled, &u.MFASecretEnc, &mfaEnrolledAt, &u.PasswordHash, &created, &updated)
	if err != nil {
		return u, err
	}
	u.IPCheckOff = ipCheckDisabled != 0
	u.MFAEnabled = mfaEnabled != 0
	u.MFAEnrolled = parseTimeOrZero(mfaEnrolledAt)
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id, user_id, expires_at, created_at) VALUES(?,?,?,?)`, id, userID, expiresAt.UTC().Format(time.RFC3339Nano), now)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (model.Session, error) {
	var sess model.Session
	var exp string
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, expires_at FROM sessions WHERE id=?`, id).Scan(&sess.ID, &sess.UserID, &exp)
	if err != nil {
		return sess, err
	}
	sess.ExpiresAt, _ = time.Parse(time.RFC3339Nano, exp)
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) DeleteAllSessionsForUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

func (s *Store) PruneExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) PurgeAuditEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE created_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgeTrafficBucketsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffRaw := cutoff.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res1, err := tx.ExecContext(ctx, `DELETE FROM host_traffic_minute WHERE bucket_start < ?`, cutoffRaw)
	if err != nil {
		return 0, err
	}
	res2, err := tx.ExecContext(ctx, `DELETE FROM host_traffic_class_minute WHERE bucket_start < ?`, cutoffRaw)
	if err != nil {
		return 0, err
	}
	n1, _ := res1.RowsAffected()
	n2, _ := res2.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n1 + n2, nil
}

func (s *Store) PurgeVisitorHashesBeforeDay(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM host_visitors_daily WHERE day < ?`, cutoff.UTC().Format("2006-01-02"))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgeThreatIntelMatchesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM threat_intel_matches WHERE last_seen_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgeThreatIntelStateBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffRaw := cutoff.UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
DELETE FROM threat_intel_ip_state
WHERE last_seen_at < ?
  AND perm_block = 0
  AND (ban_until = '' OR ban_until < ?)`, cutoffRaw, cutoffRaw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgeBlockedIPsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM blocked_ips WHERE updated_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgeLoginAttemptsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE last_failed_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) PurgePasswordResetTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffRaw := cutoff.UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
DELETE FROM password_reset_tokens
WHERE expires_at < ?
   OR (used_at IS NOT NULL AND used_at < ?)`, cutoffRaw, cutoffRaw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func PrefixToken(raw string) string {
	if len(raw) < 8 {
		return raw
	}
	return raw[:8]
}

func (s *Store) CreateAPIToken(ctx context.Context, name string, role model.Role, scopes string, domainIDs []int64, expiresAt time.Time) (model.APIToken, string, error) {
	var tok model.APIToken
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT lower(hex(randomblob(32)))`).Scan(&raw); err != nil {
		return tok, "", err
	}
	tokHash := HashToken(raw)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return tok, "", err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
INSERT INTO api_tokens(name, token_prefix, token_hash, scopes, role, expires_at, created_at)
VALUES(?,?,?,?,?,?,?)`, name, PrefixToken(raw), tokHash, scopes, role, expiresAt.UTC().Format(time.RFC3339Nano), now)
	if err != nil {
		return tok, "", err
	}
	id, _ := res.LastInsertId()
	for _, did := range domainIDs {
		if did <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_token_domain_scopes(token_id, domain_id, created_at) VALUES(?,?,?)`, id, did, now); err != nil {
			return tok, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return tok, "", err
	}
	dids, _ := s.GetAPITokenDomainIDs(ctx, id)
	tok = model.APIToken{ID: id, Name: name, TokenPrefix: PrefixToken(raw), TokenHash: tokHash, Scopes: scopes, Role: role, DomainIDs: dids, ExpiresAt: expiresAt, CreatedAt: time.Now().UTC()}
	return tok, "dnx_" + base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

func (s *Store) LookupAPIToken(ctx context.Context, bearer string) (model.APIToken, error) {
	var t model.APIToken
	if !strings.HasPrefix(bearer, "dnx_") {
		return t, sql.ErrNoRows
	}
	rawB, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(bearer, "dnx_"))
	if err != nil {
		return t, err
	}
	hash := HashToken(string(rawB))
	var expires, created string
	var last sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT id, name, token_prefix, token_hash, scopes, role, expires_at, created_at, last_used_at FROM api_tokens WHERE token_hash=?`, hash).
		Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.TokenHash, &t.Scopes, &t.Role, &expires, &created, &last)
	if err != nil {
		return t, err
	}
	t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if last.Valid {
		t.LastUsedAt, _ = time.Parse(time.RFC3339Nano, last.String)
	}
	if t.ExpiresAt.Before(time.Now().UTC()) {
		return t, sql.ErrNoRows
	}
	if dids, err := s.GetAPITokenDomainIDs(ctx, t.ID); err == nil {
		t.DomainIDs = dids
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), t.ID)
	return t, nil
}

func (s *Store) ListAPITokens(ctx context.Context, limit int) ([]model.APIToken, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, token_prefix, token_hash, scopes, role, expires_at, created_at, last_used_at FROM api_tokens ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.APIToken{}
	for rows.Next() {
		var t model.APIToken
		var expires, created string
		var last sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.TokenHash, &t.Scopes, &t.Role, &expires, &created, &last); err != nil {
			return nil, err
		}
		t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if last.Valid {
			t.LastUsedAt, _ = time.Parse(time.RFC3339Nano, last.String)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		dids, _ := s.GetAPITokenDomainIDs(ctx, out[i].ID)
		out[i].DomainIDs = dids
	}
	return out, nil
}

func (s *Store) RevokeAPIToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id=?`, id)
	return err
}

func (s *Store) GetAPITokenDomainIDs(ctx context.Context, tokenID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain_id FROM api_token_domain_scopes WHERE token_id=? ORDER BY domain_id`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) UpsertDomain(ctx context.Context, d model.Domain) (model.Domain, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO domains(name, dns_mode, cert_mode, provider, zone_id, status, created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET dns_mode=excluded.dns_mode, cert_mode=excluded.cert_mode, provider=excluded.provider, zone_id=excluded.zone_id, status=excluded.status, updated_at=excluded.updated_at`,
		d.Name, d.DNSMode, d.CertMode, d.Provider, d.ZoneID, d.Status, now, now)
	if err != nil {
		return model.Domain{}, err
	}
	return s.GetDomainByName(ctx, d.Name)
}

func (s *Store) GetDomainByName(ctx context.Context, name string) (model.Domain, error) {
	var d model.Domain
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, dns_mode, cert_mode, provider, zone_id, status, created_at, updated_at FROM domains WHERE name=?`, name).
		Scan(&d.ID, &d.Name, &d.DNSMode, &d.CertMode, &d.Provider, &d.ZoneID, &d.Status, &created, &updated)
	if err != nil {
		return d, err
	}
	d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	d.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return d, nil
}

func (s *Store) GetDomainByID(ctx context.Context, id int64) (model.Domain, error) {
	var d model.Domain
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, dns_mode, cert_mode, provider, zone_id, status, created_at, updated_at FROM domains WHERE id=?`, id).
		Scan(&d.ID, &d.Name, &d.DNSMode, &d.CertMode, &d.Provider, &d.ZoneID, &d.Status, &created, &updated)
	if err != nil {
		return d, err
	}
	d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	d.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return d, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]model.Domain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, dns_mode, cert_mode, provider, zone_id, status, created_at, updated_at FROM domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Domain{}
	for rows.Next() {
		var d model.Domain
		var created, updated string
		if err := rows.Scan(&d.ID, &d.Name, &d.DNSMode, &d.CertMode, &d.Provider, &d.ZoneID, &d.Status, &created, &updated); err != nil {
			return nil, err
		}
		d.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		d.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CreateHost(ctx context.Context, domainID int64, subdomain, fqdn, upstream string, insecureTLS bool, haEnabled bool, haMode string, haBackends []model.HABackend) (model.Host, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	haBackendsJSON, err := encodeBackends(haBackends)
	if err != nil {
		return model.Host{}, err
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO hosts(domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, state, created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, domainID, subdomain, fqdn, upstream, boolToInt(insecureTLS), boolToInt(haEnabled), haMode, haBackendsJSON, "created", now, now)
	if err != nil {
		return model.Host{}, err
	}
	id, _ := res.LastInsertId()
	if err := s.transitionHostState(ctx, id, "", "created", "initial"); err != nil {
		return model.Host{}, err
	}
	return s.GetHostByID(ctx, id)
}

func (s *Store) GetHostByID(ctx context.Context, id int64) (model.Host, error) {
	var h model.Host
	var created, updated string
	var insecure, haEnabled, authEnabled int
	var haBackendsJSON string
	var geoCountriesCSV string
	err := s.db.QueryRowContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, geo_mode, geo_countries, state, error_reason, created_at, updated_at FROM hosts WHERE id=?`, id).
		Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.GeoMode, &geoCountriesCSV, &h.State, &h.ErrorReason, &created, &updated)
	if err != nil {
		return h, err
	}
	h.InsecureTLS = insecure != 0
	h.HAEnabled = haEnabled != 0
	h.HABackends = decodeBackends(haBackendsJSON)
	h.AuthEnabled = authEnabled != 0
	h.GeoCountries = decodeCSV(geoCountriesCSV)
	h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return h, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, geo_mode, geo_countries, state, error_reason, created_at, updated_at FROM hosts ORDER BY fqdn`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Host{}
	for rows.Next() {
		var h model.Host
		var created, updated string
		var insecure, haEnabled, authEnabled int
		var haBackendsJSON string
		var geoCountriesCSV string
		if err := rows.Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.GeoMode, &geoCountriesCSV, &h.State, &h.ErrorReason, &created, &updated); err != nil {
			return nil, err
		}
		h.InsecureTLS = insecure != 0
		h.HAEnabled = haEnabled != 0
		h.HABackends = decodeBackends(haBackendsJSON)
		h.AuthEnabled = authEnabled != 0
		h.GeoCountries = decodeCSV(geoCountriesCSV)
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) ListHostsByDomainID(ctx context.Context, domainID int64) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, geo_mode, geo_countries, state, error_reason, created_at, updated_at FROM hosts WHERE domain_id=? ORDER BY fqdn`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Host{}
	for rows.Next() {
		var h model.Host
		var created, updated string
		var insecure, haEnabled, authEnabled int
		var haBackendsJSON string
		var geoCountriesCSV string
		if err := rows.Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.GeoMode, &geoCountriesCSV, &h.State, &h.ErrorReason, &created, &updated); err != nil {
			return nil, err
		}
		h.InsecureTLS = insecure != 0
		h.HAEnabled = haEnabled != 0
		h.HABackends = decodeBackends(haBackendsJSON)
		h.AuthEnabled = authEnabled != 0
		h.GeoCountries = decodeCSV(geoCountriesCSV)
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) SetHostState(ctx context.Context, hostID int64, toState, reason string) error {
	h, err := s.GetHostByID(ctx, hostID)
	if err != nil {
		return err
	}
	if !validTransition(h.State, toState) {
		return fmt.Errorf("invalid transition %s -> %s", h.State, toState)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE hosts SET state=?, error_reason=?, updated_at=? WHERE id=?`, toState, reason, time.Now().UTC().Format(time.RFC3339Nano), hostID)
	if err != nil {
		return err
	}
	return s.transitionHostState(ctx, hostID, h.State, toState, reason)
}

func validTransition(from, to string) bool {
	if from == "" && to == "created" {
		return true
	}
	allowed := map[string]map[string]bool{
		"created":      {"dns_pending": true, "cert_pending": true, "error": true, "disabled": true},
		"dns_pending":  {"cert_pending": true, "error": true, "disabled": true},
		"cert_pending": {"active": true, "error": true, "disabled": true},
		"active":       {"error": true, "cert_pending": true, "disabled": true, "maintenance": true},
		"maintenance":  {"active": true, "error": true, "disabled": true},
		"disabled":     {"active": true, "error": true},
		"error":        {"dns_pending": true, "cert_pending": true, "disabled": true, "maintenance": true},
	}
	return allowed[from][to]
}

func (s *Store) transitionHostState(ctx context.Context, hostID int64, from, to, reason string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO state_transitions(host_id, from_state, to_state, reason, created_at) VALUES(?,?,?,?,?)`, hostID, from, to, reason, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) StoreSecret(ctx context.Context, keyName, encVal string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO secrets(key_name, enc_value, created_at, updated_at)
VALUES(?,?,?,?)
ON CONFLICT(key_name) DO UPDATE SET enc_value=excluded.enc_value, updated_at=excluded.updated_at`, keyName, encVal, now, now)
	return err
}

func (s *Store) DeleteSecret(ctx context.Context, keyName string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE key_name=?`, keyName)
	return err
}

func (s *Store) GetSecret(ctx context.Context, keyName string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT enc_value FROM secrets WHERE key_name=?`, keyName).Scan(&v)
	return v, err
}

func (s *Store) AddAuditEvent(ctx context.Context, e model.AuditEvent) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor, action, target, meta, created_at) VALUES(?,?,?,?,?)`, e.Actor, e.Action, e.Target, e.Meta, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	e.CreatedAt = now
	e.SourceIP = parseSourceFromMeta(e.Meta)
	s.hookMu.RLock()
	hook := s.auditHookFn
	s.hookMu.RUnlock()
	if hook != nil {
		hook(e)
	}
	return err
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, actor, action, target, meta, created_at FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEvent{}
	for rows.Next() {
		var e model.AuditEvent
		var created string
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.Meta, &created); err != nil {
			return nil, err
		}
		e.SourceIP = parseSourceFromMeta(e.Meta)
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, e)
	}
	return out, rows.Err()
}

func parseSourceFromMeta(meta string) string {
	meta = strings.TrimSpace(meta)
	if meta == "" {
		return ""
	}
	parts := strings.Split(meta, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "source=") {
			return strings.TrimSpace(strings.TrimPrefix(p, "source="))
		}
	}
	return ""
}

func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, nil
	}
	var c int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM blocked_ips WHERE ip=?`, ip).Scan(&c); err != nil {
		return false, err
	}
	return c > 0, nil
}

func (s *Store) UpsertBlockedIP(ctx context.Context, ip, reason string) error {
	ip = strings.TrimSpace(ip)
	reason = strings.TrimSpace(reason)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO blocked_ips(ip, reason, created_at, updated_at)
VALUES(?,?,?,?)
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, updated_at=excluded.updated_at`, ip, reason, now, now)
	return err
}

func (s *Store) RemoveBlockedIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blocked_ips WHERE ip=?`, strings.TrimSpace(ip))
	return err
}

func (s *Store) ListBlockedIPs(ctx context.Context, limit int) ([]model.BlockedIP, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ip, reason, created_at, updated_at FROM blocked_ips ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BlockedIP{}
	for rows.Next() {
		var b model.BlockedIP
		var created, updated string
		if err := rows.Scan(&b.IP, &b.Reason, &created, &updated); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		b.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) RemoveHost(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
	return err
}

func (s *Store) RemoveDomain(ctx context.Context, id int64) error {
	var c int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM hosts WHERE domain_id=? AND state='active'`, id).Scan(&c); err != nil {
		return err
	}
	if c > 0 {
		return errors.New("cannot remove domain with active hosts")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, id)
	return err
}

func (s *Store) SetDomainStatus(ctx context.Context, id int64, status string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return errors.New("domain status required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE domains SET status=?, updated_at=? WHERE id=?`, status, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) FindHostByFQDN(ctx context.Context, fqdn string) (model.Host, error) {
	var h model.Host
	var created, updated string
	var insecure, haEnabled, authEnabled int
	var haBackendsJSON string
	var geoCountriesCSV string
	err := s.db.QueryRowContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, geo_mode, geo_countries, state, error_reason, created_at, updated_at FROM hosts WHERE fqdn=?`, fqdn).
		Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.GeoMode, &geoCountriesCSV, &h.State, &h.ErrorReason, &created, &updated)
	if err != nil {
		return h, err
	}
	h.InsecureTLS = insecure != 0
	h.HAEnabled = haEnabled != 0
	h.HABackends = decodeBackends(haBackendsJSON)
	h.AuthEnabled = authEnabled != 0
	h.GeoCountries = decodeCSV(geoCountriesCSV)
	h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return h, nil
}

func (s *Store) UpdateHostAuth(ctx context.Context, id int64, enabled bool, username, passHash string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE hosts
SET auth_enabled=?, auth_user=?, auth_pass_hash=?, updated_at=?
WHERE id=?`, boolToInt(enabled), username, passHash, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) UpdateHostRouting(ctx context.Context, id int64, upstream string, insecureTLS bool, haEnabled bool, haMode string, haBackends []model.HABackend) error {
	haBackendsJSON, err := encodeBackends(haBackends)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE hosts
SET upstream_url=?, insecure_tls=?, ha_enabled=?, ha_mode=?, ha_backends=?, updated_at=?
WHERE id=?`, upstream, boolToInt(insecureTLS), boolToInt(haEnabled), haMode, haBackendsJSON, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) UpdateHostGeoPolicy(ctx context.Context, id int64, mode string, countries []string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE hosts
SET geo_mode=?, geo_countries=?, updated_at=?
WHERE id=?`, mode, encodeCSV(countries), time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) UpsertHostTrafficMinute(ctx context.Context, hostID int64, fqdn, country, bucketStart string, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO host_traffic_minute(host_id, fqdn, country, bucket_start, requests, bytes_in, bytes_out, blocked, status_2xx, status_3xx, status_4xx, status_5xx)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(host_id, country, bucket_start) DO UPDATE SET
  fqdn=excluded.fqdn,
  requests=host_traffic_minute.requests + excluded.requests,
  bytes_in=host_traffic_minute.bytes_in + excluded.bytes_in,
  bytes_out=host_traffic_minute.bytes_out + excluded.bytes_out,
  blocked=host_traffic_minute.blocked + excluded.blocked,
  status_2xx=host_traffic_minute.status_2xx + excluded.status_2xx,
  status_3xx=host_traffic_minute.status_3xx + excluded.status_3xx,
  status_4xx=host_traffic_minute.status_4xx + excluded.status_4xx,
  status_5xx=host_traffic_minute.status_5xx + excluded.status_5xx`,
		hostID, fqdn, country, bucketStart, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx)
	return err
}

func (s *Store) UpsertHostTrafficClassMinute(ctx context.Context, hostID int64, fqdn, country, class, bucketStart string, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx int64) error {
	class = strings.ToLower(strings.TrimSpace(class))
	if class == "" {
		class = "unknown"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO host_traffic_class_minute(host_id, fqdn, country, class, bucket_start, requests, bytes_in, bytes_out, blocked, status_2xx, status_3xx, status_4xx, status_5xx)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(host_id, country, class, bucket_start) DO UPDATE SET
  fqdn=excluded.fqdn,
  requests=host_traffic_class_minute.requests + excluded.requests,
  bytes_in=host_traffic_class_minute.bytes_in + excluded.bytes_in,
  bytes_out=host_traffic_class_minute.bytes_out + excluded.bytes_out,
  blocked=host_traffic_class_minute.blocked + excluded.blocked,
  status_2xx=host_traffic_class_minute.status_2xx + excluded.status_2xx,
  status_3xx=host_traffic_class_minute.status_3xx + excluded.status_3xx,
  status_4xx=host_traffic_class_minute.status_4xx + excluded.status_4xx,
  status_5xx=host_traffic_class_minute.status_5xx + excluded.status_5xx`,
		hostID, fqdn, country, class, bucketStart, requests, bytesIn, bytesOut, blocked, status2xx, status3xx, status4xx, status5xx)
	return err
}

func (s *Store) UpsertHostVisitorDaily(ctx context.Context, hostID int64, day, ipHash string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO host_visitors_daily(host_id, day, ip_hash)
VALUES(?,?,?)
ON CONFLICT(host_id, day, ip_hash) DO NOTHING`, hostID, day, ipHash)
	return err
}

type HostTrafficSummaryRow struct {
	HostID         int64
	FQDN           string
	Requests       int64
	BytesIn        int64
	BytesOut       int64
	Blocked        int64
	Status2xx      int64
	Status3xx      int64
	Status4xx      int64
	Status5xx      int64
	UniqueVisitors int64
}

type HostTrafficPointRow struct {
	BucketStart string
	Requests    int64
	BytesIn     int64
	BytesOut    int64
	Blocked     int64
	Status2xx   int64
	Status3xx   int64
	Status4xx   int64
	Status5xx   int64
}

type CountryTrafficRow struct {
	Country   string
	Requests  int64
	Blocked   int64
	Status2xx int64
	Status3xx int64
	Status4xx int64
	Status5xx int64
	BytesOut  int64
}

type HostCountryTrafficRow struct {
	HostID    int64
	FQDN      string
	Requests  int64
	Blocked   int64
	Status2xx int64
	Status3xx int64
	Status4xx int64
	Status5xx int64
	BytesOut  int64
}

func (s *Store) ListHostTrafficSummaries(ctx context.Context, since time.Time) ([]HostTrafficSummaryRow, error) {
	sinceBucket := since.UTC().Format(time.RFC3339)
	sinceDay := since.UTC().Format("2006-01-02")
	rows, err := s.db.QueryContext(ctx, `
SELECT m.host_id, m.fqdn,
       SUM(m.requests), SUM(m.bytes_in), SUM(m.bytes_out), SUM(m.blocked),
       SUM(m.status_2xx), SUM(m.status_3xx), SUM(m.status_4xx), SUM(m.status_5xx),
       COALESCE(v.uniques, 0)
FROM host_traffic_minute m
LEFT JOIN (
  SELECT host_id, COUNT(DISTINCT ip_hash) AS uniques
  FROM host_visitors_daily
  WHERE day >= ?
  GROUP BY host_id
) v ON v.host_id = m.host_id
WHERE m.bucket_start >= ?
GROUP BY m.host_id, m.fqdn, v.uniques
ORDER BY SUM(m.requests) DESC`, sinceDay, sinceBucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostTrafficSummaryRow{}
	for rows.Next() {
		var r HostTrafficSummaryRow
		if err := rows.Scan(&r.HostID, &r.FQDN, &r.Requests, &r.BytesIn, &r.BytesOut, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.UniqueVisitors); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetHostTrafficSeries(ctx context.Context, hostID int64, since time.Time) ([]HostTrafficPointRow, error) {
	sinceBucket := since.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
SELECT bucket_start,
       SUM(requests), SUM(bytes_in), SUM(bytes_out), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx)
FROM host_traffic_minute
WHERE host_id=? AND bucket_start>=?
GROUP BY bucket_start
ORDER BY bucket_start`, hostID, sinceBucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostTrafficPointRow{}
	for rows.Next() {
		var r HostTrafficPointRow
		if err := rows.Scan(&r.BucketStart, &r.Requests, &r.BytesIn, &r.BytesOut, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountHostUniqueVisitors(ctx context.Context, hostID int64, since time.Time) (int64, error) {
	sinceDay := since.UTC().Format("2006-01-02")
	var c int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip_hash) FROM host_visitors_daily WHERE host_id=? AND day>=?`, hostID, sinceDay).Scan(&c)
	return c, err
}

func normalizeTrafficClass(class string) string {
	c := strings.ToLower(strings.TrimSpace(class))
	switch c {
	case "", "all":
		return "all"
	case "crawler", "human", "unknown":
		return c
	default:
		return "all"
	}
}

func (s *Store) ListTrafficCountries(ctx context.Context, since time.Time, hostID int64, class string) ([]CountryTrafficRow, error) {
	sinceBucket := since.UTC().Format(time.RFC3339)
	class = normalizeTrafficClass(class)
	var (
		rows *sql.Rows
		err  error
	)
	if hostID > 0 {
		if class == "all" {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND host_id=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket, hostID)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND host_id=? AND class=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket, hostID, class)
		}
	} else {
		if class == "all" {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND class=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket, class)
		}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CountryTrafficRow{}
	for rows.Next() {
		var r CountryTrafficRow
		if err := rows.Scan(&r.Country, &r.Requests, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 && class == "all" {
		// Backward-compatible fallback for historical data before class-based tracking existed.
		if hostID > 0 {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_minute
WHERE bucket_start>=? AND host_id=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket, hostID)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT country,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_minute
WHERE bucket_start>=?
GROUP BY country
ORDER BY SUM(requests) DESC`, sinceBucket)
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out = []CountryTrafficRow{}
		for rows.Next() {
			var r CountryTrafficRow
			if err := rows.Scan(&r.Country, &r.Requests, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesOut); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) ListHostCountryTraffic(ctx context.Context, since time.Time, country string, hostID int64, class string) ([]HostCountryTrafficRow, error) {
	sinceBucket := since.UTC().Format(time.RFC3339)
	country = strings.ToUpper(strings.TrimSpace(country))
	class = normalizeTrafficClass(class)
	if country == "" {
		return nil, fmt.Errorf("country is required")
	}
	var (
		rows *sql.Rows
		err  error
	)
	if hostID > 0 {
		if class == "all" {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND country=? AND host_id=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country, hostID)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND country=? AND host_id=? AND class=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country, hostID, class)
		}
	} else {
		if class == "all" {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND country=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_class_minute
WHERE bucket_start>=? AND country=? AND class=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country, class)
		}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostCountryTrafficRow{}
	for rows.Next() {
		var r HostCountryTrafficRow
		if err := rows.Scan(&r.HostID, &r.FQDN, &r.Requests, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 && class == "all" {
		if hostID > 0 {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_minute
WHERE bucket_start>=? AND country=? AND host_id=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country, hostID)
		} else {
			rows, err = s.db.QueryContext(ctx, `
SELECT host_id, fqdn,
       SUM(requests), SUM(blocked),
       SUM(status_2xx), SUM(status_3xx), SUM(status_4xx), SUM(status_5xx),
       SUM(bytes_out)
FROM host_traffic_minute
WHERE bucket_start>=? AND country=?
GROUP BY host_id, fqdn
ORDER BY SUM(requests) DESC`, sinceBucket, country)
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out = []HostCountryTrafficRow{}
		for rows.Next() {
			var r HostCountryTrafficRow
			if err := rows.Scan(&r.HostID, &r.FQDN, &r.Requests, &r.Blocked, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.BytesOut); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func encodeBackends(in []model.HABackend) (string, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeBackends(raw string) []model.HABackend {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []model.HABackend
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return out
	}
	// Backward compatibility: old format was []string URLs.
	var legacy []string
	if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
		return nil
	}
	converted := make([]model.HABackend, 0, len(legacy))
	for i, url := range legacy {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		converted = append(converted, model.HABackend{Name: fmt.Sprintf("backend-%d", i+1), URL: url})
	}
	return converted
}

func encodeCSV(values []string) string {
	if len(values) == 0 {
		return ""
	}
	trimmed := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			trimmed = append(trimmed, v)
		}
	}
	return strings.Join(trimmed, ",")
}

func decodeCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func SplitScopes(scopes string) map[string]bool {
	out := map[string]bool{}
	for _, s := range strings.Split(scopes, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out[s] = true
		}
	}
	return out
}

func (s *Store) GetLoginAttempt(ctx context.Context, username string) (failedCount int, lockUntil time.Time, err error) {
	var lockUntilRaw string
	err = s.db.QueryRowContext(ctx, `SELECT failed_count, lock_until FROM login_attempts WHERE username=?`, username).Scan(&failedCount, &lockUntilRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, time.Time{}, nil
		}
		return 0, time.Time{}, err
	}
	lockUntil, _ = time.Parse(time.RFC3339Nano, lockUntilRaw)
	return failedCount, lockUntil, nil
}

func (s *Store) RegisterLoginFailure(ctx context.Context, username string) (int, time.Time, error) {
	failed, _, err := s.GetLoginAttempt(ctx, username)
	if err != nil {
		return 0, time.Time{}, err
	}
	failed++
	delay := loginFailureDelay(failed)
	lockUntil := time.Now().UTC().Add(delay)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO login_attempts(username, failed_count, last_failed_at, lock_until)
VALUES(?,?,?,?)
ON CONFLICT(username) DO UPDATE SET failed_count=excluded.failed_count, last_failed_at=excluded.last_failed_at, lock_until=excluded.lock_until`,
		username, failed, now, lockUntil.Format(time.RFC3339Nano))
	return failed, lockUntil, err
}

func (s *Store) ClearLoginFailures(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE username=?`, username)
	return err
}

func loginFailureDelay(fails int) time.Duration {
	if fails < 5 {
		return 0
	}
	sec := 1 << min(fails-4, 8)
	if sec > 300 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO password_reset_tokens(token_hash, user_id, expires_at, created_at) VALUES(?,?,?,?)`,
		tokenHash, userID, expiresAt.UTC().Format(time.RFC3339Nano), now)
	return err
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (int64, error) {
	var userID int64
	var expiresRaw string
	var used sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash=?`, tokenHash).Scan(&userID, &expiresRaw, &used)
	if err != nil {
		return 0, err
	}
	if used.Valid {
		return 0, errors.New("reset token already used")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expiresRaw)
	if time.Now().UTC().After(expiresAt) {
		return 0, errors.New("reset token expired")
	}
	_, err = s.db.ExecContext(ctx, `UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?`, time.Now().UTC().Format(time.RFC3339Nano), tokenHash)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (s *Store) SetUserPasswordHashByID(ctx context.Context, userID int64, passHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, passHash, time.Now().UTC().Format(time.RFC3339Nano), userID)
	return err
}

func (s *Store) SetUserMFAState(ctx context.Context, userID int64, enabled bool, secretEnc string, enrolledAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	enrolledRaw := ""
	if !enrolledAt.IsZero() {
		enrolledRaw = enrolledAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE users
SET mfa_enabled=?, mfa_secret_enc=?, mfa_enrolled_at=?, updated_at=?
WHERE id=?`, boolToInt(enabled), strings.TrimSpace(secretEnc), enrolledRaw, now, userID)
	return err
}

func (s *Store) ResetUserMFA(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
UPDATE users
SET mfa_enabled=0, mfa_secret_enc='', mfa_enrolled_at='', ip_check_disabled=0, updated_at=?
WHERE id=?`, now, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplaceUserMFARecoveryCodes(ctx context.Context, userID int64, codeHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, h := range codeHashes {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_mfa_recovery_codes(user_id, code_hash, used_at, created_at) VALUES(?,?,?,?)`, userID, h, "", now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ConsumeUserMFARecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
UPDATE user_mfa_recovery_codes
SET used_at=?
WHERE user_id=? AND code_hash=? AND (used_at='' OR used_at IS NULL)`, now, userID, strings.TrimSpace(codeHash))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) CountUserMFARecoveryCodesRemaining(ctx context.Context, userID int64) (int, error) {
	var c int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM user_mfa_recovery_codes WHERE user_id=? AND (used_at='' OR used_at IS NULL)`, userID).Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func (s *Store) CreateUser(ctx context.Context, username string, role model.Role, allowedCIDRs string, ipCheckDisabled bool, passHash string) (model.User, error) {
	if ipCheckDisabled {
		return model.User{}, fmt.Errorf("ip check can be disabled only after MFA is enabled for this user")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, role, allowed_cidrs, ip_check_disabled, password_hash, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`, username, string(role), strings.TrimSpace(allowedCIDRs), boolToInt(ipCheckDisabled), passHash, now, now)
	if err != nil {
		return model.User{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetUserByID(ctx, id)
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, role, allowed_cidrs, ip_check_disabled, mfa_enabled, mfa_secret_enc, mfa_enrolled_at, password_hash, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		var u model.User
		var created, updated, mfaEnrolledAt string
		var ipCheckDisabled, mfaEnabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.AllowedCIDRs, &ipCheckDisabled, &mfaEnabled, &u.MFASecretEnc, &mfaEnrolledAt, &u.PasswordHash, &created, &updated); err != nil {
			return nil, err
		}
		u.IPCheckOff = ipCheckDisabled != 0
		u.MFAEnabled = mfaEnabled != 0
		u.MFAEnrolled = parseTimeOrZero(mfaEnrolledAt)
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID)
	return err
}

func (s *Store) SetUserDomainScopes(ctx context.Context, userID int64, domainIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_domain_scopes WHERE user_id=?`, userID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, did := range domainIDs {
		if did <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_domain_scopes(user_id, domain_id, created_at) VALUES(?,?,?)`, userID, did, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetUserRoleAndDomainScopes(ctx context.Context, userID int64, role model.Role, domainIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `UPDATE users SET role=?, updated_at=? WHERE id=?`, string(role), now, userID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_domain_scopes WHERE user_id=?`, userID); err != nil {
		return err
	}
	if role == model.RoleDomainAdmin {
		for _, did := range domainIDs {
			if did <= 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_domain_scopes(user_id, domain_id, created_at) VALUES(?,?,?)`, userID, did, now); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) SetUserAccessPolicy(ctx context.Context, userID int64, role model.Role, domainIDs []int64, allowedCIDRs string, ipCheckDisabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if ipCheckDisabled {
		var mfaEnabled int
		if err := tx.QueryRowContext(ctx, `SELECT mfa_enabled FROM users WHERE id=?`, userID).Scan(&mfaEnabled); err != nil {
			return err
		}
		if mfaEnabled == 0 {
			return fmt.Errorf("ip check can be disabled only for MFA-enabled users")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `UPDATE users SET role=?, allowed_cidrs=?, ip_check_disabled=?, updated_at=? WHERE id=?`, string(role), strings.TrimSpace(allowedCIDRs), boolToInt(ipCheckDisabled), now, userID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_domain_scopes WHERE user_id=?`, userID); err != nil {
		return err
	}
	if role == model.RoleDomainAdmin {
		for _, did := range domainIDs {
			if did <= 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_domain_scopes(user_id, domain_id, created_at) VALUES(?,?,?)`, userID, did, now); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) GetUserDomainIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain_id FROM user_domain_scopes WHERE user_id=? ORDER BY domain_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO settings(key, value, updated_at) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, now)
	return err
}

func (s *Store) EnsureThreatIntelDefaultFeed(ctx context.Context, defaultURL string) error {
	defaultURL = strings.TrimSpace(defaultURL)
	if defaultURL == "" {
		return fmt.Errorf("default threat intel feed URL required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO threat_intel_feeds(name, url, enabled, is_default, entry_count, created_at, updated_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(url) DO UPDATE SET
  is_default=1,
  updated_at=excluded.updated_at`,
		"blocklist.de all", defaultURL, 1, 1, 0, now, now)
	return err
}

func (s *Store) GetThreatIntelConfig(ctx context.Context) (model.ThreatIntelConfig, error) {
	cfg := model.ThreatIntelConfig{
		Enabled:          false,
		Mode:             "monitor_only",
		SyncHours:        24,
		EventMinHits:     2,
		OffenderMinHits:  10,
		MonitorMaxLevel:  2,
		SoftMinLevel:     3,
		HardLevel:        6,
		SoftBlockMinutes: 15,
	}
	if v, err := s.GetSetting(ctx, "threatintel.enabled"); err == nil {
		cfg.Enabled = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.GetSetting(ctx, "threatintel.mode"); err == nil {
		mode := strings.ToLower(strings.TrimSpace(v))
		switch mode {
		case "monitor_only", "auto_mode":
			cfg.Mode = mode
		case "log_only":
			cfg.Mode = "monitor_only"
		case "hard_check", "soft_block", "hard_block":
			cfg.Mode = "auto_mode"
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.sync_hours"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 1 && n <= 168 {
			cfg.SyncHours = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.event_min_hits"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 1 && n <= 100 {
			cfg.EventMinHits = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.offender_min_hits"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 2 && n <= 10000 {
			cfg.OffenderMinHits = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.monitor_max_level"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 0 && n <= 32 {
			cfg.MonitorMaxLevel = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.soft_min_level"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 1 && n <= 32 {
			cfg.SoftMinLevel = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.hard_level"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 2 && n <= 64 {
			cfg.HardLevel = n
		}
	}
	if v, err := s.GetSetting(ctx, "threatintel.soft_block_minutes"); err == nil {
		if n, nErr := strconv.Atoi(strings.TrimSpace(v)); nErr == nil && n >= 1 && n <= 24*60 {
			cfg.SoftBlockMinutes = n
		}
	}
	if cfg.OffenderMinHits <= cfg.EventMinHits {
		cfg.OffenderMinHits = cfg.EventMinHits + 1
	}
	if cfg.SoftMinLevel <= cfg.MonitorMaxLevel {
		cfg.SoftMinLevel = cfg.MonitorMaxLevel + 1
	}
	if cfg.HardLevel <= cfg.SoftMinLevel {
		cfg.HardLevel = cfg.SoftMinLevel + 1
	}
	return cfg, nil
}

func (s *Store) SetThreatIntelConfig(ctx context.Context, cfg model.ThreatIntelConfig) error {
	if cfg.Mode == "" {
		cfg.Mode = "monitor_only"
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "monitor_only", "auto_mode":
	default:
		return fmt.Errorf("invalid threat intel mode")
	}
	if cfg.SyncHours <= 0 {
		cfg.SyncHours = 24
	}
	if cfg.SyncHours > 168 {
		cfg.SyncHours = 168
	}
	if cfg.EventMinHits <= 0 {
		cfg.EventMinHits = 2
	}
	if cfg.OffenderMinHits <= cfg.EventMinHits {
		cfg.OffenderMinHits = cfg.EventMinHits + 1
	}
	if cfg.MonitorMaxLevel < 0 {
		cfg.MonitorMaxLevel = 0
	}
	if cfg.SoftMinLevel <= cfg.MonitorMaxLevel {
		cfg.SoftMinLevel = cfg.MonitorMaxLevel + 1
	}
	if cfg.HardLevel <= cfg.SoftMinLevel {
		cfg.HardLevel = cfg.SoftMinLevel + 1
	}
	if cfg.SoftBlockMinutes <= 0 {
		cfg.SoftBlockMinutes = 15
	}
	if cfg.SoftBlockMinutes > 24*60 {
		cfg.SoftBlockMinutes = 24 * 60
	}
	if err := s.SetSetting(ctx, "threatintel.enabled", strconv.FormatBool(cfg.Enabled)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.mode", mode); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.sync_hours", strconv.Itoa(cfg.SyncHours)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.event_min_hits", strconv.Itoa(cfg.EventMinHits)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.offender_min_hits", strconv.Itoa(cfg.OffenderMinHits)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.monitor_max_level", strconv.Itoa(cfg.MonitorMaxLevel)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.soft_min_level", strconv.Itoa(cfg.SoftMinLevel)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, "threatintel.hard_level", strconv.Itoa(cfg.HardLevel)); err != nil {
		return err
	}
	return s.SetSetting(ctx, "threatintel.soft_block_minutes", strconv.Itoa(cfg.SoftBlockMinutes))
}

func (s *Store) PromoteThreatIntelHardBlocks(ctx context.Context, hardLevel int) (int64, error) {
	if hardLevel <= 0 {
		hardLevel = 6
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO blocked_ips(ip, reason, created_at, updated_at)
SELECT s.ip, ?, ?, ?
FROM threat_intel_ip_state s
LEFT JOIN threat_intel_allowlist a ON a.ip = s.ip
WHERE s.level >= ? AND a.ip IS NULL
ON CONFLICT(ip) DO UPDATE SET
  reason=excluded.reason,
  updated_at=excluded.updated_at`, "threat_intel_auto:level_hard", now, now, hardLevel); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
UPDATE threat_intel_ip_state
SET perm_block=1, ban_until='', risk_state='hardblock', updated_at=?
WHERE level >= ?
  AND ip NOT IN (SELECT ip FROM threat_intel_allowlist)`, now, hardLevel)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *Store) UpsertThreatIntelFeed(ctx context.Context, in model.ThreatIntelFeed) (model.ThreatIntelFeed, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.URL = strings.TrimSpace(in.URL)
	if in.Name == "" {
		return model.ThreatIntelFeed{}, fmt.Errorf("feed name required")
	}
	if in.URL == "" {
		return model.ThreatIntelFeed{}, fmt.Errorf("feed URL required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if in.ID > 0 {
		_, err := s.db.ExecContext(ctx, `
UPDATE threat_intel_feeds
SET name=?, url=?, enabled=?, updated_at=?
WHERE id=?`, in.Name, in.URL, boolToInt(in.Enabled), now, in.ID)
		if err != nil {
			return model.ThreatIntelFeed{}, err
		}
		return s.GetThreatIntelFeedByID(ctx, in.ID)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO threat_intel_feeds(name, url, enabled, is_default, entry_count, created_at, updated_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(url) DO UPDATE SET
  name=excluded.name,
  enabled=excluded.enabled,
  updated_at=excluded.updated_at`, in.Name, in.URL, boolToInt(in.Enabled), boolToInt(in.IsDefault), 0, now, now)
	if err != nil {
		return model.ThreatIntelFeed{}, err
	}
	return s.GetThreatIntelFeedByURL(ctx, in.URL)
}

func (s *Store) DeleteThreatIntelFeed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM threat_intel_feeds WHERE id=?`, id)
	return err
}

func (s *Store) GetThreatIntelFeedByID(ctx context.Context, id int64) (model.ThreatIntelFeed, error) {
	var out model.ThreatIntelFeed
	var created, updated string
	var lastSync sql.NullString
	var enabled, isDefault int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, url, enabled, is_default, entry_count, last_sync_at, last_error, last_hash, created_at, updated_at
FROM threat_intel_feeds WHERE id=?`, id).
		Scan(&out.ID, &out.Name, &out.URL, &enabled, &isDefault, &out.EntryCount, &lastSync, &out.LastError, &out.LastHash, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled != 0
	out.IsDefault = isDefault != 0
	out.LastSyncAt = parseNullableTime(lastSync)
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return out, nil
}

func (s *Store) GetThreatIntelFeedByURL(ctx context.Context, url string) (model.ThreatIntelFeed, error) {
	var out model.ThreatIntelFeed
	var created, updated string
	var lastSync sql.NullString
	var enabled, isDefault int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, url, enabled, is_default, entry_count, last_sync_at, last_error, last_hash, created_at, updated_at
FROM threat_intel_feeds WHERE url=?`, strings.TrimSpace(url)).
		Scan(&out.ID, &out.Name, &out.URL, &enabled, &isDefault, &out.EntryCount, &lastSync, &out.LastError, &out.LastHash, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled != 0
	out.IsDefault = isDefault != 0
	out.LastSyncAt = parseNullableTime(lastSync)
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return out, nil
}

func (s *Store) ListThreatIntelFeeds(ctx context.Context) ([]model.ThreatIntelFeed, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, url, enabled, is_default, entry_count, last_sync_at, last_error, last_hash, created_at, updated_at
FROM threat_intel_feeds
ORDER BY is_default DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ThreatIntelFeed{}
	for rows.Next() {
		var it model.ThreatIntelFeed
		var created, updated string
		var lastSync sql.NullString
		var enabled, isDefault int
		if err := rows.Scan(&it.ID, &it.Name, &it.URL, &enabled, &isDefault, &it.EntryCount, &lastSync, &it.LastError, &it.LastHash, &created, &updated); err != nil {
			return nil, err
		}
		it.Enabled = enabled != 0
		it.IsDefault = isDefault != 0
		it.LastSyncAt = parseNullableTime(lastSync)
		it.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		it.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceThreatIntelFeedEntries(ctx context.Context, feedID int64, ips []string, hash, syncErr string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_intel_entries WHERE feed_id=?`, feedID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO threat_intel_entries(feed_id, ip, created_at) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	count := int64(0)
	seen := map[string]bool{}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		if _, err := stmt.ExecContext(ctx, feedID, ip, now); err != nil {
			return err
		}
		count++
	}
	_, err = tx.ExecContext(ctx, `
UPDATE threat_intel_feeds
SET entry_count=?, last_sync_at=?, last_error=?, last_hash=?, updated_at=?
WHERE id=?`, count, now, strings.TrimSpace(syncErr), strings.TrimSpace(hash), now, feedID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListThreatIntelEntriesByIP(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT e.ip, f.name
FROM threat_intel_entries e
JOIN threat_intel_feeds f ON f.id = e.feed_id
WHERE f.enabled=1
ORDER BY e.ip, f.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return nil, err
		}
		out[ip] = append(out[ip], name)
	}
	return out, rows.Err()
}

func (s *Store) UpsertThreatIntelAllowIP(ctx context.Context, ip, reason string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("ip required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO threat_intel_allowlist(ip, reason, created_at, updated_at)
VALUES(?,?,?,?)
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, updated_at=excluded.updated_at`,
		ip, strings.TrimSpace(reason), now, now)
	return err
}

func (s *Store) RemoveThreatIntelAllowIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM threat_intel_allowlist WHERE ip=?`, strings.TrimSpace(ip))
	return err
}

func (s *Store) ListThreatIntelAllowIPs(ctx context.Context) ([]model.BlockedIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ip, reason, created_at, updated_at FROM threat_intel_allowlist ORDER BY updated_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BlockedIP{}
	for rows.Next() {
		var b model.BlockedIP
		var created, updated string
		if err := rows.Scan(&b.IP, &b.Reason, &created, &updated); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		b.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) RecordThreatIntelMatch(ctx context.Context, in model.ThreatIntelMatchEvent) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	in.IP = strings.TrimSpace(in.IP)
	in.Feed = strings.TrimSpace(in.Feed)
	in.Host = strings.TrimSpace(in.Host)
	in.Path = strings.TrimSpace(in.Path)
	in.Country = strings.ToUpper(strings.TrimSpace(in.Country))
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	in.Decision = strings.ToLower(strings.TrimSpace(in.Decision))
	if in.IP == "" || in.Feed == "" {
		return nil
	}
	if in.Host == "" {
		in.Host = "_unknown"
	}
	if in.Path == "" {
		in.Path = "/"
	}
	if in.Country == "" {
		in.Country = "ZZ"
	}
	if strings.TrimSpace(in.TierAfter) == "" {
		in.TierAfter = "tier0"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO threat_intel_matches(ip, feed, host, path, country, mode, decision, hits, first_seen_at, last_seen_at, last_trace_id, source_scope, xp_delta, xp_after, level_after, tier_after)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(ip, feed, host, path, decision) DO UPDATE SET
  country=excluded.country,
  mode=excluded.mode,
  hits=threat_intel_matches.hits + 1,
  last_seen_at=excluded.last_seen_at,
  last_trace_id=excluded.last_trace_id,
  source_scope=excluded.source_scope,
  xp_delta=excluded.xp_delta,
  xp_after=excluded.xp_after,
  level_after=excluded.level_after,
  tier_after=excluded.tier_after`,
		in.IP, in.Feed, in.Host, in.Path, in.Country, in.Mode, in.Decision, 1, now, now, in.TraceID, in.SourceScope, in.XPDelta, in.XPAfter, in.LevelAfter, in.TierAfter)
	return err
}

func (s *Store) GetThreatIntelIPState(ctx context.Context, ip string) (model.ThreatIntelIPState, error) {
	ip = strings.TrimSpace(ip)
	var st model.ThreatIntelIPState
	var banUntil, lastSeen, signalCounts string
	var permBlocked int
	err := s.db.QueryRowContext(ctx, `
SELECT ip, xp, level, risk_state, ban_until, perm_block, temp_block_count, last_seen_at, top_signal, signal_counts
FROM threat_intel_ip_state
WHERE ip=?`, ip).Scan(&st.IP, &st.XP, &st.Level, &st.RiskState, &banUntil, &permBlocked, &st.TempBlockCount, &lastSeen, &st.TopSignal, &signalCounts)
	if err != nil {
		return st, err
	}
	st.PermBlocked = permBlocked != 0
	st.LastSeenAt = parseTimeOrZero(lastSeen)
	st.BanUntil = parseTimeOrZero(banUntil)
	st.SignalCounts = map[string]int{}
	if strings.TrimSpace(signalCounts) != "" {
		_ = json.Unmarshal([]byte(signalCounts), &st.SignalCounts)
	}
	return st, nil
}

func (s *Store) UpsertThreatIntelIPState(ctx context.Context, st model.ThreatIntelIPState) error {
	st.IP = strings.TrimSpace(st.IP)
	if st.IP == "" {
		return fmt.Errorf("ip required")
	}
	if st.RiskState == "" {
		st.RiskState = "monitoring"
	}
	if st.SignalCounts == nil {
		st.SignalCounts = map[string]int{}
	}
	payload, _ := json.Marshal(st.SignalCounts)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	lastSeen := now
	if !st.LastSeenAt.IsZero() {
		lastSeen = st.LastSeenAt.UTC().Format(time.RFC3339Nano)
	}
	banUntil := ""
	if !st.BanUntil.IsZero() {
		banUntil = st.BanUntil.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO threat_intel_ip_state(ip, xp, level, risk_state, ban_until, perm_block, temp_block_count, last_seen_at, top_signal, signal_counts, created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(ip) DO UPDATE SET
  xp=excluded.xp,
  level=excluded.level,
  risk_state=excluded.risk_state,
  ban_until=excluded.ban_until,
  perm_block=excluded.perm_block,
  temp_block_count=excluded.temp_block_count,
  last_seen_at=excluded.last_seen_at,
  top_signal=excluded.top_signal,
  signal_counts=excluded.signal_counts,
  updated_at=excluded.updated_at`,
		st.IP, st.XP, st.Level, st.RiskState, banUntil, boolToInt(st.PermBlocked), st.TempBlockCount, lastSeen, st.TopSignal, string(payload), now, now)
	return err
}

func (s *Store) ListThreatIntelIPStates(ctx context.Context, limit int) ([]model.ThreatIntelIPState, error) {
	if limit <= 0 || limit > 50000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, xp, level, risk_state, ban_until, perm_block, temp_block_count, last_seen_at, top_signal, signal_counts
FROM threat_intel_ip_state
ORDER BY updated_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ThreatIntelIPState{}
	for rows.Next() {
		var st model.ThreatIntelIPState
		var banUntil, lastSeen, signalCounts string
		var permBlocked int
		if err := rows.Scan(&st.IP, &st.XP, &st.Level, &st.RiskState, &banUntil, &permBlocked, &st.TempBlockCount, &lastSeen, &st.TopSignal, &signalCounts); err != nil {
			return nil, err
		}
		st.PermBlocked = permBlocked != 0
		st.BanUntil = parseTimeOrZero(banUntil)
		st.LastSeenAt = parseTimeOrZero(lastSeen)
		st.SignalCounts = map[string]int{}
		if strings.TrimSpace(signalCounts) != "" {
			_ = json.Unmarshal([]byte(signalCounts), &st.SignalCounts)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) DeleteThreatIntelState(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM threat_intel_ip_state WHERE ip=?`, ip)
	return err
}

func (s *Store) DeleteThreatIntelMatchesByIP(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM threat_intel_matches WHERE ip=?`, ip)
	return err
}

func (s *Store) ListThreatIntelMatches(ctx context.Context, since time.Time, decision, q string, eventMinHits, offenderMinHits, limit, offset int) ([]model.ThreatIntelMatch, int64, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	if eventMinHits <= 0 {
		eventMinHits = 2
	}
	if offenderMinHits <= eventMinHits {
		offenderMinHits = eventMinHits + 1
	}
	decision = strings.ToLower(strings.TrimSpace(decision))
	q = strings.TrimSpace(q)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	baseArgs := []any{since.UTC().Format(time.RFC3339Nano), now}
	where := []string{"m.last_seen_at >= ?", "m.ip NOT IN (SELECT ip FROM blocked_ips)", "(s.level > 0 OR s.xp > 0 OR (s.ban_until != '' AND s.ban_until > ?))"}
	if decision != "" && decision != "all" {
		where = append(where, "m.decision = ?")
		baseArgs = append(baseArgs, decision)
	}
	if q != "" {
		where = append(where, "(m.ip LIKE ? OR m.host LIKE ? OR m.path LIKE ? OR m.feed LIKE ? OR m.country LIKE ? OR m.decision LIKE ?)")
		like := "%" + q + "%"
		baseArgs = append(baseArgs, like, like, like, like, like, like)
	}
	countQuery := `SELECT COUNT(1) FROM (
SELECT m.ip
FROM threat_intel_matches m
LEFT JOIN threat_intel_ip_state s ON s.ip = m.ip
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY m.ip
HAVING SUM(m.hits) >= ? AND SUM(m.hits) < ?
) t`
	var total int64
	countArgs := append([]any{}, baseArgs...)
	countArgs = append(countArgs, eventMinHits, offenderMinHits)
	if err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append([]any{}, baseArgs...)
	args = append(args, limit, offset)
	query := `
SELECT
  MIN(m.id) AS id,
  m.ip,
  GROUP_CONCAT(DISTINCT m.feed) AS feed,
  '' AS host,
  '' AS path,
  COUNT(DISTINCT m.host || '|' || m.path) AS target_count,
  MAX(m.country) AS country,
  GROUP_CONCAT(DISTINCT m.mode) AS mode,
  GROUP_CONCAT(DISTINCT m.decision) AS decision,
  SUM(m.hits) AS hits,
  MIN(m.first_seen_at) AS first_seen_at,
  MAX(m.last_seen_at) AS last_seen_at,
  MAX(m.last_trace_id) AS last_trace_id,
  MAX(m.source_scope) AS source_scope,
  COALESCE(MAX(s.xp), 0) AS xp,
  COALESCE(MAX(s.level), 0) AS level,
  CASE
    WHEN COALESCE(MAX(s.level), 0) >= 6 THEN 'tier6'
    WHEN COALESCE(MAX(s.level), 0) >= 5 THEN 'tier5'
    WHEN COALESCE(MAX(s.level), 0) >= 4 THEN 'tier4'
    WHEN COALESCE(MAX(s.level), 0) >= 3 THEN 'tier3'
    WHEN COALESCE(MAX(s.level), 0) >= 2 THEN 'tier2'
    WHEN COALESCE(MAX(s.level), 0) >= 1 THEN 'tier1'
    ELSE 'tier0'
  END AS tier,
  COALESCE(MAX(s.risk_state), 'monitoring') AS risk_state
FROM threat_intel_matches m
LEFT JOIN threat_intel_ip_state s ON s.ip = m.ip
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY m.ip
HAVING SUM(m.hits) >= ? AND SUM(m.hits) < ?
ORDER BY SUM(m.hits) DESC, MAX(m.last_seen_at) DESC
LIMIT ? OFFSET ?`
	args = append(args, eventMinHits, offenderMinHits)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.ThreatIntelMatch{}
	for rows.Next() {
		var m model.ThreatIntelMatch
		var first, last string
		if err := rows.Scan(&m.ID, &m.IP, &m.Feed, &m.Host, &m.Path, &m.TargetCount, &m.Country, &m.Mode, &m.Decision, &m.Hits, &first, &last, &m.LastTraceID, &m.SourceScope, &m.XP, &m.Level, &m.Tier, &m.RiskState); err != nil {
			return nil, 0, err
		}
		m.FirstSeenAt, _ = time.Parse(time.RFC3339Nano, first)
		m.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) ListThreatIntelTargetsByIP(ctx context.Context, since time.Time, ip string, limit int) ([]model.ThreatIntelTarget, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("ip required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT host, path, GROUP_CONCAT(DISTINCT feed), GROUP_CONCAT(DISTINCT decision), SUM(hits), MAX(last_seen_at)
FROM threat_intel_matches
WHERE ip=? AND last_seen_at>=?
GROUP BY host, path
ORDER BY SUM(hits) DESC, MAX(last_seen_at) DESC
LIMIT ?`, ip, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ThreatIntelTarget{}
	for rows.Next() {
		var t model.ThreatIntelTarget
		var last string
		if err := rows.Scan(&t.Host, &t.Path, &t.Feed, &t.Decision, &t.Hits, &last); err != nil {
			return nil, err
		}
		t.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListThreatIntelOffenders(ctx context.Context, since time.Time, offenderMinHits, limit, offset int) ([]model.ThreatIntelOffender, int64, error) {
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	if offenderMinHits <= 1 {
		offenderMinHits = 10
	}
	var total int64
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM (
  SELECT m.ip
  FROM threat_intel_matches m
  LEFT JOIN blocked_ips b ON b.ip = m.ip
  LEFT JOIN threat_intel_ip_state s ON s.ip = m.ip
  WHERE m.last_seen_at >= ? AND b.ip IS NULL AND (s.level > 0 OR s.xp > 0 OR (s.ban_until != '' AND s.ban_until > ?))
  GROUP BY m.ip
  HAVING SUM(m.hits) >= ?
) t`, since.UTC().Format(time.RFC3339Nano), now, offenderMinHits).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT m.ip,
       SUM(m.hits) AS total_hits,
       COUNT(DISTINCT m.feed) AS distinct_feeds,
       COUNT(DISTINCT m.host) AS distinct_hosts,
       COALESCE((
         SELECT GROUP_CONCAT(x, ' | ') FROM (
           SELECT (CASE WHEN COALESCE(mf.feed, '') = '' THEN '(none)' ELSE mf.feed END || ' (' || SUM(mf.hits) || ')') AS x
           FROM threat_intel_matches mf
           WHERE mf.ip = m.ip AND mf.last_seen_at >= ?
           GROUP BY mf.feed
           ORDER BY SUM(mf.hits) DESC
           LIMIT 3
         )
       ), '') AS feed_summary,
       COALESCE((
         SELECT m2.decision
         FROM threat_intel_matches m2
         WHERE m2.ip = m.ip
         ORDER BY m2.last_seen_at DESC
         LIMIT 1
       ), 'monitor_observe') AS latest_decision,
       MAX(m.last_seen_at),
       CASE WHEN b.ip IS NULL THEN 0 ELSE 1 END AS blocked,
       CASE WHEN a.ip IS NULL THEN 0 ELSE 1 END AS allowlisted,
       COALESCE(MAX(s.xp), 0) AS xp,
       COALESCE(MAX(s.level), 0) AS level,
       CASE
         WHEN COALESCE(MAX(s.level), 0) >= 6 THEN 'tier6'
         WHEN COALESCE(MAX(s.level), 0) >= 5 THEN 'tier5'
         WHEN COALESCE(MAX(s.level), 0) >= 4 THEN 'tier4'
         WHEN COALESCE(MAX(s.level), 0) >= 3 THEN 'tier3'
         WHEN COALESCE(MAX(s.level), 0) >= 2 THEN 'tier2'
         WHEN COALESCE(MAX(s.level), 0) >= 1 THEN 'tier1'
         ELSE 'tier0'
       END AS tier,
       COALESCE(MAX(s.risk_state), 'monitoring') AS risk_state
FROM threat_intel_matches m
LEFT JOIN blocked_ips b ON b.ip = m.ip
LEFT JOIN threat_intel_allowlist a ON a.ip = m.ip
LEFT JOIN threat_intel_ip_state s ON s.ip = m.ip
WHERE m.last_seen_at >= ? AND b.ip IS NULL
  AND (s.level > 0 OR s.xp > 0 OR (s.ban_until != '' AND s.ban_until > ?))
GROUP BY m.ip, b.ip, a.ip
HAVING SUM(m.hits) >= ?
ORDER BY total_hits DESC, MAX(m.last_seen_at) DESC
LIMIT ? OFFSET ?`, since.UTC().Format(time.RFC3339Nano), since.UTC().Format(time.RFC3339Nano), now, offenderMinHits, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.ThreatIntelOffender{}
	for rows.Next() {
		var o model.ThreatIntelOffender
		var feedSummary, decisions, last string
		var blocked, allowlisted int
		if err := rows.Scan(&o.IP, &o.TotalHits, &o.DistinctFeeds, &o.DistinctHosts, &feedSummary, &decisions, &last, &blocked, &allowlisted, &o.XP, &o.Level, &o.Tier, &o.RiskState); err != nil {
			return nil, 0, err
		}
		o.FeedSummary = strings.TrimSpace(feedSummary)
		o.Decisions = decisions
		o.LastSeenAt, _ = time.Parse(time.RFC3339Nano, last)
		o.Blocked = blocked != 0
		o.Allowlisted = allowlisted != 0
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) ListThreatIntelBlocked(ctx context.Context, since time.Time, q string, limit, offset int) ([]model.ThreatIntelBlocked, int64, error) {
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	q = strings.TrimSpace(q)
	where := []string{"1=1"}
	args := []any{}
	if q != "" {
		where = append(where, "(b.ip LIKE ? OR b.reason LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	countQuery := `SELECT COUNT(1) FROM blocked_ips b WHERE ` + strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, since.UTC().Format(time.RFC3339Nano), limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT b.ip,
       b.reason,
       COALESCE((
         SELECT GROUP_CONCAT(x, ' | ') FROM (
           SELECT (COALESCE(m2.decision, 'unknown') || ' @ ' || COALESCE(m2.host, '_') || COALESCE(m2.path, '/')) AS x
           FROM threat_intel_matches m2
           WHERE m2.ip = b.ip
           ORDER BY m2.last_seen_at DESC
           LIMIT 3
         )
       ), '') AS history_snippet,
       b.created_at,
       COALESCE(MAX(s.ban_until), '') AS blocked_until,
       b.updated_at,
       COALESCE(SUM(m.hits), 0) AS total_hits,
       COUNT(DISTINCT m.feed) AS distinct_feeds,
       COUNT(DISTINCT m.host) AS distinct_hosts,
       COALESCE(MAX(m.last_seen_at), '') AS last_seen_at,
       COALESCE(MAX(s.xp), 0) AS xp,
       COALESCE(MAX(s.level), 0) AS level,
       CASE
         WHEN COALESCE(MAX(s.level), 0) >= 6 THEN 'tier6'
         WHEN COALESCE(MAX(s.level), 0) >= 5 THEN 'tier5'
         WHEN COALESCE(MAX(s.level), 0) >= 4 THEN 'tier4'
         WHEN COALESCE(MAX(s.level), 0) >= 3 THEN 'tier3'
         WHEN COALESCE(MAX(s.level), 0) >= 2 THEN 'tier2'
         WHEN COALESCE(MAX(s.level), 0) >= 1 THEN 'tier1'
         ELSE 'tier0'
       END AS tier,
       COALESCE(MAX(s.risk_state), 'monitoring') AS risk_state
FROM blocked_ips b
LEFT JOIN threat_intel_matches m ON m.ip = b.ip AND m.last_seen_at >= ?
LEFT JOIN threat_intel_ip_state s ON s.ip = b.ip
WHERE `+strings.Join(where, " AND ")+`
GROUP BY b.ip, b.reason, b.created_at, b.updated_at
ORDER BY b.updated_at DESC, total_hits DESC
LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.ThreatIntelBlocked{}
	for rows.Next() {
		var b model.ThreatIntelBlocked
		var blockedOn, blockedUntil, updated, last string
		if err := rows.Scan(&b.IP, &b.Reason, &b.History, &blockedOn, &blockedUntil, &updated, &b.TotalHits, &b.DistinctFeeds, &b.DistinctHosts, &last, &b.XP, &b.Level, &b.Tier, &b.RiskState); err != nil {
			return nil, 0, err
		}
		b.BlockedOn = parseTimeOrZero(blockedOn)
		b.BlockedUntil = parseTimeOrZero(blockedUntil)
		b.UpdatedAt = parseTimeOrZero(updated)
		b.LastSeenAt = parseTimeOrZero(last)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) ListThreatIntelGeoPoints(ctx context.Context) ([]model.ThreatIntelGeoPoint, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, `
WITH candidate_ips AS (
  SELECT ip FROM threat_intel_ip_state
  WHERE level > 0 OR xp > 0 OR risk_state <> 'monitoring' OR (ban_until <> '' AND ban_until > ?)
  UNION
  SELECT ip FROM blocked_ips
  UNION
  SELECT ip FROM threat_intel_matches
),
latest_country AS (
  SELECT m.ip, m.country
  FROM threat_intel_matches m
  JOIN (
    SELECT ip, MAX(last_seen_at) AS last_seen_at
    FROM threat_intel_matches
    GROUP BY ip
  ) lm ON lm.ip = m.ip AND lm.last_seen_at = m.last_seen_at
),
hit_totals AS (
  SELECT ip, SUM(hits) AS total_hits
  FROM threat_intel_matches
  GROUP BY ip
)
SELECT
  CASE
    WHEN UPPER(TRIM(COALESCE(lc.country, ''))) GLOB '[A-Z][A-Z]' THEN UPPER(TRIM(lc.country))
    ELSE 'ZZ'
  END AS country,
  CASE
    WHEN b.ip IS NOT NULL OR COALESCE(s.risk_state, '') = 'hardblock' THEN 'hard'
    WHEN (COALESCE(s.ban_until, '') <> '' AND s.ban_until > ?) OR COALESCE(s.risk_state, '') = 'softblock' THEN 'soft'
    ELSE 'monitor'
  END AS state,
  COUNT(1) AS ip_count,
  COALESCE(SUM(ht.total_hits), 0) AS total_hits
FROM candidate_ips c
LEFT JOIN threat_intel_ip_state s ON s.ip = c.ip
LEFT JOIN blocked_ips b ON b.ip = c.ip
LEFT JOIN latest_country lc ON lc.ip = c.ip
LEFT JOIN hit_totals ht ON ht.ip = c.ip
GROUP BY country, state
ORDER BY ip_count DESC, total_hits DESC, country ASC`, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ThreatIntelGeoPoint{}
	for rows.Next() {
		var p model.ThreatIntelGeoPoint
		if err := rows.Scan(&p.Country, &p.State, &p.IPs, &p.Hits); err != nil {
			return nil, err
		}
		p.Country = strings.ToUpper(strings.TrimSpace(p.Country))
		if len(p.Country) != 2 {
			p.Country = "ZZ"
		}
		switch p.State {
		case "hard", "soft", "monitor":
		default:
			p.State = "monitor"
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func parseNullableTime(v sql.NullString) time.Time {
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return time.Time{}
	}
	return parseTimeOrZero(v.String)
}

func parseTimeOrZero(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, v)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func (s *Store) UpsertSSHBastionRoute(ctx context.Context, in model.SSHBastionRoute) (model.SSHBastionRoute, error) {
	in.FQDN = strings.ToLower(strings.TrimSpace(in.FQDN))
	in.TargetHost = strings.TrimSpace(in.TargetHost)
	if in.FQDN == "" || in.TargetHost == "" || in.TargetPort <= 0 || in.TargetPort > 65535 {
		return model.SSHBastionRoute{}, fmt.Errorf("invalid ssh bastion route")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if in.ID > 0 {
		_, err := s.db.ExecContext(ctx, `
UPDATE ssh_bastion_routes
SET fqdn=?, target_host=?, target_port=?, enabled=?, updated_at=?
WHERE id=?`, in.FQDN, in.TargetHost, in.TargetPort, boolToInt(in.Enabled), now, in.ID)
		if err != nil {
			return model.SSHBastionRoute{}, err
		}
		return s.GetSSHBastionRouteByID(ctx, in.ID)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO ssh_bastion_routes(fqdn, target_host, target_port, enabled, created_at, updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(fqdn) DO UPDATE SET
  target_host=excluded.target_host,
  target_port=excluded.target_port,
  enabled=excluded.enabled,
  updated_at=excluded.updated_at`, in.FQDN, in.TargetHost, in.TargetPort, boolToInt(in.Enabled), now, now)
	if err != nil {
		return model.SSHBastionRoute{}, err
	}
	return s.GetSSHBastionRouteByFQDN(ctx, in.FQDN)
}

func (s *Store) GetSSHBastionRouteByFQDN(ctx context.Context, fqdn string) (model.SSHBastionRoute, error) {
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	var out model.SSHBastionRoute
	var created, updated string
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, fqdn, target_host, target_port, enabled, created_at, updated_at
FROM ssh_bastion_routes WHERE fqdn=?`, fqdn).
		Scan(&out.ID, &out.FQDN, &out.TargetHost, &out.TargetPort, &enabled, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled != 0
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return out, nil
}

func (s *Store) GetSSHBastionRouteByID(ctx context.Context, id int64) (model.SSHBastionRoute, error) {
	var out model.SSHBastionRoute
	var created, updated string
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, fqdn, target_host, target_port, enabled, created_at, updated_at
FROM ssh_bastion_routes WHERE id=?`, id).
		Scan(&out.ID, &out.FQDN, &out.TargetHost, &out.TargetPort, &enabled, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled != 0
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return out, nil
}

func (s *Store) ListSSHBastionRoutes(ctx context.Context) ([]model.SSHBastionRoute, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, fqdn, target_host, target_port, enabled, created_at, updated_at
FROM ssh_bastion_routes
ORDER BY fqdn`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SSHBastionRoute{}
	for rows.Next() {
		var item model.SSHBastionRoute
		var created, updated string
		var enabled int
		if err := rows.Scan(&item.ID, &item.FQDN, &item.TargetHost, &item.TargetPort, &enabled, &created, &updated); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSSHBastionRoute(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ssh_bastion_routes WHERE id=?`, id)
	return err
}

func (s *Store) CreateSSHBastionKey(ctx context.Context, name, publicKey, fingerprint string, enabled bool, routeIDs []int64) (model.SSHBastionKey, error) {
	name = strings.TrimSpace(name)
	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	if name == "" || publicKey == "" || fingerprint == "" {
		return model.SSHBastionKey{}, fmt.Errorf("invalid ssh bastion key")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.SSHBastionKey{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
INSERT INTO ssh_bastion_keys(name, public_key, fingerprint, enabled, created_at, updated_at)
VALUES(?,?,?,?,?,?)`, name, publicKey, fingerprint, boolToInt(enabled), now, now)
	if err != nil {
		return model.SSHBastionKey{}, err
	}
	keyID, _ := res.LastInsertId()
	for _, rid := range routeIDs {
		if rid <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ssh_bastion_key_routes(key_id, route_id, created_at)
VALUES(?,?,?)`, keyID, rid, now); err != nil {
			return model.SSHBastionKey{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.SSHBastionKey{}, err
	}
	return s.GetSSHBastionKeyByID(ctx, keyID)
}

func (s *Store) GetSSHBastionKeyByID(ctx context.Context, id int64) (model.SSHBastionKey, error) {
	var out model.SSHBastionKey
	var created, updated string
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, public_key, fingerprint, enabled, created_at, updated_at
FROM ssh_bastion_keys WHERE id=?`, id).
		Scan(&out.ID, &out.Name, &out.PublicKey, &out.Fingerprint, &enabled, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Enabled = enabled != 0
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	routeRows, err := s.db.QueryContext(ctx, `SELECT route_id FROM ssh_bastion_key_routes WHERE key_id=? ORDER BY route_id`, out.ID)
	if err != nil {
		return out, err
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var rid int64
		if err := routeRows.Scan(&rid); err != nil {
			return out, err
		}
		out.RouteIDs = append(out.RouteIDs, rid)
	}
	return out, routeRows.Err()
}

func (s *Store) ListSSHBastionKeys(ctx context.Context) ([]model.SSHBastionKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, public_key, fingerprint, enabled, created_at, updated_at
FROM ssh_bastion_keys
ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SSHBastionKey{}
	for rows.Next() {
		var item model.SSHBastionKey
		var created, updated string
		var enabled int
		if err := rows.Scan(&item.ID, &item.Name, &item.PublicKey, &item.Fingerprint, &enabled, &created, &updated); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, item)
	}
	for i := range out {
		routeRows, err := s.db.QueryContext(ctx, `SELECT route_id FROM ssh_bastion_key_routes WHERE key_id=? ORDER BY route_id`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for routeRows.Next() {
			var rid int64
			if err := routeRows.Scan(&rid); err != nil {
				routeRows.Close()
				return nil, err
			}
			out[i].RouteIDs = append(out[i].RouteIDs, rid)
		}
		routeRows.Close()
	}
	return out, nil
}

func (s *Store) DeleteSSHBastionKey(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ssh_bastion_keys WHERE id=?`, id)
	return err
}

func (s *Store) GetSSHBastionAuthByFingerprint(ctx context.Context, fingerprint string) (model.SSHBastionKeyAuth, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	var out model.SSHBastionKeyAuth
	var enabled int
	var created, updated string
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, public_key, fingerprint, enabled, created_at, updated_at
FROM ssh_bastion_keys
WHERE fingerprint=?`, fingerprint).
		Scan(&out.Key.ID, &out.Key.Name, &out.Key.PublicKey, &out.Key.Fingerprint, &enabled, &created, &updated)
	if err != nil {
		return out, err
	}
	out.Key.Enabled = enabled != 0
	out.Key.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	out.Key.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	rows, err := s.db.QueryContext(ctx, `
SELECT r.id, r.fqdn, r.target_host, r.target_port, r.enabled, r.created_at, r.updated_at
FROM ssh_bastion_key_routes kr
JOIN ssh_bastion_routes r ON r.id = kr.route_id
WHERE kr.key_id=?
ORDER BY r.id`, out.Key.ID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var rt model.SSHBastionRoute
		var rtEnabled int
		var rtCreated, rtUpdated string
		if err := rows.Scan(&rt.ID, &rt.FQDN, &rt.TargetHost, &rt.TargetPort, &rtEnabled, &rtCreated, &rtUpdated); err != nil {
			return out, err
		}
		rt.Enabled = rtEnabled != 0
		rt.CreatedAt, _ = time.Parse(time.RFC3339Nano, rtCreated)
		rt.UpdatedAt, _ = time.Parse(time.RFC3339Nano, rtUpdated)
		out.Key.RouteIDs = append(out.Key.RouteIDs, rt.ID)
		out.Routes = append(out.Routes, rt)
	}
	return out, rows.Err()
}

func (s *Store) InsertBackupArchive(ctx context.Context, in model.BackupArchive) (model.BackupArchive, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `
INSERT INTO backup_archives(file_name, storage, location, size_bytes, sha256, status, created_at)
VALUES(?,?,?,?,?,?,?)`,
		strings.TrimSpace(in.FileName),
		strings.TrimSpace(in.Storage),
		strings.TrimSpace(in.Location),
		in.SizeBytes,
		strings.TrimSpace(in.SHA256),
		strings.TrimSpace(in.Status),
		now,
	)
	if err != nil {
		return model.BackupArchive{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetBackupArchiveByID(ctx, id)
}

func (s *Store) GetBackupArchiveByID(ctx context.Context, id int64) (model.BackupArchive, error) {
	var out model.BackupArchive
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT id, file_name, storage, location, size_bytes, sha256, status, created_at
FROM backup_archives WHERE id=?`, id).
		Scan(&out.ID, &out.FileName, &out.Storage, &out.Location, &out.SizeBytes, &out.SHA256, &out.Status, &created)
	if err != nil {
		return out, err
	}
	out.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return out, nil
}

func (s *Store) ListBackupArchives(ctx context.Context, limit int) ([]model.BackupArchive, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, file_name, storage, location, size_bytes, sha256, status, created_at
FROM backup_archives
ORDER BY created_at DESC, id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BackupArchive{}
	for rows.Next() {
		var it model.BackupArchive
		var created string
		if err := rows.Scan(&it.ID, &it.FileName, &it.Storage, &it.Location, &it.SizeBytes, &it.SHA256, &it.Status, &created); err != nil {
			return nil, err
		}
		it.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) ListBackupArchivesByStorageOldestFirst(ctx context.Context, storage string) ([]model.BackupArchive, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, file_name, storage, location, size_bytes, sha256, status, created_at
FROM backup_archives
WHERE storage=?
ORDER BY created_at ASC, id ASC`, strings.TrimSpace(storage))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BackupArchive{}
	for rows.Next() {
		var it model.BackupArchive
		var created string
		if err := rows.Scan(&it.ID, &it.FileName, &it.Storage, &it.Location, &it.SizeBytes, &it.SHA256, &it.Status, &created); err != nil {
			return nil, err
		}
		it.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBackupArchiveByID(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM backup_archives WHERE id=?`, id)
	return err
}

func (s *Store) VacuumInto(ctx context.Context, outPath string) error {
	outPath = strings.TrimSpace(outPath)
	if outPath == "" {
		return fmt.Errorf("snapshot path required")
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(FULL)`); err != nil {
		return err
	}
	escaped := strings.ReplaceAll(outPath, `'`, `''`)
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`VACUUM INTO '%s'`, escaped))
	return err
}

func (s *Store) RestoreFromSnapshot(ctx context.Context, snapshotPath string) error {
	snapshotPath = strings.TrimSpace(snapshotPath)
	if snapshotPath == "" {
		return fmt.Errorf("snapshot path required")
	}
	escaped := strings.ReplaceAll(snapshotPath, `'`, `''`)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ATTACH DATABASE '%s' AS restoredb`, escaped)); err != nil {
		return err
	}
	defer func() {
		_, _ = tx.ExecContext(context.Background(), `DETACH DATABASE restoredb`)
	}()
	mainTables, err := listUserTables(ctx, tx, "main")
	if err != nil {
		return err
	}
	restoreTables, err := listUserTables(ctx, tx, "restoredb")
	if err != nil {
		return err
	}
	restoreSet := map[string]bool{}
	for _, t := range restoreTables {
		restoreSet[t] = true
	}
	for _, t := range mainTables {
		if !restoreSet[t] {
			continue
		}
		mainCols, err := listTableColumns(ctx, tx, "main", t)
		if err != nil {
			return err
		}
		restoreCols, err := listTableColumns(ctx, tx, "restoredb", t)
		if err != nil {
			return err
		}
		if len(mainCols) == 0 || len(restoreCols) == 0 {
			continue
		}
		restoreColSet := map[string]bool{}
		for _, c := range restoreCols {
			restoreColSet[c] = true
		}
		cols := make([]string, 0, len(mainCols))
		for _, c := range mainCols {
			if restoreColSet[c] {
				cols = append(cols, c)
			}
		}
		if len(cols) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s`, quoteIdent(t))); err != nil {
			return err
		}
		colList := quoteIdentList(cols)
		insertSQL := fmt.Sprintf(
			`INSERT INTO %s(%s) SELECT %s FROM restoredb.%s`,
			quoteIdent(t),
			colList,
			colList,
			quoteIdent(t),
		)
		if _, err := tx.ExecContext(ctx, insertSQL); err != nil {
			return err
		}
	}
	if slices.Contains(mainTables, "sessions") {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DETACH DATABASE restoredb`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func listUserTables(ctx context.Context, tx *sql.Tx, schema string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
SELECT name
FROM %s.sqlite_master
WHERE type='table' AND name NOT LIKE 'sqlite_%%'
ORDER BY name`, quoteIdent(schema)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func listTableColumns(ctx context.Context, tx *sql.Tx, schema, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`PRAGMA %s.table_info(%s)`, quoteIdent(schema), quoteIdent(table)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(strings.TrimSpace(s), `"`, `""`) + `"`
}

func quoteIdentList(cols []string) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, quoteIdent(c))
	}
	return strings.Join(parts, ",")
}
