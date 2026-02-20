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
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

type Store struct {
	db *sql.DB
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

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(username, role, password_hash, created_at, updated_at) VALUES(?,?,?,?,?)`, username, role, passHash, now, now)
	return true, err
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (model.User, error) {
	var u model.User
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, password_hash, created_at, updated_at FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &created, &updated)
	if err != nil {
		return u, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (model.User, error) {
	var u model.User
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, password_hash, created_at, updated_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &created, &updated)
	if err != nil {
		return u, err
	}
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
	err := s.db.QueryRowContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, state, error_reason, created_at, updated_at FROM hosts WHERE id=?`, id).
		Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.State, &h.ErrorReason, &created, &updated)
	if err != nil {
		return h, err
	}
	h.InsecureTLS = insecure != 0
	h.HAEnabled = haEnabled != 0
	h.HABackends = decodeBackends(haBackendsJSON)
	h.AuthEnabled = authEnabled != 0
	h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return h, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, state, error_reason, created_at, updated_at FROM hosts ORDER BY fqdn`)
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
		if err := rows.Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.State, &h.ErrorReason, &created, &updated); err != nil {
			return nil, err
		}
		h.InsecureTLS = insecure != 0
		h.HAEnabled = haEnabled != 0
		h.HABackends = decodeBackends(haBackendsJSON)
		h.AuthEnabled = authEnabled != 0
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) ListHostsByDomainID(ctx context.Context, domainID int64) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, state, error_reason, created_at, updated_at FROM hosts WHERE domain_id=? ORDER BY fqdn`, domainID)
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
		if err := rows.Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.State, &h.ErrorReason, &created, &updated); err != nil {
			return nil, err
		}
		h.InsecureTLS = insecure != 0
		h.HAEnabled = haEnabled != 0
		h.HABackends = decodeBackends(haBackendsJSON)
		h.AuthEnabled = authEnabled != 0
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
		"created":      {"dns_pending": true, "cert_pending": true, "error": true},
		"dns_pending":  {"cert_pending": true, "error": true},
		"cert_pending": {"active": true, "error": true},
		"active":       {"error": true, "cert_pending": true},
		"error":        {"dns_pending": true, "cert_pending": true},
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

func (s *Store) GetSecret(ctx context.Context, keyName string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT enc_value FROM secrets WHERE key_name=?`, keyName).Scan(&v)
	return v, err
}

func (s *Store) AddAuditEvent(ctx context.Context, e model.AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor, action, target, meta, created_at) VALUES(?,?,?,?,?)`, e.Actor, e.Action, e.Target, e.Meta, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
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
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, e)
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

func (s *Store) FindHostByFQDN(ctx context.Context, fqdn string) (model.Host, error) {
	var h model.Host
	var created, updated string
	var insecure, haEnabled, authEnabled int
	var haBackendsJSON string
	err := s.db.QueryRowContext(ctx, `SELECT id, domain_id, subdomain, fqdn, upstream_url, insecure_tls, ha_enabled, ha_mode, ha_backends, auth_enabled, auth_user, auth_pass_hash, state, error_reason, created_at, updated_at FROM hosts WHERE fqdn=?`, fqdn).
		Scan(&h.ID, &h.DomainID, &h.Subdomain, &h.FQDN, &h.UpstreamURL, &insecure, &haEnabled, &h.HAMode, &haBackendsJSON, &authEnabled, &h.AuthUser, &h.AuthPassHash, &h.State, &h.ErrorReason, &created, &updated)
	if err != nil {
		return h, err
	}
	h.InsecureTLS = insecure != 0
	h.HAEnabled = haEnabled != 0
	h.HABackends = decodeBackends(haBackendsJSON)
	h.AuthEnabled = authEnabled != 0
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

func (s *Store) CreateUser(ctx context.Context, username string, role model.Role, passHash string) (model.User, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, role, password_hash, created_at, updated_at) VALUES(?,?,?,?,?)`, username, string(role), passHash, now, now)
	if err != nil {
		return model.User{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetUserByID(ctx, id)
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, role, password_hash, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.User{}
	for rows.Next() {
		var u model.User
		var created, updated string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &created, &updated); err != nil {
			return nil, err
		}
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
