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

CREATE INDEX IF NOT EXISTS idx_host_traffic_minute_bucket ON host_traffic_minute(bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_minute_host_bucket ON host_traffic_minute(host_id, bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_class_minute_bucket ON host_traffic_class_minute(bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_traffic_class_minute_host_bucket ON host_traffic_class_minute(host_id, bucket_start);
CREATE INDEX IF NOT EXISTS idx_host_visitors_daily_day ON host_visitors_daily(day);
CREATE INDEX IF NOT EXISTS idx_ssh_bastion_key_fingerprint ON ssh_bastion_keys(fingerprint);
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
		"created":      {"dns_pending": true, "cert_pending": true, "error": true},
		"dns_pending":  {"cert_pending": true, "error": true},
		"cert_pending": {"active": true, "error": true},
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
