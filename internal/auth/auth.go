package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/mfa"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/domnexdomain/domnexdomain/internal/netutil"
	"github.com/domnexdomain/domnexdomain/internal/store"
)

type Store interface {
	FindUserByUsername(ctx context.Context, username string) (model.User, error)
	GetUserByID(ctx context.Context, id int64) (model.User, error)
	CreateSession(ctx context.Context, id string, userID int64, expiresAt time.Time) error
	GetSession(ctx context.Context, id string) (model.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteAllSessionsForUser(ctx context.Context, userID int64) error
	LookupAPIToken(ctx context.Context, bearer string) (model.APIToken, error)
	AddAuditEvent(ctx context.Context, e model.AuditEvent) error
	GetLoginAttempt(ctx context.Context, username string) (failedCount int, lockUntil time.Time, err error)
	RegisterLoginFailure(ctx context.Context, username string) (failedCount int, lockUntil time.Time, err error)
	ClearLoginFailures(ctx context.Context, username string) error
	GetUserDomainIDs(ctx context.Context, userID int64) ([]int64, error)
	IsIPBlocked(ctx context.Context, ip string) (bool, error)
	ConsumeUserMFARecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error)
	GetSetting(ctx context.Context, key string) (string, error)
	GetSecret(ctx context.Context, key string) (string, error)
	UpsertExternalUser(ctx context.Context, username string, role model.Role, domainIDs []int64, provider, passHash string) (model.User, error)
	ListDomainIDs(ctx context.Context) ([]int64, error)
}

type Service struct {
	store             Store
	sessionTTL        time.Duration
	allowed           []*net.IPNet
	trusted           []*net.IPNet
	keystore          *crypto.Keystore
	dummyPasswordHash string
}

type Identity struct {
	UserID    int64           `json:"userId"`
	Username  string          `json:"username"`
	Role      model.Role      `json:"role"`
	DomainIDs []int64         `json:"domainIds,omitempty"`
	Scopes    map[string]bool `json:"scopes,omitempty"`
	Type      string          `json:"type"`
}

func New(store Store, ks *crypto.Keystore, sessionTTL time.Duration, allowedCIDRs, trustedProxyCIDRs []string) (*Service, error) {
	allowed, err := netutil.ParseCIDRs(allowedCIDRs)
	if err != nil {
		return nil, err
	}
	trusted, err := netutil.ParseCIDRs(trustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	dummyPasswordHash, err := crypto.HashPassword("domnex-auth-burner", crypto.DefaultArgonConfig())
	if err != nil {
		return nil, err
	}
	return &Service{
		store:             store,
		keystore:          ks,
		sessionTTL:        sessionTTL,
		allowed:           allowed,
		trusted:           trusted,
		dummyPasswordHash: dummyPasswordHash,
	}, nil
}

func (s *Service) AuthenticatePassword(ctx context.Context, username, password, otpOrRecovery, source string) (string, model.User, error) {
	failErr := errors.New("login failed")
	username = strings.TrimSpace(username)
	normUsername := strings.ToLower(username)
	if normUsername == "" {
		normUsername = username
	}
	if strings.TrimSpace(source) == "" {
		source = "n/a"
	}
	if blocked, err := s.store.IsIPBlocked(ctx, source); err == nil && blocked {
		s.burnPasswordCheck(password)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.blocked_ip", Target: "user", Meta: "source=" + source})
		return "", model.User{}, failErr
	}
	failed, lockUntil, err := s.store.GetLoginAttempt(ctx, normUsername)
	if err != nil {
		return "", model.User{}, err
	}
	if failed > 0 && lockUntil.After(time.Now().UTC()) {
		s.burnPasswordCheck(password)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.locked", Target: "user", Meta: "lock_until=" + lockUntil.Format(time.RFC3339) + ";source=" + source})
		return "", model.User{}, failErr
	}

	u, err := s.store.FindUserByUsername(ctx, normUsername)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			extUser, detail, extErr := s.tryLDAPLogin(ctx, username, password)
			if extErr == nil {
				u = extUser
			} else {
				s.burnPasswordCheck(password)
				fc, lu, counted := s.registerFailureIfEligible(ctx, normUsername, detail)
				meta := "unknown_user;source=" + source + ";" + loginFailureMeta(fc, lu, counted)
				if strings.TrimSpace(detail) != "" {
					meta += ";ldap=" + detail
				}
				_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: meta})
				return "", model.User{}, failErr
			}
		}
		return "", model.User{}, err
	}
	if strings.EqualFold(strings.TrimSpace(u.AuthProvider), "ldap") {
		extUser, detail, extErr := s.tryLDAPLogin(ctx, username, password)
		if extErr != nil {
			fc, lu, counted := s.registerFailureIfEligible(ctx, normUsername, detail)
			meta := "ldap_auth_failed;source=" + source + ";" + loginFailureMeta(fc, lu, counted)
			if strings.TrimSpace(detail) != "" {
				meta += ";ldap=" + detail
			}
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: meta})
			return "", model.User{}, failErr
		}
		u = extUser
	} else {
		if !crypto.VerifyPassword(password, u.PasswordHash) {
			fc, lu, _ := s.store.RegisterLoginFailure(ctx, normUsername)
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: "bad_password;failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
			return "", model.User{}, failErr
		}
	}
	if ok, detail := s.isSourceAllowedForUser(u, source); !ok {
		fc, lu, _ := s.store.RegisterLoginFailure(ctx, normUsername)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: "ip_policy_denied;" + detail + ";failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
		return "", model.User{}, failErr
	}
	if required, mfaDetail := s.userRequiresMFA(ctx, u); required {
		if !u.MFAEnabled {
			fc, lu, _ := s.store.RegisterLoginFailure(ctx, normUsername)
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: "mfa_required_not_enrolled;" + mfaDetail + ";failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
			return "", model.User{}, failErr
		}
		ok, detail := s.validateMFA(ctx, u, otpOrRecovery)
		if !ok {
			fc, lu, _ := s.store.RegisterLoginFailure(ctx, normUsername)
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: normUsername, Action: "auth.login.failed", Target: "user", Meta: "mfa_failed;" + detail + ";failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
			return "", model.User{}, failErr
		}
	}
	_ = s.store.ClearLoginFailures(ctx, normUsername)
	sid, err := randomHex(32)
	if err != nil {
		return "", model.User{}, err
	}
	expires := time.Now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateSession(ctx, sid, u.ID, expires); err != nil {
		return "", model.User{}, err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: u.Username, Action: "auth.login.success", Target: "session", Meta: "password+mfa;provider=" + strings.TrimSpace(u.AuthProvider) + ";source=" + source})
	return sid, u, nil
}

func (s *Service) AuthenticateExternal(ctx context.Context, username string, role model.Role, domainIDs []int64, provider, source string) (string, model.User, error) {
	failErr := errors.New("login failed")
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", model.User{}, failErr
	}
	if strings.TrimSpace(source) == "" {
		source = "n/a"
	}
	if blocked, err := s.store.IsIPBlocked(ctx, source); err == nil && blocked {
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.blocked_ip", Target: "user", Meta: "source=" + source + ";provider=" + strings.TrimSpace(provider)})
		return "", model.User{}, failErr
	}
	u, err := s.store.UpsertExternalUser(ctx, username, role, domainIDs, provider, s.dummyPasswordHash)
	if err != nil {
		return "", model.User{}, err
	}
	if ok, detail := s.isSourceAllowedForUser(u, source); !ok {
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.failed", Target: "user", Meta: "ip_policy_denied;" + detail + ";source=" + source + ";provider=" + strings.TrimSpace(provider)})
		return "", model.User{}, failErr
	}
	_ = s.store.ClearLoginFailures(ctx, username)
	sid, err := randomHex(32)
	if err != nil {
		return "", model.User{}, err
	}
	expires := time.Now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateSession(ctx, sid, u.ID, expires); err != nil {
		return "", model.User{}, err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: u.Username, Action: "auth.login.success", Target: "session", Meta: "provider=" + strings.TrimSpace(provider) + ";source=" + source})
	return sid, u, nil
}

func (s *Service) burnPasswordCheck(password string) {
	if strings.TrimSpace(s.dummyPasswordHash) == "" {
		return
	}
	_ = crypto.VerifyPassword(password, s.dummyPasswordHash)
}

func shouldCountLoginFailure(ldapDetail string) bool {
	switch strings.ToLower(strings.TrimSpace(ldapDetail)) {
	case "dial_failed", "starttls_failed", "bind_failed", "rebind_failed", "group_search_failed", "account_locked", "config_error", "ldap_disabled":
		return false
	default:
		return true
	}
}

func loginFailureMeta(fails int, lockUntil time.Time, counted bool) string {
	if !counted {
		return "failures=skipped;lock_until=none"
	}
	return "failures=" + strconv.Itoa(fails) + ";lock_until=" + lockUntil.Format(time.RFC3339)
}

func (s *Service) registerFailureIfEligible(ctx context.Context, username, ldapDetail string) (int, time.Time, bool) {
	if !shouldCountLoginFailure(ldapDetail) {
		return 0, time.Time{}, false
	}
	fc, lu, _ := s.store.RegisterLoginFailure(ctx, username)
	return fc, lu, true
}

func (s *Service) userRequiresMFA(ctx context.Context, u model.User) (bool, string) {
	if strings.EqualFold(strings.TrimSpace(u.AuthProvider), "ldap") {
		return false, "external_provider_ldap"
	}
	if u.MFAEnabled {
		return true, "user_enrolled"
	}
	key := ""
	switch u.Role {
	case model.RoleAdmin:
		key = "auth.mfa.enforce_admin"
	case model.RoleDomainAdmin:
		key = "auth.mfa.enforce_domain_admin"
	case model.RoleReadOnly:
		key = "auth.mfa.enforce_read_only"
	default:
		return false, "role_not_enforced"
	}
	v, err := s.store.GetSetting(ctx, key)
	if err != nil {
		return false, "policy_unset"
	}
	if strings.EqualFold(strings.TrimSpace(v), "true") {
		return true, "policy_enforced"
	}
	return false, "policy_not_enforced"
}

func (s *Service) validateMFA(ctx context.Context, u model.User, otpOrRecovery string) (bool, string) {
	raw := strings.TrimSpace(otpOrRecovery)
	if raw == "" {
		return false, "missing_code"
	}
	if s.keystore != nil && strings.TrimSpace(u.MFASecretEnc) != "" {
		secret, err := s.keystore.Decrypt(strings.TrimSpace(u.MFASecretEnc))
		if err == nil && mfa.ValidateTOTP(secret, raw, time.Now().UTC()) {
			return true, "totp_ok"
		}
	}
	if mfa.IsRecoveryCodeFormat(raw) {
		norm := mfa.NormalizeRecoveryCode(raw)
		sum := sha256.Sum256([]byte(norm))
		ok, err := s.store.ConsumeUserMFARecoveryCode(ctx, u.ID, hex.EncodeToString(sum[:]))
		if err == nil && ok {
			return true, "recovery_ok"
		}
	}
	return false, "invalid_code"
}

func (s *Service) ResolveIdentity(r *http.Request) (Identity, error) {
	source := s.requestIP(r)
	if blocked, err := s.store.IsIPBlocked(r.Context(), source); err == nil && blocked {
		return Identity{}, errors.New("unauthorized")
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		tok, err := s.store.LookupAPIToken(r.Context(), token)
		if err == nil {
			return Identity{Username: "token:" + tok.Name, Role: tok.Role, DomainIDs: tok.DomainIDs, Scopes: store.SplitScopes(tok.Scopes), Type: "token"}, nil
		}
	}
	cookie, err := r.Cookie("domnex_session")
	if err != nil {
		return Identity{}, errors.New("unauthorized")
	}
	sess, err := s.store.GetSession(r.Context(), cookie.Value)
	if err != nil || sess.ExpiresAt.Before(time.Now().UTC()) {
		return Identity{}, errors.New("unauthorized")
	}
	u, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		return Identity{}, errors.New("unauthorized")
	}
	if ok, detail := s.isSourceAllowedForUser(u, source); !ok {
		_ = s.store.AddAuditEvent(r.Context(), model.AuditEvent{Actor: u.Username, Action: "auth.session.denied", Target: "session", Meta: detail + ";source=" + source})
		return Identity{}, errors.New("unauthorized")
	}
	domainIDs, _ := s.store.GetUserDomainIDs(r.Context(), u.ID)
	return Identity{UserID: u.ID, Username: u.Username, Role: u.Role, DomainIDs: domainIDs, Type: "session"}, nil
}

func (s *Service) isSourceAllowedForUser(u model.User, source string) (bool, string) {
	if u.IPCheckOff {
		if u.MFAEnabled {
			return true, "ip_check_disabled=1;mfa_enabled=1"
		}
		// Security guard: IP-check bypass is only valid for MFA-enabled users.
		// If MFA is not enabled, continue with normal CIDR policy evaluation.
	}
	ip := net.ParseIP(strings.TrimSpace(source))
	if ip == nil {
		return false, "invalid_source_ip"
	}
	var nets []*net.IPNet
	var err error
	if strings.TrimSpace(u.AllowedCIDRs) != "" {
		nets, err = parseCIDRsCSV(u.AllowedCIDRs)
		if err != nil {
			return false, "invalid_user_cidrs"
		}
	} else {
		nets = s.allowed
	}
	if len(nets) == 0 {
		return true, "no_cidr_policy"
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true, "cidr_match"
		}
	}
	return false, "cidr_miss"
}

func parseCIDRsCSV(raw string) ([]*net.IPNet, error) {
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func (s *Service) Logout(ctx context.Context, sessionID string, actor string) error {
	if err := s.store.DeleteSession(ctx, sessionID); err != nil {
		return err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: actor, Action: "auth.logout", Target: "session", Meta: "single"})
	return nil
}

func (s *Service) LogoutAll(ctx context.Context, userID int64, actor string) error {
	if err := s.store.DeleteAllSessionsForUser(ctx, userID); err != nil {
		return err
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: actor, Action: "auth.logout_all", Target: "session", Meta: "all"})
	return nil
}

func (s *Service) CheckAdminNetwork(r *http.Request) bool {
	source := s.requestIP(r)
	if blocked, err := s.store.IsIPBlocked(r.Context(), source); err == nil && blocked {
		_ = s.store.AddAuditEvent(r.Context(), model.AuditEvent{Actor: "system", Action: "auth.admin_network.blocked_ip", Target: "admin_api", Meta: "source=" + source})
		return false
	}
	ip := net.ParseIP(source)
	if ip == nil {
		return false
	}
	for _, cidr := range s.allowed {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) requestIP(r *http.Request) string {
	return netutil.ClientIP(r, s.trusted)
}

func (s *Service) SourceIP(r *http.Request) string {
	return s.requestIP(r)
}

func RoleAllows(role model.Role, need model.Role) bool {
	ord := map[model.Role]int{model.RoleReadOnly: 1, model.RoleOperator: 2, model.RoleDomainAdmin: 2, model.RoleAdmin: 3}
	return ord[role] >= ord[need]
}

func ScopeAllows(scopes map[string]bool, want string) bool {
	if len(scopes) == 0 {
		return true
	}
	if scopes[want] || scopes["*"] {
		return true
	}
	if strings.HasSuffix(want, ":read") {
		if scopes[strings.TrimSuffix(want, ":read")+":write"] {
			return true
		}
	}
	return false
}

func bearerToken(v string) string {
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
