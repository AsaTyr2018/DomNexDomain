package auth

import (
	"context"
	"crypto/rand"
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
	"github.com/domnexdomain/domnexdomain/internal/model"
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
}

type Service struct {
	store      Store
	sessionTTL time.Duration
	allowed    []*net.IPNet
}

type Identity struct {
	UserID    int64           `json:"userId"`
	Username  string          `json:"username"`
	Role      model.Role      `json:"role"`
	DomainIDs []int64         `json:"domainIds,omitempty"`
	Scopes    map[string]bool `json:"scopes,omitempty"`
	Type      string          `json:"type"`
}

func New(store Store, sessionTTL time.Duration, allowedCIDRs []string) (*Service, error) {
	allowed := make([]*net.IPNet, 0, len(allowedCIDRs))
	for _, c := range allowedCIDRs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, network)
	}
	return &Service{store: store, sessionTTL: sessionTTL, allowed: allowed}, nil
}

func (s *Service) AuthenticatePassword(ctx context.Context, username, password, source string) (string, model.User, error) {
	failErr := errors.New("login failed")
	if strings.TrimSpace(source) == "" {
		source = "n/a"
	}
	if blocked, err := s.store.IsIPBlocked(ctx, source); err == nil && blocked {
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.blocked_ip", Target: "user", Meta: "source=" + source})
		return "", model.User{}, failErr
	}
	failed, lockUntil, err := s.store.GetLoginAttempt(ctx, username)
	if err != nil {
		return "", model.User{}, err
	}
	if failed > 0 && lockUntil.After(time.Now().UTC()) {
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.locked", Target: "user", Meta: "lock_until=" + lockUntil.Format(time.RFC3339) + ";source=" + source})
		return "", model.User{}, failErr
	}

	u, err := s.store.FindUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fc, lu, _ := s.store.RegisterLoginFailure(ctx, username)
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.failed", Target: "user", Meta: "unknown_user;failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
			return "", model.User{}, failErr
		}
		return "", model.User{}, err
	}
	if !crypto.VerifyPassword(password, u.PasswordHash) {
		fc, lu, _ := s.store.RegisterLoginFailure(ctx, username)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.failed", Target: "user", Meta: "bad_password;failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
		return "", model.User{}, failErr
	}
	if ok, detail := s.isSourceAllowedForUser(u, source); !ok {
		fc, lu, _ := s.store.RegisterLoginFailure(ctx, username)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: username, Action: "auth.login.failed", Target: "user", Meta: "ip_policy_denied;" + detail + ";failures=" + strconv.Itoa(fc) + ";lock_until=" + lu.Format(time.RFC3339) + ";source=" + source})
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
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{Actor: u.Username, Action: "auth.login.success", Target: "session", Meta: "password;source=" + source})
	return sid, u, nil
}

func (s *Service) ResolveIdentity(r *http.Request) (Identity, error) {
	source := requestIP(r)
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
		return true, "ip_check_disabled=1"
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
	source := requestIP(r)
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

func requestIP(r *http.Request) string {
	if cfip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfip != "" {
		return cfip
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if p := strings.TrimSpace(strings.Split(xff, ",")[0]); p != "" {
			return p
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
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
