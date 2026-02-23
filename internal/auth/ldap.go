package auth

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
	ldap "github.com/go-ldap/ldap/v3"
)

type ldapRuntimeConfig struct {
	Enabled              bool    `json:"enabled"`
	URL                  string  `json:"url"`
	StartTLS             bool    `json:"startTls"`
	InsecureSkipVerify   bool    `json:"insecureSkipVerify"`
	BindDN               string  `json:"bindDn"`
	UserBaseDN           string  `json:"userBaseDn"`
	GroupBaseDN          string  `json:"groupBaseDn"`
	UserAttr             string  `json:"userAttr"`
	AdminGroup           string  `json:"adminGroup"`
	DomainAdminGroup     string  `json:"domainAdminGroup"`
	ReadOnlyGroup        string  `json:"readOnlyGroup"`
	DomainAdminDomainIDs []int64 `json:"domainAdminDomainIds"`
}

func normalizeLDAPConfig(in ldapRuntimeConfig) ldapRuntimeConfig {
	out := in
	out.URL = strings.TrimSpace(out.URL)
	out.BindDN = strings.TrimSpace(out.BindDN)
	out.UserBaseDN = strings.TrimSpace(out.UserBaseDN)
	out.GroupBaseDN = strings.TrimSpace(out.GroupBaseDN)
	out.UserAttr = strings.TrimSpace(out.UserAttr)
	if out.UserAttr == "" {
		out.UserAttr = "uid"
	}
	out.AdminGroup = strings.TrimSpace(out.AdminGroup)
	out.DomainAdminGroup = strings.TrimSpace(out.DomainAdminGroup)
	out.ReadOnlyGroup = strings.TrimSpace(out.ReadOnlyGroup)
	return out
}

func (s *Service) loadLDAPConfig(ctx context.Context) (ldapRuntimeConfig, string, error) {
	raw, err := s.store.GetSetting(ctx, "auth.ldap.config")
	if err != nil {
		if err == sql.ErrNoRows {
			return ldapRuntimeConfig{}, "", nil
		}
		return ldapRuntimeConfig{}, "", err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ldapRuntimeConfig{}, "", nil
	}
	var cfg ldapRuntimeConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return ldapRuntimeConfig{}, "", fmt.Errorf("invalid ldap config json")
	}
	cfg = normalizeLDAPConfig(cfg)
	if !cfg.Enabled {
		return cfg, "", nil
	}
	enc, err := s.store.GetSecret(ctx, "auth.ldap.bind_password")
	if err != nil {
		if err == sql.ErrNoRows {
			return ldapRuntimeConfig{}, "", fmt.Errorf("ldap bind password missing")
		}
		return ldapRuntimeConfig{}, "", err
	}
	dec, err := s.keystore.Decrypt(enc)
	if err != nil {
		return ldapRuntimeConfig{}, "", fmt.Errorf("ldap bind password decrypt failed")
	}
	return cfg, dec, nil
}

func (s *Service) tryLDAPLogin(ctx context.Context, loginUsername, password string) (model.User, string, error) {
	cfg, bindPassword, err := s.loadLDAPConfig(ctx)
	if err != nil {
		return model.User{}, "config_error", err
	}
	if !cfg.Enabled {
		return model.User{}, "ldap_disabled", fmt.Errorf("ldap disabled")
	}
	role, domainIDs, sourceUsername, detail, err := ldapAuthenticate(ctx, cfg, bindPassword, loginUsername, password)
	if err != nil {
		return model.User{}, detail, err
	}
	if role == model.RoleDomainAdmin && len(domainIDs) == 0 {
		all, derr := s.store.ListDomainIDs(ctx)
		if derr == nil {
			domainIDs = all
		}
	}
	provisioned, err := s.store.UpsertExternalUser(ctx, strings.ToLower(strings.TrimSpace(sourceUsername)), role, domainIDs, "ldap", s.dummyPasswordHash)
	if err != nil {
		return model.User{}, "shadow_upsert_failed", err
	}
	return provisioned, detail, nil
}

func ldapAuthenticate(ctx context.Context, cfg ldapRuntimeConfig, bindPassword, loginUsername, loginPassword string) (model.Role, []int64, string, string, error) {
	_ = ctx
	if strings.TrimSpace(loginUsername) == "" || strings.TrimSpace(loginPassword) == "" {
		return "", nil, "", "missing_credentials", fmt.Errorf("missing credentials")
	}
	if strings.TrimSpace(cfg.URL) == "" || strings.TrimSpace(cfg.BindDN) == "" || strings.TrimSpace(cfg.UserBaseDN) == "" || strings.TrimSpace(cfg.GroupBaseDN) == "" {
		return "", nil, "", "config_incomplete", fmt.Errorf("ldap config incomplete")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return "", nil, "", "bad_url", err
	}
	if u.Scheme == "" {
		cfg.URL = "ldaps://" + cfg.URL
	}
	dialOpts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second})}
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://") {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}))
	}
	conn, err := ldap.DialURL(cfg.URL, dialOpts...)
	if err != nil {
		return "", nil, "", "dial_failed", err
	}
	defer conn.Close()
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldap://") && cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}); err != nil {
			return "", nil, "", "starttls_failed", err
		}
	}
	if err := conn.Bind(cfg.BindDN, bindPassword); err != nil {
		return "", nil, "", "bind_failed", err
	}

	loginUsername = strings.TrimSpace(loginUsername)
	candidates := []string{loginUsername}
	if low := strings.ToLower(loginUsername); low != loginUsername {
		candidates = append(candidates, low)
	}
	var userDN, matchedUsername string
	for _, cand := range candidates {
		filter := fmt.Sprintf("(%s=%s)", cfg.UserAttr, ldap.EscapeFilter(cand))
		req := ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{"dn", cfg.UserAttr}, nil)
		res, err := conn.Search(req)
		if err != nil || len(res.Entries) == 0 {
			continue
		}
		userDN = res.Entries[0].DN
		matchedUsername = strings.TrimSpace(res.Entries[0].GetAttributeValue(cfg.UserAttr))
		if matchedUsername == "" {
			matchedUsername = cand
		}
		break
	}
	if userDN == "" {
		return "", nil, "", "user_not_found", fmt.Errorf("user not found")
	}
	if err := conn.Bind(userDN, loginPassword); err != nil {
		if isLDAPAccountLocked(err) {
			return "", nil, "", "account_locked", err
		}
		return "", nil, "", "bad_password", err
	}
	if err := conn.Bind(cfg.BindDN, bindPassword); err != nil {
		return "", nil, "", "rebind_failed", err
	}

	groupFilter := fmt.Sprintf("(|(memberUid=%s)(member=%s)(uniqueMember=%s))", ldap.EscapeFilter(matchedUsername), ldap.EscapeFilter(userDN), ldap.EscapeFilter(userDN))
	grpReq := ldap.NewSearchRequest(cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false, groupFilter, []string{"cn"}, nil)
	grpRes, err := conn.Search(grpReq)
	if err != nil {
		return "", nil, "", "group_search_failed", err
	}
	groupSet := map[string]bool{}
	for _, e := range grpRes.Entries {
		for _, cn := range e.GetAttributeValues("cn") {
			cn = strings.ToLower(strings.TrimSpace(cn))
			if cn != "" {
				groupSet[cn] = true
			}
		}
	}
	adminGroup := strings.ToLower(strings.TrimSpace(cfg.AdminGroup))
	domAdminGroup := strings.ToLower(strings.TrimSpace(cfg.DomainAdminGroup))
	readOnlyGroup := strings.ToLower(strings.TrimSpace(cfg.ReadOnlyGroup))

	role := model.Role("")
	switch {
	case adminGroup != "" && groupSet[adminGroup]:
		role = model.RoleAdmin
	case domAdminGroup != "" && groupSet[domAdminGroup]:
		role = model.RoleDomainAdmin
	case readOnlyGroup != "" && groupSet[readOnlyGroup]:
		role = model.RoleReadOnly
	default:
		return "", nil, "", "group_mapping_missing", fmt.Errorf("no mapped ldap group")
	}

	domainIDs := append([]int64(nil), cfg.DomainAdminDomainIDs...)
	sort.Slice(domainIDs, func(i, j int) bool { return domainIDs[i] < domainIDs[j] })
	if role == model.RoleDomainAdmin && len(domainIDs) == 0 {
		detail := "role=domain-admin;source=ldap;domains=all"
		return role, domainIDs, matchedUsername, detail, nil
	}
	detail := "role=" + string(role) + ";source=ldap;domains=" + strconv.Itoa(len(domainIDs))
	return role, domainIDs, matchedUsername, detail, nil
}

func isLDAPAccountLocked(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "account locked") || strings.Contains(msg, "data 775") {
		return true
	}
	return false
}
