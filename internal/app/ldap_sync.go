package app

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

func (s *Service) StartLDAPUserSync(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	run := func() {
		if err := s.syncLDAPUsersOnce(ctx); err != nil {
			s.log.Warn("ldap user sync failed", map[string]any{"err": err.Error()})
		}
	}

	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Service) syncLDAPUsersOnce(ctx context.Context) error {
	cfg := s.getLDAPSettings(ctx)
	if !cfg.Enabled {
		return nil
	}
	bindPassword, err := s.loadLDAPBindPassword(ctx)
	if err != nil {
		return err
	}
	conn, err := dialLDAPConnection(cfg, bindPassword)
	if err != nil {
		return err
	}
	defer conn.Close()

	remoteUsers, err := listLDAPMappedUsers(conn, cfg)
	if err != nil {
		return err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}

	localLDAP := map[string]model.User{}
	for _, u := range users {
		if !strings.EqualFold(strings.TrimSpace(u.AuthProvider), "ldap") {
			continue
		}
		un := strings.ToLower(strings.TrimSpace(u.Username))
		if un == "" {
			continue
		}
		localLDAP[un] = u
	}

	shadowRemoved := 0
	for un, u := range localLDAP {
		if remoteUsers[un] {
			continue
		}
		if err := s.store.DeleteUser(ctx, u.ID); err != nil {
			s.log.Warn("ldap sync shadow delete failed", map[string]any{"username": un, "err": err.Error()})
			continue
		}
		shadowRemoved++
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
			Actor:  "system",
			Action: "auth.ldap.sync.shadow_removed",
			Target: un,
			Meta:   "reason=missing_in_ldap",
		})
	}

	queued, err := s.store.ListLDAPDeleteQueue(ctx, 2000)
	if err != nil {
		return err
	}
	remoteDeleted := 0
	for _, un := range queued {
		dn, found, ferr := findLDAPUserDN(conn, cfg, un)
		if ferr != nil {
			_ = s.store.SetLDAPDeleteQueueError(ctx, un, ferr.Error())
			continue
		}
		if !found {
			_ = s.store.RemoveLDAPDeleteQueue(ctx, un)
			_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
				Actor:  "system",
				Action: "auth.ldap.sync.remote_delete_skipped",
				Target: un,
				Meta:   "reason=not_found",
			})
			continue
		}
		if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			_ = s.store.SetLDAPDeleteQueueError(ctx, un, err.Error())
			continue
		}
		remoteDeleted++
		_ = s.store.RemoveLDAPDeleteQueue(ctx, un)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
			Actor:  "system",
			Action: "auth.ldap.sync.remote_deleted",
			Target: un,
			Meta:   "dn=" + dn,
		})
	}

	if shadowRemoved > 0 || remoteDeleted > 0 {
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
			Actor:  "system",
			Action: "auth.ldap.sync.summary",
			Target: "ldap",
			Meta:   fmt.Sprintf("shadow_removed=%d;remote_deleted=%d", shadowRemoved, remoteDeleted),
		})
	}
	return nil
}

func (s *Service) loadLDAPBindPassword(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, "auth.ldap.bind_password")
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("ldap bind password missing")
		}
		return "", err
	}
	dec, err := s.keystore.Decrypt(enc)
	if err != nil {
		return "", fmt.Errorf("ldap bind password decrypt failed")
	}
	return dec, nil
}

func dialLDAPConnection(cfg LDAPSettings, bindPassword string) (*ldap.Conn, error) {
	rawURL := strings.TrimSpace(cfg.URL)
	if rawURL == "" {
		return nil, fmt.Errorf("ldap url missing")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		rawURL = "ldaps://" + rawURL
	}
	dialOpts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second})}
	if strings.HasPrefix(strings.ToLower(rawURL), "ldaps://") {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}))
	}
	conn, err := ldap.DialURL(rawURL, dialOpts...)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.ToLower(rawURL), "ldap://") && cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := conn.Bind(strings.TrimSpace(cfg.BindDN), bindPassword); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func listLDAPMappedUsers(conn *ldap.Conn, cfg LDAPSettings) (map[string]bool, error) {
	groups := dedupLower([]string{cfg.AdminGroup, cfg.DomainAdminGroup, cfg.ReadOnlyGroup})
	out := map[string]bool{}
	for _, g := range groups {
		req := ldap.NewSearchRequest(
			strings.TrimSpace(cfg.GroupBaseDN),
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			8,
			false,
			fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(g)),
			[]string{"memberUid", "member", "uniqueMember"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			return nil, err
		}
		for _, e := range res.Entries {
			for _, uid := range e.GetAttributeValues("memberUid") {
				uid = strings.ToLower(strings.TrimSpace(uid))
				if uid != "" {
					out[uid] = true
				}
			}
			for _, dn := range append(e.GetAttributeValues("member"), e.GetAttributeValues("uniqueMember")...) {
				if un, ok := resolveUsernameFromDN(conn, cfg, dn); ok {
					out[un] = true
				}
			}
		}
	}
	return out, nil
}

func resolveUsernameFromDN(conn *ldap.Conn, cfg LDAPSettings, dn string) (string, bool) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return "", false
	}
	attrs := []string{strings.TrimSpace(cfg.UserAttr), "uid", "sAMAccountName", "cn"}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", attrs, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return "", false
	}
	e := res.Entries[0]
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(e.GetAttributeValue(a)))
		if v != "" {
			return v, true
		}
	}
	return "", false
}

func findLDAPUserDN(conn *ldap.Conn, cfg LDAPSettings, username string) (string, bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", false, nil
	}
	attr := strings.TrimSpace(cfg.UserAttr)
	if attr == "" {
		attr = "uid"
	}
	req := ldap.NewSearchRequest(
		strings.TrimSpace(cfg.UserBaseDN),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		8,
		false,
		fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", false, err
	}
	if len(res.Entries) == 0 {
		return "", false, nil
	}
	return strings.TrimSpace(res.Entries[0].DN), true, nil
}

func dedupLower(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
