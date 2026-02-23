package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

type PermissionCatalogItem struct {
	Key         string `json:"key"`
	Category    string `json:"category"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Critical    bool   `json:"critical"`
}

type PermissionGroupView struct {
	Group       model.PermissionGroup `json:"group"`
	Permissions []string              `json:"permissions"`
	UserCount   int                   `json:"userCount"`
}

type PermissionMatrixRow struct {
	Permission string   `json:"permission"`
	Category   string   `json:"category"`
	Label      string   `json:"label"`
	Critical   bool     `json:"critical"`
	GroupCount int      `json:"groupCount"`
	UserCount  int      `json:"userCount"`
	Groups     []string `json:"groups"`
	Users      []string `json:"users"`
}

var permissionCatalog = []PermissionCatalogItem{
	{Key: "system:read", Category: "system", Label: "System Read", Description: "Read system runtime state"},
	{Key: "system:reload", Category: "system", Label: "System Reload", Description: "Trigger service reload", Critical: true},
	{Key: "domains:read", Category: "domains", Label: "Domains Read", Description: "Read domain inventory"},
	{Key: "domains:create", Category: "domains", Label: "Domains Create", Description: "Create or onboard domains"},
	{Key: "domains:update", Category: "domains", Label: "Domains Update", Description: "Modify domain settings"},
	{Key: "domains:delete", Category: "domains", Label: "Domains Delete", Description: "Delete domains", Critical: true},
	{Key: "hosts:read", Category: "subdomains", Label: "Subdomains Read", Description: "Read subdomain routing"},
	{Key: "hosts:write", Category: "subdomains", Label: "Subdomains Write", Description: "Create/update subdomains"},
	{Key: "hosts:delete", Category: "subdomains", Label: "Subdomains Delete", Description: "Delete subdomains", Critical: true},
	{Key: "users:read", Category: "identity", Label: "Users Read", Description: "View users and access policy"},
	{Key: "users:write", Category: "identity", Label: "Users Write", Description: "Create/edit/delete users", Critical: true},
	{Key: "groups:read", Category: "identity", Label: "Groups Read", Description: "View permission groups"},
	{Key: "groups:write", Category: "identity", Label: "Groups Write", Description: "Create/edit/delete permission groups", Critical: true},
	{Key: "settings:read", Category: "settings", Label: "Settings Read", Description: "Read runtime settings"},
	{Key: "settings:write", Category: "settings", Label: "Settings Write", Description: "Modify runtime settings", Critical: true},
	{Key: "tokens:read", Category: "api", Label: "API Tokens Read", Description: "View API tokens"},
	{Key: "tokens:write", Category: "api", Label: "API Tokens Write", Description: "Create/revoke API tokens", Critical: true},
	{Key: "logs:read", Category: "observability", Label: "Logs Read", Description: "View audit/log center"},
	{Key: "logs:export", Category: "observability", Label: "Logs Export", Description: "Export operational logs"},
	{Key: "threatintel:read", Category: "security", Label: "Threat Intel Read", Description: "View threat intel pages"},
	{Key: "threatintel:write", Category: "security", Label: "Threat Intel Write", Description: "Modify threat intel policy/feeds", Critical: true},
	{Key: "security:block_ip", Category: "security", Label: "Security Block IP", Description: "Block/unblock IP entries", Critical: true},
	{Key: "backup:read", Category: "operations", Label: "Backup Read", Description: "View backup center"},
	{Key: "backup:write", Category: "operations", Label: "Backup Write", Description: "Create/restore backups", Critical: true},
	{Key: "ssh:read", Category: "edge", Label: "SSH Bastion Read", Description: "View SSH bastion routes/keys"},
	{Key: "ssh:write", Category: "edge", Label: "SSH Bastion Write", Description: "Manage SSH bastion routes/keys", Critical: true},
}

var permissionTemplates = []struct {
	Name        string
	Template    string
	Description string
	Permissions []string
}{
	{
		Name:        "Platform Admin",
		Template:    "platform-admin",
		Description: "Full platform control baseline template.",
		Permissions: allPermissionKeys(),
	},
	{
		Name:        "Security Admin",
		Template:    "security-admin",
		Description: "Security operations without full platform ownership.",
		Permissions: []string{"logs:read", "logs:export", "threatintel:read", "threatintel:write", "security:block_ip", "settings:read", "tokens:read"},
	},
	{
		Name:        "Domain Operator",
		Template:    "domain-operator",
		Description: "Domain and subdomain operations.",
		Permissions: []string{"domains:read", "domains:create", "domains:update", "hosts:read", "hosts:write", "logs:read", "settings:read"},
	},
	{
		Name:        "Auditor",
		Template:    "auditor",
		Description: "Read and export focused operations.",
		Permissions: []string{"domains:read", "hosts:read", "users:read", "groups:read", "logs:read", "logs:export", "threatintel:read", "settings:read", "backup:read", "tokens:read"},
	},
}

func allPermissionKeys() []string {
	out := make([]string, 0, len(permissionCatalog))
	for _, p := range permissionCatalog {
		out = append(out, p.Key)
	}
	return out
}

func (s *Service) EnsureIdentityTemplates(ctx context.Context) error {
	groups, err := s.store.ListPermissionGroups(ctx)
	if err != nil {
		return err
	}
	byTemplate := map[string]bool{}
	for _, g := range groups {
		byTemplate[strings.ToLower(strings.TrimSpace(g.Template))] = true
	}
	for _, t := range permissionTemplates {
		if byTemplate[strings.ToLower(t.Template)] {
			continue
		}
		if _, err := s.store.CreatePermissionGroup(ctx, t.Name, t.Description, t.Template, true, t.Permissions); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) PermissionCatalog() []PermissionCatalogItem {
	out := make([]PermissionCatalogItem, len(permissionCatalog))
	copy(out, permissionCatalog)
	return out
}

func (s *Service) ListPermissionGroups(ctx context.Context) ([]PermissionGroupView, error) {
	if err := s.EnsureIdentityTemplates(ctx); err != nil {
		return nil, err
	}
	groups, err := s.store.ListPermissionGroups(ctx)
	if err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	membership, err := s.store.ListUsersGroupMemberships(ctx)
	if err != nil {
		return nil, err
	}
	userCountByGroup := map[int64]int{}
	for _, u := range users {
		for _, m := range membership[u.ID] {
			userCountByGroup[m.GroupID]++
		}
	}
	out := make([]PermissionGroupView, 0, len(groups))
	for _, g := range groups {
		perms, _ := s.store.ListPermissionGroupPermissions(ctx, g.ID)
		out = append(out, PermissionGroupView{
			Group:       g,
			Permissions: perms,
			UserCount:   userCountByGroup[g.ID],
		})
	}
	return out, nil
}

func (s *Service) CreatePermissionGroup(ctx context.Context, name, description, template string, permissions []string) (PermissionGroupView, error) {
	normPerms, err := normalizePermissions(permissions)
	if err != nil {
		return PermissionGroupView{}, err
	}
	g, err := s.store.CreatePermissionGroup(ctx, name, description, template, false, normPerms)
	if err != nil {
		return PermissionGroupView{}, err
	}
	perms, _ := s.store.ListPermissionGroupPermissions(ctx, g.ID)
	return PermissionGroupView{Group: g, Permissions: perms, UserCount: 0}, nil
}

func (s *Service) UpdatePermissionGroup(ctx context.Context, groupID int64, name, description, template string, permissions []string) error {
	normPerms, err := normalizePermissions(permissions)
	if err != nil {
		return err
	}
	return s.store.UpdatePermissionGroup(ctx, groupID, name, description, template, normPerms)
}

func (s *Service) DeletePermissionGroup(ctx context.Context, groupID int64) error {
	return s.store.DeletePermissionGroup(ctx, groupID)
}

func (s *Service) SetManagedUserGroups(ctx context.Context, userID int64, groupIDs []int64) error {
	return s.store.SetUserGroupMemberships(ctx, userID, groupIDs)
}

func (s *Service) BuildPermissionMatrix(ctx context.Context) ([]PermissionMatrixRow, error) {
	if err := s.EnsureIdentityTemplates(ctx); err != nil {
		return nil, err
	}
	catalog := s.PermissionCatalog()
	groups, err := s.store.ListPermissionGroups(ctx)
	if err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	userMembership, err := s.store.ListUsersGroupMemberships(ctx)
	if err != nil {
		return nil, err
	}
	groupPerms := map[int64]map[string]bool{}
	for _, g := range groups {
		perms, _ := s.store.ListPermissionGroupPermissions(ctx, g.ID)
		set := map[string]bool{}
		for _, p := range perms {
			set[p] = true
		}
		groupPerms[g.ID] = set
	}
	rows := make([]PermissionMatrixRow, 0, len(catalog))
	for _, c := range catalog {
		row := PermissionMatrixRow{
			Permission: c.Key,
			Category:   c.Category,
			Label:      c.Label,
			Critical:   c.Critical,
		}
		for _, g := range groups {
			if groupPerms[g.ID][c.Key] {
				row.GroupCount++
				row.Groups = append(row.Groups, g.Name)
			}
		}
		for _, u := range users {
			mm := userMembership[u.ID]
			for _, m := range mm {
				if groupPerms[m.GroupID][c.Key] {
					row.UserCount++
					row.Users = append(row.Users, u.Username)
					break
				}
			}
		}
		sort.Strings(row.Groups)
		sort.Strings(row.Users)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category == rows[j].Category {
			return rows[i].Permission < rows[j].Permission
		}
		return rows[i].Category < rows[j].Category
	})
	return rows, nil
}

func normalizePermissions(perms []string) ([]string, error) {
	valid := map[string]bool{}
	for _, item := range permissionCatalog {
		valid[item.Key] = true
	}
	out := make([]string, 0, len(perms))
	seen := map[string]bool{}
	for _, p := range perms {
		key := strings.ToLower(strings.TrimSpace(p))
		if key == "" || seen[key] {
			continue
		}
		if !valid[key] {
			return nil, fmt.Errorf("unknown permission: %s", key)
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}
