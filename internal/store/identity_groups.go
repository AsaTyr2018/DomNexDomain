package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

func (s *Store) ListPermissionGroups(ctx context.Context) ([]model.PermissionGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, description, template_name, is_system, created_at, updated_at
FROM permission_groups
ORDER BY is_system DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.PermissionGroup, 0, 16)
	for rows.Next() {
		var g model.PermissionGroup
		var system int
		var created, updated string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Template, &system, &created, &updated); err != nil {
			return nil, err
		}
		g.System = system != 0
		g.CreatedAt = parseTimeOrZero(created)
		g.UpdatedAt = parseTimeOrZero(updated)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CreatePermissionGroup(ctx context.Context, name, description, template string, system bool, permissions []string) (model.PermissionGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return model.PermissionGroup{}, fmt.Errorf("group name required")
	}
	perms := dedupPerms(permissions)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.PermissionGroup{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
INSERT INTO permission_groups(name, description, template_name, is_system, created_at, updated_at)
VALUES(?,?,?,?,?,?)`,
		name,
		strings.TrimSpace(description),
		strings.TrimSpace(template),
		boolToInt(system),
		now,
		now,
	)
	if err != nil {
		return model.PermissionGroup{}, err
	}
	groupID, _ := res.LastInsertId()
	for _, p := range perms {
		if _, err := tx.ExecContext(ctx, `INSERT INTO permission_group_entries(group_id, permission, created_at) VALUES(?,?,?)`, groupID, p, now); err != nil {
			return model.PermissionGroup{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.PermissionGroup{}, err
	}
	var g model.PermissionGroup
	var created, updated string
	var systemFlag int
	if err := s.db.QueryRowContext(ctx, `
SELECT id, name, description, template_name, is_system, created_at, updated_at
FROM permission_groups WHERE id=?`, groupID).
		Scan(&g.ID, &g.Name, &g.Description, &g.Template, &systemFlag, &created, &updated); err != nil {
		return model.PermissionGroup{}, err
	}
	g.System = systemFlag != 0
	g.CreatedAt = parseTimeOrZero(created)
	g.UpdatedAt = parseTimeOrZero(updated)
	return g, nil
}

func (s *Store) UpdatePermissionGroup(ctx context.Context, groupID int64, name, description, template string, permissions []string) error {
	if groupID <= 0 {
		return fmt.Errorf("invalid group id")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("group name required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var isSystem int
	if err := tx.QueryRowContext(ctx, `SELECT is_system FROM permission_groups WHERE id=?`, groupID).Scan(&isSystem); err != nil {
		return err
	}
	if isSystem != 0 {
		return fmt.Errorf("system group is immutable")
	}
	res, err := tx.ExecContext(ctx, `
UPDATE permission_groups
SET name=?, description=?, template_name=?, updated_at=?
WHERE id=?`,
		name,
		strings.TrimSpace(description),
		strings.TrimSpace(template),
		now,
		groupID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permission_group_entries WHERE group_id=?`, groupID); err != nil {
		return err
	}
	for _, p := range dedupPerms(permissions) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO permission_group_entries(group_id, permission, created_at) VALUES(?,?,?)`, groupID, p, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeletePermissionGroup(ctx context.Context, groupID int64) error {
	if groupID <= 0 {
		return fmt.Errorf("invalid group id")
	}
	var isSystem int
	if err := s.db.QueryRowContext(ctx, `SELECT is_system FROM permission_groups WHERE id=?`, groupID).Scan(&isSystem); err != nil {
		return err
	}
	if isSystem != 0 {
		return fmt.Errorf("system group cannot be deleted")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM permission_groups WHERE id=?`, groupID)
	return err
}

func (s *Store) ListPermissionGroupPermissions(ctx context.Context, groupID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT permission FROM permission_group_entries WHERE group_id=? ORDER BY permission`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 32)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

func (s *Store) SetUserGroupMemberships(ctx context.Context, userID int64, groupIDsOrdered []int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user id")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_group_memberships WHERE user_id=?`, userID); err != nil {
		return err
	}
	dedup := make([]int64, 0, len(groupIDsOrdered))
	seen := map[int64]bool{}
	for _, gid := range groupIDsOrdered {
		if gid <= 0 || seen[gid] {
			continue
		}
		seen[gid] = true
		dedup = append(dedup, gid)
	}
	for idx, gid := range dedup {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO user_group_memberships(user_id, group_id, priority, created_at, updated_at)
VALUES(?,?,?,?,?)`,
			userID,
			gid,
			idx+1,
			now,
			now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListUserGroupMemberships(ctx context.Context, userID int64) ([]model.UserGroupMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT m.user_id, m.group_id, m.priority, m.created_at, m.updated_at, g.name, g.is_system
FROM user_group_memberships m
JOIN permission_groups g ON g.id=m.group_id
WHERE m.user_id=?
ORDER BY m.priority ASC, m.group_id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.UserGroupMembership, 0, 8)
	for rows.Next() {
		var m model.UserGroupMembership
		var created, updated string
		var system int
		if err := rows.Scan(&m.UserID, &m.GroupID, &m.Priority, &created, &updated, &m.GroupName, &system); err != nil {
			return nil, err
		}
		m.CreatedAt = parseTimeOrZero(created)
		m.UpdatedAt = parseTimeOrZero(updated)
		m.IsTemplate = system != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) ListUsersGroupMemberships(ctx context.Context) (map[int64][]model.UserGroupMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT m.user_id, m.group_id, m.priority, m.created_at, m.updated_at, g.name, g.is_system
FROM user_group_memberships m
JOIN permission_groups g ON g.id=m.group_id
ORDER BY m.user_id ASC, m.priority ASC, m.group_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]model.UserGroupMembership{}
	for rows.Next() {
		var m model.UserGroupMembership
		var created, updated string
		var system int
		if err := rows.Scan(&m.UserID, &m.GroupID, &m.Priority, &created, &updated, &m.GroupName, &system); err != nil {
			return nil, err
		}
		m.CreatedAt = parseTimeOrZero(created)
		m.UpdatedAt = parseTimeOrZero(updated)
		m.IsTemplate = system != 0
		out[m.UserID] = append(out[m.UserID], m)
	}
	return out, rows.Err()
}

func dedupPerms(perms []string) []string {
	out := make([]string, 0, len(perms))
	seen := map[string]bool{}
	for _, p := range perms {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
