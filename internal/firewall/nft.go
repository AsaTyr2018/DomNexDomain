package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type NftEnforcer struct {
	table   string
	chain   string
	set4    string
	ruleTag string
}

func NewNftEnforcer() *NftEnforcer {
	return &NftEnforcer{
		table:   "domnex",
		chain:   "domnex_input",
		set4:    "domnex_blocked_v4",
		ruleTag: "domnex_ti_drop_v4",
	}
}

func (n *NftEnforcer) Ensure(ctx context.Context) error {
	if err := n.run(ctx, "add", "table", "inet", n.table); err != nil && !isAlreadyExists(err) {
		return err
	}
	if err := n.run(ctx, "add", "set", "inet", n.table, n.set4, "{", "type", "ipv4_addr", ";", "}"); err != nil && !isAlreadyExists(err) {
		return err
	}
	if err := n.run(ctx, "add", "chain", "inet", n.table, n.chain, "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"); err != nil && !isAlreadyExists(err) {
		return err
	}
	out, err := n.output(ctx, "list", "chain", "inet", n.table, n.chain)
	if err != nil {
		return err
	}
	if !strings.Contains(out, n.ruleTag) {
		if err := n.run(ctx, "add", "rule", "inet", n.table, n.chain, "ip", "saddr", "@"+n.set4, "tcp", "dport", "{", "80,", "443,", "2222", "}", "drop", "comment", n.ruleTag); err != nil {
			return err
		}
	}
	return nil
}

func (n *NftEnforcer) Disable(ctx context.Context) error {
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set4); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (n *NftEnforcer) ReplaceIPv4(ctx context.Context, ips []string) error {
	if err := n.Ensure(ctx); err != nil {
		return err
	}
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set4); err != nil {
		return err
	}
	if len(ips) == 0 {
		return nil
	}
	const chunk = 200
	for i := 0; i < len(ips); i += chunk {
		end := i + chunk
		if end > len(ips) {
			end = len(ips)
		}
		part := strings.Join(ips[i:end], ", ")
		if err := n.run(ctx, "add", "element", "inet", n.table, n.set4, "{", part, "}"); err != nil {
			return err
		}
	}
	return nil
}

func (n *NftEnforcer) run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft %s failed: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func (n *NftEnforcer) output(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("nft %s failed: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file or directory") || strings.Contains(s, "not found")
}
