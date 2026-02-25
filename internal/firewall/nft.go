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
	set6    string
	ruleTag string
	rule6   string
}

func NewNftEnforcer() *NftEnforcer {
	return &NftEnforcer{
		table:   "domnex",
		chain:   "domnex_input",
		set4:    "domnex_blocked_v4",
		set6:    "domnex_blocked_v6",
		ruleTag: "domnex_ti_drop_v4",
		rule6:   "domnex_ti_drop_v6",
	}
}

func (n *NftEnforcer) Ensure(ctx context.Context) error {
	if err := n.run(ctx, "add", "table", "inet", n.table); err != nil && !isAlreadyExists(err) {
		return err
	}
	if err := n.run(ctx, "add", "set", "inet", n.table, n.set4, "{", "type", "ipv4_addr", ";", "}"); err != nil && !isAlreadyExists(err) {
		return err
	}
	if err := n.run(ctx, "add", "set", "inet", n.table, n.set6, "{", "type", "ipv6_addr", ";", "}"); err != nil && !isAlreadyExists(err) {
		return err
	}
	// Keep DomNex drop chain ahead of distro firewalls (UFW/iptables-nft) so blocked sources
	// are dropped before generic allow rules can accept traffic to 80/443/2222.
	if err := n.ensureInputChainPriority(ctx); err != nil {
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
	if !strings.Contains(out, n.rule6) {
		if err := n.run(ctx, "add", "rule", "inet", n.table, n.chain, "ip6", "saddr", "@"+n.set6, "tcp", "dport", "{", "80,", "443,", "2222", "}", "drop", "comment", n.rule6); err != nil {
			return err
		}
	}
	return nil
}

func (n *NftEnforcer) ensureInputChainPriority(ctx context.Context) error {
	// Desired priority is -300 (raw-like), earlier than UFW filter(0).
	const desired = "-300"
	out, err := n.output(ctx, "list", "chain", "inet", n.table, n.chain)
	if err != nil {
		if isNotFound(err) {
			return n.run(ctx, "add", "chain", "inet", n.table, n.chain, "{", "type", "filter", "hook", "input", "priority", desired, ";", "policy", "accept", ";", "}")
		}
		return err
	}
	if strings.Contains(out, "priority -300") || strings.Contains(out, "priority raw") {
		return nil
	}
	_ = n.run(ctx, "flush", "chain", "inet", n.table, n.chain)
	_ = n.run(ctx, "delete", "chain", "inet", n.table, n.chain)
	return n.run(ctx, "add", "chain", "inet", n.table, n.chain, "{", "type", "filter", "hook", "input", "priority", desired, ";", "policy", "accept", ";", "}")
}

func (n *NftEnforcer) Disable(ctx context.Context) error {
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set4); err != nil && !isNotFound(err) {
		return err
	}
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set6); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (n *NftEnforcer) Replace(ctx context.Context, ipv4, ipv6 []string) error {
	if err := n.Ensure(ctx); err != nil {
		return err
	}
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set4); err != nil {
		return err
	}
	if err := n.run(ctx, "flush", "set", "inet", n.table, n.set6); err != nil {
		return err
	}
	const chunk = 200
	for i := 0; i < len(ipv4); i += chunk {
		end := i + chunk
		if end > len(ipv4) {
			end = len(ipv4)
		}
		part := strings.Join(ipv4[i:end], ", ")
		if err := n.run(ctx, "add", "element", "inet", n.table, n.set4, "{", part, "}"); err != nil {
			return err
		}
	}
	for i := 0; i < len(ipv6); i += chunk {
		end := i + chunk
		if end > len(ipv6) {
			end = len(ipv6)
		}
		part := strings.Join(ipv6[i:end], ", ")
		if err := n.run(ctx, "add", "element", "inet", n.table, n.set6, "{", part, "}"); err != nil {
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
