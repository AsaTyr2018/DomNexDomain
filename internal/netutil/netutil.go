package netutil

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", c)
		}
		out = append(out, n)
	}
	return out, nil
}

func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		if ip := parseCandidateIP(host); ip != "" {
			return ip
		}
	}
	return parseCandidateIP(strings.TrimSpace(r.RemoteAddr))
}

func IsTrustedProxy(r *http.Request, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	ip := net.ParseIP(RemoteIP(r))
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	if IsTrustedProxy(r, trusted) {
		if cfip := parseCandidateIP(r.Header.Get("CF-Connecting-IP")); cfip != "" {
			return cfip
		}
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			for _, part := range strings.Split(xff, ",") {
				if ip := parseCandidateIP(part); ip != "" {
					return ip
				}
			}
		}
		if xrip := parseCandidateIP(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	return RemoteIP(r)
}

func CountryFromHeaders(r *http.Request, trusted []*net.IPNet) string {
	if !IsTrustedProxy(r, trusted) {
		return ""
	}
	candidates := []string{
		r.Header.Get("CF-IPCountry"),
		r.Header.Get("X-Country-Code"),
		r.Header.Get("X-Appengine-Country"),
	}
	for _, c := range candidates {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(cc) == 2 && cc != "XX" && cc != "T1" {
			return cc
		}
	}
	return ""
}

func parseCandidateIP(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "[") && strings.Contains(raw, "]") {
		raw = strings.TrimPrefix(raw, "[")
		if idx := strings.Index(raw, "]"); idx >= 0 {
			raw = raw[:idx]
		}
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
			return ip.String()
		}
	}
	return ""
}
