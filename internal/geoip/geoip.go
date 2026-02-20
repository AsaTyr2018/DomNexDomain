package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Resolver struct {
	mu    sync.RWMutex
	cache map[string]cacheItem
	http  *http.Client
	ttl   time.Duration
}

type cacheItem struct {
	country string
	expires time.Time
}

func New(ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Resolver{
		cache: map[string]cacheItem{},
		http:  &http.Client{Timeout: 1200 * time.Millisecond},
		ttl:   ttl,
	}
}

func (r *Resolver) CountryCode(ctx context.Context, ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "ZZ"
	}
	if isPrivateIP(parsed) {
		return "LOCAL"
	}
	ip = parsed.String()
	now := time.Now()

	r.mu.RLock()
	cached, ok := r.cache[ip]
	r.mu.RUnlock()
	if ok && now.Before(cached.expires) {
		return cached.country
	}

	country := r.lookupCountryCode(ctx, ip)
	if country == "" {
		country = "ZZ"
	}
	r.mu.Lock()
	r.cache[ip] = cacheItem{country: country, expires: now.Add(r.ttl)}
	r.mu.Unlock()
	return country
}

func (r *Resolver) lookupCountryCode(ctx context.Context, ip string) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://ipapi.co/%s/json/", ip), nil)
	resp, err := r.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ""
	}
	var payload struct {
		CountryCode string `json:"country_code"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&payload); err != nil {
		return ""
	}
	code := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	if len(code) != 2 {
		return ""
	}
	return code
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 127 || v4[0] == 10 || (v4[0] == 192 && v4[1] == 168) || (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) {
			return true
		}
	}
	return false
}
