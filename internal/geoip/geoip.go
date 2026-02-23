package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]cacheItem
	http     *http.Client
	ttl      time.Duration
	mmdbs    []*maxminddb.Reader
	labels   []string
	lastScan time.Time
}

type cacheItem struct {
	country string
	expires time.Time
}

func New(ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = time.Hour
	}
	readers, labels := openLocalMMDBs()
	return &Resolver{
		cache:  map[string]cacheItem{},
		http:   &http.Client{Timeout: 1200 * time.Millisecond},
		ttl:    ttl,
		mmdbs:  readers,
		labels: labels,
	}
}

func (r *Resolver) CountryCode(ctx context.Context, ip string) string {
	r.maybeReloadSources()
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

	country := ""
	if len(r.mmdbs) > 0 {
		country = r.lookupCountryCodeMMDB(parsed)
	}
	if country == "" {
		country = r.lookupCountryCode(ctx, ip)
	}
	if country == "" {
		country = "ZZ"
	}
	r.mu.Lock()
	r.cache[ip] = cacheItem{country: country, expires: now.Add(r.ttl)}
	r.mu.Unlock()
	return country
}

func (r *Resolver) maybeReloadSources() {
	now := time.Now()
	r.mu.RLock()
	if !r.lastScan.IsZero() && now.Sub(r.lastScan) < 5*time.Minute {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()
	readers, labels := openLocalMMDBs()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lastScan.IsZero() && now.Sub(r.lastScan) < 5*time.Minute {
		for _, db := range readers {
			_ = db.Close()
		}
		return
	}
	r.lastScan = now
	if sameStringSlice(r.labels, labels) {
		for _, db := range readers {
			_ = db.Close()
		}
		return
	}
	for _, db := range r.mmdbs {
		_ = db.Close()
	}
	r.mmdbs = readers
	r.labels = labels
	r.cache = map[string]cacheItem{}
}

func (r *Resolver) lookupCountryCodeMMDB(ip net.IP) string {
	if len(r.mmdbs) == 0 || ip == nil {
		return ""
	}
	for _, db := range r.mmdbs {
		var payload struct {
			Country struct {
				ISOCode     string `maxminddb:"iso_code"`
				CountryCode string `maxminddb:"country_code"`
			} `maxminddb:"country"`
			RegisteredCountry struct {
				ISOCode     string `maxminddb:"iso_code"`
				CountryCode string `maxminddb:"country_code"`
			} `maxminddb:"registered_country"`
			CountryCode string `maxminddb:"country_code"`
		}
		if err := db.Lookup(ip, &payload); err != nil {
			continue
		}
		if code := normalizeCountryCode(payload.Country.ISOCode); code != "" {
			return code
		}
		if code := normalizeCountryCode(payload.Country.CountryCode); code != "" {
			return code
		}
		if code := normalizeCountryCode(payload.RegisteredCountry.ISOCode); code != "" {
			return code
		}
		if code := normalizeCountryCode(payload.RegisteredCountry.CountryCode); code != "" {
			return code
		}
		if code := normalizeCountryCode(payload.CountryCode); code != "" {
			return code
		}
	}
	return ""
}

func openLocalMMDBs() ([]*maxminddb.Reader, []string) {
	paths := []string{}
	if envs := strings.TrimSpace(os.Getenv("DOMNEX_GEOIP_MMDBS")); envs != "" {
		for _, p := range strings.Split(envs, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				paths = append(paths, p)
			}
		}
	}
	if env := strings.TrimSpace(os.Getenv("DOMNEX_GEOIP_MMDB")); env != "" {
		paths = append(paths, env)
	}
	paths = append(paths,
		"/var/lib/domnexdomain/geoip-compiled/domnex-country.mmdb",
		"/var/lib/domnexdomain/geoip/compiled/domnex-country.mmdb",
		"/var/lib/domnexdomain/geoip/dbip-country-lite.mmdb",
		"/var/lib/domnexdomain/geoip/dbip-country-lite-2026-02.mmdb",
		"/var/lib/domnexdomain/geoip/DBIP-Country-Lite.mmdb",
		"/var/lib/domnexdomain/geoip/IP2LOCATION-LITE-DB1.MMDB",
		"/var/lib/domnexdomain/geoip/GeoLite2-Country.mmdb",
		"/etc/domnexdomain/dbip-country-lite.mmdb",
		"/etc/domnexdomain/IP2LOCATION-LITE-DB1.MMDB",
		"/media/i2l/IP2LOCATION-LITE-DB1.MMDB",
	)
	seen := map[string]bool{}
	readers := make([]*maxminddb.Reader, 0, len(paths))
	labels := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, err := os.Stat(p); err != nil {
			continue
		}
		reader, err := maxminddb.Open(p)
		if err == nil {
			readers = append(readers, reader)
			labels = append(labels, p)
		}
	}
	return readers, labels
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *Resolver) lookupCountryCode(ctx context.Context, ip string) string {
	type provider struct {
		url     string
		extract func([]byte) string
	}
	providers := []provider{
		{
			url: fmt.Sprintf("https://ipapi.co/%s/json/", ip),
			extract: func(body []byte) string {
				var payload struct {
					CountryCode string `json:"country_code"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					return ""
				}
				return normalizeCountryCode(payload.CountryCode)
			},
		},
		{
			url: fmt.Sprintf("https://ipwho.is/%s", ip),
			extract: func(body []byte) string {
				var payload struct {
					Success     bool   `json:"success"`
					CountryCode string `json:"country_code"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					return ""
				}
				if !payload.Success {
					return ""
				}
				return normalizeCountryCode(payload.CountryCode)
			},
		},
		{
			url: fmt.Sprintf("https://ipinfo.io/%s/json", ip),
			extract: func(body []byte) string {
				var payload struct {
					Country string `json:"country"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					return ""
				}
				return normalizeCountryCode(payload.Country)
			},
		},
	}

	for _, p := range providers {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
		resp, err := r.http.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			continue
		}
		if code := p.extract(body); code != "" {
			return code
		}
	}
	return ""
}

func normalizeCountryCode(raw string) string {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if len(code) != 2 {
		return ""
	}
	// provider placeholders or anonymized values
	if code == "XX" || code == "T1" {
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
