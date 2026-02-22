package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/geoip"
	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/metrics"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/domnexdomain/domnexdomain/internal/traffic"
)

type HostSource interface {
	ListHosts(ctx context.Context) ([]model.Host, error)
	ListDomains(ctx context.Context) ([]model.Domain, error)
	ListSSHBastionRoutes(ctx context.Context) ([]model.SSHBastionRoute, error)
	PublicIPv4(ctx context.Context) string
	AddAuditEvent(ctx context.Context, e model.AuditEvent) error
	GetStyleSettings(ctx context.Context) (string, string, error)
	GetThreatIntelSnapshot(ctx context.Context) (model.ThreatIntelSnapshot, error)
	ApplyThreatIntelEvent(ctx context.Context, in model.ThreatIntelEventInput) (model.ThreatIntelEventResult, error)
	IsIPBlocked(ctx context.Context, ip string) (bool, error)
	UpsertBlockedIP(ctx context.Context, ip, reason string) error
}

type Engine struct {
	source   HostSource
	log      *logx.Logger
	m        *metrics.Collector
	geo      *geoip.Resolver
	tr       *traffic.Recorder
	live     *traffic.LiveHub
	publicIP string
	mu       sync.RWMutex
	routes   map[string]*routeEntry
	bastion  map[string]bool
	managed  map[string]bool
	auth     map[string]authSession
	theme    edgeTheme
	wafMu    sync.Mutex
	wafCount map[string]wafCounter
	wafBlock map[string]time.Time
	wafWhy   map[string]string
	tiSnap   model.ThreatIntelSnapshot
}

type wafCounter struct {
	windowStart time.Time
	count       int
}

type edgeTheme struct {
	bg      string
	surface string
	border  string
	text    string
	dim     string
	accent  string
	danger  string
	inputBg string
	success string
	heroA   string
	heroB   string
}

func New(source HostSource, log *logx.Logger, m *metrics.Collector, tr *traffic.Recorder, live *traffic.LiveHub) *Engine {
	return &Engine{
		source:   source,
		log:      log,
		m:        m,
		geo:      geoip.New(1 * time.Hour),
		tr:       tr,
		live:     live,
		routes:   map[string]*routeEntry{},
		bastion:  map[string]bool{},
		managed:  map[string]bool{},
		auth:     map[string]authSession{},
		theme:    monolithEdgeTheme(),
		wafCount: map[string]wafCounter{},
		wafBlock: map[string]time.Time{},
		wafWhy:   map[string]string{},
		tiSnap: model.ThreatIntelSnapshot{
			Mode:      "monitor_only",
			Allowlist: map[string]bool{},
			FeedByIP:  map[string][]string{},
		},
	}
}

func monolithEdgeTheme() edgeTheme {
	return edgeTheme{
		bg:      "#0b0c12",
		surface: "#13141c",
		border:  "#2a2d3a",
		text:    "#f3f4f6",
		dim:     "#9ca3af",
		accent:  "#2563eb",
		danger:  "#fca5a5",
		inputBg: "#0f1119",
		success: "#10b981",
		heroA:   "rgba(56,189,248,.15)",
		heroB:   "rgba(99,102,241,.2)",
	}
}

func cyberMonolithEdgeTheme() edgeTheme {
	return edgeTheme{
		bg:      "#16161a",
		surface: "#1c1c22",
		border:  "#2a2a36",
		text:    "#e6e6f0",
		dim:     "#8b8b99",
		accent:  "#8b5cf6",
		danger:  "#dc2626",
		inputBg: "#17171d",
		success: "#10b981",
		heroA:   "rgba(139,92,246,.16)",
		heroB:   "rgba(124,58,237,.12)",
	}
}

func parseEdgeTheme(profile, custom string) edgeTheme {
	base := monolithEdgeTheme()
	if strings.EqualFold(strings.TrimSpace(profile), "cybermonolith") {
		base = cyberMonolithEdgeTheme()
	}
	if strings.EqualFold(strings.TrimSpace(profile), "custom") {
		base = monolithEdgeTheme()
	}
	custom = strings.TrimSpace(custom)
	if custom == "" {
		return base
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(custom), &m); err != nil {
		return base
	}
	set := func(dst *string, key string) {
		v := strings.TrimSpace(m[key])
		if v == "" || len(v) > 64 {
			return
		}
		if !isSafeThemeValue(v) {
			return
		}
		*dst = v
	}
	set(&base.bg, "bg")
	set(&base.surface, "surface")
	set(&base.border, "border")
	set(&base.text, "text")
	set(&base.dim, "textDim")
	set(&base.accent, "accent")
	set(&base.danger, "danger")
	set(&base.inputBg, "inputBg")
	set(&base.success, "success")
	set(&base.heroA, "heroA")
	set(&base.heroB, "heroB")
	return base
}

func isSafeThemeValue(v string) bool {
	for _, ch := range v {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case strings.ContainsRune("#(),.%- _", ch):
		default:
			return false
		}
	}
	return true
}

func (e *Engine) currentTheme() edgeTheme {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.theme
}

type routeEntry struct {
	proxy    *httputil.ReverseProxy
	backends []backendRoute
	host     model.Host
	rr       uint64
}

type backendRoute struct {
	name   string
	raw    string
	parsed *url.URL
	proxy  *httputil.ReverseProxy
}

type authSession struct {
	host      string
	expiresAt time.Time
}

const hostAuthCookieName = "dnx_host_auth"
const hostAuthPathLogin = "/_domnex/auth/login"
const hostAuthPathLogout = "/_domnex/auth/logout"
const hostAuthTTL = 12 * time.Hour

const wafUnknownWindow = 60 * time.Second
const wafUnknownThreshold = 80
const wafTempBlockTTL = 15 * time.Minute

func (e *Engine) Refresh(ctx context.Context) error {
	hosts, err := e.source.ListHosts(ctx)
	if err != nil {
		return err
	}
	domains, err := e.source.ListDomains(ctx)
	if err != nil {
		return err
	}
	sshRoutes, err := e.source.ListSSHBastionRoutes(ctx)
	if err != nil {
		return err
	}
	publicIP := strings.TrimSpace(e.source.PublicIPv4(ctx))
	styleProfile, styleCustom, _ := e.source.GetStyleSettings(ctx)
	tiSnap, _ := e.source.GetThreatIntelSnapshot(ctx)
	theme := parseEdgeTheme(styleProfile, styleCustom)
	routes := map[string]*routeEntry{}
	bastion := map[string]bool{}
	managed := map[string]bool{}
	for _, r := range sshRoutes {
		if !r.Enabled {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSpace(r.FQDN))
		if fqdn != "" {
			bastion[fqdn] = true
		}
	}
	for _, d := range domains {
		if strings.EqualFold(strings.TrimSpace(d.Status), "inactive") {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(d.Name))
		if name != "" {
			managed[name] = true
		}
	}
	for _, h := range hosts {
		if h.State != "active" && h.State != "disabled" && h.State != "maintenance" {
			continue
		}
		entry := &routeEntry{host: h}
		if h.State == "disabled" {
			routes[strings.ToLower(h.FQDN)] = entry
			continue
		}
		if h.HAEnabled && len(h.HABackends) > 0 {
			for _, be := range h.HABackends {
				raw := strings.TrimSpace(be.URL)
				u, err := url.Parse(raw)
				if err != nil || u.Host == "" {
					e.log.Warn("invalid HA backend URL", map[string]any{"fqdn": h.FQDN, "url": raw})
					continue
				}
				name := strings.TrimSpace(be.Name)
				if name == "" {
					name = u.Host
				}
				entry.backends = append(entry.backends, backendRoute{name: name, raw: raw, parsed: u, proxy: newReverseProxy(e, u, h, raw)})
			}
			if len(entry.backends) == 0 {
				e.log.Warn("no valid HA backends; falling back to upstream", map[string]any{"fqdn": h.FQDN})
			}
		}
		if entry.proxy == nil {
			u, err := url.Parse(h.UpstreamURL)
			if err != nil || u.Host == "" {
				e.log.Warn("invalid upstream URL", map[string]any{"fqdn": h.FQDN, "url": h.UpstreamURL})
				continue
			}
			entry.proxy = newReverseProxy(e, u, h, h.UpstreamURL)
		}
		routes[strings.ToLower(h.FQDN)] = entry
	}
	e.mu.Lock()
	e.routes = routes
	e.bastion = bastion
	e.managed = managed
	e.publicIP = publicIP
	e.theme = theme
	e.tiSnap = tiSnap
	e.mu.Unlock()
	e.log.Info("proxy routes refreshed", map[string]any{"count": len(routes), "bastionHosts": len(bastion), "managedApex": len(managed), "publicIP": publicIP})
	return nil
}

func (e *Engine) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := newStatusWriter(w)
		var selectedRoute *routeEntry
		var country string
		var clientIP string
		var publicIP string
		var blocked bool
		var scannerSignal bool
		defer func() {
			hostLabel := "_unknown"
			host := r.Host
			if idx := strings.Index(host, ":"); idx >= 0 {
				host = host[:idx]
			}
			host = strings.TrimSpace(strings.ToLower(host))
			if host != "" {
				hostLabel = host
			}
			if e.m != nil {
				e.m.ProxyRequests.WithLabelValues(hostLabel, strconv.Itoa(sw.StatusCode())).Inc()
			}
			if e.live != nil && e.live.SubscriberCount() > 0 && clientIP != "" {
				liveCountry := strings.TrimSpace(strings.ToUpper(country))
				if liveCountry == "" {
					liveCountry = countryFromHeaders(r)
				}
				if liveCountry == "" {
					liveCountry = e.geo.CountryCode(r.Context(), clientIP)
				}
				if liveCountry == "" {
					liveCountry = "ZZ"
				}
				sourceType := requestScope(clientIP, publicIP)
				fqdn := hostLabel
				hostID := int64(0)
				domainID := int64(0)
				if selectedRoute != nil {
					fqdn = selectedRoute.host.FQDN
					hostID = selectedRoute.host.ID
					domainID = selectedRoute.host.DomainID
				}
				class := "human"
				if isLikelyCrawlerUA(r.UserAgent()) {
					class = "crawler"
				}
				if strings.TrimSpace(r.UserAgent()) == "" {
					class = "unknown"
				}
				isScanner := scannerSignal || class == "crawler"
				e.live.Publish(traffic.LiveTraceEvent{
					Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
					HostID:     hostID,
					DomainID:   domainID,
					FQDN:       fqdn,
					Country:    liveCountry,
					Class:      class,
					Scanner:    isScanner,
					Status:     sw.StatusCode(),
					Path:       r.URL.Path,
					SourceType: sourceType,
				})
			}
			edgeError := strings.EqualFold(strings.TrimSpace(sw.Header().Get("X-DomNex-Edge-Error")), "1")
			if e.tr != nil && selectedRoute != nil && !edgeError {
				contentIn := int64(0)
				if r.ContentLength > 0 {
					contentIn = r.ContentLength
				}
				e.tr.Record(traffic.Event{
					HostID:    selectedRoute.host.ID,
					FQDN:      selectedRoute.host.FQDN,
					Country:   country,
					UserAgent: r.UserAgent(),
					ClientIP:  clientIP,
					Status:    sw.StatusCode(),
					BytesIn:   contentIn,
					BytesOut:  sw.BytesWritten(),
					Blocked:   blocked,
					Timestamp: time.Now().UTC(),
				})
			}
		}()

		if r.URL.Path == edgeLogoPath {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(edgeLogoPNG)
			return
		}

		host := normalizeHostHeader(r.Host)
		clientIP = clientIPFromRequest(r)
		scannerSignal = isLikelyCrawlerUA(r.UserAgent())
		e.mu.RLock()
		publicIP = e.publicIP
		route, ok := e.routes[host]
		isBastionHost := e.bastion[host]
		managedApex := e.managed[host]
		tiSnap := e.tiSnap
		e.mu.RUnlock()
		selectedRoute = route
		if isBlockedIP, _ := e.source.IsIPBlocked(r.Context(), clientIP); isBlockedIP {
			blocked = true
			scannerSignal = true
			traceID, _ := randomHex(8)
			e.auditProxyEvent(r.Context(), "proxy.block.hard_drop", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path+";reason=blocked_ip")
			dropConnection(sw)
			return
		}
		matchFeeds := append([]string{}, tiSnap.FeedByIP[clientIP]...)
		behaviorFeeds := detectBehaviorThreatSignals(host, ok, r.URL.Path, r.UserAgent())
		if tiSnap.Allowlist[clientIP] {
			matchFeeds = nil
			behaviorFeeds = nil
		}
		allFeeds := uniqueThreatFeeds(append(matchFeeds, behaviorFeeds...))
		hasThreatSignal := len(allFeeds) > 0 && !isLANClient(clientIP, publicIP)
		threatIntelRecognized := hasThreatSignal
		if hasThreatSignal {
			scannerSignal = true
			if country == "" {
				country = countryFromHeaders(r)
				if country == "" {
					country = e.geo.CountryCode(r.Context(), clientIP)
				}
			}
			traceID, _ := randomHex(8)
			scope := requestScope(clientIP, publicIP)
			mode := strings.ToLower(strings.TrimSpace(tiSnap.Mode))
			if mode == "" {
				mode = "monitor_only"
			}
			if !tiSnap.Enabled {
				mode = "monitor_only"
			}
			recordPath := normalizeThreatPath(r.URL.Path)
			out, err := e.source.ApplyThreatIntelEvent(r.Context(), model.ThreatIntelEventInput{
				IP:          clientIP,
				Host:        host,
				Path:        recordPath,
				Country:     country,
				SourceScope: scope,
				TraceID:     traceID,
				Signals:     allFeeds,
				Mode:        mode,
			})
			if err != nil {
				e.log.Warn("threat intel apply failed", map[string]any{"ip": clientIP, "err": err.Error()})
			}
			if out.Blocked {
				scannerSignal = true
				if out.HardBlock {
					blocked = true
					e.auditProxyEvent(r.Context(), "proxy.block.hard_drop", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path+";reason=threat_intel_hardblock")
					dropConnection(sw)
					return
				}
				e.renderSmartErrorPage(sw, r, smartErrorPage{
					HTTPStatus:   http.StatusTooManyRequests,
					Title:        "Temporarily Blocked",
					Description:  "Threat intelligence policy triggered temporary protection for this source.",
					Code:         "DNX-TI-429",
					FailurePoint: "threat-intel: xp/level soft block",
					Host:         host,
					TraceID:      traceID,
					Theme:        "warn",
					Scope:        scope,
				})
				return
			}
		}
		if isBlocked, until, _ := e.wafIsBlocked(clientIP, publicIP); isBlocked {
			scannerSignal = true
			traceID, _ := randomHex(8)
			e.auditProxyEvent(r.Context(), "proxy.waf.temp_block.hit", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path+";until="+until.UTC().Format(time.RFC3339))
			e.renderSmartErrorPage(sw, r, smartErrorPage{
				HTTPStatus:   http.StatusTooManyRequests,
				Title:        "Temporarily Blocked",
				Description:  "Automated edge protection temporarily limited requests from this source.",
				Code:         "DNX-WAF-429",
				FailurePoint: "waf: unknown-host flood detected",
				Host:         host,
				TraceID:      traceID,
				Theme:        "warn",
				Scope:        requestScope(clientIP, publicIP),
			})
			return
		}
		if !ok {
			scannerSignal = true
			if managedApex {
				traceID, _ := randomHex(8)
				e.renderManagedDomainPage(host, traceID, sw, r)
				return
			}
			if threatIntelRecognized {
				traceID, _ := randomHex(8)
				e.renderSmartErrorPage(sw, r, smartErrorPage{
					HTTPStatus:   http.StatusNotFound,
					Title:        "Nothing here yet",
					Description:  "This subdomain is not active yet. Check back later, something might appear soon.",
					Code:         "DNX-ROUTE-404",
					FailurePoint: "routing: host not configured (yet)",
					Host:         host,
					TraceID:      traceID,
					Theme:        "ok",
				})
				return
			}
			triggered, until, hits := e.wafTrackUnknownHost(clientIP, publicIP)
			traceID, _ := randomHex(8)
			if triggered {
				scannerSignal = true
				e.log.Warn("waf temporary block set", map[string]any{
					"source":  clientIP,
					"host":    host,
					"path":    r.URL.Path,
					"hits":    hits,
					"until":   until.UTC().Format(time.RFC3339),
					"traceID": traceID,
				})
				e.auditProxyEvent(r.Context(), "proxy.waf.temp_block.set", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path+";hits="+strconv.Itoa(hits)+";until="+until.UTC().Format(time.RFC3339))
				e.renderSmartErrorPage(sw, r, smartErrorPage{
					HTTPStatus:   http.StatusTooManyRequests,
					Title:        "Temporarily Blocked",
					Description:  "Automated edge protection temporarily limited requests from this source.",
					Code:         "DNX-WAF-429",
					FailurePoint: "waf: unknown-host flood detected",
					Host:         host,
					TraceID:      traceID,
					Theme:        "warn",
					Scope:        requestScope(clientIP, publicIP),
				})
				return
			}
			e.auditProxyEvent(r.Context(), "proxy.error.unknown_host", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path)
			e.renderSmartErrorPage(sw, r, smartErrorPage{
				HTTPStatus:   http.StatusNotFound,
				Title:        "Nothing here yet",
				Description:  "This subdomain is not active yet. Check back later, something might appear soon.",
				Code:         "DNX-ROUTE-404",
				FailurePoint: "routing: host not configured (yet)",
				Host:         host,
				TraceID:      traceID,
				Theme:        "ok",
			})
			return
		}
		if isBastionHost {
			traceID, _ := randomHex(8)
			e.auditProxyEvent(r.Context(), "proxy.error.unknown_host", host, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path)
			e.renderSmartErrorPage(sw, r, smartErrorPage{
				HTTPStatus:   http.StatusNotFound,
				Title:        "Nothing here yet",
				Description:  "This subdomain is not active yet. Check back later, something might appear soon.",
				Code:         "DNX-ROUTE-404",
				FailurePoint: "routing: host not configured (yet)",
				Host:         host,
				TraceID:      traceID,
				Theme:        "ok",
			})
			return
		}
		if route.host.State == "disabled" {
			traceID, _ := randomHex(8)
			e.auditProxyEvent(r.Context(), "proxy.error.host_disabled", route.host.FQDN, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path)
			e.renderHostDisabledPage(route.host, traceID, sw, r)
			return
		}
		if route.host.State == "maintenance" && !isLANClient(clientIP, publicIP) {
			traceID, _ := randomHex(8)
			e.auditProxyEvent(r.Context(), "proxy.error.maintenance", route.host.FQDN, "trace="+traceID+";source="+clientIP+";path="+r.URL.Path)
			e.renderHostMaintenancePage(route.host, traceID, sw, r)
			return
		}
		country = countryFromHeaders(r)
		if country == "" {
			country = e.geo.CountryCode(r.Context(), clientIP)
		}
		if deny, mode := e.isGeoBlocked(country, route.host); deny {
			blocked = true
			scannerSignal = true
			traceID, _ := randomHex(8)
			if e.m != nil {
				e.m.GeoBlocks.WithLabelValues(route.host.FQDN, country, mode).Inc()
			}
			e.log.Warn("geo policy blocked request", map[string]any{
				"fqdn":    route.host.FQDN,
				"country": country,
				"mode":    mode,
				"path":    r.URL.Path,
				"traceID": traceID,
			})
			e.auditProxyEvent(r.Context(), "proxy.error.geo_blocked", route.host.FQDN, "trace="+traceID+";source="+clientIP+";country="+country+";mode="+mode+";path="+r.URL.Path)
			e.renderGeoBlockedPage(route.host.FQDN, country, mode, traceID, sw, r)
			return
		}
		if route.host.AuthEnabled {
			e.pruneAuthSessions()
			if strings.HasPrefix(r.URL.Path, hostAuthPathLogout) {
				e.logoutHostAuth(sw, r)
				next := "/"
				if strings.HasPrefix(r.URL.Path, hostAuthPathLogout) && len(r.URL.Path) > len(hostAuthPathLogout) {
					next = "/"
				}
				http.Redirect(sw, r, next, http.StatusSeeOther)
				return
			}
			if r.URL.Path == hostAuthPathLogin && r.Method == http.MethodPost {
				e.handleHostAuthLogin(route.host, sw, r)
				return
			}
			if !e.isHostAuthorized(host, r) {
				e.renderHostLoginPage(route.host, sw, r, "")
				return
			}
		}
		if route.host.HAEnabled && len(route.backends) > 0 {
			idx, online, total, offline := e.selectBackendIndex(route)
			if idx < 0 {
				scannerSignal = true
				traceID, _ := randomHex(8)
				scope := requestScope(clientIP, publicIP)
				e.log.Warn("ha all backends unreachable", map[string]any{
					"fqdn":    route.host.FQDN,
					"online":  online,
					"total":   total,
					"offline": strings.Join(offline, ","),
					"traceID": traceID,
				})
				e.auditProxyEvent(r.Context(), "proxy.error.ha_all_backends_down", route.host.FQDN, "trace="+traceID+";source="+clientIP+";online="+strconv.Itoa(online)+";total="+strconv.Itoa(total)+";offline="+strings.Join(offline, ",")+";path="+r.URL.Path)
				e.renderSmartErrorPage(sw, r, smartErrorPage{
					HTTPStatus:   http.StatusServiceUnavailable,
					Title:        "HA Backends Unavailable",
					Description:  "All configured high-availability backends are currently unreachable.",
					Code:         "DNX-HA-503",
					FailurePoint: "origin: all HA backends down (" + strconv.Itoa(online) + "/" + strconv.Itoa(total) + " healthy)",
					Host:         route.host.FQDN,
					TraceID:      traceID,
					Theme:        "err",
					Scope:        scope,
				})
				return
			}
			route.backends[idx].proxy.ServeHTTP(sw, r)
			return
		}
		route.proxy.ServeHTTP(sw, r)
	})
}

func (e *Engine) isGeoBlocked(country string, h model.Host) (bool, string) {
	mode := strings.ToLower(strings.TrimSpace(h.GeoMode))
	if mode == "" {
		return false, ""
	}
	countrySet := map[string]bool{}
	for _, c := range h.GeoCountries {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(cc) == 2 {
			countrySet[cc] = true
		}
	}
	if len(countrySet) == 0 {
		return false, mode
	}
	if country == "LOCAL" {
		return false, mode
	}
	switch mode {
	case "allow":
		return !countrySet[country], mode
	case "deny":
		return countrySet[country], mode
	default:
		return false, mode
	}
}

func clientIPFromRequest(r *http.Request) string {
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
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		if ip := parseCandidateIP(host); ip != "" {
			return ip
		}
	}
	return parseCandidateIP(strings.TrimSpace(r.RemoteAddr))
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

func countryFromHeaders(r *http.Request) string {
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

func isLANClient(raw, publicIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if pip := net.ParseIP(strings.TrimSpace(publicIP)); pip != nil && ip.Equal(pip) {
		// NAT loopback/hairpin access from the local network often appears as server public IP.
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// IPv6 ULA fc00::/7
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return (v6[0] & 0xfe) == 0xfc
	}
	return false
}

func normalizeHostHeader(host string) string {
	host = strings.TrimSpace(host)
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func uniqueThreatFeeds(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
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

func isLikelyCrawlerUA(ua string) bool {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return false
	}
	botHints := []string{
		"bot", "crawler", "spider", "slurp",
		"googlebot", "bingbot", "duckduckbot", "yandexbot", "baiduspider",
		"semrush", "ahrefs", "mj12bot", "dotbot", "petalbot", "facebookexternalhit",
		"curl/", "wget/", "python-requests", "go-http-client",
		"scanner", "nmap", "zgrab", "nikto", "masscan", "sqlmap",
	}
	for _, h := range botHints {
		if strings.Contains(ua, h) {
			return true
		}
	}
	return false
}

func normalizeThreatPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if idx := strings.Index(p, "?"); idx >= 0 {
		p = p[:idx]
	}
	if len(p) > 96 {
		p = p[:96]
	}
	return p
}

func detectBehaviorThreatSignals(host string, routeKnown bool, path, ua string) []string {
	signals := []string{}
	lp := strings.ToLower(normalizeThreatPath(path))
	lua := strings.ToLower(strings.TrimSpace(ua))
	if !routeKnown {
		signals = append(signals, "behavior.unknown_host")
	}
	pathNeedles := []string{
		"/.env", "/wp-admin", "/wp-login", "/xmlrpc.php", "/vendor/phpunit",
		"/boaform/admin", "/actuator", "/cgi-bin", "/.git", "/etc/passwd",
		"/api/v1/namespaces", "/hudson", "/jenkins", "/manager/html",
	}
	for _, n := range pathNeedles {
		if strings.Contains(lp, n) {
			signals = append(signals, "behavior.path_scan")
			break
		}
	}
	uaNeedles := []string{
		"zgrab", "masscan", "nmap", "sqlmap", "nikto", "nuclei", "dirbuster", "gobuster", "curl/",
	}
	for _, n := range uaNeedles {
		if strings.Contains(lua, n) {
			signals = append(signals, "behavior.ua_scanner")
			break
		}
	}
	if strings.TrimSpace(host) == "" {
		signals = append(signals, "behavior.invalid_host")
	}
	return uniqueThreatFeeds(signals)
}

func (e *Engine) wafPrune(now time.Time) {
	for ip, until := range e.wafBlock {
		if !until.After(now) {
			delete(e.wafBlock, ip)
			delete(e.wafWhy, ip)
		}
	}
	staleCutoff := now.Add(-(wafUnknownWindow + wafTempBlockTTL))
	for ip, c := range e.wafCount {
		if c.windowStart.Before(staleCutoff) {
			delete(e.wafCount, ip)
		}
	}
}

func (e *Engine) wafIsBlocked(clientIP, publicIP string) (bool, time.Time, string) {
	if clientIP == "" || isLANClient(clientIP, publicIP) {
		return false, time.Time{}, ""
	}
	now := time.Now().UTC()
	e.wafMu.Lock()
	defer e.wafMu.Unlock()
	e.wafPrune(now)
	until, ok := e.wafBlock[clientIP]
	if !ok || !until.After(now) {
		return false, time.Time{}, ""
	}
	return true, until, strings.TrimSpace(e.wafWhy[clientIP])
}

func (e *Engine) wafTrackUnknownHost(clientIP, publicIP string) (bool, time.Time, int) {
	if clientIP == "" || isLANClient(clientIP, publicIP) {
		return false, time.Time{}, 0
	}
	now := time.Now().UTC()
	e.wafMu.Lock()
	defer e.wafMu.Unlock()
	e.wafPrune(now)
	if until, ok := e.wafBlock[clientIP]; ok && until.After(now) {
		return true, until, wafUnknownThreshold
	}
	c := e.wafCount[clientIP]
	if c.windowStart.IsZero() || now.Sub(c.windowStart) >= wafUnknownWindow {
		c.windowStart = now
		c.count = 0
	}
	c.count++
	e.wafCount[clientIP] = c
	if c.count < wafUnknownThreshold {
		return false, time.Time{}, c.count
	}
	until := now.Add(wafTempBlockTTL)
	e.wafBlock[clientIP] = until
	e.wafWhy[clientIP] = "unknown_host_flood"
	delete(e.wafCount, clientIP)
	return true, until, c.count
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

const droppedStatusCode = 444

func newStatusWriter(w http.ResponseWriter) *statusWriter {
	return &statusWriter{ResponseWriter: w}
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.bytes += int64(n)
	}
	return n, err
}

func (w *statusWriter) StatusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		n, err := rf.ReadFrom(r)
		if n > 0 {
			w.bytes += n
		}
		return n, err
	}
	n, err := io.Copy(w.ResponseWriter, r)
	if n > 0 {
		w.bytes += n
	}
	return n, err
}

func (w *statusWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *statusWriter) BytesWritten() int64 {
	return w.bytes
}

func dropConnection(w *statusWriter) {
	if w != nil {
		w.status = droppedStatusCode
		w.Header().Set("Connection", "close")
		w.Header().Set("X-DomNex-Edge-Error", "1")
	}
	conn, _, err := w.Hijack()
	if err == nil && conn != nil {
		_ = conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

func newReverseProxy(e *Engine, u *url.URL, h model.Host, upstreamRef string) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(u)
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if strings.EqualFold(u.Scheme, "https") && h.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	rp.Transport = transport
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		traceID, _ := randomHex(8)
		clientIP := clientIPFromRequest(r)
		e.log.Error("proxy error", map[string]any{"host": r.Host, "upstream": upstreamRef, "traceID": traceID, "source": clientIP, "err": err.Error()})
		e.auditProxyEvent(r.Context(), "proxy.error.origin_unreachable", h.FQDN, "trace="+traceID+";source="+clientIP+";upstream="+upstreamRef+";path="+r.URL.Path+";err="+err.Error())
		e.mu.RLock()
		publicIP := e.publicIP
		e.mu.RUnlock()
		e.renderSmartErrorPage(w, r, smartErrorPage{
			HTTPStatus:   http.StatusBadGateway,
			Title:        "Upstream Unreachable",
			Description:  "The edge received your request, but could not reach the configured origin service.",
			Code:         "DNX-ORIGIN-502",
			FailurePoint: "origin",
			Host:         h.FQDN,
			TraceID:      traceID,
			Theme:        "err",
			Scope:        requestScope(clientIP, publicIP),
		})
	}
	return rp
}

func (e *Engine) selectBackendIndex(route *routeEntry) (int, int, int, []string) {
	n := len(route.backends)
	if n == 0 {
		return -1, 0, 0, nil
	}
	mode := strings.ToLower(strings.TrimSpace(route.host.HAMode))
	if mode == "" {
		mode = "failover"
	}
	if mode == "round_robin" {
		return int((atomic.AddUint64(&route.rr, 1) - 1) % uint64(n)), n, n, nil
	}
	online := 0
	offline := []string{}
	for i := 0; i < n; i++ {
		if isBackendReachable(route.backends[i].parsed) {
			online++
			if online == 1 {
				return i, online, n, offline
			}
			continue
		}
		name := strings.TrimSpace(route.backends[i].name)
		if name == "" {
			name = route.backends[i].raw
		}
		offline = append(offline, name)
	}
	return -1, online, n, offline
}

func isBackendReachable(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (e *Engine) isHostAuthorized(host string, r *http.Request) bool {
	c, err := r.Cookie(hostAuthCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return false
	}
	e.mu.RLock()
	s, ok := e.auth[c.Value]
	e.mu.RUnlock()
	if !ok {
		return false
	}
	if s.host != host || time.Now().After(s.expiresAt) {
		e.mu.Lock()
		delete(e.auth, c.Value)
		e.mu.Unlock()
		return false
	}
	return true
}

func (e *Engine) handleHostAuthLogin(h model.Host, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		e.renderHostLoginPage(h, w, r, "invalid login form")
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	next := normalizeNext(r.FormValue("next"))
	if !strings.EqualFold(user, strings.TrimSpace(h.AuthUser)) || !crypto.VerifyPassword(pass, h.AuthPassHash) {
		e.renderHostLoginPage(h, w, r, "invalid credentials")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("auth error"))
		return
	}
	e.mu.Lock()
	e.auth[token] = authSession{host: strings.ToLower(h.FQDN), expiresAt: time.Now().Add(hostAuthTTL)}
	e.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     hostAuthCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(hostAuthTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (e *Engine) logoutHostAuth(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(hostAuthCookieName); err == nil && c.Value != "" {
		e.mu.Lock()
		delete(e.auth, c.Value)
		e.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     hostAuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (e *Engine) pruneAuthSessions() {
	now := time.Now()
	e.mu.Lock()
	for k, v := range e.auth {
		if now.After(v.expiresAt) {
			delete(e.auth, k)
		}
	}
	e.mu.Unlock()
}

func (e *Engine) renderHostLoginPage(h model.Host, w http.ResponseWriter, r *http.Request, errMsg string) {
	next := normalizeNext(r.URL.RequestURI())
	th := e.currentTheme()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Protected</title>
<style>
:root{--bg:` + th.bg + `;--surface:` + th.surface + `;--border:` + th.border + `;--text:` + th.text + `;--dim:` + th.dim + `;--accent:` + th.accent + `;--danger:` + th.danger + `;--input:` + th.inputBg + `}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 700px at 80% -10%,` + th.heroA + `,transparent 45%),radial-gradient(900px 600px at -10% 110%,` + th.heroB + `,transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(460px,92vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem 1rem .95rem}
.brand{display:grid;place-items:center;margin-bottom:.5rem}
.brand img{width:100%;max-width:250px;height:auto;display:block;border-radius:16px;filter:drop-shadow(0 3px 10px rgba(0,0,0,.28));-webkit-mask-image:radial-gradient(125% 105% at 50% 48%,rgba(0,0,0,1) 48%,rgba(0,0,0,.86) 62%,rgba(0,0,0,.52) 78%,rgba(0,0,0,0) 100%),linear-gradient(to bottom,rgba(0,0,0,0) 0%,rgba(0,0,0,.95) 16%,rgba(0,0,0,.95) 84%,rgba(0,0,0,0) 100%),linear-gradient(to right,rgba(0,0,0,0) 0%,rgba(0,0,0,.96) 12%,rgba(0,0,0,.96) 88%,rgba(0,0,0,0) 100%);mask-image:radial-gradient(125% 105% at 50% 48%,rgba(0,0,0,1) 48%,rgba(0,0,0,.86) 62%,rgba(0,0,0,.52) 78%,rgba(0,0,0,0) 100%),linear-gradient(to bottom,rgba(0,0,0,0) 0%,rgba(0,0,0,.95) 16%,rgba(0,0,0,.95) 84%,rgba(0,0,0,0) 100%),linear-gradient(to right,rgba(0,0,0,0) 0%,rgba(0,0,0,.96) 12%,rgba(0,0,0,.96) 88%,rgba(0,0,0,0) 100%);-webkit-mask-composite:source-in;mask-composite:intersect}
h1{margin:.4rem 0 .2rem;font-size:1.2rem}p{margin:.2rem 0 .9rem;color:var(--dim)}
form{display:grid;gap:.55rem}label{display:grid;gap:.25rem;color:var(--dim);font-size:.87rem}
input{width:100%;padding:.62rem .72rem;border:1px solid var(--border);background:var(--input);color:var(--text);border-radius:10px}
button{margin-top:.2rem;padding:.64rem .8rem;border:0;border-radius:10px;background:var(--accent);color:white;font-weight:600;cursor:pointer}
.err{margin:.2rem 0 .1rem;color:var(--danger);font-size:.86rem}
.host{margin-top:.75rem;color:var(--dim);font-size:.82rem}
</style></head><body><main class="card"><div class="brand"><img src="` + edgeLogoPath + `" alt="DomNexDomain"></div><h1>Protected Endpoint</h1><p>Sign in with this subdomain's dedicated credentials.</p>`
	if strings.TrimSpace(errMsg) != "" {
		body += `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	body += `<form method="post" action="` + hostAuthPathLogin + `"><input type="hidden" name="next" value="` + html.EscapeString(next) + `">
<label>Username<input name="username" autocomplete="username" required></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Continue</button></form><div class="host">Host: ` + html.EscapeString(h.FQDN) + `</div></main></body></html>`
	_, _ = w.Write([]byte(body))
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func normalizeNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, hostAuthPathLogin) {
		return "/"
	}
	return raw
}

type smartErrorPage struct {
	HTTPStatus   int
	Title        string
	Description  string
	Code         string
	FailurePoint string
	Host         string
	TraceID      string
	Theme        string
	Scope        string
}

func (e *Engine) renderSmartErrorPage(w http.ResponseWriter, r *http.Request, p smartErrorPage) {
	status := p.HTTPStatus
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	host := strings.TrimSpace(p.Host)
	if host == "" {
		h := r.Host
		if idx := strings.Index(h, ":"); idx >= 0 {
			h = h[:idx]
		}
		host = strings.TrimSpace(strings.ToLower(h))
	}
	if host == "" {
		host = "unknown"
	}
	theme := strings.TrimSpace(strings.ToLower(p.Theme))
	th := e.currentTheme()
	gradA := th.heroA
	gradB := th.heroB
	if theme == "ok" {
		gradA = "rgba(16,185,129,.18)"
		gradB = "rgba(34,197,94,.12)"
	}
	if theme == "warn" {
		gradA = "rgba(245,158,11,.18)"
		gradB = th.heroB
	}
	if theme == "err" {
		gradA = "rgba(239,68,68,.2)"
		gradB = "rgba(245,158,11,.12)"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-DomNex-Trace", p.TraceID)
	w.Header().Set("X-DomNex-Edge-Error", "1")
	w.WriteHeader(status)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(p.Title) + `</title>
<style>
:root{--bg:` + th.bg + `;--surface:` + th.surface + `;--border:` + th.border + `;--text:` + th.text + `;--dim:` + th.dim + `;--accent:` + th.accent + `}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1100px 650px at 80% -10%,` + gradA + `,transparent 45%),radial-gradient(900px 600px at -10% 110%,` + gradB + `,transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(680px,94vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem}
.brand{display:grid;place-items:center;margin-bottom:.5rem}
.brand img{width:100%;max-width:270px;height:auto;display:block;border-radius:16px;filter:drop-shadow(0 3px 10px rgba(0,0,0,.28));-webkit-mask-image:radial-gradient(125% 105% at 50% 48%,rgba(0,0,0,1) 48%,rgba(0,0,0,.86) 62%,rgba(0,0,0,.52) 78%,rgba(0,0,0,0) 100%),linear-gradient(to bottom,rgba(0,0,0,0) 0%,rgba(0,0,0,.95) 16%,rgba(0,0,0,.95) 84%,rgba(0,0,0,0) 100%),linear-gradient(to right,rgba(0,0,0,0) 0%,rgba(0,0,0,.96) 12%,rgba(0,0,0,.96) 88%,rgba(0,0,0,0) 100%);mask-image:radial-gradient(125% 105% at 50% 48%,rgba(0,0,0,1) 48%,rgba(0,0,0,.86) 62%,rgba(0,0,0,.52) 78%,rgba(0,0,0,0) 100%),linear-gradient(to bottom,rgba(0,0,0,0) 0%,rgba(0,0,0,.95) 16%,rgba(0,0,0,.95) 84%,rgba(0,0,0,0) 100%),linear-gradient(to right,rgba(0,0,0,0) 0%,rgba(0,0,0,.96) 12%,rgba(0,0,0,.96) 88%,rgba(0,0,0,0) 100%);-webkit-mask-composite:source-in;mask-composite:intersect}
.top{display:flex;justify-content:space-between;align-items:center;gap:.75rem}
.tag{font-size:.74rem;letter-spacing:.07em;text-transform:uppercase;color:var(--accent)}
h1{margin:.65rem 0 .25rem;font-size:1.22rem}
p{margin:.2rem 0 .75rem;color:var(--dim)}
.row{display:grid;grid-template-columns:190px 1fr;gap:.45rem;padding:.4rem 0;border-top:1px solid var(--border)}
.k{color:var(--dim)}.v{color:var(--text);word-break:break-word}
@media (max-width:640px){.row{grid-template-columns:1fr}}
</style></head><body><main class="card"><div class="brand"><img src="` + edgeLogoPath + `" alt="DomNexDomain"></div><div class="top"><div class="tag">DomNexDomain Smart Error</div><div>` + strconv.Itoa(status) + `</div></div>
<h1>` + html.EscapeString(p.Title) + `</h1><p>` + html.EscapeString(p.Description) + `</p>
<div class="row"><div class="k">Host</div><div class="v">` + html.EscapeString(host) + `</div></div>
<div class="row"><div class="k">Trace ID</div><div class="v"><strong>` + html.EscapeString(p.TraceID) + `</strong></div></div>
</main></body></html>`
	_, _ = w.Write([]byte(body))
}

func requestScope(clientIP, publicIP string) string {
	if isLANClient(clientIP, publicIP) {
		return "internal (LAN/hairpin request)"
	}
	return "external (internet request)"
}

func (e *Engine) auditProxyEvent(ctx context.Context, action, target, meta string) {
	_ = e.source.AddAuditEvent(ctx, model.AuditEvent{
		Actor:  "edge",
		Action: action,
		Target: target,
		Meta:   meta,
	})
}

func (e *Engine) renderGeoBlockedPage(fqdn, country, mode, traceID string, w http.ResponseWriter, r *http.Request) {
	e.renderSmartErrorPage(w, r, smartErrorPage{
		HTTPStatus:   http.StatusForbidden,
		Title:        "Access Blocked",
		Description:  "This request was denied by host access policy.",
		Code:         "DNX-GEO-403",
		FailurePoint: "policy: geo " + mode + " / country " + country,
		Host:         fqdn,
		TraceID:      traceID,
		Theme:        "warn",
	})
}

func (e *Engine) renderHostDisabledPage(h model.Host, traceID string, w http.ResponseWriter, r *http.Request) {
	e.renderSmartErrorPage(w, r, smartErrorPage{
		HTTPStatus:   http.StatusServiceUnavailable,
		Title:        "Host Disabled",
		Description:  "External access is blocked by administrator policy for this host.",
		Code:         "DNX-HOST-503",
		FailurePoint: "policy",
		Host:         h.FQDN,
		TraceID:      traceID,
		Theme:        "warn",
	})
}

func (e *Engine) renderHostMaintenancePage(h model.Host, traceID string, w http.ResponseWriter, r *http.Request) {
	e.renderSmartErrorPage(w, r, smartErrorPage{
		HTTPStatus:   http.StatusServiceUnavailable,
		Title:        "Maintenance Mode",
		Description:  "This endpoint is currently in maintenance mode for external traffic.",
		Code:         "DNX-MAINT-503",
		FailurePoint: "policy",
		Host:         h.FQDN,
		TraceID:      traceID,
		Theme:        "warn",
	})
}

func (e *Engine) renderManagedDomainPage(host, traceID string, w http.ResponseWriter, r *http.Request) {
	repo := "https://github.com/AsaTyr2018/DomNexDomain"
	discord := "https://discord.gg/GnAUmXhfeG"
	desc := "This apex domain is managed by DomNexDomain."
	htmlBody := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(host) + `</title><style>
:root{--bg:#0b0c12;--surface:#13141c;--border:#2a2d3a;--text:#f3f4f6;--dim:#9ca3af;--accent:#6366f1}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:radial-gradient(900px 320px at 85% -20%,rgba(99,102,241,.18),transparent 56%),radial-gradient(900px 300px at 10% -20%,rgba(14,165,233,.12),transparent 56%),var(--bg);color:var(--text)}
.wrap{min-height:100vh;display:grid;place-items:center;padding:1rem}.card{width:min(820px,100%);background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.2rem;text-align:center}
.brand{display:grid;place-items:center;margin-bottom:.6rem}.brand img{width:100%;max-width:280px;height:auto;display:block;border-radius:16px;filter:drop-shadow(0 3px 10px rgba(0,0,0,.28))}
h1{margin:.35rem 0 .2rem;font-size:1.45rem}.lead{margin:.35rem 0;color:var(--dim)}.lead strong{color:var(--text)}.k{display:grid;gap:.45rem;margin:.9rem 0;text-align:left}.k div{border:1px solid var(--border);border-radius:10px;padding:.55rem .65rem;background:#10121a;color:var(--dim)}
.pill-row{display:flex;gap:.45rem;justify-content:center;flex-wrap:wrap;margin:.7rem 0}.pill{border:1px solid var(--border);border-radius:999px;padding:.22rem .55rem;color:var(--dim);background:#10121a;font-size:.82rem}
.cta-row{display:flex;gap:.6rem;justify-content:center;flex-wrap:wrap;margin-top:.95rem}.cta{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;padding:.6rem .9rem;border-radius:10px}.cta.alt{background:#1f2937}.trace{margin-top:.7rem;color:var(--dim);font-size:.8rem}
</style></head><body><main class="wrap"><section class="card"><div class="brand"><img src="` + edgeLogoPath + `" alt="DomNexDomain"></div><h1>Managed by DomNexDomain</h1><p class="lead">` + html.EscapeString(desc) + `</p><p class="lead">Domain: <strong>` + html.EscapeString(host) + `</strong></p><div class="pill-row"><span class="pill">Edge Proxy</span><span class="pill">TLS Automation</span><span class="pill">DNS Control</span><span class="pill">Threat Defense</span><span class="pill">HA Routing</span></div><div class="k"><div><strong>Built for secure public self-hosting:</strong> expose your services with HTTPS, policy controls, and production-style observability.</div><div><strong>Operations in one place:</strong> domain onboarding, subdomain routing, cert lifecycle, logs, metrics, and role-based access.</div><div><strong>Deployment that stays simple:</strong> one Linux binary, systemd-ready runtime, and no Node.js requirement in production.</div><div><strong>Enterprise mindset for homelabs and SMEs:</strong> defense-first defaults, guided workflows, and transparent traceability for every edge response.</div></div><div class="cta-row"><a class="cta" href="` + html.EscapeString(repo) + `" target="_blank" rel="noopener noreferrer">Explore on GitHub</a><a class="cta alt" href="` + html.EscapeString(discord) + `" target="_blank" rel="noopener noreferrer">Join Discord Support</a></div><div class="trace">Trace ID: ` + html.EscapeString(traceID) + `</div></section></main></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-DomNex-Edge-Error", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, htmlBody)
}

func randomHex(n int) (string, error) {
	if n <= 0 {
		n = 8
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (e *Engine) StartRefresher(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Refresh(ctx); err != nil && !errors.Is(err, context.Canceled) {
				e.log.Error("proxy refresh failed", map[string]any{"err": err.Error()})
			}
		}
	}
}
