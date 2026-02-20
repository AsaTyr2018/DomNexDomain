package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	PublicIPv4(ctx context.Context) string
}

type Engine struct {
	source   HostSource
	log      *logx.Logger
	m        *metrics.Collector
	geo      *geoip.Resolver
	tr       *traffic.Recorder
	publicIP string
	mu       sync.RWMutex
	routes   map[string]*routeEntry
	auth     map[string]authSession
}

func New(source HostSource, log *logx.Logger, m *metrics.Collector, tr *traffic.Recorder) *Engine {
	return &Engine{
		source: source,
		log:    log,
		m:      m,
		geo:    geoip.New(1 * time.Hour),
		tr:     tr,
		routes: map[string]*routeEntry{},
		auth:   map[string]authSession{},
	}
}

type routeEntry struct {
	proxy    *httputil.ReverseProxy
	backends []backendRoute
	host     model.Host
	rr       uint64
}

type backendRoute struct {
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

func (e *Engine) Refresh(ctx context.Context) error {
	hosts, err := e.source.ListHosts(ctx)
	if err != nil {
		return err
	}
	publicIP := strings.TrimSpace(e.source.PublicIPv4(ctx))
	routes := map[string]*routeEntry{}
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
				entry.backends = append(entry.backends, backendRoute{raw: raw, parsed: u, proxy: newReverseProxy(e, u, h)})
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
			entry.proxy = newReverseProxy(e, u, h)
		}
		routes[strings.ToLower(h.FQDN)] = entry
	}
	e.mu.Lock()
	e.routes = routes
	e.publicIP = publicIP
	e.mu.Unlock()
	e.log.Info("proxy routes refreshed", map[string]any{"count": len(routes), "publicIP": publicIP})
	return nil
}

func (e *Engine) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := newStatusWriter(w)
		var selectedRoute *routeEntry
		var country string
		var clientIP string
		var blocked bool
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
			if e.tr != nil && selectedRoute != nil {
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

		host := r.Host
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		host = strings.ToLower(host)
		e.mu.RLock()
		route, ok := e.routes[host]
		e.mu.RUnlock()
		selectedRoute = route
		if !ok {
			sw.WriteHeader(http.StatusNotFound)
			_, _ = sw.Write([]byte("unknown host"))
			return
		}
		clientIP = clientIPFromRequest(r)
		if route.host.State == "disabled" {
			e.renderHostDisabledPage(route.host, sw, r)
			return
		}
		e.mu.RLock()
		publicIP := e.publicIP
		e.mu.RUnlock()
		if route.host.State == "maintenance" && !isLANClient(clientIP, publicIP) {
			e.renderHostMaintenancePage(route.host, sw, r)
			return
		}
		country = countryFromHeaders(r)
		if country == "" {
			country = e.geo.CountryCode(r.Context(), clientIP)
		}
		if deny, mode := e.isGeoBlocked(country, route.host); deny {
			blocked = true
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
			idx := e.selectBackendIndex(route)
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

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

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

func newReverseProxy(e *Engine, u *url.URL, h model.Host) *httputil.ReverseProxy {
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
		e.log.Error("proxy error", map[string]any{"host": r.Host, "err": err.Error()})
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}
	return rp
}

func (e *Engine) selectBackendIndex(route *routeEntry) int {
	n := len(route.backends)
	if n == 0 {
		return 0
	}
	mode := strings.ToLower(strings.TrimSpace(route.host.HAMode))
	if mode == "" {
		mode = "failover"
	}
	if mode == "round_robin" {
		return int((atomic.AddUint64(&route.rr, 1) - 1) % uint64(n))
	}
	for i := 0; i < n; i++ {
		if isBackendReachable(route.backends[i].parsed) {
			return i
		}
	}
	return 0
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Protected</title>
<style>
:root{--bg:#0b0c12;--surface:#13141c;--border:#2a2d3a;--text:#f3f4f6;--dim:#9ca3af;--accent:#2563eb;--danger:#fca5a5}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 700px at 80% -10%,rgba(37,99,235,.22),transparent 45%),radial-gradient(900px 600px at -10% 110%,rgba(14,165,233,.16),transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(420px,92vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem 1rem .95rem}
.logo{font-size:.8rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase}
h1{margin:.4rem 0 .2rem;font-size:1.2rem}p{margin:.2rem 0 .9rem;color:var(--dim)}
form{display:grid;gap:.55rem}label{display:grid;gap:.25rem;color:var(--dim);font-size:.87rem}
input{width:100%;padding:.62rem .72rem;border:1px solid var(--border);background:#0f1119;color:var(--text);border-radius:10px}
button{margin-top:.2rem;padding:.64rem .8rem;border:0;border-radius:10px;background:var(--accent);color:white;font-weight:600;cursor:pointer}
.err{margin:.2rem 0 .1rem;color:var(--danger);font-size:.86rem}
.host{margin-top:.75rem;color:var(--dim);font-size:.82rem}
</style></head><body><main class="card"><div class="logo">DomNexDomain Access</div><h1>Protected Endpoint</h1><p>Sign in with this subdomain's dedicated credentials.</p>`
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

func (e *Engine) renderGeoBlockedPage(fqdn, country, mode, traceID string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Blocked</title>
<style>
:root{--bg:#0b0c12;--surface:#13141c;--border:#2a2d3a;--text:#f3f4f6;--dim:#9ca3af}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 700px at 80% -10%,rgba(245,158,11,.18),transparent 45%),radial-gradient(900px 600px at -10% 110%,rgba(239,68,68,.14),transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(620px,94vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem 1rem .95rem}
.logo{font-size:.8rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase}
h1{margin:.45rem 0 .25rem;font-size:1.2rem}p{margin:.25rem 0 .8rem;color:var(--dim)}
.row{display:grid;grid-template-columns:180px 1fr;gap:.45rem;padding:.4rem 0;border-top:1px solid #232533}
.k{color:var(--dim)}.v{color:var(--text);word-break:break-word}
.trace{margin-top:.7rem;padding:.55rem .65rem;border:1px solid #5a4318;background:#2b1f0c;border-radius:10px;color:#ffd89a}
.hint{margin-top:.65rem;color:var(--dim);font-size:.9rem}
a{color:#93c5fd}
@media (max-width:620px){.row{grid-template-columns:1fr}}
</style></head><body><main class="card"><div class="logo">DomNexDomain Protection</div><h1>Access Blocked</h1><p>This request was denied by the host access policy.</p>
<div class="row"><div class="k">Host</div><div class="v">` + html.EscapeString(fqdn) + `</div></div>
<div class="row"><div class="k">Path</div><div class="v">` + html.EscapeString(r.URL.Path) + `</div></div>
<div class="row"><div class="k">Policy</div><div class="v">geo ` + html.EscapeString(mode) + `</div></div>
<div class="row"><div class="k">Detected Country</div><div class="v">` + html.EscapeString(country) + `</div></div>
<div class="row"><div class="k">Timestamp (UTC)</div><div class="v">` + time.Now().UTC().Format(time.RFC3339) + `</div></div>
<div class="trace">Trace ID: <strong>` + html.EscapeString(traceID) + `</strong></div>
<div class="hint">If you believe this is an error, contact the site owner and include the Trace ID.</div></main></body></html>`
	_, _ = w.Write([]byte(body))
}

func (e *Engine) renderHostDisabledPage(h model.Host, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Host Disabled</title>
<style>
:root{--bg:#0b0c12;--surface:#13141c;--border:#2a2d3a;--text:#f3f4f6;--dim:#9ca3af;--warn:#f59e0b}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1100px 650px at 80% -10%,rgba(245,158,11,.18),transparent 45%),radial-gradient(900px 600px at -10% 110%,rgba(239,68,68,.12),transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(520px,92vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem}
.top{display:flex;justify-content:space-between;align-items:center;gap:.75rem}
.tag{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:#fcd34d}
h1{margin:.65rem 0 .25rem;font-size:1.24rem}
p{margin:.2rem 0 .75rem;color:var(--dim)}
.meta{margin-top:.65rem;padding-top:.65rem;border-top:1px solid var(--border);font-size:.86rem;color:var(--dim)}
</style></head><body><main class="card"><div class="top"><div class="tag">Host Disabled</div><div>DomNexDomain</div></div><h1>This endpoint is currently disabled</h1><p>External access is blocked by administrator policy for this host.</p><div class="meta">Host: ` + html.EscapeString(h.FQDN) + `</div></main></body></html>`
	_, _ = w.Write([]byte(body))
}

func (e *Engine) renderHostMaintenancePage(h model.Host, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Maintenance</title>
<style>
:root{--bg:#0b0c12;--surface:#13141c;--border:#2a2d3a;--text:#f3f4f6;--dim:#9ca3af;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1100px 650px at 80% -10%,rgba(56,189,248,.18),transparent 45%),radial-gradient(900px 600px at -10% 110%,rgba(99,102,241,.14),transparent 45%),var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:var(--text)}
.card{width:min(540px,92vw);background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1rem}
.tag{font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;color:#7dd3fc}
h1{margin:.65rem 0 .25rem;font-size:1.24rem}
p{margin:.2rem 0 .75rem;color:var(--dim)}
.meta{margin-top:.65rem;padding-top:.65rem;border-top:1px solid var(--border);font-size:.86rem;color:var(--dim)}
</style></head><body><main class="card"><div class="tag">Maintenance Mode</div><h1>This service is temporarily unavailable</h1><p>This endpoint is currently in maintenance mode for external traffic.</p><div class="meta">Host: ` + html.EscapeString(h.FQDN) + `</div></main></body></html>`
	_, _ = w.Write([]byte(body))
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
