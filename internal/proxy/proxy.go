package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
)

type HostSource interface {
	ListHosts(ctx context.Context) ([]model.Host, error)
}

type Engine struct {
	source HostSource
	log    *logx.Logger
	m      *metrics.Collector
	geo    *geoip.Resolver
	mu     sync.RWMutex
	routes map[string]*routeEntry
	auth   map[string]authSession
}

func New(source HostSource, log *logx.Logger, m *metrics.Collector) *Engine {
	return &Engine{
		source: source,
		log:    log,
		m:      m,
		geo:    geoip.New(1 * time.Hour),
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
	routes := map[string]*routeEntry{}
	for _, h := range hosts {
		if h.State != "active" {
			continue
		}
		entry := &routeEntry{host: h}
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
	e.mu.Unlock()
	e.log.Info("proxy routes refreshed", map[string]any{"count": len(routes)})
	return nil
}

func (e *Engine) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := newStatusWriter(w)
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
		}()

		host := r.Host
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		host = strings.ToLower(host)
		e.mu.RLock()
		route, ok := e.routes[host]
		e.mu.RUnlock()
		if !ok {
			sw.WriteHeader(http.StatusNotFound)
			_, _ = sw.Write([]byte("unknown host"))
			return
		}
		if blocked, country, mode := e.isGeoBlocked(r, route.host); blocked {
			if e.m != nil {
				e.m.GeoBlocks.WithLabelValues(route.host.FQDN, country, mode).Inc()
			}
			e.log.Warn("geo policy blocked request", map[string]any{"fqdn": route.host.FQDN, "country": country, "mode": mode})
			sw.WriteHeader(http.StatusForbidden)
			_, _ = sw.Write([]byte("geo blocked"))
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

func (e *Engine) isGeoBlocked(r *http.Request, h model.Host) (bool, string, string) {
	mode := strings.ToLower(strings.TrimSpace(h.GeoMode))
	if mode == "" {
		return false, "", ""
	}
	countrySet := map[string]bool{}
	for _, c := range h.GeoCountries {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(cc) == 2 {
			countrySet[cc] = true
		}
	}
	if len(countrySet) == 0 {
		return false, "", mode
	}
	ip := clientIPFromRequest(r)
	country := e.geo.CountryCode(r.Context(), ip)
	if country == "LOCAL" {
		return false, country, mode
	}
	switch mode {
	case "allow":
		return !countrySet[country], country, mode
	case "deny":
		return countrySet[country], country, mode
	default:
		return false, country, mode
	}
}

func clientIPFromRequest(r *http.Request) string {
	if cfip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfip != "" {
		return cfip
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if idx := strings.Index(xff, ","); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

type statusWriter struct {
	http.ResponseWriter
	status int
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
	return w.ResponseWriter.Write(b)
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
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

func (w *statusWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
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
