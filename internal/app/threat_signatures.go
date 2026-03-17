package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type threatSignatureRule struct {
	ID           string   `json:"id"`
	Signal       string   `json:"signal"`
	Family       string   `json:"family"`
	PathContains []string `json:"pathContains"`
	PathPrefix   []string `json:"pathPrefix"`
	HostContains []string `json:"hostContains"`
	UAContains   []string `json:"uaContains"`
}

type threatSignatureBundle struct {
	Version int                   `json:"version"`
	Source  string                `json:"source"`
	Rules   []threatSignatureRule `json:"rules"`
}

type ThreatSignatureConfig struct {
	Enabled    bool      `json:"enabled"`
	AutoUpdate bool      `json:"autoUpdate"`
	SourceURL  string    `json:"sourceUrl"`
	LastSyncAt time.Time `json:"lastSyncAt"`
	LastHash   string    `json:"lastHash"`
	RuleCount  int       `json:"ruleCount"`
	Source     string    `json:"source"`
}

func defaultThreatSignatures() []threatSignatureRule {
	return []threatSignatureRule{
		{ID: "wp-core", Signal: "signature.wp_scanner", Family: "wp_scanner", PathContains: []string{"/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "xmlrpc.php", "wlwmanifest.xml", "wp-trackback"}},
		{ID: "secret-leaks", Signal: "signature.secret_hunter", Family: "secret_hunter", PathContains: []string{"/.env", "/.git/config", "/config.env", "/api/.env", "/laravel/.env", "/docker/.env"}},
		{ID: "webshell-probe", Signal: "signature.webshell_probe", Family: "webshell_probe", PathContains: []string{"ioxi-o.php", "/file.php", "/rip.php", "/sf.php", "/wso.php", "/r57.php", "/shell.php", "/cmd.php", "/xmr.php", "/xmrlpc.php", "/zwso.php"}},
		{ID: "flat-php-probe", Signal: "signature.flat_php_probe", Family: "flat_php_probe", PathContains: []string{"/inputs.php", "/adminfuns.php", "/class-t.api.php", "/ms-edit.php", "/randkeyword.php", "/randkeyword.php7", "/kbfr.php"}},
		{ID: "hidden-index-dropper", Signal: "signature.hidden_index_dropper", Family: "hidden_index_dropper", PathContains: []string{"/wk/index.php", "/.well-known/logs233/index.php", "/.trash7206/index.php", "/update/da222.php"}},
		{ID: "admin-surface", Signal: "signature.admin_surface_probe", Family: "admin_surface_probe", PathContains: []string{"/admin.php", "/admin/", "/manager/html", "/hudson", "/jenkins", "/server-status", "/actuator/env"}},
		{ID: "api-enum", Signal: "signature.api_enum", Family: "api_enum", PathPrefix: []string{"/api/"}, PathContains: []string{"/api/settings", "/api/config", "/graphql"}},
		{ID: "scanner-ua", Signal: "signature.scanner_ua", Family: "scanner_ua", UAContains: []string{"zgrab", "masscan", "nmap", "sqlmap", "nikto", "nuclei", "dirbuster", "gobuster", "wpscan"}},
	}
}

func normalizeThreatSignatureRule(in threatSignatureRule) (threatSignatureRule, bool) {
	out := threatSignatureRule{
		ID:     strings.ToLower(strings.TrimSpace(in.ID)),
		Signal: strings.ToLower(strings.TrimSpace(in.Signal)),
		Family: strings.ToLower(strings.TrimSpace(in.Family)),
	}
	if out.ID == "" {
		out.ID = out.Signal
	}
	if out.Signal == "" {
		return threatSignatureRule{}, false
	}
	if !strings.HasPrefix(out.Signal, "signature.") {
		out.Signal = "signature." + out.Signal
	}
	if out.Family == "" {
		out.Family = strings.TrimPrefix(out.Signal, "signature.")
	}
	for _, v := range in.PathContains {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out.PathContains = append(out.PathContains, v)
		}
	}
	for _, v := range in.PathPrefix {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out.PathPrefix = append(out.PathPrefix, v)
		}
	}
	for _, v := range in.HostContains {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out.HostContains = append(out.HostContains, v)
		}
	}
	for _, v := range in.UAContains {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			out.UAContains = append(out.UAContains, v)
		}
	}
	if len(out.PathContains)+len(out.PathPrefix)+len(out.HostContains)+len(out.UAContains) == 0 {
		return threatSignatureRule{}, false
	}
	return out, true
}

func normalizeThreatSignatureRules(in []threatSignatureRule) []threatSignatureRule {
	out := make([]threatSignatureRule, 0, len(in))
	seen := map[string]bool{}
	for _, r := range in {
		n, ok := normalizeThreatSignatureRule(r)
		if !ok {
			continue
		}
		key := n.ID + "|" + n.Signal
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out
}

func (s *Service) getThreatSignatureURL(ctx context.Context) string {
	if v, err := s.store.GetSetting(ctx, "threatintel.signature_url"); err == nil && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return defaultThreatIntelSignatureURL
}

func (s *Service) isThreatSignatureAutoUpdateEnabled(ctx context.Context) bool {
	if v, err := s.store.GetSetting(ctx, "threatintel.signature_auto_update"); err == nil && strings.TrimSpace(v) != "" {
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return true
}

func (s *Service) isThreatSignatureEnabled(ctx context.Context) bool {
	if v, err := s.store.GetSetting(ctx, "threatintel.signature_enabled"); err == nil && strings.TrimSpace(v) != "" {
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func (s *Service) GetThreatSignatureConfig(ctx context.Context) (ThreatSignatureConfig, error) {
	cfg := ThreatSignatureConfig{
		Enabled:    s.isThreatSignatureEnabled(ctx),
		AutoUpdate: s.isThreatSignatureAutoUpdateEnabled(ctx),
		SourceURL:  s.getThreatSignatureURL(ctx),
	}
	s.sigMu.RLock()
	cfg.LastSyncAt = s.sigLastSync
	cfg.LastHash = s.sigSourceHash
	cfg.RuleCount = len(s.sigRules)
	cfg.Source = s.sigSourceURL
	s.sigMu.RUnlock()
	return cfg, nil
}

func (s *Service) SetThreatSignatureConfig(ctx context.Context, cfg ThreatSignatureConfig) error {
	url := strings.TrimSpace(cfg.SourceURL)
	if url == "" {
		url = defaultThreatIntelSignatureURL
	}
	if err := s.store.SetSetting(ctx, "threatintel.signature_enabled", strings.ToLower(strconv.FormatBool(cfg.Enabled))); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, "threatintel.signature_auto_update", strings.ToLower(strconv.FormatBool(cfg.AutoUpdate))); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, "threatintel.signature_url", url); err != nil {
		return err
	}
	s.sigMu.Lock()
	s.sigEnabled = cfg.Enabled
	s.sigAutoUpdate = cfg.AutoUpdate
	s.sigSourceURL = url
	s.sigMu.Unlock()
	if cfg.Enabled {
		s.ensureThreatSignaturesLoaded(ctx)
		_ = s.syncThreatSignatures(ctx, true)
	}
	return nil
}

func (s *Service) ensureThreatSignaturesLoaded(ctx context.Context) {
	s.sigMu.RLock()
	hasRules := len(s.sigRules) > 0
	s.sigMu.RUnlock()
	if hasRules {
		return
	}
	base := normalizeThreatSignatureRules(defaultThreatSignatures())
	s.sigMu.Lock()
	s.sigRules = base
	s.sigSourceURL = "builtin"
	s.sigSourceHash = ""
	s.sigLastSync = time.Time{}
	s.sigMu.Unlock()
	_ = ctx
}

func (s *Service) syncThreatSignatures(ctx context.Context, force bool) error {
	if !s.isThreatSignatureEnabled(ctx) {
		return nil
	}
	if !force && !s.isThreatSignatureAutoUpdateEnabled(ctx) {
		return nil
	}
	s.sigMu.RLock()
	last := s.sigLastSync
	s.sigMu.RUnlock()
	if !force && !last.IsZero() && time.Since(last) < 6*time.Hour {
		return nil
	}
	url := s.getThreatSignatureURL(ctx)
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("signature update http status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	var bundle threatSignatureBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return fmt.Errorf("invalid signature bundle json")
	}
	rules := normalizeThreatSignatureRules(bundle.Rules)
	if len(rules) == 0 {
		return fmt.Errorf("signature bundle has no valid rules")
	}
	now := time.Now().UTC()
	s.sigMu.Lock()
	s.sigRules = rules
	s.sigLastSync = now
	s.sigSourceURL = url
	s.sigSourceHash = hash
	s.sigMu.Unlock()
	_ = s.store.SetSetting(ctx, "threatintel.signature_url", url)
	_ = s.store.SetSetting(ctx, "threatintel.signature_auto_update", "true")
	_ = s.store.SetSetting(ctx, "threatintel.signature_last_sync", now.Format(time.RFC3339Nano))
	_ = s.store.SetSetting(ctx, "threatintel.signature_last_hash", hash)
	return nil
}

func (s *Service) detectThreatSignatureSignals(host, path, ua string) []string {
	if !s.isThreatSignatureEnabled(context.Background()) {
		return nil
	}
	s.ensureThreatSignaturesLoaded(context.Background())
	lp := strings.ToLower(strings.TrimSpace(path))
	lh := strings.ToLower(strings.TrimSpace(host))
	lua := strings.ToLower(strings.TrimSpace(ua))
	if lp == "" {
		lp = "/"
	}
	s.sigMu.RLock()
	rules := append([]threatSignatureRule{}, s.sigRules...)
	s.sigMu.RUnlock()
	out := make([]string, 0, 4)
	for _, r := range rules {
		if matchThreatSignatureRule(r, lh, lp, lua) {
			out = append(out, r.Signal)
		}
	}
	return uniqueThreatSignals(out)
}

func matchThreatSignatureRule(r threatSignatureRule, host, path, ua string) bool {
	for _, p := range r.PathContains {
		if strings.Contains(path, p) {
			return true
		}
	}
	for _, p := range r.PathPrefix {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, h := range r.HostContains {
		if strings.Contains(host, h) {
			return true
		}
	}
	for _, u := range r.UAContains {
		if strings.Contains(ua, u) {
			return true
		}
	}
	return false
}
