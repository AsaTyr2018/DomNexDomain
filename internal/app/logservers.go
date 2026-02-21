package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

const secretLogHTTPBearer = "log.http_bearer"

type LogServerSettings struct {
	Syslog  LogServerSyslogSettings  `json:"syslog"`
	HTTP    LogServerHTTPSettings    `json:"http"`
	TCPJSON LogServerTCPJSONSettings `json:"tcpJson"`
}

type LogServerSyslogSettings struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	MinLevel string `json:"minLevel"`
	AppName  string `json:"appName"`
}

type LogServerHTTPSettings struct {
	Enabled    bool   `json:"enabled"`
	URL        string `json:"url"`
	TimeoutSec int    `json:"timeoutSec"`
	MinLevel   string `json:"minLevel"`
	Insecure   bool   `json:"insecure"`
}

type LogServerTCPJSONSettings struct {
	Enabled    bool   `json:"enabled"`
	Address    string `json:"address"`
	TimeoutSec int    `json:"timeoutSec"`
	MinLevel   string `json:"minLevel"`
}

type logEnvelope struct {
	Timestamp string `json:"ts"`
	Host      string `json:"host"`
	Service   string `json:"service"`
	Level     string `json:"level"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Meta      string `json:"meta"`
	SourceIP  string `json:"sourceIp,omitempty"`
}

func defaultLogServerSettings() LogServerSettings {
	return LogServerSettings{
		Syslog: LogServerSyslogSettings{
			Enabled:  false,
			Protocol: "udp",
			Address:  "",
			MinLevel: "info",
			AppName:  "DomNexDomain",
		},
		HTTP: LogServerHTTPSettings{
			Enabled:    false,
			URL:        "",
			TimeoutSec: 4,
			MinLevel:   "warn",
			Insecure:   false,
		},
		TCPJSON: LogServerTCPJSONSettings{
			Enabled:    false,
			Address:    "",
			TimeoutSec: 3,
			MinLevel:   "info",
		},
	}
}

func normalizeLogLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info", "warn", "error":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "info"
	}
}

func normalizeLogServerSettings(in LogServerSettings) (LogServerSettings, error) {
	out := defaultLogServerSettings()
	out.Syslog.Enabled = in.Syslog.Enabled
	out.Syslog.Protocol = strings.ToLower(strings.TrimSpace(in.Syslog.Protocol))
	if out.Syslog.Protocol == "" {
		out.Syslog.Protocol = "udp"
	}
	if out.Syslog.Protocol != "udp" && out.Syslog.Protocol != "tcp" {
		return out, fmt.Errorf("syslog protocol must be udp or tcp")
	}
	out.Syslog.Address = strings.TrimSpace(in.Syslog.Address)
	if out.Syslog.Enabled {
		if _, _, err := net.SplitHostPort(out.Syslog.Address); err != nil {
			return out, fmt.Errorf("syslog address must be host:port")
		}
	}
	out.Syslog.MinLevel = normalizeLogLevel(in.Syslog.MinLevel)
	out.Syslog.AppName = strings.TrimSpace(in.Syslog.AppName)
	if out.Syslog.AppName == "" {
		out.Syslog.AppName = "DomNexDomain"
	}

	out.HTTP.Enabled = in.HTTP.Enabled
	out.HTTP.URL = strings.TrimSpace(in.HTTP.URL)
	if out.HTTP.Enabled {
		if out.HTTP.URL == "" {
			return out, fmt.Errorf("http log URL is required when enabled")
		}
		if !strings.HasPrefix(strings.ToLower(out.HTTP.URL), "http://") && !strings.HasPrefix(strings.ToLower(out.HTTP.URL), "https://") {
			return out, fmt.Errorf("http log URL must start with http:// or https://")
		}
	}
	out.HTTP.TimeoutSec = in.HTTP.TimeoutSec
	if out.HTTP.TimeoutSec <= 0 {
		out.HTTP.TimeoutSec = 4
	}
	if out.HTTP.TimeoutSec > 30 {
		out.HTTP.TimeoutSec = 30
	}
	out.HTTP.MinLevel = normalizeLogLevel(in.HTTP.MinLevel)
	out.HTTP.Insecure = in.HTTP.Insecure

	out.TCPJSON.Enabled = in.TCPJSON.Enabled
	out.TCPJSON.Address = strings.TrimSpace(in.TCPJSON.Address)
	if out.TCPJSON.Enabled {
		if _, _, err := net.SplitHostPort(out.TCPJSON.Address); err != nil {
			return out, fmt.Errorf("tcp json address must be host:port")
		}
	}
	out.TCPJSON.TimeoutSec = in.TCPJSON.TimeoutSec
	if out.TCPJSON.TimeoutSec <= 0 {
		out.TCPJSON.TimeoutSec = 3
	}
	if out.TCPJSON.TimeoutSec > 30 {
		out.TCPJSON.TimeoutSec = 30
	}
	out.TCPJSON.MinLevel = normalizeLogLevel(in.TCPJSON.MinLevel)
	return out, nil
}

func auditSeverity(action string) string {
	a := strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(a, ".error"), strings.Contains(a, ".hard_drop"), strings.Contains(a, ".hard_block"):
		return "error"
	case strings.Contains(a, ".failed"), strings.Contains(a, ".blocked"), strings.Contains(a, ".warn"), strings.Contains(a, ".soft_block"):
		return "warn"
	default:
		return "info"
	}
}

func shouldShip(minLevel, eventLevel string) bool {
	lv := map[string]int{"info": 1, "warn": 2, "error": 3}
	return lv[eventLevel] >= lv[normalizeLogLevel(minLevel)]
}

func (s *Service) enqueueRemoteAudit(e model.AuditEvent) {
	select {
	case s.logCh <- e:
	default:
		if s.log != nil {
			s.log.Warn("remote log queue full; dropping event", map[string]any{"action": e.Action, "target": e.Target})
		}
	}
}

func (s *Service) runRemoteAuditDispatcher() {
	for e := range s.logCh {
		s.dispatchAuditEvent(e)
	}
}

func (s *Service) dispatchAuditEvent(e model.AuditEvent) {
	s.logMu.RLock()
	cfg := s.logCfg
	token := s.logToken
	host := s.hostName
	s.logMu.RUnlock()
	level := auditSeverity(e.Action)
	env := logEnvelope{
		Timestamp: e.CreatedAt.UTC().Format(time.RFC3339Nano),
		Host:      host,
		Service:   "DomNexDomain",
		Level:     level,
		Actor:     strings.TrimSpace(e.Actor),
		Action:    strings.TrimSpace(e.Action),
		Target:    strings.TrimSpace(e.Target),
		Meta:      strings.TrimSpace(e.Meta),
		SourceIP:  strings.TrimSpace(e.SourceIP),
	}
	if env.Actor == "" {
		env.Actor = "system"
	}

	if cfg.Syslog.Enabled && cfg.Syslog.Address != "" && shouldShip(cfg.Syslog.MinLevel, level) {
		if err := sendSyslog(cfg.Syslog, env); err != nil && s.log != nil {
			s.log.Warn("remote syslog send failed", map[string]any{"err": err.Error(), "addr": cfg.Syslog.Address})
		}
	}
	if cfg.HTTP.Enabled && cfg.HTTP.URL != "" && shouldShip(cfg.HTTP.MinLevel, level) {
		if err := sendHTTPLog(cfg.HTTP, token, env); err != nil && s.log != nil {
			s.log.Warn("remote http log send failed", map[string]any{"err": err.Error(), "url": cfg.HTTP.URL})
		}
	}
	if cfg.TCPJSON.Enabled && cfg.TCPJSON.Address != "" && shouldShip(cfg.TCPJSON.MinLevel, level) {
		if err := sendTCPJSON(cfg.TCPJSON, env); err != nil && s.log != nil {
			s.log.Warn("remote tcp-json send failed", map[string]any{"err": err.Error(), "addr": cfg.TCPJSON.Address})
		}
	}
}

func sendSyslog(cfg LogServerSyslogSettings, env logEnvelope) error {
	hostname := env.Host
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "domnexdomain"
	}
	severity := 6
	switch env.Level {
	case "warn":
		severity = 4
	case "error":
		severity = 3
	}
	priority := 16*1 + severity
	msg := fmt.Sprintf("<%d>1 %s %s %s - - - actor=%s action=%s target=%s meta=%s source=%s",
		priority, env.Timestamp, hostname, cfg.AppName,
		sanitizeSyslog(env.Actor), sanitizeSyslog(env.Action), sanitizeSyslog(env.Target), sanitizeSyslog(env.Meta), sanitizeSyslog(env.SourceIP))
	return dialAndWrite(strings.ToLower(cfg.Protocol), cfg.Address, []byte(msg+"\n"), 3*time.Second)
}

func sanitizeSyslog(in string) string {
	in = strings.TrimSpace(in)
	in = strings.ReplaceAll(in, "\n", " ")
	in = strings.ReplaceAll(in, "\r", " ")
	return in
}

func sendHTTPLog(cfg LogServerHTTPSettings, token string, env logEnvelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}, // #nosec G402
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func sendTCPJSON(cfg LogServerTCPJSONSettings, env logEnvelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return dialAndWrite("tcp", cfg.Address, append(b, '\n'), time.Duration(cfg.TimeoutSec)*time.Second)
}

func dialAndWrite(network, addr string, payload []byte, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial(network, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(payload)
	return err
}

func (s *Service) SetLogHTTPBearer(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	enc, err := s.keystore.Encrypt(token)
	if err != nil {
		return err
	}
	return s.store.StoreSecret(ctx, secretLogHTTPBearer, enc)
}

func (s *Service) GetLogHTTPBearer(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, secretLogHTTPBearer)
	if err != nil {
		return "", err
	}
	return s.keystore.Decrypt(enc)
}

func (s *Service) loadLogServerSettings(ctx context.Context) (LogServerSettings, string, bool, error) {
	cfg := defaultLogServerSettings()
	if raw, err := s.store.GetSetting(ctx, settingLogServers); err == nil && strings.TrimSpace(raw) != "" {
		var parsed LogServerSettings
		if uErr := json.Unmarshal([]byte(raw), &parsed); uErr == nil {
			norm, nErr := normalizeLogServerSettings(parsed)
			if nErr == nil {
				cfg = norm
			}
		}
	}
	token, err := s.GetLogHTTPBearer(ctx)
	if err != nil {
		token = ""
	}
	hasToken := strings.TrimSpace(token) != ""
	return cfg, token, hasToken, nil
}

func (s *Service) applyLogServerSettings(ctx context.Context, cfg LogServerSettings, httpBearer string) error {
	norm, err := normalizeLogServerSettings(cfg)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingLogServers, string(raw)); err != nil {
		return err
	}
	if strings.TrimSpace(httpBearer) != "" {
		if err := s.SetLogHTTPBearer(ctx, httpBearer); err != nil {
			return err
		}
	}
	s.logMu.RLock()
	newToken := s.logToken
	s.logMu.RUnlock()
	if strings.TrimSpace(httpBearer) != "" {
		newToken = strings.TrimSpace(httpBearer)
	}
	s.logMu.Lock()
	s.logCfg = norm
	s.logToken = newToken
	s.logMu.Unlock()
	return nil
}

func (s *Service) syncLogServerSettings(ctx context.Context) {
	cfg, token, _, err := s.loadLogServerSettings(ctx)
	if err != nil {
		return
	}
	s.logMu.Lock()
	s.logCfg = cfg
	s.logToken = strings.TrimSpace(token)
	s.logMu.Unlock()
}
