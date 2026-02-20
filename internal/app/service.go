package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/config"
	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/dns"
	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/domnexdomain/domnexdomain/internal/store"
)

type Service struct {
	cfg      config.Config
	store    *store.Store
	keystore *crypto.Keystore
	dns      dns.Provider
	log      *logx.Logger
	publicIP string
	backoff  map[int64]time.Time
}

const settingPublicIPv4 = "network.public_ipv4"

type RuntimeSettings struct {
	Domain      string `json:"domain"`
	BaseDomain  string `json:"baseDomain"`
	AdminFQDN   string `json:"adminFqdn"`
	ACMEEmail   string `json:"acmeEmail"`
	ACMEStaging bool   `json:"acmeStaging"`
	HasCFToken  bool   `json:"hasCloudflareToken"`
	PublicIPv4  string `json:"publicIpv4"`
}

type ManagedUser struct {
	ID        int64      `json:"id"`
	Username  string     `json:"username"`
	Role      model.Role `json:"role"`
	DomainIDs []int64    `json:"domainIds"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

type HostDiagnostic struct {
	FQDN         string   `json:"fqdn"`
	DNSRecords   []string `json:"dnsRecords"`
	HTTPStatus   int      `json:"httpStatus"`
	HTTPSStatus  int      `json:"httpsStatus"`
	TLSOK        bool     `json:"tlsOk"`
	CertSubject  string   `json:"certSubject"`
	CertIssuer   string   `json:"certIssuer"`
	CertNotAfter string   `json:"certNotAfter"`
	CertDaysLeft int      `json:"certDaysLeft"`
	HAEnabled    bool     `json:"haEnabled,omitempty"`
	HAMode       string   `json:"haMode,omitempty"`
	HAOnline     int      `json:"haOnline,omitempty"`
	HATotal      int      `json:"haTotal,omitempty"`
	HAOffline    []string `json:"haOffline,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type HostLiveCheck struct {
	FQDN                  string `json:"fqdn"`
	DNSOK                 bool   `json:"dnsOk"`
	DNSPointsToServer     bool   `json:"dnsPointsToServer"`
	HTTPReachable         bool   `json:"httpReachable"`
	HTTPSReachable        bool   `json:"httpsReachable"`
	TLSOK                 bool   `json:"tlsOk"`
	CertDaysLeft          int    `json:"certDaysLeft"`
	CloudflareRecordFound bool   `json:"cloudflareRecordFound"`
	Error                 string `json:"error,omitempty"`
}

type DomainLiveCheck struct {
	Domain             string          `json:"domain"`
	DNSMode            string          `json:"dnsMode"`
	Provider           string          `json:"provider"`
	ServerIPv4         string          `json:"serverIpv4,omitempty"`
	ApexDNSOK          bool            `json:"apexDnsOk"`
	ApexPointsToServer bool            `json:"apexPointsToServer"`
	CloudflareAPIOK    bool            `json:"cloudflareApiOk"`
	CloudflareZoneID   string          `json:"cloudflareZoneId,omitempty"`
	CloudflareError    string          `json:"cloudflareError,omitempty"`
	Hosts              []HostLiveCheck `json:"hosts"`
	Warnings           []string        `json:"warnings,omitempty"`
	OverallOK          bool            `json:"overallOk"`
}

type DomainPreflightCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type DomainPreflight struct {
	Domain       string                 `json:"domain"`
	DNSMode      string                 `json:"dnsMode"`
	Provider     string                 `json:"provider"`
	ZoneID       string                 `json:"zoneId,omitempty"`
	ResolvedZone string                 `json:"resolvedZone,omitempty"`
	PublicIPv4   string                 `json:"publicIpv4,omitempty"`
	Checks       []DomainPreflightCheck `json:"checks"`
	Ready        bool                   `json:"ready"`
}

type HostPreflightCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type HostPreflight struct {
	Domain      string               `json:"domain"`
	FQDN        string               `json:"fqdn,omitempty"`
	Upstream    string               `json:"upstream"`
	InsecureTLS bool                 `json:"insecureTls,omitempty"`
	DNSMode     string               `json:"dnsMode,omitempty"`
	Provider    string               `json:"provider,omitempty"`
	ZoneID      string               `json:"zoneId,omitempty"`
	Checks      []HostPreflightCheck `json:"checks"`
	Ready       bool                 `json:"ready"`
}

type TrafficPoint struct {
	BucketStart string `json:"bucketStart"`
	Requests    int64  `json:"requests"`
	BytesIn     int64  `json:"bytesIn"`
	BytesOut    int64  `json:"bytesOut"`
	Blocked     int64  `json:"blocked"`
	Status2xx   int64  `json:"status2xx"`
	Status3xx   int64  `json:"status3xx"`
	Status4xx   int64  `json:"status4xx"`
	Status5xx   int64  `json:"status5xx"`
}

type HostTrafficSummary struct {
	HostID         int64  `json:"hostId"`
	FQDN           string `json:"fqdn"`
	Requests       int64  `json:"requests"`
	BytesIn        int64  `json:"bytesIn"`
	BytesOut       int64  `json:"bytesOut"`
	Blocked        int64  `json:"blocked"`
	Status2xx      int64  `json:"status2xx"`
	Status3xx      int64  `json:"status3xx"`
	Status4xx      int64  `json:"status4xx"`
	Status5xx      int64  `json:"status5xx"`
	UniqueVisitors int64  `json:"uniqueVisitors"`
}

type TrafficOverview struct {
	Hours          int                  `json:"hours"`
	GeneratedAt    string               `json:"generatedAt"`
	TotalRequests  int64                `json:"totalRequests"`
	TotalBytesIn   int64                `json:"totalBytesIn"`
	TotalBytesOut  int64                `json:"totalBytesOut"`
	TotalBlocked   int64                `json:"totalBlocked"`
	UniqueVisitors int64                `json:"uniqueVisitors"`
	Hosts          []HostTrafficSummary `json:"hosts"`
}

type HostTrafficDetails struct {
	Hours          int            `json:"hours"`
	HostID         int64          `json:"hostId"`
	FQDN           string         `json:"fqdn"`
	Requests       int64          `json:"requests"`
	BytesIn        int64          `json:"bytesIn"`
	BytesOut       int64          `json:"bytesOut"`
	Blocked        int64          `json:"blocked"`
	Status2xx      int64          `json:"status2xx"`
	Status3xx      int64          `json:"status3xx"`
	Status4xx      int64          `json:"status4xx"`
	Status5xx      int64          `json:"status5xx"`
	UniqueVisitors int64          `json:"uniqueVisitors"`
	Series         []TrafficPoint `json:"series"`
}

type CountryTraffic struct {
	Country   string `json:"country"`
	Requests  int64  `json:"requests"`
	Blocked   int64  `json:"blocked"`
	Status2xx int64  `json:"status2xx"`
	Status3xx int64  `json:"status3xx"`
	Status4xx int64  `json:"status4xx"`
	Status5xx int64  `json:"status5xx"`
	BytesOut  int64  `json:"bytesOut"`
}

type TrafficCountryOverview struct {
	Hours            int                  `json:"hours"`
	GeneratedAt      string               `json:"generatedAt"`
	RequestClass     string               `json:"requestClass"`
	HostID           int64                `json:"hostId,omitempty"`
	HostFQDN         string               `json:"hostFqdn,omitempty"`
	TotalRequests    int64                `json:"totalRequests"`
	TotalBlocked     int64                `json:"totalBlocked"`
	TotalBytesOut    int64                `json:"totalBytesOut"`
	Countries        []CountryTraffic     `json:"countries"`
	UnknownBreakdown []HostCountryTraffic `json:"unknownBreakdown,omitempty"`
}

type HostCountryTraffic struct {
	HostID    int64  `json:"hostId"`
	FQDN      string `json:"fqdn"`
	Requests  int64  `json:"requests"`
	Blocked   int64  `json:"blocked"`
	Status2xx int64  `json:"status2xx"`
	Status3xx int64  `json:"status3xx"`
	Status4xx int64  `json:"status4xx"`
	Status5xx int64  `json:"status5xx"`
	BytesOut  int64  `json:"bytesOut"`
}

func normalizeRequestClass(class string) string {
	c := strings.ToLower(strings.TrimSpace(class))
	switch c {
	case "", "all":
		return "all"
	case "crawler", "human", "unknown":
		return c
	default:
		return "all"
	}
}

func New(cfg config.Config, st *store.Store, ks *crypto.Keystore, dnsProvider dns.Provider, log *logx.Logger) *Service {
	return &Service{cfg: cfg, store: st, keystore: ks, dns: dnsProvider, log: log, backoff: map[int64]time.Time{}}
}

func (s *Service) Store() *store.Store { return s.store }

func (s *Service) Bootstrap(ctx context.Context, bootstrapUser, bootstrapPass string) error {
	hash, err := crypto.HashPassword(bootstrapPass, crypto.DefaultArgonConfig())
	if err != nil {
		return err
	}
	created, err := s.store.EnsureBootstrapUser(ctx, bootstrapUser, string(model.RoleAdmin), hash)
	if err != nil {
		return err
	}
	if created {
		s.log.Info("bootstrap admin created", map[string]any{"username": bootstrapUser})
	}
	if strings.TrimSpace(s.cfg.Domain) == "" {
		s.log.Info("no master domain configured; skipping auto domain/bootstrap host provisioning", nil)
		return nil
	}

	adminDomain := "admin." + s.cfg.Domain
	_, err = s.store.UpsertDomain(ctx, model.Domain{Name: s.cfg.Domain, DNSMode: "manual", CertMode: "letsencrypt", Provider: "manual", ZoneID: "", Status: "active"})
	if err != nil {
		return err
	}
	d, err := s.store.GetDomainByName(ctx, s.cfg.Domain)
	if err != nil {
		return err
	}
	_, err = s.store.FindHostByFQDN(ctx, adminDomain)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	adminUpstream := "http://" + s.cfg.AdminBindAddr
	if strings.HasPrefix(s.cfg.AdminBindAddr, ":") {
		adminUpstream = "http://127.0.0.1" + s.cfg.AdminBindAddr
	}
	h, err := s.store.CreateHost(ctx, d.ID, "admin", adminDomain, adminUpstream, false, false, "", nil)
	if err != nil {
		return err
	}
	_ = s.store.SetHostState(ctx, h.ID, "dns_pending", "bootstrap")
	_ = s.store.SetHostState(ctx, h.ID, "cert_pending", "bootstrap")
	_ = s.store.SetHostState(ctx, h.ID, "active", "bootstrap")
	return nil
}

func (s *Service) ListFQDNs(ctx context.Context) ([]string, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h.State == "active" || h.State == "cert_pending" || h.State == "maintenance" || h.State == "disabled" {
			out = append(out, h.FQDN)
		}
	}
	return out, nil
}

func (s *Service) SetCloudflareToken(ctx context.Context, token string) error {
	enc, err := s.keystore.Encrypt(token)
	if err != nil {
		return err
	}
	return s.store.StoreSecret(ctx, "cloudflare.api_token", enc)
}

func (s *Service) GetCloudflareToken(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, "cloudflare.api_token")
	if err != nil {
		return "", err
	}
	return s.keystore.Decrypt(enc)
}

func (s *Service) GetRuntimeSettings(ctx context.Context) (RuntimeSettings, error) {
	out := RuntimeSettings{
		Domain:      s.cfg.Domain,
		ACMEEmail:   s.cfg.ACMEEmail,
		ACMEStaging: s.cfg.ACMEStaging,
	}
	if v, err := s.store.GetSetting(ctx, "runtime.base_domain"); err == nil && strings.TrimSpace(v) != "" {
		out.BaseDomain = strings.ToLower(strings.TrimSpace(v))
	} else if strings.TrimSpace(s.cfg.Domain) != "" {
		out.BaseDomain = strings.ToLower(strings.TrimSpace(s.cfg.Domain))
	}
	if out.BaseDomain != "" {
		out.AdminFQDN = "admin." + out.BaseDomain
	}
	if v, err := s.store.GetSetting(ctx, "acme.email"); err == nil && strings.TrimSpace(v) != "" {
		out.ACMEEmail = v
	}
	if v, err := s.store.GetSetting(ctx, "acme.staging"); err == nil && strings.TrimSpace(v) != "" {
		out.ACMEStaging = strings.EqualFold(v, "true")
	}
	if _, err := s.GetCloudflareToken(ctx); err == nil {
		out.HasCFToken = true
	}
	if v, err := s.store.GetSetting(ctx, settingPublicIPv4); err == nil && strings.TrimSpace(v) != "" {
		if ip, ipErr := parseIPv4(v); ipErr == nil {
			out.PublicIPv4 = ip
			s.publicIP = ip
		}
	}
	if out.PublicIPv4 == "" && strings.TrimSpace(s.publicIP) != "" {
		out.PublicIPv4 = strings.TrimSpace(s.publicIP)
	}
	return out, nil
}

func (s *Service) SetRuntimeSettings(ctx context.Context, acmeEmail string, acmeStaging bool, cfToken, publicIPv4, baseDomain string) error {
	acmeEmail = strings.TrimSpace(acmeEmail)
	if acmeEmail != "" {
		if err := s.store.SetSetting(ctx, "acme.email", acmeEmail); err != nil {
			return err
		}
	}
	if err := s.store.SetSetting(ctx, "acme.staging", strconv.FormatBool(acmeStaging)); err != nil {
		return err
	}
	if strings.TrimSpace(cfToken) != "" {
		if err := s.SetCloudflareToken(ctx, cfToken); err != nil {
			return err
		}
	}
	publicIPv4 = strings.TrimSpace(publicIPv4)
	if publicIPv4 != "" {
		ip, err := parseIPv4(publicIPv4)
		if err != nil {
			return err
		}
		if err := s.store.SetSetting(ctx, settingPublicIPv4, ip); err != nil {
			return err
		}
		if err := s.UpdatePublicIP(ctx, ip); err != nil {
			return err
		}
	}
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))
	if baseDomain != "" {
		if _, err := s.store.GetDomainByName(ctx, baseDomain); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("base domain must be one of configured domains")
			}
			return err
		}
		if err := s.store.SetSetting(ctx, "runtime.base_domain", baseDomain); err != nil {
			return err
		}
		if err := s.ensureAdminHostForDomain(ctx, baseDomain); err != nil {
			return fmt.Errorf("admin endpoint setup failed: %w", err)
		}
	} else {
		if err := s.store.SetSetting(ctx, "runtime.base_domain", ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ensureAdminHostForDomain(ctx context.Context, domainName string) error {
	fqdn := "admin." + strings.ToLower(strings.TrimSpace(domainName))
	if fqdn == "admin." {
		return nil
	}
	if _, err := s.store.FindHostByFQDN(ctx, fqdn); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err := s.CreateHost(ctx, domainName, "admin", s.adminUpstreamURL(), false, false, "", nil)
	return err
}

func (s *Service) adminUpstreamURL() string {
	adminUpstream := "http://" + s.cfg.AdminBindAddr
	if strings.HasPrefix(s.cfg.AdminBindAddr, ":") {
		adminUpstream = "http://127.0.0.1" + s.cfg.AdminBindAddr
	}
	return adminUpstream
}

func (s *Service) UpsertDomain(ctx context.Context, name, dnsMode, certMode, provider, zoneID string) (model.Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.Count(name, ".") < 1 {
		return model.Domain{}, fmt.Errorf("invalid domain")
	}
	zoneID = strings.TrimSpace(zoneID)
	if dnsMode == "cloudflare" && zoneID == "" {
		resolved, err := s.resolveCloudflareZoneID(ctx, name)
		if err != nil {
			return model.Domain{}, fmt.Errorf("cloudflare zone resolution failed: %w", err)
		}
		zoneID = resolved
	}
	domain, err := s.store.UpsertDomain(ctx, model.Domain{Name: name, DNSMode: dnsMode, CertMode: certMode, Provider: provider, ZoneID: zoneID, Status: "active"})
	if err != nil {
		return model.Domain{}, err
	}
	if dnsMode != "cloudflare" || s.dns == nil {
		return domain, nil
	}
	publicIP, err := s.ensurePublicIPv4(ctx)
	if err != nil {
		return domain, fmt.Errorf("public ipv4 unavailable for cloudflare setup: %w", err)
	}
	if err := s.dns.UpsertARecord(ctx, zoneID, name, publicIP, false); err != nil {
		return domain, fmt.Errorf("cloudflare apex setup failed: %w", err)
	}
	hosts, err := s.store.ListHostsByDomainID(ctx, domain.ID)
	if err != nil {
		return domain, err
	}
	for _, h := range hosts {
		if err := s.dns.UpsertARecord(ctx, zoneID, h.FQDN, publicIP, false); err != nil {
			return domain, fmt.Errorf("cloudflare host setup failed for %s: %w", h.FQDN, err)
		}
	}
	return domain, nil
}

func (s *Service) RunDomainPreflight(ctx context.Context, name, dnsMode, provider, zoneID string) (DomainPreflight, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	dnsMode = strings.ToLower(strings.TrimSpace(dnsMode))
	provider = strings.ToLower(strings.TrimSpace(provider))
	zoneID = strings.TrimSpace(zoneID)
	out := DomainPreflight{Domain: name, DNSMode: dnsMode, Provider: provider, ZoneID: zoneID, Checks: []DomainPreflightCheck{}}

	if strings.Count(name, ".") < 1 {
		return out, fmt.Errorf("invalid domain")
	}
	publicIP, ipErr := s.currentPublicIPv4(ctx)
	if ipErr != nil {
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "public_ipv4", OK: false, Detail: ipErr.Error()})
	} else {
		out.PublicIPv4 = publicIP
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "public_ipv4", OK: true, Detail: publicIP})
	}

	apexIPs, source, apexErr := resolveIPv4ListRobust(ctx, name)
	apexOK := apexErr == nil && len(apexIPs) > 0
	if apexOK {
		detail := strings.Join(apexIPs, ",")
		if source != "resolver" {
			detail += " via " + source
		}
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "apex_dns_resolves", OK: true, Detail: detail})
	} else {
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "apex_dns_resolves", OK: false, Detail: "no public A record yet"})
	}
	if publicIP != "" && containsString(apexIPs, publicIP) {
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "apex_points_to_server", OK: true, Detail: publicIP})
	} else {
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "apex_points_to_server", OK: false, Detail: "expected " + publicIP})
	}

	if dnsMode == "cloudflare" {
		token, err := s.GetCloudflareToken(ctx)
		if err != nil || strings.TrimSpace(token) == "" {
			out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_token", OK: false, Detail: "missing token"})
			return out, nil
		}
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_token", OK: true})

		resolvedZone := zoneID
		if resolvedZone == "" {
			zone, err := s.resolveCloudflareZoneID(ctx, name)
			if err != nil {
				out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_zone", OK: false, Detail: err.Error()})
				return out, nil
			}
			resolvedZone = zone
		}
		out.ResolvedZone = resolvedZone
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_zone", OK: true, Detail: resolvedZone})

		cf, _ := s.dns.(*dns.Cloudflare)
		if cf == nil {
			return out, fmt.Errorf("cloudflare provider unavailable")
		}
		if err := cf.CheckZoneAccess(ctx, resolvedZone); err != nil {
			out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_api", OK: false, Detail: err.Error()})
			return out, nil
		}
		out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_api", OK: true})

		// For Cloudflare-managed domains, preflight proactively ensures apex A exists.
		if publicIP != "" {
			if err := cf.UpsertARecord(ctx, resolvedZone, name, publicIP, false); err != nil {
				out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_apex_upsert", OK: false, Detail: err.Error()})
			} else {
				out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_apex_upsert", OK: true, Detail: publicIP})
			}
		}
	}

	ready := true
	for _, c := range out.Checks {
		if !c.OK {
			if dnsMode == "cloudflare" && (c.Name == "apex_dns_resolves" || c.Name == "apex_points_to_server") {
				continue
			}
			ready = false
		}
	}
	out.Ready = ready
	return out, nil
}

func (s *Service) RemoveDomain(ctx context.Context, id int64) error {
	return s.store.RemoveDomain(ctx, id)
}

func (s *Service) ListDomains(ctx context.Context) ([]model.Domain, error) {
	return s.store.ListDomains(ctx)
}

func (s *Service) ListHosts(ctx context.Context) ([]model.Host, error) {
	return s.store.ListHosts(ctx)
}

func (s *Service) PublicIPv4(ctx context.Context) string {
	_ = ctx
	return strings.TrimSpace(s.publicIP)
}

func (s *Service) RemoveHost(ctx context.Context, id int64) error {
	return s.store.RemoveHost(ctx, id)
}

func (s *Service) SetHostDisabled(ctx context.Context, hostID int64, disabled bool) (model.Host, error) {
	h, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return model.Host{}, err
	}
	if disabled {
		if h.State == "disabled" {
			return h, nil
		}
		if err := s.store.SetHostState(ctx, hostID, "disabled", "manual_disable"); err != nil {
			return model.Host{}, err
		}
	} else {
		if h.State != "disabled" {
			return h, nil
		}
		if err := s.store.SetHostState(ctx, hostID, "active", "manual_enable"); err != nil {
			return model.Host{}, err
		}
	}
	return s.store.GetHostByID(ctx, hostID)
}

func (s *Service) SetHostMaintenance(ctx context.Context, hostID int64, enabled bool) (model.Host, error) {
	h, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return model.Host{}, err
	}
	if enabled {
		if h.State == "maintenance" {
			return h, nil
		}
		if err := s.store.SetHostState(ctx, hostID, "maintenance", "manual_maintenance_on"); err != nil {
			return model.Host{}, err
		}
	} else {
		if h.State != "maintenance" {
			return h, nil
		}
		if err := s.store.SetHostState(ctx, hostID, "active", "manual_maintenance_off"); err != nil {
			return model.Host{}, err
		}
	}
	return s.store.GetHostByID(ctx, hostID)
}

func normalizeTrafficHours(hours int) int {
	if hours <= 0 {
		return 24
	}
	if hours > 24*30 {
		return 24 * 30
	}
	return hours
}

func (s *Service) GetTrafficOverview(ctx context.Context, hours int) (TrafficOverview, error) {
	hours = normalizeTrafficHours(hours)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := s.store.ListHostTrafficSummaries(ctx, since)
	if err != nil {
		return TrafficOverview{}, err
	}
	out := TrafficOverview{
		Hours:       hours,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Hosts:       make([]HostTrafficSummary, 0, len(rows)),
	}
	visitorSet := map[int64]bool{}
	for _, r := range rows {
		item := HostTrafficSummary{
			HostID:         r.HostID,
			FQDN:           r.FQDN,
			Requests:       r.Requests,
			BytesIn:        r.BytesIn,
			BytesOut:       r.BytesOut,
			Blocked:        r.Blocked,
			Status2xx:      r.Status2xx,
			Status3xx:      r.Status3xx,
			Status4xx:      r.Status4xx,
			Status5xx:      r.Status5xx,
			UniqueVisitors: r.UniqueVisitors,
		}
		out.Hosts = append(out.Hosts, item)
		out.TotalRequests += item.Requests
		out.TotalBytesIn += item.BytesIn
		out.TotalBytesOut += item.BytesOut
		out.TotalBlocked += item.Blocked
		if item.UniqueVisitors > 0 && !visitorSet[item.HostID] {
			out.UniqueVisitors += item.UniqueVisitors
			visitorSet[item.HostID] = true
		}
	}
	return out, nil
}

func (s *Service) GetHostTraffic(ctx context.Context, hostID int64, hours int) (HostTrafficDetails, error) {
	hours = normalizeTrafficHours(hours)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	host, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return HostTrafficDetails{}, err
	}
	seriesRows, err := s.store.GetHostTrafficSeries(ctx, hostID, since)
	if err != nil {
		return HostTrafficDetails{}, err
	}
	uv, err := s.store.CountHostUniqueVisitors(ctx, hostID, since)
	if err != nil {
		return HostTrafficDetails{}, err
	}
	out := HostTrafficDetails{
		Hours:          hours,
		HostID:         hostID,
		FQDN:           host.FQDN,
		UniqueVisitors: uv,
		Series:         make([]TrafficPoint, 0, len(seriesRows)),
	}
	for _, r := range seriesRows {
		p := TrafficPoint{
			BucketStart: r.BucketStart,
			Requests:    r.Requests,
			BytesIn:     r.BytesIn,
			BytesOut:    r.BytesOut,
			Blocked:     r.Blocked,
			Status2xx:   r.Status2xx,
			Status3xx:   r.Status3xx,
			Status4xx:   r.Status4xx,
			Status5xx:   r.Status5xx,
		}
		out.Series = append(out.Series, p)
		out.Requests += p.Requests
		out.BytesIn += p.BytesIn
		out.BytesOut += p.BytesOut
		out.Blocked += p.Blocked
		out.Status2xx += p.Status2xx
		out.Status3xx += p.Status3xx
		out.Status4xx += p.Status4xx
		out.Status5xx += p.Status5xx
	}
	return out, nil
}

func (s *Service) GetTrafficCountries(ctx context.Context, hostID int64, hours int, class string) (TrafficCountryOverview, error) {
	hours = normalizeTrafficHours(hours)
	class = normalizeRequestClass(class)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	out := TrafficCountryOverview{
		Hours:            hours,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		RequestClass:     class,
		Countries:        []CountryTraffic{},
		UnknownBreakdown: []HostCountryTraffic{},
	}
	if hostID > 0 {
		h, err := s.store.GetHostByID(ctx, hostID)
		if err != nil {
			return out, err
		}
		out.HostID = h.ID
		out.HostFQDN = h.FQDN
	}
	rows, err := s.store.ListTrafficCountries(ctx, since, hostID, class)
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Country), "LOCAL") {
			continue
		}
		item := CountryTraffic{
			Country:   r.Country,
			Requests:  r.Requests,
			Blocked:   r.Blocked,
			Status2xx: r.Status2xx,
			Status3xx: r.Status3xx,
			Status4xx: r.Status4xx,
			Status5xx: r.Status5xx,
			BytesOut:  r.BytesOut,
		}
		out.Countries = append(out.Countries, item)
		out.TotalRequests += item.Requests
		out.TotalBlocked += item.Blocked
		out.TotalBytesOut += item.BytesOut
	}
	zzRows, err := s.store.ListHostCountryTraffic(ctx, since, "ZZ", hostID, class)
	if err == nil {
		for _, r := range zzRows {
			out.UnknownBreakdown = append(out.UnknownBreakdown, HostCountryTraffic{
				HostID:    r.HostID,
				FQDN:      r.FQDN,
				Requests:  r.Requests,
				Blocked:   r.Blocked,
				Status2xx: r.Status2xx,
				Status3xx: r.Status3xx,
				Status4xx: r.Status4xx,
				Status5xx: r.Status5xx,
				BytesOut:  r.BytesOut,
			})
		}
	}
	return out, nil
}

func (s *Service) SetHostAuth(ctx context.Context, hostID int64, enabled bool, username, password string) (model.Host, error) {
	h, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return model.Host{}, err
	}
	if !enabled {
		if err := s.store.UpdateHostAuth(ctx, hostID, false, "", ""); err != nil {
			return model.Host{}, err
		}
		return s.store.GetHostByID(ctx, hostID)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return model.Host{}, fmt.Errorf("auth username required")
	}
	passHash := h.AuthPassHash
	if strings.TrimSpace(password) != "" {
		if len(password) < 8 {
			return model.Host{}, fmt.Errorf("auth password must be at least 8 chars")
		}
		passHash, err = crypto.HashPassword(password, crypto.DefaultArgonConfig())
		if err != nil {
			return model.Host{}, err
		}
	}
	if passHash == "" {
		return model.Host{}, fmt.Errorf("auth password required")
	}
	if err := s.store.UpdateHostAuth(ctx, hostID, true, username, passHash); err != nil {
		return model.Host{}, err
	}
	return s.store.GetHostByID(ctx, hostID)
}

func (s *Service) SetHostGeoPolicy(ctx context.Context, hostID int64, mode string, countries []string) (model.Host, error) {
	if _, err := s.store.GetHostByID(ctx, hostID); err != nil {
		return model.Host{}, err
	}
	normalizedMode, normalizedCountries, err := normalizeHostGeoPolicy(mode, countries)
	if err != nil {
		return model.Host{}, err
	}
	if err := s.store.UpdateHostGeoPolicy(ctx, hostID, normalizedMode, normalizedCountries); err != nil {
		return model.Host{}, err
	}
	return s.store.GetHostByID(ctx, hostID)
}

func (s *Service) UpdateHostRouting(ctx context.Context, hostID int64, upstream string, insecureTLS bool, haEnabled bool, haMode string, haBackends []model.HABackend) (model.Host, error) {
	current, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return model.Host{}, err
	}
	// Keep existing upstream when switching non-HA settings without editing the URL field.
	if !haEnabled && strings.TrimSpace(upstream) == "" {
		upstream = current.UpstreamURL
	}
	upstream, haMode, haBackends, err = validateRoutingInput(strings.TrimSpace(upstream), haEnabled, haMode, haBackends)
	if err != nil {
		return model.Host{}, err
	}
	if !haEnabled {
		haMode = ""
		haBackends = nil
	}
	if err := s.store.UpdateHostRouting(ctx, hostID, upstream, insecureTLS, haEnabled, haMode, haBackends); err != nil {
		return model.Host{}, err
	}
	return s.store.GetHostByID(ctx, hostID)
}

func (s *Service) CreateHost(ctx context.Context, domainName, subdomain, upstream string, insecureTLS bool, haEnabled bool, haMode string, haBackends []model.HABackend) (model.Host, error) {
	d, err := s.store.GetDomainByName(ctx, strings.ToLower(domainName))
	if err != nil {
		return model.Host{}, err
	}
	if subdomain == "" || strings.Contains(subdomain, ".") {
		return model.Host{}, fmt.Errorf("subdomain must be single label")
	}
	upstream, haMode, haBackends, err = validateRoutingInput(strings.TrimSpace(upstream), haEnabled, haMode, haBackends)
	if err != nil {
		return model.Host{}, err
	}
	fqdn := fmt.Sprintf("%s.%s", strings.ToLower(subdomain), d.Name)

	h, err := s.store.CreateHost(ctx, d.ID, strings.ToLower(subdomain), fqdn, upstream, insecureTLS, haEnabled, haMode, haBackends)
	if err != nil {
		return model.Host{}, err
	}
	if err := s.store.SetHostState(ctx, h.ID, "dns_pending", "created"); err != nil {
		return h, err
	}
	if d.DNSMode == "cloudflare" && s.dns != nil {
		zoneID, err := s.ensureDomainZoneID(ctx, d)
		if err != nil {
			_ = s.store.SetHostState(ctx, h.ID, "error", "dns: missing zone id on domain")
			return h, err
		}
		publicIP, err := s.ensurePublicIPv4(ctx)
		if err != nil {
			_ = s.store.SetHostState(ctx, h.ID, "error", "dns: missing public ipv4")
			return h, err
		}
		if err := s.dns.UpsertARecord(ctx, zoneID, d.Name, publicIP, false); err != nil {
			_ = s.store.SetHostState(ctx, h.ID, "error", "dns: "+err.Error())
			return h, err
		}
		if err := s.dns.UpsertARecord(ctx, zoneID, fqdn, publicIP, false); err != nil {
			_ = s.store.SetHostState(ctx, h.ID, "error", "dns: "+err.Error())
			return h, err
		}
	}
	if err := s.store.SetHostState(ctx, h.ID, "cert_pending", "dns_ok"); err != nil {
		return h, err
	}
	if err := s.store.SetHostState(ctx, h.ID, "active", "cert_manager_async"); err != nil {
		return h, err
	}
	return s.store.GetHostByID(ctx, h.ID)
}

func (s *Service) RunHostPreflight(ctx context.Context, domainName, subdomain, upstream string, insecureTLS bool, haEnabled bool, haMode string, haBackends []model.HABackend) (HostPreflight, error) {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	upstream = strings.TrimSpace(upstream)
	out := HostPreflight{Domain: domainName, Upstream: upstream, InsecureTLS: insecureTLS, Checks: []HostPreflightCheck{}}

	d, err := s.store.GetDomainByName(ctx, domainName)
	if err != nil {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "domain_exists", OK: false, Detail: "unknown domain"})
		return out, nil
	}
	out.DNSMode = d.DNSMode
	out.Provider = d.Provider
	out.ZoneID = d.ZoneID
	out.Checks = append(out.Checks, HostPreflightCheck{Name: "domain_exists", OK: true})

	if subdomain == "" || strings.Contains(subdomain, ".") {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "subdomain_label", OK: false, Detail: "single label required"})
		return out, nil
	}
	out.Checks = append(out.Checks, HostPreflightCheck{Name: "subdomain_label", OK: true})

	upstream, haMode, haBackends, err = validateRoutingInput(upstream, haEnabled, haMode, haBackends)
	if err != nil {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "routing_config", OK: false, Detail: err.Error()})
		return out, nil
	}
	if haEnabled {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "ha_mode", OK: true, Detail: haMode})
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "ha_backends", OK: true, Detail: strconv.Itoa(len(haBackends))})
	} else {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "upstream_url", OK: true})
	}

	fqdn := fmt.Sprintf("%s.%s", subdomain, d.Name)
	out.FQDN = fqdn
	if _, err := s.store.FindHostByFQDN(ctx, fqdn); err == nil {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "fqdn_available", OK: false, Detail: "already exists"})
	} else if errors.Is(err, sql.ErrNoRows) {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "fqdn_available", OK: true})
	} else {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "fqdn_available", OK: false, Detail: err.Error()})
	}

	checkURL := upstream
	if haEnabled && len(haBackends) > 0 {
		checkURL = haBackends[0].URL
	}
	if st := probeHTTPStatus(ctx, checkURL, insecureTLS); st >= 200 && st < 600 {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "upstream_reachable", OK: true, Detail: strconv.Itoa(st)})
	} else {
		out.Checks = append(out.Checks, HostPreflightCheck{Name: "upstream_reachable", OK: false, Detail: "upstream not reachable from server"})
	}

	if d.DNSMode == "cloudflare" {
		if _, err := s.ensurePublicIPv4(ctx); err != nil {
			out.Checks = append(out.Checks, HostPreflightCheck{Name: "public_ipv4", OK: false, Detail: err.Error()})
		} else {
			out.Checks = append(out.Checks, HostPreflightCheck{Name: "public_ipv4", OK: true})
		}
		if _, err := s.ensureDomainZoneID(ctx, d); err != nil {
			out.Checks = append(out.Checks, HostPreflightCheck{Name: "cloudflare_zone", OK: false, Detail: err.Error()})
		} else {
			out.Checks = append(out.Checks, HostPreflightCheck{Name: "cloudflare_zone", OK: true})
		}
	}

	ready := true
	for _, c := range out.Checks {
		if !c.OK {
			ready = false
			break
		}
	}
	out.Ready = ready
	return out, nil
}

func validateRoutingInput(upstream string, haEnabled bool, haMode string, haBackends []model.HABackend) (string, string, []model.HABackend, error) {
	validateURL := func(raw string) error {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid upstream URL")
		}
		return nil
	}
	if !haEnabled {
		if err := validateURL(upstream); err != nil {
			return "", "", nil, err
		}
		return strings.TrimSpace(upstream), "", nil, nil
	}
	mode := strings.ToLower(strings.TrimSpace(haMode))
	if mode == "" {
		mode = "failover"
	}
	if mode != "failover" && mode != "round_robin" {
		return "", "", nil, fmt.Errorf("invalid ha mode")
	}
	out := make([]model.HABackend, 0, len(haBackends))
	seen := map[string]bool{}
	for i, b := range haBackends {
		url := strings.TrimSpace(b.URL)
		name := strings.TrimSpace(b.Name)
		if name == "" {
			name = fmt.Sprintf("backend-%d", i+1)
		}
		if url == "" || seen[url] {
			continue
		}
		if err := validateURL(url); err != nil {
			return "", "", nil, fmt.Errorf("invalid ha backend URL")
		}
		seen[url] = true
		out = append(out, model.HABackend{Name: name, URL: url})
	}
	if len(out) < 2 {
		return "", "", nil, fmt.Errorf("ha requires at least 2 backends")
	}
	return out[0].URL, mode, out, nil
}

func normalizeHostGeoPolicy(mode string, countries []string) (string, []string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "", "off":
		return "", nil, nil
	case "allow":
	case "deny":
	default:
		return "", nil, fmt.Errorf("invalid geo mode")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(countries))
	for _, c := range countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return "", nil, fmt.Errorf("invalid country code: %s", c)
		}
		seen[c] = true
		out = append(out, c)
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("at least one country code required for geo policy")
	}
	return mode, out, nil
}

func (s *Service) UpdatePublicIP(ctx context.Context, ip string) error {
	ipv4, err := parseIPv4(ip)
	if err != nil {
		return err
	}
	if ipv4 != s.publicIP {
		old := s.publicIP
		s.publicIP = ipv4
		s.log.Info("public IP changed", map[string]any{"old": old, "new": s.publicIP})
	}

	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return err
	}
	for _, d := range domains {
		if d.DNSMode != "cloudflare" || s.dns == nil {
			continue
		}
		zoneID, err := s.ensureDomainZoneID(ctx, d)
		if err != nil {
			s.log.Warn("dynDNS skipped, zone resolution failed", map[string]any{"domain": d.Name, "err": err.Error()})
			continue
		}
		if err := s.dns.UpsertARecord(ctx, zoneID, d.Name, s.publicIP, false); err != nil {
			s.log.Warn("dynDNS update failed", map[string]any{"domain": d.Name, "err": err.Error()})
		}
	}
	return nil
}

func (s *Service) RetryHost(ctx context.Context, hostID int64) error {
	next, ok := s.backoff[hostID]
	if ok && time.Now().Before(next) {
		return fmt.Errorf("retry backoff active until %s", next.Format(time.RFC3339))
	}
	h, err := s.store.GetHostByID(ctx, hostID)
	if err != nil {
		return err
	}
	if h.State != "error" {
		return fmt.Errorf("host not in error state")
	}
	delay := 30 * time.Second
	if strings.Contains(h.ErrorReason, "rate") {
		delay = 5 * time.Minute
	}
	s.backoff[hostID] = time.Now().Add(delay)
	if err := s.store.SetHostState(ctx, hostID, "dns_pending", "manual_retry"); err != nil {
		return err
	}
	if err := s.store.SetHostState(ctx, hostID, "cert_pending", "manual_retry"); err != nil {
		return err
	}
	return s.store.SetHostState(ctx, hostID, "active", "manual_retry")
}

func (s *Service) GetHostsDiagnostics(ctx context.Context) ([]HostDiagnostic, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]HostDiagnostic, 0, len(hosts))
	for _, h := range hosts {
		d := s.diagnoseHost(ctx, h.FQDN)
		if h.HAEnabled && len(h.HABackends) > 0 {
			d.HAEnabled = true
			d.HAMode = h.HAMode
			d.HATotal = len(h.HABackends)
			for _, b := range h.HABackends {
				st := probeHTTPStatus(ctx, b.URL, h.InsecureTLS)
				if st >= 200 && st < 600 {
					d.HAOnline++
				} else {
					if strings.TrimSpace(b.Name) != "" {
						d.HAOffline = append(d.HAOffline, b.Name)
					} else {
						d.HAOffline = append(d.HAOffline, b.URL)
					}
				}
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *Service) RunDomainLiveCheck(ctx context.Context, domainID int64) (DomainLiveCheck, error) {
	domain, err := s.store.GetDomainByID(ctx, domainID)
	if err != nil {
		return DomainLiveCheck{}, err
	}
	hosts, err := s.store.ListHostsByDomainID(ctx, domainID)
	if err != nil {
		return DomainLiveCheck{}, err
	}

	out := DomainLiveCheck{
		Domain:    domain.Name,
		DNSMode:   domain.DNSMode,
		Provider:  domain.Provider,
		Hosts:     []HostLiveCheck{},
		OverallOK: true,
	}
	serverIP, ipErr := s.currentPublicIPv4(ctx)
	if ipErr != nil {
		out.Warnings = append(out.Warnings, "public IPv4 unavailable: "+ipErr.Error())
	}
	out.ServerIPv4 = serverIP

	apexIPs, apexSource, err := resolveIPv4ListRobust(ctx, domain.Name)
	if err == nil && len(apexIPs) > 0 {
		out.ApexDNSOK = true
		if apexSource != "resolver" {
			out.Warnings = append(out.Warnings, "apex DNS resolved via "+apexSource+" fallback")
		}
	} else {
		out.OverallOK = false
	}
	if serverIP != "" && containsString(apexIPs, serverIP) {
		out.ApexPointsToServer = true
	} else if serverIP != "" {
		out.OverallOK = false
	}

	var cfClient *dns.Cloudflare
	if domain.DNSMode == "cloudflare" {
		resolvedZoneID, zoneErr := s.ensureDomainZoneID(ctx, domain)
		if zoneErr == nil {
			domain.ZoneID = resolvedZoneID
		}
		out.CloudflareZoneID = domain.ZoneID
		token, err := s.GetCloudflareToken(ctx)
		if err != nil || strings.TrimSpace(token) == "" {
			out.CloudflareError = "cloudflare token missing"
			out.OverallOK = false
		} else if strings.TrimSpace(domain.ZoneID) == "" {
			if zoneErr != nil {
				out.CloudflareError = "cloudflare zone resolution failed: " + zoneErr.Error()
			} else {
				out.CloudflareError = "cloudflare zone id missing on domain"
			}
			out.OverallOK = false
		} else {
			cfClient = dns.NewCloudflare(token)
			if err := cfClient.CheckZoneAccess(ctx, domain.ZoneID); err != nil {
				out.CloudflareError = err.Error()
				out.OverallOK = false
			} else {
				out.CloudflareAPIOK = true
			}
		}
	}

	for _, h := range hosts {
		ch := HostLiveCheck{FQDN: h.FQDN}
		ips, hostSource, err := resolveIPv4ListRobust(ctx, h.FQDN)
		if err == nil && len(ips) > 0 {
			ch.DNSOK = true
			if hostSource != "resolver" {
				ch.Error = joinErr(ch.Error, "dns via "+hostSource+" fallback")
			}
		} else {
			ch.Error = "dns unresolved"
			out.OverallOK = false
		}
		if serverIP != "" && containsString(ips, serverIP) {
			ch.DNSPointsToServer = true
		} else if serverIP != "" {
			out.OverallOK = false
		}
		primaryIP := ""
		if len(ips) > 0 {
			primaryIP = ips[0]
		}
		probeIP := primaryIP
		if serverIP != "" && primaryIP == serverIP {
			probeIP = "127.0.0.1"
		}
		if st := probeHTTPStatusForHost(ctx, h.FQDN, probeIP); st > 0 {
			ch.HTTPReachable = true
		} else {
			out.OverallOK = false
		}
		httpsStatus, tlsOK, daysLeft := probeHTTPSAndCertForHost(ctx, h.FQDN, probeIP)
		if httpsStatus > 0 {
			ch.HTTPSReachable = true
		}
		ch.TLSOK = tlsOK
		ch.CertDaysLeft = daysLeft
		if !tlsOK {
			out.OverallOK = false
		}

		if cfClient != nil && out.CloudflareAPIOK {
			found, err := cfClient.HasRecord(ctx, domain.ZoneID, h.FQDN)
			if err != nil {
				ch.Error = joinErr(ch.Error, "cloudflare lookup failed")
				out.OverallOK = false
			} else {
				ch.CloudflareRecordFound = found
				if !found {
					out.OverallOK = false
				}
			}
		}
		out.Hosts = append(out.Hosts, ch)
	}

	return out, nil
}

func resolveIPv4ListRobust(ctx context.Context, host string) ([]string, string, error) {
	if ip, err := parseIPv4(host); err == nil {
		return []string{ip}, "literal-ip", nil
	}

	if shouldPreferLocalResolver(host) {
		if ips, err := resolveIPv4List(ctx, host); err == nil && len(ips) > 0 {
			return ips, "resolver", nil
		}
		if ips, err := resolveIPv4ViaDOH(ctx, "https://dns.google/resolve", host); err == nil && len(ips) > 0 {
			return ips, "doh-google", nil
		}
		if ips, err := resolveIPv4ViaDOH(ctx, "https://cloudflare-dns.com/dns-query", host); err == nil && len(ips) > 0 {
			return ips, "doh-cloudflare", nil
		}
		return nil, "", fmt.Errorf("dns unresolved")
	}

	if ips, err := resolveIPv4ViaDOH(ctx, "https://dns.google/resolve", host); err == nil && len(ips) > 0 {
		return ips, "doh-google", nil
	}
	if ips, err := resolveIPv4ViaDOH(ctx, "https://cloudflare-dns.com/dns-query", host); err == nil && len(ips) > 0 {
		return ips, "doh-cloudflare", nil
	}
	if ips, err := resolveIPv4List(ctx, host); err == nil && len(ips) > 0 {
		return ips, "resolver", nil
	}
	return nil, "", fmt.Errorf("dns unresolved")
}

func shouldPreferLocalResolver(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return false
	}
	if !strings.Contains(h, ".") {
		return true
	}
	localSuffixes := []string{
		".local",
		".lan",
		".internal",
		".home.arpa",
		".localhost",
	}
	for _, suffix := range localSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

func (s *Service) resolveCloudflareZoneID(ctx context.Context, domain string) (string, error) {
	cf, ok := s.dns.(*dns.Cloudflare)
	if !ok || cf == nil {
		return "", fmt.Errorf("cloudflare provider unavailable")
	}
	return cf.ResolveZoneIDByName(ctx, domain)
}

func (s *Service) ensureDomainZoneID(ctx context.Context, d model.Domain) (string, error) {
	if strings.TrimSpace(d.ZoneID) != "" {
		return strings.TrimSpace(d.ZoneID), nil
	}
	resolved, err := s.resolveCloudflareZoneID(ctx, d.Name)
	if err != nil {
		return "", err
	}
	d.ZoneID = resolved
	if _, err := s.store.UpsertDomain(ctx, d); err != nil {
		return "", err
	}
	return resolved, nil
}

func (s *Service) InitializePublicIPv4(ctx context.Context) {
	ip, err := s.currentPublicIPv4(ctx)
	if err != nil {
		s.log.Warn("public IPv4 initialization failed", map[string]any{"err": err.Error()})
		return
	}
	s.publicIP = ip
	s.log.Info("public IPv4 initialized", map[string]any{"ip": ip})
}

func (s *Service) currentPublicIPv4(ctx context.Context) (string, error) {
	if ip, err := parseIPv4(strings.TrimSpace(s.publicIP)); err == nil {
		return ip, nil
	}
	if v, err := s.store.GetSetting(ctx, settingPublicIPv4); err == nil {
		ip, ipErr := parseIPv4(v)
		if ipErr != nil {
			return "", fmt.Errorf("invalid settings public ipv4: %w", ipErr)
		}
		s.publicIP = ip
		return ip, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	ip, err := detectPublicIPv4(ctx)
	if err != nil {
		return "", err
	}
	if err := s.store.SetSetting(ctx, settingPublicIPv4, ip); err != nil {
		return "", err
	}
	s.publicIP = ip
	return ip, nil
}

func (s *Service) ensurePublicIPv4(ctx context.Context) (string, error) {
	ip, err := s.currentPublicIPv4(ctx)
	if err != nil {
		return "", err
	}
	if err := s.UpdatePublicIP(ctx, ip); err != nil {
		return "", err
	}
	return ip, nil
}

func parseIPv4(raw string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("invalid IPv4")
	}
	return parsed.String(), nil
}

func (s *Service) diagnoseHost(ctx context.Context, fqdn string) HostDiagnostic {
	d := HostDiagnostic{FQDN: fqdn}
	rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	ips, source, err := resolveIPv4ListRobust(rctx, fqdn)
	if err == nil {
		d.DNSRecords = ips
		if source != "resolver" {
			d.Error = "dns: resolved via " + source
		}
	} else {
		d.Error = "dns: unresolved (" + err.Error() + ")"
	}

	primaryIP := ""
	if len(d.DNSRecords) > 0 {
		primaryIP = d.DNSRecords[0]
	}
	probeIP := primaryIP
	if strings.TrimSpace(s.publicIP) != "" && primaryIP == strings.TrimSpace(s.publicIP) {
		probeIP = "127.0.0.1"
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if probeIP != "" {
		httpClient.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(probeIP, "80"))
			},
		}
	}
	reqHTTP, _ := http.NewRequestWithContext(rctx, http.MethodGet, "http://"+fqdn, nil)
	reqHTTP.Host = fqdn
	if resp, err := httpClient.Do(reqHTTP); err == nil {
		d.HTTPStatus = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	tlsTarget := net.JoinHostPort(fqdn, "443")
	if probeIP != "" {
		tlsTarget = net.JoinHostPort(probeIP, "443")
	}
	tlsDialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(tlsDialer, "tcp", tlsTarget, &tls.Config{
		ServerName:         fqdn,
		InsecureSkipVerify: true,
	})
	if err == nil {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			d.TLSOK = true
			d.CertSubject = c.Subject.String()
			d.CertIssuer = c.Issuer.String()
			d.CertNotAfter = c.NotAfter.UTC().Format(time.RFC3339)
			d.CertDaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
		}
		_ = conn.Close()
	} else if d.Error == "" {
		d.Error = "tls: " + err.Error()
	}

	httpsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if probeIP != "" {
		httpsTransport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(probeIP, "443"))
		}
		httpsTransport.TLSClientConfig.ServerName = fqdn
	}
	httpsClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpsTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	reqHTTPS, _ := http.NewRequestWithContext(rctx, http.MethodGet, "https://"+fqdn, nil)
	reqHTTPS.Host = fqdn
	if resp, err := httpsClient.Do(reqHTTPS); err == nil {
		d.HTTPSStatus = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return d
}

func resolveIPv4List(ctx context.Context, host string) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, ip := range addrs {
		if v4 := ip.IP.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out, nil
}

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

func resolveIPv4ViaDOH(ctx context.Context, endpoint, host string) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?name="+url.QueryEscape(host)+"&type=A", nil)
	req.Header.Set("accept", "application/dns-json")
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("doh status=%d", resp.StatusCode)
	}
	var out dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != 0 {
		return nil, fmt.Errorf("doh rcode=%d", out.Status)
	}
	ips := []string{}
	for _, a := range out.Answer {
		if a.Type != 1 {
			continue
		}
		if ip, err := parseIPv4(a.Data); err == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records")
	}
	return ips, nil
}

func detectPublicIPv4(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 response")
	}
	return ip, nil
}

func probeHTTPStatus(ctx context.Context, rawURL string, insecureTLS bool) int {
	transport := &http.Transport{}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c := &http.Client{
		Timeout:   8 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func probeHTTPSAndCert(ctx context.Context, host string) (status int, tlsOK bool, certDaysLeft int) {
	tlsDialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(tlsDialer, "tcp", host+":443", &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err == nil {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			tlsOK = true
			certDaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
		}
		_ = conn.Close()
	}

	c := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host, nil)
	resp, err := c.Do(req)
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		status = resp.StatusCode
	}
	return status, tlsOK, certDaysLeft
}

func probeHTTPStatusForHost(ctx context.Context, host, ip string) int {
	if strings.TrimSpace(ip) == "" {
		return probeHTTPStatus(ctx, "http://"+host, false)
	}
	c := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 8 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host, nil)
	req.Host = host
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func probeHTTPSAndCertForHost(ctx context.Context, host, ip string) (status int, tlsOK bool, certDaysLeft int) {
	if strings.TrimSpace(ip) == "" {
		return probeHTTPSAndCert(ctx, host)
	}
	tlsDialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(tlsDialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err == nil {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			tlsOK = true
			certDaysLeft = int(time.Until(c.NotAfter).Hours() / 24)
		}
		_ = conn.Close()
	}

	c := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 8 * time.Second}
				return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host, nil)
	req.Host = host
	resp, err := c.Do(req)
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		status = resp.StatusCode
	}
	return status, tlsOK, certDaysLeft
}

func containsString(items []string, v string) bool {
	for _, i := range items {
		if i == v {
			return true
		}
	}
	return false
}

func joinErr(base, add string) string {
	if strings.TrimSpace(base) == "" {
		return add
	}
	return base + "; " + add
}

func (s *Service) ListAPITokens(ctx context.Context, limit int) ([]model.APIToken, error) {
	return s.store.ListAPITokens(ctx, limit)
}

func (s *Service) RevokeAPIToken(ctx context.Context, id int64) error {
	return s.store.RevokeAPIToken(ctx, id)
}

func (s *Service) CreatePasswordResetToken(ctx context.Context, username string, ttl time.Duration) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username required")
	}
	u, err := s.store.FindUserByUsername(ctx, username)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := "prt_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	if err := s.store.CreatePasswordResetToken(ctx, u.ID, hash, time.Now().UTC().Add(ttl)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) ConsumePasswordResetToken(ctx context.Context, token, newPassword string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("token required")
	}
	if len(newPassword) < 10 {
		return fmt.Errorf("password too short")
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	userID, err := s.store.ConsumePasswordResetToken(ctx, hash)
	if err != nil {
		return err
	}
	newHash, err := crypto.HashPassword(newPassword, crypto.DefaultArgonConfig())
	if err != nil {
		return err
	}
	if err := s.store.SetUserPasswordHashByID(ctx, userID, newHash); err != nil {
		return err
	}
	return nil
}

func (s *Service) CreateManagedUser(ctx context.Context, username, password string, role model.Role, domainIDs []int64) (ManagedUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return ManagedUser{}, fmt.Errorf("username required")
	}
	if len(password) < 10 {
		return ManagedUser{}, fmt.Errorf("password too short")
	}
	if role != model.RoleAdmin && role != model.RoleDomainAdmin {
		return ManagedUser{}, fmt.Errorf("role must be admin or domain-admin")
	}
	hash, err := crypto.HashPassword(password, crypto.DefaultArgonConfig())
	if err != nil {
		return ManagedUser{}, err
	}
	u, err := s.store.CreateUser(ctx, username, role, hash)
	if err != nil {
		return ManagedUser{}, err
	}
	if role == model.RoleDomainAdmin {
		if len(domainIDs) == 0 {
			return ManagedUser{}, fmt.Errorf("domain-admin requires at least one domain assignment")
		}
		if err := s.store.SetUserDomainScopes(ctx, u.ID, domainIDs); err != nil {
			return ManagedUser{}, err
		}
	}
	ids, _ := s.store.GetUserDomainIDs(ctx, u.ID)
	return ManagedUser{ID: u.ID, Username: u.Username, Role: u.Role, DomainIDs: ids, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}, nil
}

func (s *Service) ListManagedUsers(ctx context.Context) ([]ManagedUser, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ManagedUser, 0, len(users))
	for _, u := range users {
		ids, _ := s.store.GetUserDomainIDs(ctx, u.ID)
		out = append(out, ManagedUser{ID: u.ID, Username: u.Username, Role: u.Role, DomainIDs: ids, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt})
	}
	return out, nil
}

func (s *Service) SetManagedUserDomains(ctx context.Context, userID int64, domainIDs []int64) error {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.Role != model.RoleDomainAdmin {
		return fmt.Errorf("user is not domain-admin")
	}
	if len(domainIDs) == 0 {
		return fmt.Errorf("domain-admin requires at least one domain assignment")
	}
	return s.store.SetUserDomainScopes(ctx, userID, domainIDs)
}

func (s *Service) DeleteManagedUser(ctx context.Context, userID int64) error {
	return s.store.DeleteUser(ctx, userID)
}

func (s *Service) SetManagedUserPassword(ctx context.Context, userID int64, newPassword string) error {
	if len(newPassword) < 10 {
		return fmt.Errorf("password too short")
	}
	if _, err := s.store.GetUserByID(ctx, userID); err != nil {
		return err
	}
	newHash, err := crypto.HashPassword(newPassword, crypto.DefaultArgonConfig())
	if err != nil {
		return err
	}
	return s.store.SetUserPasswordHashByID(ctx, userID, newHash)
}

func (s *Service) ChangeOwnPassword(ctx context.Context, userID int64, currentPassword, newPassword string) error {
	if strings.TrimSpace(currentPassword) == "" {
		return fmt.Errorf("current password required")
	}
	if len(newPassword) < 10 {
		return fmt.Errorf("password too short")
	}
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !crypto.VerifyPassword(currentPassword, u.PasswordHash) {
		return fmt.Errorf("invalid current password")
	}
	newHash, err := crypto.HashPassword(newPassword, crypto.DefaultArgonConfig())
	if err != nil {
		return err
	}
	return s.store.SetUserPasswordHashByID(ctx, userID, newHash)
}
