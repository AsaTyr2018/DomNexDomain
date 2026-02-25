package app

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/config"
	"github.com/domnexdomain/domnexdomain/internal/crypto"
	"github.com/domnexdomain/domnexdomain/internal/dns"
	"github.com/domnexdomain/domnexdomain/internal/firewall"
	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/mfa"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"github.com/domnexdomain/domnexdomain/internal/store"
	"golang.org/x/crypto/ssh"
)

type Service struct {
	cfg              config.Config
	store            *store.Store
	keystore         *crypto.Keystore
	dns              dns.Provider
	log              *logx.Logger
	publicIP         string
	backoff          map[int64]time.Time
	logMu            sync.RWMutex
	logCfg           LogServerSettings
	logToken         string
	logCh            chan model.AuditEvent
	hostName         string
	tiMu             sync.RWMutex
	tiSnap           model.ThreatIntelSnapshot
	tiWinMu          sync.Mutex
	tiWin            map[string]tiWindow
	sigMu            sync.RWMutex
	sigRules         []threatSignatureRule
	sigEnabled       bool
	sigAutoUpdate    bool
	sigLastSync      time.Time
	sigSourceURL     string
	sigSourceHash    string
	sysMu            sync.Mutex
	netLast          uint64
	netLastT         time.Time
	setupMu          sync.Mutex
	setupInitialized bool
	setupOTSHash     [32]byte
	setupOTSExpires  time.Time
	setupUnlockUntil time.Time
	setupAttempts    int
	setupCooldown    time.Time
	setupRestore     *backupSnapshot
	backupRunMu      sync.Mutex
	nft              *firewall.NftEnforcer
}

type tiWindow struct {
	start      time.Time
	perSignal  map[string]int
	categories map[string]bool
}

const settingPublicIPv4 = "network.public_ipv4"
const defaultThreatIntelFeedURL = "https://lists.blocklist.de/lists/all.txt"
const defaultThreatIntelSignatureURL = "https://raw.githubusercontent.com/AsaTyr2018/DomNexDomain/main/security/signatures/threat-signatures.json"
const (
	settingTimeSyncMode          = "runtime.time_sync_mode"
	settingTimeSyncLANServers    = "runtime.time_sync_lan_servers"
	settingLogServers            = "runtime.log_servers"
	settingRetentionAuditDays    = "runtime.retention.audit_days"
	settingRetentionTrafficDays  = "runtime.retention.traffic_days"
	settingRetentionVisitorsDays = "runtime.retention.visitors_days"
	settingRetentionThreatDays   = "runtime.retention.threat_days"
	settingRetentionBlockedDays  = "runtime.retention.blocked_days"
	settingRetentionLoginDays    = "runtime.retention.login_days"
	settingRetentionResetDays    = "runtime.retention.password_reset_days"
	settingMFAEnforceAdmin       = "auth.mfa.enforce_admin"
	settingMFAEnforceDomainAdmin = "auth.mfa.enforce_domain_admin"
	settingMFAEnforceReadOnly    = "auth.mfa.enforce_read_only"
	settingLDAPConfig            = "auth.ldap.config"
	settingOIDCConfig            = "auth.oidc.config"
)

const (
	defaultTIMonitorMaxLevel  = 2
	defaultTISoftMinLevel     = 3
	defaultTIHardLevel        = 6
	defaultTISoftBlockMinutes = 15
	defaultTIHardToWatchDays  = 60
	defaultTIWatchLevel       = 3
)

type RuntimeSettings struct {
	Domain              string            `json:"domain"`
	BaseDomain          string            `json:"baseDomain"`
	AdminFQDN           string            `json:"adminFqdn"`
	ACMEEmail           string            `json:"acmeEmail"`
	ACMEStaging         bool              `json:"acmeStaging"`
	HasCFToken          bool              `json:"hasCloudflareToken"`
	PublicIPv4          string            `json:"publicIpv4"`
	StyleProfile        string            `json:"styleProfile"`
	StyleCustom         string            `json:"styleCustom"`
	TimeSyncMode        string            `json:"timeSyncMode"`
	TimeSyncLANServers  []string          `json:"timeSyncLANServers"`
	LogServers          LogServerSettings `json:"logServers"`
	HasLogHTTPBearer    bool              `json:"hasLogHTTPBearer"`
	Retention           RetentionPolicy   `json:"retention"`
	MFAPolicy           MFAPolicy         `json:"mfaPolicy"`
	LDAP                LDAPSettings      `json:"ldap"`
	HasLDAPBindPass     bool              `json:"hasLdapBindPassword"`
	OIDC                OIDCSettings      `json:"oidc"`
	HasOIDCClientSecret bool              `json:"hasOidcClientSecret"`
}

type LDAPSettings struct {
	Enabled              bool    `json:"enabled"`
	URL                  string  `json:"url"`
	StartTLS             bool    `json:"startTls"`
	InsecureSkipVerify   bool    `json:"insecureSkipVerify"`
	BindDN               string  `json:"bindDn"`
	UserBaseDN           string  `json:"userBaseDn"`
	GroupBaseDN          string  `json:"groupBaseDn"`
	UserAttr             string  `json:"userAttr"`
	AdminGroup           string  `json:"adminGroup"`
	DomainAdminGroup     string  `json:"domainAdminGroup"`
	ReadOnlyGroup        string  `json:"readOnlyGroup"`
	DomainAdminDomainIDs []int64 `json:"domainAdminDomainIds"`
}

type OIDCSettings struct {
	Enabled              bool    `json:"enabled"`
	IssuerURL            string  `json:"issuerUrl"`
	ClientID             string  `json:"clientId"`
	RedirectURL          string  `json:"redirectUrl"`
	Scopes               string  `json:"scopes"`
	UsernameClaim        string  `json:"usernameClaim"`
	GroupsClaim          string  `json:"groupsClaim"`
	AdminGroup           string  `json:"adminGroup"`
	DomainAdminGroup     string  `json:"domainAdminGroup"`
	ReadOnlyGroup        string  `json:"readOnlyGroup"`
	DomainAdminDomainIDs []int64 `json:"domainAdminDomainIds"`
}

type MFAPolicy struct {
	EnforceAdmin       bool `json:"enforceAdmin"`
	EnforceDomainAdmin bool `json:"enforceDomainAdmin"`
	EnforceReadOnly    bool `json:"enforceReadOnly"`
}

type RetentionPolicy struct {
	AuditDays         int `json:"auditDays"`
	TrafficDays       int `json:"trafficDays"`
	VisitorsDays      int `json:"visitorsDays"`
	ThreatDays        int `json:"threatDays"`
	BlockedDays       int `json:"blockedDays"`
	LoginAttemptDays  int `json:"loginAttemptDays"`
	PasswordResetDays int `json:"passwordResetDays"`
}

type RetentionPurgeResult struct {
	AuditEvents         int64 `json:"auditEvents"`
	TrafficBuckets      int64 `json:"trafficBuckets"`
	VisitorHashes       int64 `json:"visitorHashes"`
	ThreatMatches       int64 `json:"threatMatches"`
	ThreatStates        int64 `json:"threatStates"`
	BlockedIPs          int64 `json:"blockedIps"`
	LoginAttempts       int64 `json:"loginAttempts"`
	PasswordResetTokens int64 `json:"passwordResetTokens"`
}

func (r RetentionPurgeResult) Total() int64 {
	return r.AuditEvents + r.TrafficBuckets + r.VisitorHashes + r.ThreatMatches + r.ThreatStates + r.BlockedIPs + r.LoginAttempts + r.PasswordResetTokens
}

type TimeSyncProbe struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	OK       bool   `json:"ok"`
	OffsetMS int64  `json:"offsetMs"`
	RTTMS    int64  `json:"rttMs"`
	Error    string `json:"error,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type TimeSyncStatus struct {
	Mode     string          `json:"mode"`
	Healthy  bool            `json:"healthy"`
	Severity string          `json:"severity"`
	Summary  string          `json:"summary"`
	Source   string          `json:"source"`
	OffsetMS int64           `json:"offsetMs"`
	Checked  time.Time       `json:"checkedAt"`
	Probes   []TimeSyncProbe `json:"probes"`
}

type SystemHealthStatus struct {
	CPUPercent         float64 `json:"cpuPercent"`
	RAMPercent         float64 `json:"ramPercent"`
	RAMTotalBytes      uint64  `json:"ramTotalBytes"`
	RAMUsedBytes       uint64  `json:"ramUsedBytes"`
	NetworkLoadPct     float64 `json:"networkLoadPct"`
	NetworkBaselineBps uint64  `json:"networkBaselineBps"`
	NetworkBytesPerSec uint64  `json:"networkBytesPerSec"`
	Load1              float64 `json:"load1"`
	CPUCores           int     `json:"cpuCores"`
}

type ManagedUser struct {
	ID              int64                       `json:"id"`
	Username        string                      `json:"username"`
	Role            model.Role                  `json:"role"`
	AuthProvider    string                      `json:"authProvider"`
	DomainIDs       []int64                     `json:"domainIds"`
	GroupMembership []model.UserGroupMembership `json:"groupMemberships,omitempty"`
	AllowedCIDRs    string                      `json:"allowedCidrs"`
	IPCheckDisabled bool                        `json:"ipCheckDisabled"`
	MFAEnabled      bool                        `json:"mfaEnabled"`
	MFAEnrolledAt   time.Time                   `json:"mfaEnrolledAt"`
	CreatedAt       time.Time                   `json:"createdAt"`
	UpdatedAt       time.Time                   `json:"updatedAt"`
}

type MFAStatus struct {
	Enabled                bool      `json:"enabled"`
	RequiredByPolicy       bool      `json:"requiredByPolicy"`
	EnrolledAt             time.Time `json:"enrolledAt"`
	RecoveryCodesRemaining int       `json:"recoveryCodesRemaining"`
}

type MFAEnrollStart struct {
	Secret    string `json:"secret"`
	OTPAuth   string `json:"otpAuthUri"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	StartedAt string `json:"startedAt"`
}

type MFAEnrollConfirm struct {
	Enabled       bool      `json:"enabled"`
	EnrolledAt    time.Time `json:"enrolledAt"`
	RecoveryCodes []string  `json:"recoveryCodes"`
}

type GeoIPSourceFile struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

type GeoIPStats struct {
	SourceFiles        int       `json:"sourceFiles"`
	SourceCSVFiles     int       `json:"sourceCSVFiles"`
	SourceMMDBFiles    int       `json:"sourceMMDBFiles"`
	SourceBytes        int64     `json:"sourceBytes"`
	CompiledPath       string    `json:"compiledPath"`
	CompiledExists     bool      `json:"compiledExists"`
	CompiledSize       int64     `json:"compiledSize"`
	CompiledModTime    time.Time `json:"compiledModTime,omitempty"`
	LastCompileAt      time.Time `json:"lastCompileAt,omitempty"`
	LastCompileSources int       `json:"lastCompileSources"`
	LastCompileRecords int       `json:"lastCompileRecords"`
	LastUploadAt       time.Time `json:"lastUploadAt,omitempty"`
	LastUploadFile     string    `json:"lastUploadFile"`
}

func (s *Service) GetSystemHealth(ctx context.Context) (SystemHealthStatus, error) {
	_ = ctx
	load1, err := readLoad1Linux()
	if err != nil {
		return SystemHealthStatus{}, err
	}
	memPct, memUsedBytes, memTotalBytes, err := readRAMUsagePercentLinux()
	if err != nil {
		return SystemHealthStatus{}, err
	}
	now := time.Now().UTC()
	totalBytes, err := readNetworkBytesLinux()
	if err != nil {
		return SystemHealthStatus{}, err
	}
	cores := runtime.NumCPU()
	cpuPct := 0.0
	if cores > 0 {
		cpuPct = (load1 / float64(cores)) * 100.0
	}
	if cpuPct < 0 {
		cpuPct = 0
	}
	s.sysMu.Lock()
	netBps := uint64(0)
	if !s.netLastT.IsZero() && now.After(s.netLastT) {
		sec := now.Sub(s.netLastT).Seconds()
		if sec > 0 {
			delta := totalBytes
			if totalBytes >= s.netLast {
				delta = totalBytes - s.netLast
			}
			netBps = uint64(float64(delta) / sec)
		}
	}
	s.netLast = totalBytes
	s.netLastT = now
	s.sysMu.Unlock()
	// 100 Mbps baseline for the gauge; values above are clamped to 100%.
	const gaugeBaselineBps = (100 * 1000 * 1000) / 8
	netPct := (float64(netBps) / float64(gaugeBaselineBps)) * 100.0
	if netPct < 0 {
		netPct = 0
	}
	return SystemHealthStatus{
		CPUPercent:         cpuPct,
		RAMPercent:         memPct,
		RAMTotalBytes:      memTotalBytes,
		RAMUsedBytes:       memUsedBytes,
		NetworkLoadPct:     netPct,
		NetworkBaselineBps: gaugeBaselineBps,
		NetworkBytesPerSec: netBps,
		Load1:              load1,
		CPUCores:           cores,
	}, nil
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

type SSHBastionKeyCreateResult struct {
	Key              model.SSHBastionKey `json:"key"`
	PrivateKey       string              `json:"privateKey,omitempty"`
	PrivateKeyPPK    string              `json:"privateKeyPpk,omitempty"`
	PublicKeyRFC4716 string              `json:"publicKeyRfc4716,omitempty"`
	PPKError         string              `json:"ppkError,omitempty"`
}

type ThreatIntelMatchesPage struct {
	Items    []model.ThreatIntelMatch `json:"items"`
	Total    int64                    `json:"total"`
	Page     int                      `json:"page"`
	PageSize int                      `json:"pageSize"`
}

type ThreatIntelOffendersPage struct {
	Items    []model.ThreatIntelOffender `json:"items"`
	Total    int64                       `json:"total"`
	Page     int                         `json:"page"`
	PageSize int                         `json:"pageSize"`
}

type ThreatIntelBlockedPage struct {
	Items    []model.ThreatIntelBlocked `json:"items"`
	Total    int64                      `json:"total"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"pageSize"`
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
	hname, _ := os.Hostname()
	svc := &Service{
		cfg:      cfg,
		store:    st,
		keystore: ks,
		dns:      dnsProvider,
		log:      log,
		backoff:  map[int64]time.Time{},
		logCfg:   defaultLogServerSettings(),
		logCh:    make(chan model.AuditEvent, 2048),
		hostName: strings.TrimSpace(hname),
		tiSnap: model.ThreatIntelSnapshot{
			Mode:             "monitor_only",
			EventMinHits:     2,
			OffenderMinHits:  10,
			MonitorMaxLevel:  defaultTIMonitorMaxLevel,
			SoftMinLevel:     defaultTISoftMinLevel,
			HardLevel:        defaultTIHardLevel,
			SoftBlockMinutes: defaultTISoftBlockMinutes,
			Allowlist:        map[string]bool{},
			FeedByIP:         map[string][]string{},
		},
		tiWin: map[string]tiWindow{},
		nft:   firewall.NewNftEnforcer(),
	}
	if svc.hostName == "" {
		svc.hostName = "domnexdomain"
	}
	st.SetAuditHook(func(e model.AuditEvent) {
		svc.enqueueRemoteAudit(e)
	})
	svc.syncLogServerSettings(context.Background())
	go svc.runRemoteAuditDispatcher()
	return svc
}

func (s *Service) Store() *store.Store { return s.store }

func (s *Service) Bootstrap(ctx context.Context, bootstrapUser, bootstrapPass string) error {
	if err := s.EnsureIdentityTemplates(ctx); err != nil {
		s.log.Warn("identity templates setup failed", map[string]any{"err": err.Error()})
	}
	if err := s.store.EnsureThreatIntelDefaultFeed(ctx, defaultThreatIntelFeedURL); err != nil {
		s.log.Warn("threat intel default feed setup failed", map[string]any{"err": err.Error()})
	}
	s.ensureThreatSignaturesLoaded(ctx)
	if err := s.syncThreatSignatures(ctx, false); err != nil {
		s.log.Warn("threat signature sync failed", map[string]any{"err": err.Error()})
	}
	if _, err := s.GetThreatIntelSnapshot(ctx); err != nil {
		s.log.Warn("threat intel snapshot init failed", map[string]any{"err": err.Error()})
	}
	if strings.TrimSpace(bootstrapPass) == "" {
		// Setup assistant mode: no automatic admin/domain bootstrap.
		if err := s.ensureSetupState(ctx); err != nil {
			return err
		}
		return nil
	}
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
	return s.ensureSetupState(ctx)
}

func (s *Service) ListFQDNs(ctx context.Context) ([]string, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hosts)+len(domains))
	seen := map[string]bool{}
	for _, d := range domains {
		if strings.EqualFold(strings.TrimSpace(d.Status), "inactive") {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(d.Name))
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, h := range hosts {
		if h.State == "active" || h.State == "cert_pending" || h.State == "maintenance" || h.State == "disabled" {
			fqdn := strings.ToLower(strings.TrimSpace(h.FQDN))
			if fqdn != "" && !seen[fqdn] {
				seen[fqdn] = true
				out = append(out, fqdn)
			}
		}
	}
	return out, nil
}

func (s *Service) ListCatchAllDomains(ctx context.Context) ([]string, error) {
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		dnsMode := strings.ToLower(strings.TrimSpace(d.DNSMode))
		certMode := strings.ToLower(strings.TrimSpace(d.CertMode))
		if dnsMode != "cloudflare" {
			continue
		}
		// Keep HTTP-01 default behavior but allow opt-in catch-all mode.
		// For backwards compatibility, existing "letsencrypt" Cloudflare domains
		// are treated as catch-all enabled as well.
		if certMode == "letsencrypt" || certMode == "letsencrypt-catchall" {
			out = append(out, strings.ToLower(strings.TrimSpace(d.Name)))
		}
	}
	return out, nil
}

func (s *Service) ListWildcardDomains(ctx context.Context) ([]string, error) {
	domains, err := s.store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if strings.ToLower(strings.TrimSpace(d.DNSMode)) != "cloudflare" {
			continue
		}
		certMode := strings.ToLower(strings.TrimSpace(d.CertMode))
		if !strings.HasPrefix(certMode, "letsencrypt") {
			continue
		}
		out = append(out, strings.ToLower(strings.TrimSpace(d.Name)))
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
		Domain:       s.cfg.Domain,
		ACMEEmail:    s.cfg.ACMEEmail,
		ACMEStaging:  s.cfg.ACMEStaging,
		StyleProfile: "monolith",
		TimeSyncMode: "system_only",
		LogServers:   defaultLogServerSettings(),
		Retention:    defaultRetentionPolicy(),
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
	if v, err := s.store.GetSetting(ctx, "runtime.style_profile"); err == nil && strings.TrimSpace(v) != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "monolith", "cybermonolith", "custom":
			out.StyleProfile = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if v, err := s.store.GetSetting(ctx, "runtime.style_custom"); err == nil {
		out.StyleCustom = strings.TrimSpace(v)
	}
	if v, err := s.store.GetSetting(ctx, settingTimeSyncMode); err == nil && strings.TrimSpace(v) != "" {
		out.TimeSyncMode = normalizeTimeSyncMode(v)
	}
	if v, err := s.store.GetSetting(ctx, settingTimeSyncLANServers); err == nil {
		out.TimeSyncLANServers = parseTimeSyncServerList(v)
	}
	if cfg, _, hasToken, err := s.loadLogServerSettings(ctx); err == nil {
		out.LogServers = cfg
		out.HasLogHTTPBearer = hasToken
	}
	out.Retention = s.getRetentionPolicy(ctx)
	out.MFAPolicy = s.getMFAPolicy(ctx)
	out.LDAP = s.getLDAPSettings(ctx)
	if _, err := s.store.GetSecret(ctx, "auth.ldap.bind_password"); err == nil {
		out.HasLDAPBindPass = true
	}
	out.OIDC = s.getOIDCSettings(ctx)
	if _, err := s.store.GetSecret(ctx, "auth.oidc.client_secret"); err == nil {
		out.HasOIDCClientSecret = true
	}
	return out, nil
}

func (s *Service) SetRuntimeSettings(ctx context.Context, acmeEmail string, acmeStaging bool, cfToken, publicIPv4, baseDomain, styleProfile, styleCustom, timeSyncMode, timeSyncLANServers string, logServers LogServerSettings, logHTTPBearer string, retention RetentionPolicy, mfaPolicy MFAPolicy, ldap LDAPSettings, ldapBindPass string, oidc OIDCSettings, oidcClientSecret string) error {
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
	styleProfile = strings.ToLower(strings.TrimSpace(styleProfile))
	if styleProfile == "" {
		styleProfile = "monolith"
	}
	switch styleProfile {
	case "monolith", "cybermonolith", "custom":
	default:
		return fmt.Errorf("invalid style profile")
	}
	if err := s.store.SetSetting(ctx, "runtime.style_profile", styleProfile); err != nil {
		return err
	}
	styleCustom = strings.TrimSpace(styleCustom)
	if styleCustom != "" {
		var tmp map[string]string
		if err := json.Unmarshal([]byte(styleCustom), &tmp); err != nil {
			return fmt.Errorf("invalid style custom json: %w", err)
		}
		if len(tmp) > 32 {
			return fmt.Errorf("style custom json has too many keys")
		}
	}
	if err := s.store.SetSetting(ctx, "runtime.style_custom", styleCustom); err != nil {
		return err
	}
	timeSyncMode = normalizeTimeSyncMode(timeSyncMode)
	lanServers := parseTimeSyncServerList(timeSyncLANServers)
	if timeSyncMode == "external_lan" && len(lanServers) == 0 {
		return fmt.Errorf("at least one LAN NTP server is required for external_lan mode")
	}
	if err := s.applySystemTimeSyncPolicy(ctx, timeSyncMode, lanServers); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingTimeSyncMode, timeSyncMode); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingTimeSyncLANServers, strings.Join(lanServers, ",")); err != nil {
		return err
	}
	if err := s.applyLogServerSettings(ctx, logServers, logHTTPBearer); err != nil {
		return err
	}
	retention = normalizeRetentionPolicy(retention)
	if err := s.store.SetSetting(ctx, settingRetentionAuditDays, strconv.Itoa(retention.AuditDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionTrafficDays, strconv.Itoa(retention.TrafficDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionVisitorsDays, strconv.Itoa(retention.VisitorsDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionThreatDays, strconv.Itoa(retention.ThreatDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionBlockedDays, strconv.Itoa(retention.BlockedDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionLoginDays, strconv.Itoa(retention.LoginAttemptDays)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingRetentionResetDays, strconv.Itoa(retention.PasswordResetDays)); err != nil {
		return err
	}
	mfaPolicy = normalizeMFAPolicy(mfaPolicy)
	if err := s.store.SetSetting(ctx, settingMFAEnforceAdmin, strconv.FormatBool(mfaPolicy.EnforceAdmin)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingMFAEnforceDomainAdmin, strconv.FormatBool(mfaPolicy.EnforceDomainAdmin)); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingMFAEnforceReadOnly, strconv.FormatBool(mfaPolicy.EnforceReadOnly)); err != nil {
		return err
	}
	ldap = normalizeLDAPSettings(ldap)
	if ldap.Enabled {
		if strings.TrimSpace(ldap.URL) == "" {
			return fmt.Errorf("ldap url required when ldap is enabled")
		}
		if strings.TrimSpace(ldap.BindDN) == "" {
			return fmt.Errorf("ldap bind dn required when ldap is enabled")
		}
		if strings.TrimSpace(ldap.UserBaseDN) == "" {
			return fmt.Errorf("ldap user base dn required when ldap is enabled")
		}
		if strings.TrimSpace(ldap.GroupBaseDN) == "" {
			return fmt.Errorf("ldap group base dn required when ldap is enabled")
		}
		if strings.TrimSpace(ldap.AdminGroup) == "" && strings.TrimSpace(ldap.DomainAdminGroup) == "" && strings.TrimSpace(ldap.ReadOnlyGroup) == "" {
			return fmt.Errorf("at least one ldap role mapping group is required")
		}
	}
	if err := s.store.SetSetting(ctx, settingLDAPConfig, mustJSON(ldap)); err != nil {
		return err
	}
	if strings.TrimSpace(ldapBindPass) != "" {
		enc, err := s.keystore.Encrypt(strings.TrimSpace(ldapBindPass))
		if err != nil {
			return err
		}
		if err := s.store.StoreSecret(ctx, "auth.ldap.bind_password", enc); err != nil {
			return err
		}
	}
	oidc = normalizeOIDCSettings(oidc)
	if oidc.Enabled {
		if strings.TrimSpace(oidc.IssuerURL) == "" {
			return fmt.Errorf("oidc issuer url required when oidc is enabled")
		}
		if strings.TrimSpace(oidc.ClientID) == "" {
			return fmt.Errorf("oidc client id required when oidc is enabled")
		}
		if strings.TrimSpace(oidc.RedirectURL) == "" {
			return fmt.Errorf("oidc redirect url required when oidc is enabled")
		}
		if strings.TrimSpace(oidc.AdminGroup) == "" && strings.TrimSpace(oidc.DomainAdminGroup) == "" && strings.TrimSpace(oidc.ReadOnlyGroup) == "" {
			return fmt.Errorf("at least one oidc role mapping group is required")
		}
		if strings.TrimSpace(oidcClientSecret) == "" {
			if _, err := s.store.GetSecret(ctx, "auth.oidc.client_secret"); err != nil {
				return fmt.Errorf("oidc client secret required when oidc is enabled")
			}
		}
	}
	if err := s.store.SetSetting(ctx, settingOIDCConfig, mustJSON(oidc)); err != nil {
		return err
	}
	if strings.TrimSpace(oidcClientSecret) != "" {
		enc, err := s.keystore.Encrypt(strings.TrimSpace(oidcClientSecret))
		if err != nil {
			return err
		}
		if err := s.store.StoreSecret(ctx, "auth.oidc.client_secret", enc); err != nil {
			return err
		}
	}
	return nil
}

func normalizeLDAPSettings(in LDAPSettings) LDAPSettings {
	out := in
	out.URL = strings.TrimSpace(out.URL)
	out.BindDN = strings.TrimSpace(out.BindDN)
	out.UserBaseDN = strings.TrimSpace(out.UserBaseDN)
	out.GroupBaseDN = strings.TrimSpace(out.GroupBaseDN)
	out.UserAttr = strings.TrimSpace(out.UserAttr)
	if out.UserAttr == "" {
		out.UserAttr = "uid"
	}
	out.AdminGroup = strings.TrimSpace(out.AdminGroup)
	out.DomainAdminGroup = strings.TrimSpace(out.DomainAdminGroup)
	out.ReadOnlyGroup = strings.TrimSpace(out.ReadOnlyGroup)
	d := out.DomainAdminDomainIDs[:0]
	seen := map[int64]bool{}
	for _, id := range out.DomainAdminDomainIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		d = append(d, id)
	}
	out.DomainAdminDomainIDs = d
	return out
}

func (s *Service) getLDAPSettings(ctx context.Context) LDAPSettings {
	raw, err := s.store.GetSetting(ctx, settingLDAPConfig)
	if err != nil || strings.TrimSpace(raw) == "" {
		return normalizeLDAPSettings(LDAPSettings{})
	}
	var out LDAPSettings
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return normalizeLDAPSettings(LDAPSettings{})
	}
	return normalizeLDAPSettings(out)
}

func normalizeOIDCSettings(in OIDCSettings) OIDCSettings {
	out := in
	out.IssuerURL = strings.TrimSpace(out.IssuerURL)
	out.ClientID = strings.TrimSpace(out.ClientID)
	out.RedirectURL = strings.TrimSpace(out.RedirectURL)
	out.Scopes = strings.TrimSpace(out.Scopes)
	out.UsernameClaim = strings.TrimSpace(out.UsernameClaim)
	if out.UsernameClaim == "" {
		out.UsernameClaim = "preferred_username"
	}
	out.GroupsClaim = strings.TrimSpace(out.GroupsClaim)
	if out.GroupsClaim == "" {
		out.GroupsClaim = "groups"
	}
	out.AdminGroup = strings.TrimSpace(out.AdminGroup)
	out.DomainAdminGroup = strings.TrimSpace(out.DomainAdminGroup)
	out.ReadOnlyGroup = strings.TrimSpace(out.ReadOnlyGroup)
	d := out.DomainAdminDomainIDs[:0]
	seen := map[int64]bool{}
	for _, id := range out.DomainAdminDomainIDs {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		d = append(d, id)
	}
	out.DomainAdminDomainIDs = d
	return out
}

func (s *Service) getOIDCSettings(ctx context.Context) OIDCSettings {
	raw, err := s.store.GetSetting(ctx, settingOIDCConfig)
	if err != nil || strings.TrimSpace(raw) == "" {
		return normalizeOIDCSettings(OIDCSettings{})
	}
	var out OIDCSettings
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return normalizeOIDCSettings(OIDCSettings{})
	}
	return normalizeOIDCSettings(out)
}

func (s *Service) GetOIDCSettings(ctx context.Context) OIDCSettings {
	return s.getOIDCSettings(ctx)
}

func (s *Service) GetOIDCClientSecret(ctx context.Context) (string, error) {
	enc, err := s.store.GetSecret(ctx, "auth.oidc.client_secret")
	if err != nil {
		return "", err
	}
	return s.keystore.Decrypt(enc)
}

func (s *Service) ResolveOIDCRole(ctx context.Context, groups []string, cfg OIDCSettings) (model.Role, []int64, error) {
	groupSet := map[string]bool{}
	for _, g := range groups {
		g = strings.ToLower(strings.TrimSpace(g))
		if g != "" {
			groupSet[g] = true
		}
	}
	admin := strings.ToLower(strings.TrimSpace(cfg.AdminGroup))
	domAdmin := strings.ToLower(strings.TrimSpace(cfg.DomainAdminGroup))
	readOnly := strings.ToLower(strings.TrimSpace(cfg.ReadOnlyGroup))

	switch {
	case admin != "" && groupSet[admin]:
		return model.RoleAdmin, nil, nil
	case domAdmin != "" && groupSet[domAdmin]:
		ids := append([]int64(nil), cfg.DomainAdminDomainIDs...)
		if len(ids) == 0 {
			all, err := s.store.ListDomainIDs(ctx)
			if err == nil {
				ids = all
			}
		}
		return model.RoleDomainAdmin, ids, nil
	case readOnly != "" && groupSet[readOnly]:
		return model.RoleReadOnly, nil, nil
	default:
		return "", nil, fmt.Errorf("oidc group mapping missing")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func normalizeMFAPolicy(in MFAPolicy) MFAPolicy {
	return MFAPolicy{
		EnforceAdmin:       in.EnforceAdmin,
		EnforceDomainAdmin: in.EnforceDomainAdmin,
		EnforceReadOnly:    in.EnforceReadOnly,
	}
}

func (s *Service) getMFAPolicy(ctx context.Context) MFAPolicy {
	out := MFAPolicy{}
	if v, err := s.store.GetSetting(ctx, settingMFAEnforceAdmin); err == nil {
		out.EnforceAdmin = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.store.GetSetting(ctx, settingMFAEnforceDomainAdmin); err == nil {
		out.EnforceDomainAdmin = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, err := s.store.GetSetting(ctx, settingMFAEnforceReadOnly); err == nil {
		out.EnforceReadOnly = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return out
}

func defaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		AuditDays:         90,
		TrafficDays:       30,
		VisitorsDays:      30,
		ThreatDays:        60,
		BlockedDays:       60,
		LoginAttemptDays:  30,
		PasswordResetDays: 7,
	}
}

func normalizeRetentionPolicy(in RetentionPolicy) RetentionPolicy {
	def := defaultRetentionPolicy()
	out := in
	if out.AuditDays < 1 {
		out.AuditDays = def.AuditDays
	}
	if out.TrafficDays < 1 {
		out.TrafficDays = def.TrafficDays
	}
	if out.VisitorsDays < 1 {
		out.VisitorsDays = def.VisitorsDays
	}
	if out.ThreatDays < 1 {
		out.ThreatDays = def.ThreatDays
	}
	if out.BlockedDays < 1 {
		out.BlockedDays = def.BlockedDays
	}
	if out.LoginAttemptDays < 1 {
		out.LoginAttemptDays = def.LoginAttemptDays
	}
	if out.PasswordResetDays < 1 {
		out.PasswordResetDays = def.PasswordResetDays
	}
	if out.AuditDays > 3650 {
		out.AuditDays = 3650
	}
	if out.TrafficDays > 3650 {
		out.TrafficDays = 3650
	}
	if out.VisitorsDays > 3650 {
		out.VisitorsDays = 3650
	}
	if out.ThreatDays > 3650 {
		out.ThreatDays = 3650
	}
	if out.BlockedDays > 3650 {
		out.BlockedDays = 3650
	}
	if out.LoginAttemptDays > 3650 {
		out.LoginAttemptDays = 3650
	}
	if out.PasswordResetDays > 3650 {
		out.PasswordResetDays = 3650
	}
	return out
}

func (s *Service) getRetentionPolicy(ctx context.Context) RetentionPolicy {
	out := defaultRetentionPolicy()
	if v, err := s.store.GetSetting(ctx, settingRetentionAuditDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.AuditDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionTrafficDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.TrafficDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionVisitorsDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.VisitorsDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionThreatDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.ThreatDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionBlockedDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.BlockedDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionLoginDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.LoginAttemptDays = n
		}
	}
	if v, err := s.store.GetSetting(ctx, settingRetentionResetDays); err == nil {
		if n, nerr := strconv.Atoi(strings.TrimSpace(v)); nerr == nil {
			out.PasswordResetDays = n
		}
	}
	return normalizeRetentionPolicy(out)
}

func (s *Service) ApplyStoredTimeSyncPolicy(ctx context.Context) error {
	mode := "system_only"
	if v, err := s.store.GetSetting(ctx, settingTimeSyncMode); err == nil && strings.TrimSpace(v) != "" {
		mode = normalizeTimeSyncMode(v)
	}
	lan := []string{}
	if v, err := s.store.GetSetting(ctx, settingTimeSyncLANServers); err == nil && strings.TrimSpace(v) != "" {
		lan = parseTimeSyncServerList(v)
	}
	return s.applySystemTimeSyncPolicy(ctx, mode, lan)
}

func (s *Service) applySystemTimeSyncPolicy(ctx context.Context, mode string, lanServers []string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	mode = normalizeTimeSyncMode(mode)
	iface, err := defaultRouteInterface(ctx)
	if err != nil {
		return err
	}
	var servers []string
	switch mode {
	case "external_public":
		servers = []string{"time.cloudflare.com", "time.google.com", "time.apple.com"}
	case "external_lan":
		servers = append(servers, lanServers...)
		if len(servers) == 0 {
			return fmt.Errorf("at least one LAN NTP server is required for external_lan mode")
		}
	default:
		servers = nil
	}
	enable := exec.CommandContext(ctx, "timedatectl", "--no-ask-password", "set-ntp", "true")
	if out, err := enable.CombinedOutput(); err != nil {
		return fmt.Errorf("enable ntp failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if len(servers) == 0 {
		revert := exec.CommandContext(ctx, "timedatectl", "--no-ask-password", "revert", iface)
		if out, err := revert.CombinedOutput(); err != nil {
			return fmt.Errorf("revert ntp servers failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	args := []string{"--no-ask-password", "ntp-servers", iface}
	args = append(args, servers...)
	setServers := exec.CommandContext(ctx, "timedatectl", args...)
	if out, err := setServers.CombinedOutput(); err != nil {
		return fmt.Errorf("set ntp servers failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultRouteInterface(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("detect default route interface failed: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				iface := strings.TrimSpace(fields[i+1])
				if iface != "" {
					return iface, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no default route interface found")
}

func (s *Service) GetStyleSettings(ctx context.Context) (string, string, error) {
	profile := "monolith"
	if v, err := s.store.GetSetting(ctx, "runtime.style_profile"); err == nil && strings.TrimSpace(v) != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "monolith", "cybermonolith", "custom":
			profile = strings.ToLower(strings.TrimSpace(v))
		}
	}
	custom := ""
	if v, err := s.store.GetSetting(ctx, "runtime.style_custom"); err == nil {
		custom = strings.TrimSpace(v)
	}
	return profile, custom, nil
}

func normalizeTimeSyncMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "system_only", "external_public", "external_lan":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "system_only"
	}
}

func parseTimeSyncServerList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(strings.ToLower(p))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func (s *Service) GetTimeSyncStatus(ctx context.Context) (TimeSyncStatus, error) {
	mode := "system_only"
	if v, err := s.store.GetSetting(ctx, settingTimeSyncMode); err == nil && strings.TrimSpace(v) != "" {
		mode = normalizeTimeSyncMode(v)
	}
	status := TimeSyncStatus{
		Mode:    mode,
		Checked: time.Now().UTC(),
	}
	switch mode {
	case "external_public":
		return s.checkExternalNTP(ctx, mode, []string{"time.cloudflare.com", "time.google.com", "time.apple.com"}), nil
	case "external_lan":
		lan := []string{}
		if v, err := s.store.GetSetting(ctx, settingTimeSyncLANServers); err == nil {
			lan = parseTimeSyncServerList(v)
		}
		if len(lan) == 0 {
			status.Severity = "critical"
			status.Summary = "No LAN NTP server configured."
			return status, nil
		}
		return s.checkExternalNTP(ctx, mode, lan), nil
	default:
		return s.checkSystemClock(ctx), nil
	}
}

func (s *Service) checkSystemClock(ctx context.Context) TimeSyncStatus {
	status := TimeSyncStatus{
		Mode:     "system_only",
		Checked:  time.Now().UTC(),
		Severity: "critical",
		Summary:  "System clock sync status unknown.",
	}
	p := TimeSyncProbe{Name: "system_clock", Target: "timedatectl"}
	cmd := exec.CommandContext(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "-p", "SystemClockSynchronized", "-p", "NTPService")
	out, err := cmd.Output()
	if err != nil {
		p.OK = false
		p.Error = err.Error()
		status.Probes = []TimeSyncProbe{p}
		status.Source = "timedatectl"
		status.Summary = "Unable to read system NTP sync state."
		return status
	}
	kv := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		kv[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	ntpOK := strings.EqualFold(kv["NTPSynchronized"], "yes")
	sysOK := strings.EqualFold(kv["SystemClockSynchronized"], "yes")
	p.OK = ntpOK || sysOK
	p.Detail = "NTPSynchronized=" + kv["NTPSynchronized"] + ";SystemClockSynchronized=" + kv["SystemClockSynchronized"]
	status.Probes = []TimeSyncProbe{p}
	status.Source = strings.TrimSpace(kv["NTPService"])
	if status.Source == "" {
		status.Source = "system"
	}
	if p.OK {
		status.Healthy = true
		status.Severity = "ok"
		status.Summary = "System clock is synchronized."
	} else {
		status.Healthy = false
		status.Severity = "critical"
		status.Summary = "System clock is not synchronized."
	}
	return status
}

func (s *Service) checkExternalNTP(ctx context.Context, mode string, servers []string) TimeSyncStatus {
	status := TimeSyncStatus{
		Mode:    mode,
		Checked: time.Now().UTC(),
	}
	offsets := make([]int64, 0, len(servers))
	success := 0
	probes := make([]TimeSyncProbe, 0, len(servers))
	for _, server := range servers {
		p := probeNTPServer(ctx, server)
		probes = append(probes, p)
		if p.OK {
			success++
			offsets = append(offsets, p.OffsetMS)
		}
	}
	status.Probes = probes
	status.Source = "ntp"
	required := 1
	if mode == "external_public" {
		required = 2
	}
	if success < required || len(offsets) == 0 {
		status.Healthy = false
		status.Severity = "critical"
		status.Summary = "NTP check failed or insufficient successful probes."
		return status
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	median := offsets[len(offsets)/2]
	status.OffsetMS = median
	abs := median
	if abs < 0 {
		abs = -abs
	}
	if abs >= 5000 {
		status.Healthy = false
		status.Severity = "critical"
		status.Summary = "Clock drift is critical (" + strconv.FormatInt(median, 10) + "ms)."
		return status
	}
	if abs >= 1000 {
		status.Healthy = true
		status.Severity = "warn"
		status.Summary = "Clock drift warning (" + strconv.FormatInt(median, 10) + "ms)."
		return status
	}
	status.Healthy = true
	status.Severity = "ok"
	status.Summary = "Clock drift within safe range (" + strconv.FormatInt(median, 10) + "ms)."
	return status
}

func probeNTPServer(ctx context.Context, server string) TimeSyncProbe {
	p := TimeSyncProbe{Name: "ntp", Target: server}
	target := strings.TrimSpace(server)
	if target == "" {
		p.Error = "empty target"
		return p
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "123")
	}
	var d net.Dialer
	d.Timeout = 2 * time.Second
	conn, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := make([]byte, 48)
	req[0] = 0x1B
	t0 := time.Now()
	if _, err := conn.Write(req); err != nil {
		p.Error = err.Error()
		return p
	}
	resp := make([]byte, 48)
	if _, err := io.ReadFull(conn, resp); err != nil {
		p.Error = err.Error()
		return p
	}
	t1 := time.Now()
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	const ntpUnixOffset = 2208988800
	if secs < ntpUnixOffset {
		p.Error = "invalid ntp timestamp"
		return p
	}
	unixSec := int64(secs) - ntpUnixOffset
	nsec := (int64(frac) * 1e9) >> 32
	serverTime := time.Unix(unixSec, nsec)
	mid := t0.Add(t1.Sub(t0) / 2)
	p.OK = true
	p.OffsetMS = serverTime.Sub(mid).Milliseconds()
	p.RTTMS = t1.Sub(t0).Milliseconds()
	return p
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
	dnsMode = strings.ToLower(strings.TrimSpace(dnsMode))
	certMode = strings.ToLower(strings.TrimSpace(certMode))
	if certMode == "" {
		certMode = "letsencrypt"
	}
	if dnsMode == "cloudflare" && certMode == "letsencrypt" {
		// Cloudflare-managed domains can safely operate in catch-all ACME mode
		// so unknown subdomains can receive certificates on-demand.
		certMode = "letsencrypt-catchall"
	}
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
	if err := s.dns.UpsertARecord(ctx, zoneID, "*."+name, publicIP, false); err != nil {
		return domain, fmt.Errorf("cloudflare wildcard setup failed: %w", err)
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
			if err := cf.UpsertARecord(ctx, resolvedZone, "*."+name, publicIP, false); err != nil {
				out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_wildcard_upsert", OK: false, Detail: err.Error()})
			} else {
				out.Checks = append(out.Checks, DomainPreflightCheck{Name: "cloudflare_wildcard_upsert", OK: true, Detail: "*." + name + " -> " + publicIP})
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

func (s *Service) DeactivateDomain(ctx context.Context, id int64) error {
	if _, err := s.store.GetDomainByID(ctx, id); err != nil {
		return err
	}
	hosts, err := s.store.ListHostsByDomainID(ctx, id)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if h.State == "disabled" {
			continue
		}
		if err := s.store.SetHostState(ctx, h.ID, "disabled", "domain_deactivated"); err != nil {
			return err
		}
	}
	return s.store.SetDomainStatus(ctx, id, "inactive")
}

func (s *Service) ListDomains(ctx context.Context) ([]model.Domain, error) {
	return s.store.ListDomains(ctx)
}

func (s *Service) ListHosts(ctx context.Context) ([]model.Host, error) {
	return s.store.ListHosts(ctx)
}

func (s *Service) AddAuditEvent(ctx context.Context, e model.AuditEvent) error {
	return s.store.AddAuditEvent(ctx, e)
}

func (s *Service) IsSourceBlocked(ctx context.Context, ip string) (bool, bool, time.Time, string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, false, time.Time{}, "", nil
	}
	blocked, err := s.store.IsIPBlocked(ctx, ip)
	if err != nil {
		return false, false, time.Time{}, "", err
	}
	if blocked {
		return true, true, time.Time{}, "blocked_ips", nil
	}
	st, err := s.store.GetThreatIntelIPState(ctx, ip)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, time.Time{}, "", nil
		}
		return false, false, time.Time{}, "", err
	}
	now := time.Now().UTC()
	if st.PermBlocked {
		return true, true, time.Time{}, "threat_intel_hardblock", nil
	}
	if !st.BanUntil.IsZero() && st.BanUntil.After(now) {
		return true, false, st.BanUntil, "threat_intel_softblock", nil
	}
	return false, false, time.Time{}, "", nil
}

func (s *Service) PublicIPv4(ctx context.Context) string {
	_ = ctx
	return strings.TrimSpace(s.publicIP)
}

func (s *Service) RemoveHost(ctx context.Context, id int64) error {
	h, err := s.store.GetHostByID(ctx, id)
	if err != nil {
		return err
	}
	d, err := s.store.GetDomainByID(ctx, h.DomainID)
	if err != nil {
		return err
	}
	if d.DNSMode == "cloudflare" && s.dns != nil {
		zoneID, err := s.ensureDomainZoneID(ctx, d)
		if err != nil {
			return fmt.Errorf("cloudflare zone resolution failed: %w", err)
		}
		if err := s.dns.DeleteARecord(ctx, zoneID, h.FQDN); err != nil {
			return fmt.Errorf("cloudflare host record delete failed: %w", err)
		}
	}
	return s.store.RemoveHost(ctx, id)
}

func (s *Service) ListSSHBastionRoutes(ctx context.Context) ([]model.SSHBastionRoute, error) {
	return s.store.ListSSHBastionRoutes(ctx)
}

func (s *Service) UpsertSSHBastionRoute(ctx context.Context, in model.SSHBastionRoute) (model.SSHBastionRoute, error) {
	return s.store.UpsertSSHBastionRoute(ctx, in)
}

func (s *Service) DeleteSSHBastionRoute(ctx context.Context, id int64) error {
	return s.store.DeleteSSHBastionRoute(ctx, id)
}

func (s *Service) ListSSHBastionKeys(ctx context.Context) ([]model.SSHBastionKey, error) {
	return s.store.ListSSHBastionKeys(ctx)
}

func (s *Service) CreateSSHBastionKeyFromPublic(ctx context.Context, name, publicKey string, routeIDs []int64) (model.SSHBastionKey, error) {
	name = strings.TrimSpace(name)
	publicKey = strings.TrimSpace(publicKey)
	if name == "" || publicKey == "" {
		return model.SSHBastionKey{}, fmt.Errorf("name and public key required")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return model.SSHBastionKey{}, fmt.Errorf("invalid public key: %w", err)
	}
	fp := ssh.FingerprintSHA256(pk)
	return s.store.CreateSSHBastionKey(ctx, name, string(ssh.MarshalAuthorizedKey(pk)), fp, true, routeIDs)
}

func (s *Service) GenerateSSHBastionKey(ctx context.Context, name string, routeIDs []int64) (SSHBastionKeyCreateResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return SSHBastionKeyCreateResult{}, fmt.Errorf("name required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SSHBastionKeyCreateResult{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return SSHBastionKeyCreateResult{}, err
	}
	fp := ssh.FingerprintSHA256(sshPub)
	key, err := s.store.CreateSSHBastionKey(ctx, name, string(ssh.MarshalAuthorizedKey(sshPub)), fp, true, routeIDs)
	if err != nil {
		return SSHBastionKeyCreateResult{}, err
	}
	openSSHBlock, err := ssh.MarshalPrivateKey(priv, name)
	if err != nil {
		return SSHBastionKeyCreateResult{}, err
	}
	privatePEM := pem.EncodeToMemory(openSSHBlock)
	rfc4716, err := toRFC4716Public(sshPub)
	if err != nil {
		return SSHBastionKeyCreateResult{}, err
	}
	ppk, ppkErr := toPPKFromPrivatePEM(privatePEM)
	out := SSHBastionKeyCreateResult{
		Key:              key,
		PrivateKey:       string(privatePEM),
		PublicKeyRFC4716: rfc4716,
	}
	if ppkErr != nil {
		out.PPKError = ppkErr.Error()
	} else {
		out.PrivateKeyPPK = ppk
	}
	return out, nil
}

func toRFC4716Public(pub ssh.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("missing public key")
	}
	b64 := base64.StdEncoding.EncodeToString(pub.Marshal())
	var lines []string
	for len(b64) > 70 {
		lines = append(lines, b64[:70])
		b64 = b64[70:]
	}
	if b64 != "" {
		lines = append(lines, b64)
	}
	return "---- BEGIN SSH2 PUBLIC KEY ----\n" + strings.Join(lines, "\n") + "\n---- END SSH2 PUBLIC KEY ----\n", nil
}

func toPPKFromPrivatePEM(privatePEM []byte) (string, error) {
	if len(privatePEM) == 0 {
		return "", fmt.Errorf("empty private key")
	}
	if _, err := exec.LookPath("puttygen"); err != nil {
		return "", fmt.Errorf("puttygen not installed")
	}
	dir, err := os.MkdirTemp("", "domnex-ppk-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	inPath := dir + "/key.pem"
	outPath := dir + "/key.ppk"
	if err := os.WriteFile(inPath, privatePEM, 0o600); err != nil {
		return "", err
	}
	cmd := exec.Command("puttygen", inPath, "-O", "private", "-o", outPath)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("puttygen failed: %s", strings.TrimSpace(string(raw)))
	}
	ppk, err := os.ReadFile(outPath)
	if err != nil {
		return "", err
	}
	return string(ppk), nil
}

func (s *Service) DeleteSSHBastionKey(ctx context.Context, id int64) error {
	return s.store.DeleteSSHBastionKey(ctx, id)
}

func (s *Service) GetSSHBastionAuthByFingerprint(ctx context.Context, fingerprint string) (model.SSHBastionKeyAuth, error) {
	return s.store.GetSSHBastionAuthByFingerprint(ctx, fingerprint)
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
		if err := s.dns.UpsertARecord(ctx, zoneID, "*."+d.Name, s.publicIP, false); err != nil {
			s.log.Warn("dynDNS wildcard update failed", map[string]any{"domain": d.Name, "err": err.Error()})
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
		probeEnabled := true
		switch strings.ToLower(strings.TrimSpace(h.State)) {
		case "disabled", "maintenance":
			probeEnabled = false
		}
		d := s.diagnoseHost(ctx, h.FQDN, probeEnabled)
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

func (s *Service) StartPublicIPSync(ctx context.Context) {
	timer := time.NewTimer(untilNextFullHour(time.Now()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.syncPublicIPOnce(ctx)
			timer.Reset(untilNextFullHour(time.Now()))
		}
	}
}

func untilNextFullHour(now time.Time) time.Duration {
	next := now.Truncate(time.Hour).Add(time.Hour)
	d := next.Sub(now)
	if d <= 0 {
		return time.Hour
	}
	return d
}

func (s *Service) syncPublicIPOnce(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()

	detected, err := detectPublicIPv4(ctx)
	if err != nil {
		s.log.Warn("public IP sync check failed", map[string]any{"err": err.Error()})
		return
	}
	current, err := s.currentPublicIPv4(ctx)
	if err != nil {
		s.log.Warn("public IP sync current value unavailable", map[string]any{"err": err.Error()})
		current = ""
	}
	if strings.TrimSpace(current) == strings.TrimSpace(detected) {
		return
	}
	if err := s.store.SetSetting(ctx, settingPublicIPv4, detected); err != nil {
		s.log.Warn("public IP sync settings update failed", map[string]any{"err": err.Error(), "new": detected})
		return
	}
	if err := s.UpdatePublicIP(ctx, detected); err != nil {
		s.log.Warn("public IP sync update failed", map[string]any{"err": err.Error(), "new": detected})
		return
	}
	_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
		Actor:  "system",
		Action: "network.public_ip.changed.auto",
		Target: detected,
		Meta:   "old=" + strings.TrimSpace(current) + ";new=" + strings.TrimSpace(detected),
	})
}

func parseIPv4(raw string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("invalid IPv4")
	}
	return parsed.String(), nil
}

func readLoad1Linux() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(b)))
	if len(fields) == 0 {
		return 0, fmt.Errorf("invalid /proc/loadavg")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func readRAMUsagePercentLinux() (float64, uint64, uint64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, err
	}
	var totalKB int64
	var availKB int64
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "MemTotal:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				totalKB, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
		if strings.HasPrefix(ln, "MemAvailable:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				availKB, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	if totalKB <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid /proc/meminfo")
	}
	usedKB := totalKB - availKB
	if usedKB < 0 {
		usedKB = 0
	}
	usedBytes := uint64(usedKB) * 1024
	totalBytes := uint64(totalKB) * 1024
	return (float64(usedKB) / float64(totalKB)) * 100.0, usedBytes, totalBytes, nil
}

func readNetworkBytesLinux() (uint64, error) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, err
	}
	var sum uint64
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines[2:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		f := strings.Fields(parts[1])
		// rx bytes = field 0, tx bytes = field 8
		if len(f) < 9 {
			continue
		}
		rx, rxErr := strconv.ParseUint(f[0], 10, 64)
		tx, txErr := strconv.ParseUint(f[8], 10, 64)
		if rxErr != nil || txErr != nil {
			continue
		}
		sum += rx + tx
	}
	return sum, nil
}

func parseAndNormalizeCIDRs(raw string) (string, error) {
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return "", fmt.Errorf("invalid cidr: %s", p)
		}
		norm := n.String()
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return strings.Join(out, ","), nil
}

func (s *Service) diagnoseHost(ctx context.Context, fqdn string, probeEnabled bool) HostDiagnostic {
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
	if !probeEnabled {
		if d.Error == "" {
			d.Error = "probes skipped (host state disables active checks)"
		}
		return d
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

func (s *Service) CreateManagedUser(ctx context.Context, username, password string, role model.Role, domainIDs []int64, allowedCIDRs string, ipCheckDisabled bool, groupIDs []int64) (ManagedUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return ManagedUser{}, fmt.Errorf("username required")
	}
	if len(password) < 10 {
		return ManagedUser{}, fmt.Errorf("password too short")
	}
	if role != model.RoleAdmin && role != model.RoleDomainAdmin && role != model.RoleReadOnly {
		return ManagedUser{}, fmt.Errorf("role must be admin, domain-admin, or read-only")
	}
	if _, err := parseAndNormalizeCIDRs(allowedCIDRs); err != nil {
		return ManagedUser{}, err
	}
	if ipCheckDisabled {
		return ManagedUser{}, fmt.Errorf("disable IP check requires MFA enabled for this user")
	}
	hash, err := crypto.HashPassword(password, crypto.DefaultArgonConfig())
	if err != nil {
		return ManagedUser{}, err
	}
	normCIDRs, _ := parseAndNormalizeCIDRs(allowedCIDRs)
	u, err := s.store.CreateUser(ctx, username, role, normCIDRs, ipCheckDisabled, hash)
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
	if err := s.store.SetUserGroupMemberships(ctx, u.ID, groupIDs); err != nil {
		return ManagedUser{}, err
	}
	ids, _ := s.store.GetUserDomainIDs(ctx, u.ID)
	gm, _ := s.store.ListUserGroupMemberships(ctx, u.ID)
	return ManagedUser{
		ID:              u.ID,
		Username:        u.Username,
		Role:            u.Role,
		AuthProvider:    strings.TrimSpace(u.AuthProvider),
		DomainIDs:       ids,
		GroupMembership: gm,
		AllowedCIDRs:    u.AllowedCIDRs,
		IPCheckDisabled: u.IPCheckOff,
		MFAEnabled:      u.MFAEnabled,
		MFAEnrolledAt:   u.MFAEnrolled,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}, nil
}

func (s *Service) ListManagedUsers(ctx context.Context) ([]ManagedUser, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	groupMap, _ := s.store.ListUsersGroupMemberships(ctx)
	out := make([]ManagedUser, 0, len(users))
	for _, u := range users {
		ids, _ := s.store.GetUserDomainIDs(ctx, u.ID)
		out = append(out, ManagedUser{
			ID:              u.ID,
			Username:        u.Username,
			Role:            u.Role,
			AuthProvider:    strings.TrimSpace(u.AuthProvider),
			DomainIDs:       ids,
			GroupMembership: groupMap[u.ID],
			AllowedCIDRs:    u.AllowedCIDRs,
			IPCheckDisabled: u.IPCheckOff,
			MFAEnabled:      u.MFAEnabled,
			MFAEnrolledAt:   u.MFAEnrolled,
			CreatedAt:       u.CreatedAt,
			UpdatedAt:       u.UpdatedAt,
		})
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

func (s *Service) SetManagedUserAccess(ctx context.Context, userID int64, role model.Role, domainIDs []int64, allowedCIDRs string, ipCheckDisabled bool, groupIDs []int64) error {
	if role != model.RoleAdmin && role != model.RoleDomainAdmin && role != model.RoleReadOnly {
		return fmt.Errorf("role must be admin, domain-admin, or read-only")
	}
	normCIDRs, err := parseAndNormalizeCIDRs(allowedCIDRs)
	if err != nil {
		return err
	}
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if ipCheckDisabled && !u.MFAEnabled {
		return fmt.Errorf("disable IP check requires MFA enabled for this user")
	}
	if role == model.RoleDomainAdmin && len(domainIDs) == 0 {
		return fmt.Errorf("domain-admin requires at least one domain assignment")
	}
	if role != model.RoleDomainAdmin {
		domainIDs = nil
	}
	if err := s.store.SetUserAccessPolicy(ctx, userID, role, domainIDs, normCIDRs, ipCheckDisabled); err != nil {
		return err
	}
	return s.store.SetUserGroupMemberships(ctx, userID, groupIDs)
}

func (s *Service) DeleteManagedUser(ctx context.Context, userID int64) error {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(u.AuthProvider), "ldap") {
		if err := s.store.EnqueueLDAPDelete(ctx, u.Username); err != nil {
			return err
		}
	}
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

func (s *Service) isMFAPolicyRequiredForRole(ctx context.Context, role model.Role) bool {
	p := s.getMFAPolicy(ctx)
	switch role {
	case model.RoleAdmin:
		return p.EnforceAdmin
	case model.RoleDomainAdmin:
		return p.EnforceDomainAdmin
	case model.RoleReadOnly:
		return p.EnforceReadOnly
	default:
		return false
	}
}

func (s *Service) GetOwnMFAStatus(ctx context.Context, userID int64) (MFAStatus, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return MFAStatus{}, err
	}
	count := 0
	if u.MFAEnabled {
		if c, cErr := s.store.CountUserMFARecoveryCodesRemaining(ctx, userID); cErr == nil {
			count = c
		}
	}
	return MFAStatus{
		Enabled:                u.MFAEnabled,
		RequiredByPolicy:       s.isMFAPolicyRequiredForRole(ctx, u.Role),
		EnrolledAt:             u.MFAEnrolled,
		RecoveryCodesRemaining: count,
	}, nil
}

func (s *Service) StartOwnMFAEnrollment(ctx context.Context, userID int64, username string) (MFAEnrollStart, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return MFAEnrollStart{}, err
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		return MFAEnrollStart{}, err
	}
	enc, err := s.keystore.Encrypt(secret)
	if err != nil {
		return MFAEnrollStart{}, err
	}
	if err := s.store.SetUserMFAState(ctx, userID, false, enc, time.Time{}); err != nil {
		return MFAEnrollStart{}, err
	}
	issuer := "DomNexDomain"
	account := strings.TrimSpace(username)
	if account == "" {
		account = strings.TrimSpace(u.Username)
	}
	return MFAEnrollStart{
		Secret:    secret,
		OTPAuth:   mfa.BuildOTPAuthURL(issuer, account, secret),
		Issuer:    issuer,
		Account:   account,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) ConfirmOwnMFAEnrollment(ctx context.Context, userID int64, otp string) (MFAEnrollConfirm, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return MFAEnrollConfirm{}, err
	}
	if strings.TrimSpace(u.MFASecretEnc) == "" {
		return MFAEnrollConfirm{}, fmt.Errorf("mfa enrollment not started")
	}
	secret, err := s.keystore.Decrypt(u.MFASecretEnc)
	if err != nil {
		return MFAEnrollConfirm{}, fmt.Errorf("mfa secret unavailable")
	}
	if !mfa.ValidateTOTP(secret, otp, time.Now().UTC()) {
		return MFAEnrollConfirm{}, fmt.Errorf("invalid otp code")
	}
	now := time.Now().UTC()
	if err := s.store.SetUserMFAState(ctx, userID, true, u.MFASecretEnc, now); err != nil {
		return MFAEnrollConfirm{}, err
	}
	recoveryCodes, err := mfa.GenerateRecoveryCodes(10)
	if err != nil {
		return MFAEnrollConfirm{}, err
	}
	hashes := make([]string, 0, len(recoveryCodes))
	for _, code := range recoveryCodes {
		hashes = append(hashes, mfa.HashRecoveryCode(code))
	}
	if err := s.store.ReplaceUserMFARecoveryCodes(ctx, userID, hashes); err != nil {
		return MFAEnrollConfirm{}, err
	}
	return MFAEnrollConfirm{
		Enabled:       true,
		EnrolledAt:    now,
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (s *Service) DisableOwnMFA(ctx context.Context, userID int64, currentPassword, otpOrRecovery string) error {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.MFAEnabled {
		return nil
	}
	if !crypto.VerifyPassword(currentPassword, u.PasswordHash) {
		return fmt.Errorf("invalid current password")
	}
	otpOrRecovery = strings.TrimSpace(otpOrRecovery)
	if otpOrRecovery == "" {
		return fmt.Errorf("mfa code required")
	}
	allowed := false
	if secretEnc := strings.TrimSpace(u.MFASecretEnc); secretEnc != "" {
		if secret, dErr := s.keystore.Decrypt(secretEnc); dErr == nil {
			allowed = mfa.ValidateTOTP(secret, otpOrRecovery, time.Now().UTC())
		}
	}
	if !allowed && mfa.IsRecoveryCodeFormat(otpOrRecovery) {
		ok, _ := s.store.ConsumeUserMFARecoveryCode(ctx, userID, mfa.HashRecoveryCode(otpOrRecovery))
		allowed = ok
	}
	if !allowed {
		return fmt.Errorf("invalid mfa code")
	}
	return s.store.ResetUserMFA(ctx, userID)
}

func (s *Service) ResetManagedUserMFA(ctx context.Context, userID int64) error {
	if _, err := s.store.GetUserByID(ctx, userID); err != nil {
		return err
	}
	return s.store.ResetUserMFA(ctx, userID)
}

func normalizeThreatIntelMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "monitor_only", "auto_mode":
		return m
	case "log_only":
		return "monitor_only"
	case "hard_check", "soft_block", "hard_block":
		return "auto_mode"
	default:
		return "monitor_only"
	}
}

func (s *Service) GetThreatIntelConfig(ctx context.Context) (model.ThreatIntelConfig, error) {
	return s.store.GetThreatIntelConfig(ctx)
}

func (s *Service) SetThreatIntelConfig(ctx context.Context, cfg model.ThreatIntelConfig) error {
	cfg.Mode = normalizeThreatIntelMode(cfg.Mode)
	if err := s.store.SetThreatIntelConfig(ctx, cfg); err != nil {
		return err
	}
	_ = s.reconcileOSFirewall(ctx)
	_, err := s.RefreshThreatIntelSnapshot(ctx)
	return err
}

func (s *Service) ListThreatIntelFeeds(ctx context.Context) ([]model.ThreatIntelFeed, error) {
	return s.store.ListThreatIntelFeeds(ctx)
}

func (s *Service) UpsertThreatIntelFeed(ctx context.Context, in model.ThreatIntelFeed) (model.ThreatIntelFeed, error) {
	if in.ID == 0 && strings.TrimSpace(in.URL) == defaultThreatIntelFeedURL && strings.TrimSpace(in.Name) == "" {
		in.Name = "blocklist.de all"
	}
	f, err := s.store.UpsertThreatIntelFeed(ctx, in)
	if err != nil {
		return model.ThreatIntelFeed{}, err
	}
	_, _ = s.RefreshThreatIntelSnapshot(ctx)
	return f, nil
}

func (s *Service) DeleteThreatIntelFeed(ctx context.Context, id int64) error {
	if err := s.store.DeleteThreatIntelFeed(ctx, id); err != nil {
		return err
	}
	_, _ = s.RefreshThreatIntelSnapshot(ctx)
	return nil
}

func (s *Service) SyncThreatIntelFeeds(ctx context.Context) (map[string]any, error) {
	feeds, err := s.store.ListThreatIntelFeeds(ctx)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 25 * time.Second}
	summary := map[string]any{
		"feeds":       len(feeds),
		"synced":      0,
		"errors":      0,
		"totalIPs":    0,
		"generatedAt": time.Now().UTC().Format(time.RFC3339Nano),
	}
	synced := 0
	errs := 0
	totalIPs := 0
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		ips, hash, fetchErr := fetchThreatIntelFeed(ctx, client, f.URL)
		if fetchErr != nil {
			errs++
			_ = s.store.ReplaceThreatIntelFeedEntries(ctx, f.ID, nil, "", fetchErr.Error())
			s.log.Warn("threat intel sync failed", map[string]any{"feed": f.Name, "url": f.URL, "err": fetchErr.Error()})
			continue
		}
		if err := s.store.ReplaceThreatIntelFeedEntries(ctx, f.ID, ips, hash, ""); err != nil {
			errs++
			s.log.Warn("threat intel feed replace failed", map[string]any{"feed": f.Name, "err": err.Error()})
			continue
		}
		synced++
		totalIPs += len(ips)
	}
	summary["synced"] = synced
	summary["errors"] = errs
	summary["totalIPs"] = totalIPs
	sigErr := s.syncThreatSignatures(ctx, true)
	summary["signatureUpdated"] = sigErr == nil
	if sigErr != nil {
		summary["signatureError"] = sigErr.Error()
	}
	_, _ = s.RefreshThreatIntelSnapshot(ctx)
	return summary, nil
}

func fetchThreatIntelFeed(ctx context.Context, client *http.Client, rawURL string) ([]string, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, "", fmt.Errorf("empty feed URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, "", fmt.Errorf("http status %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	ips := []string{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.Fields(line)[0]
		if ip := net.ParseIP(line); ip != nil {
			n := ip.String()
			if !seen[n] {
				seen[n] = true
				ips = append(ips, n)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	return ips, hash, nil
}

func (s *Service) RefreshThreatIntelSnapshot(ctx context.Context) (model.ThreatIntelSnapshot, error) {
	cfg, err := s.store.GetThreatIntelConfig(ctx)
	if err != nil {
		return model.ThreatIntelSnapshot{}, err
	}
	feedByIP, err := s.store.ListThreatIntelEntriesByIP(ctx)
	if err != nil {
		return model.ThreatIntelSnapshot{}, err
	}
	allowEntries, err := s.store.ListThreatIntelAllowIPs(ctx)
	if err != nil {
		return model.ThreatIntelSnapshot{}, err
	}
	allow := map[string]bool{}
	for _, b := range allowEntries {
		allow[strings.TrimSpace(b.IP)] = true
	}
	snap := model.ThreatIntelSnapshot{
		Enabled:          cfg.Enabled,
		Mode:             normalizeThreatIntelMode(cfg.Mode),
		EventMinHits:     cfg.EventMinHits,
		OffenderMinHits:  cfg.OffenderMinHits,
		MonitorMaxLevel:  cfg.MonitorMaxLevel,
		SoftMinLevel:     cfg.SoftMinLevel,
		HardLevel:        cfg.HardLevel,
		SoftBlockMinutes: cfg.SoftBlockMinutes,
		Allowlist:        allow,
		FeedByIP:         feedByIP,
	}
	s.tiMu.Lock()
	s.tiSnap = snap
	s.tiMu.Unlock()
	return snap, nil
}

func (s *Service) GetThreatIntelSnapshot(ctx context.Context) (model.ThreatIntelSnapshot, error) {
	return s.RefreshThreatIntelSnapshot(ctx)
}

func (s *Service) ApplyThreatIntelEvent(ctx context.Context, in model.ThreatIntelEventInput) (model.ThreatIntelEventResult, error) {
	res := model.ThreatIntelEventResult{
		Decision:  "monitor_observe",
		RiskState: "monitoring",
		Tier:      "tier0",
	}
	in.IP = strings.TrimSpace(in.IP)
	if in.IP == "" {
		return res, nil
	}
	in.Mode = normalizeThreatIntelMode(in.Mode)
	if in.Mode == "" {
		in.Mode = "monitor_only"
	}
	sigSignals := s.detectThreatSignatureSignals(in.Host, in.Path, in.UserAgent)
	if len(sigSignals) > 0 {
		in.Signals = append(in.Signals, sigSignals...)
	}
	in.Signals = uniqueThreatSignals(in.Signals)
	tiCfg, _ := s.GetThreatIntelConfig(ctx)
	hardLevel := tiCfg.HardLevel
	if hardLevel <= 0 {
		hardLevel = defaultTIHardLevel
	}
	softMinLevel := tiCfg.SoftMinLevel
	if softMinLevel <= 0 {
		softMinLevel = defaultTISoftMinLevel
	}
	if softMinLevel >= hardLevel {
		softMinLevel = hardLevel - 1
	}
	if softMinLevel < 1 {
		softMinLevel = 1
	}
	softBlockMinutes := tiCfg.SoftBlockMinutes
	if softBlockMinutes <= 0 {
		softBlockMinutes = defaultTISoftBlockMinutes
	}
	now := time.Now().UTC()

	st, err := s.store.GetThreatIntelIPState(ctx, in.IP)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return res, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		st = model.ThreatIntelIPState{
			IP:           in.IP,
			RiskState:    "monitoring",
			SignalCounts: map[string]int{},
		}
	}
	if st.SignalCounts == nil {
		st.SignalCounts = map[string]int{}
	}

	decayThreatState(&st, now)
	externalHit := hasExternalFeedSignal(in.Signals)
	behaviorHit := hasBehaviorThreatSignal(in.Signals)
	watchBoost := externalHit && !behaviorHit
	if watchBoost && st.Level < defaultTIWatchLevel {
		st.Level = defaultTIWatchLevel
		minXP := threatLevelThreshold(defaultTIWatchLevel)
		if st.XP < minXP {
			st.XP = minXP
		}
		st.RiskState = "watch"
	}
	baseXP, topSignal := calcThreatBaseXP(in.Signals)
	xpDelta := applyThreatMultipliers(baseXP, s.bumpThreatWindow(in.IP, topSignal, in.Signals, now), in.Signals)
	if xpDelta < 0 {
		xpDelta = 0
	}
	st.XP += xpDelta
	st.TopSignal = topSignal
	if topSignal != "" {
		st.SignalCounts[topSignal] = st.SignalCounts[topSignal] + 1
	}
	for {
		req := threatLevelThreshold(st.Level)
		if st.Level >= hardLevel || st.XP < req {
			break
		}
		st.XP -= req
		st.Level++
	}
	// Keep XP bounded once max level is reached so UI/analytics scales remain stable.
	if st.Level >= hardLevel {
		maxXP := threatLevelThreshold(hardLevel)
		if st.XP > maxXP {
			st.XP = maxXP
		}
	}
	st.RiskState = threatRiskState(st.Level, softMinLevel, hardLevel)
	if watchBoost && !st.PermBlocked && (st.BanUntil.IsZero() || !st.BanUntil.After(now)) {
		st.RiskState = "watch"
	}
	// Deterministic hard-block enforcement:
	// once hard level is reached in auto mode, immediately convert to permanent block.
	if in.Mode == "auto_mode" && st.Level >= hardLevel {
		st.PermBlocked = true
		st.BanUntil = time.Time{}
		st.RiskState = "hardblock"
	}
	st.LastSeenAt = now
	if st.PermBlocked {
		res.Blocked = true
		res.HardBlock = true
		res.Decision = "hard_block_permanent"
		_ = s.store.UpsertBlockedIP(ctx, in.IP, "threat_intel_auto:"+topSignal)
		_ = s.store.EnsureThreatIntelBanHistoryForIP(ctx, in.IP, "threat_intel_auto:"+topSignal, "hard")
		// Immediate host-level enforcement: do not wait for periodic firewall ticker.
		if err := s.reconcileOSFirewall(ctx); err != nil {
			s.log.Warn("threat intel os firewall reconcile failed", map[string]any{
				"ip":  in.IP,
				"err": err.Error(),
			})
		}
	} else if !st.BanUntil.IsZero() && st.BanUntil.After(now) {
		res.Blocked = true
		res.Decision = "soft_block_active"
	}

	if !res.Blocked {
		switch in.Mode {
		case "auto_mode":
			if watchBoost {
				res.Decision = "watch_boost"
			} else if st.Level >= softMinLevel {
				st.TempBlockCount++
				d := time.Duration(softBlockMinutes) * time.Minute
				st.BanUntil = now.Add(d)
				res.Blocked = true
				res.BanUntil = st.BanUntil
				res.Decision = "soft_block_set"
				_ = s.store.EnsureThreatIntelBanHistoryForIP(ctx, in.IP, "threat_intel_auto:soft_block", "soft")
			} else {
				res.Decision = "monitor_observe"
			}
		default:
			res.Decision = "monitor_observe"
		}
	}

	if err := s.store.UpsertThreatIntelIPState(ctx, st); err != nil {
		return res, err
	}
	res.XPDelta = xpDelta
	res.XPAfter = st.XP
	res.Level = st.Level
	res.Tier = threatTier(st.Level)
	res.RiskState = st.RiskState
	if !st.BanUntil.IsZero() && st.BanUntil.After(now) {
		res.BanUntil = st.BanUntil
	}
	_ = s.store.RecordThreatIntelMatch(ctx, model.ThreatIntelMatchEvent{
		IP:          in.IP,
		Feed:        strings.Join(uniqueThreatSignals(in.Signals), ","),
		Host:        in.Host,
		Path:        in.Path,
		Country:     in.Country,
		Mode:        in.Mode,
		Decision:    res.Decision,
		TraceID:     in.TraceID,
		SourceScope: in.SourceScope,
		XPDelta:     res.XPDelta,
		XPAfter:     res.XPAfter,
		LevelAfter:  res.Level,
		TierAfter:   res.Tier,
	})
	return res, nil
}

func uniqueThreatSignals(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func calcThreatBaseXP(signals []string) (int, string) {
	points := map[string]int{
		"behavior.unknown_host":         1,
		"behavior.path_scan":            4,
		"behavior.ua_scanner":           2,
		"behavior.invalid_host":         2,
		"behavior.auth_failed":          3,
		"protocol.ssh.auth_denied":      3,
		"protocol.ssh.forward_denied":   4,
		"signature.wp_scanner":          6,
		"signature.secret_hunter":       7,
		"signature.webshell_probe":      8,
		"signature.admin_surface_probe": 4,
		"signature.api_enum":            4,
		"signature.scanner_ua":          3,
	}
	total := 0
	top := ""
	topPts := 0
	seenExternal := false
	for _, sig := range uniqueThreatSignals(signals) {
		p := points[sig]
		if p == 0 && strings.HasPrefix(sig, "signature.") {
			p = 4
		}
		if p == 0 && !strings.HasPrefix(sig, "behavior.") {
			seenExternal = true
		}
		total += p
		if p > topPts {
			topPts = p
			top = sig
		}
	}
	if seenExternal {
		total += 6
		if top == "" {
			top = "external_feed_hit"
		}
	}
	if total <= 0 {
		total = 1
	}
	if top == "" {
		top = "behavior.unknown_host"
	}
	return total, top
}

func hasExternalFeedSignal(signals []string) bool {
	for _, sig := range uniqueThreatSignals(signals) {
		if !strings.HasPrefix(sig, "behavior.") && !strings.HasPrefix(sig, "protocol.") {
			return true
		}
	}
	return false
}

func hasBehaviorThreatSignal(signals []string) bool {
	for _, sig := range uniqueThreatSignals(signals) {
		if strings.HasPrefix(sig, "behavior.") || strings.HasPrefix(sig, "protocol.") {
			return true
		}
	}
	return false
}

func applyThreatMultipliers(base int, burstFactor float64, signals []string) int {
	xp := int(math.Round(float64(base) * burstFactor))
	if xp < 1 {
		xp = 1
	}
	if len(uniqueThreatSignals(signals)) >= 3 {
		xp += 2
	}
	return xp
}

func (s *Service) bumpThreatWindow(ip, primary string, signals []string, now time.Time) float64 {
	s.tiWinMu.Lock()
	defer s.tiWinMu.Unlock()
	for k, v := range s.tiWin {
		if now.Sub(v.start) > 2*time.Minute {
			delete(s.tiWin, k)
		}
	}
	w := s.tiWin[ip]
	if w.start.IsZero() || now.Sub(w.start) > time.Minute {
		w = tiWindow{start: now, perSignal: map[string]int{}, categories: map[string]bool{}}
	}
	if w.perSignal == nil {
		w.perSignal = map[string]int{}
	}
	if w.categories == nil {
		w.categories = map[string]bool{}
	}
	if primary == "" {
		primary = "behavior.unknown_host"
	}
	w.perSignal[primary] = w.perSignal[primary] + 1
	for _, sig := range uniqueThreatSignals(signals) {
		w.categories[sig] = true
	}
	s.tiWin[ip] = w
	n := w.perSignal[primary]
	switch {
	case n >= 8:
		return 2.0
	case n >= 5:
		return 1.5
	case n >= 3:
		return 1.2
	default:
		return 1.0
	}
}

func decayThreatState(st *model.ThreatIntelIPState, now time.Time) {
	if st == nil || st.LastSeenAt.IsZero() {
		return
	}
	// Prison mode: while blocked, no rehabilitation decay is applied.
	// - Hard block (perm) stays frozen until manually cleared.
	// - Soft block stays frozen until ban window expires.
	if st.PermBlocked {
		return
	}
	if !st.BanUntil.IsZero() && st.BanUntil.After(now) {
		return
	}
	idle := now.Sub(st.LastSeenAt)
	// Conservative decay: keep offenders visible longer before rehabilitation.
	if idle >= 30*time.Minute {
		steps := int(idle / (30 * time.Minute))
		for i := 0; i < steps; i++ {
			st.XP = int(math.Floor(float64(st.XP) * 0.93))
			if st.XP < 0 {
				st.XP = 0
			}
		}
	}
	if idle >= 72*time.Hour && st.Level > 0 {
		down := int(idle / (72 * time.Hour))
		if down > st.Level {
			down = st.Level
		}
		st.Level -= down
		if st.Level < 0 {
			st.Level = 0
		}
	}
}

func threatLevelThreshold(level int) int {
	if level < 0 {
		level = 0
	}
	return int(math.Round(10 * math.Pow(1.6, float64(level))))
}

func threatRiskState(level, softMinLevel, hardLevel int) string {
	switch {
	case level >= hardLevel:
		return "hardblock"
	case level >= softMinLevel:
		return "softblock"
	default:
		return "monitoring"
	}
}

func threatTier(level int) string {
	if level < 0 {
		level = 0
	}
	return "tier" + strconv.Itoa(level)
}

func (s *Service) ListThreatIntelMatches(ctx context.Context, hours int, decision, q string, page, pageSize int) (ThreatIntelMatchesPage, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	offset := (page - 1) * pageSize
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	cfg, _ := s.store.GetThreatIntelConfig(ctx)
	items, total, err := s.store.ListThreatIntelMatches(ctx, since, decision, q, cfg.EventMinHits, cfg.OffenderMinHits, pageSize, offset)
	if err != nil {
		return ThreatIntelMatchesPage{}, err
	}
	return ThreatIntelMatchesPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Service) ListThreatIntelOffenders(ctx context.Context, hours int, page, pageSize int) (ThreatIntelOffendersPage, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	offset := (page - 1) * pageSize
	shortHours := hours
	if shortHours > 6 {
		shortHours = 6
	}
	since := time.Now().UTC().Add(-time.Duration(shortHours) * time.Hour)
	cfg, _ := s.store.GetThreatIntelConfig(ctx)
	items, total, err := s.store.ListThreatIntelOffenders(ctx, since, cfg.OffenderMinHits, pageSize, offset)
	if err != nil {
		return ThreatIntelOffendersPage{}, err
	}
	return ThreatIntelOffendersPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Service) ListThreatIntelBlocked(ctx context.Context, hours int, q string, page, pageSize int) (ThreatIntelBlockedPage, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	offset := (page - 1) * pageSize
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	items, total, err := s.store.ListThreatIntelBlocked(ctx, since, q, pageSize, offset)
	if err != nil {
		return ThreatIntelBlockedPage{}, err
	}
	policy := s.getRetentionPolicy(ctx)
	retentionDays := policy.BlockedDays
	if retentionDays <= 0 {
		retentionDays = 60
	}
	for i := range items {
		if items[i].BlockedUntil.IsZero() && !items[i].BlockedOn.IsZero() {
			items[i].BlockedUntil = items[i].BlockedOn.Add(time.Duration(retentionDays) * 24 * time.Hour)
		}
	}
	return ThreatIntelBlockedPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Service) ListThreatIntelTargetsByIP(ctx context.Context, hours int, ip string, limit int) ([]model.ThreatIntelTarget, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	if limit <= 0 {
		limit = 200
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	return s.store.ListThreatIntelTargetsByIP(ctx, since, ip, limit)
}

func (s *Service) ListThreatIntelAllowlist(ctx context.Context) ([]model.BlockedIP, error) {
	return s.store.ListThreatIntelAllowIPs(ctx)
}

func (s *Service) ListThreatIntelGeoPoints(ctx context.Context) ([]model.ThreatIntelGeoPoint, error) {
	return s.store.ListThreatIntelGeoPoints(ctx)
}

func (s *Service) GetThreatIntelMetaDashboard(ctx context.Context) (model.ThreatIntelMetaDashboard, error) {
	return s.store.GetThreatIntelMetaDashboard(ctx)
}

func (s *Service) AddThreatIntelAllowIP(ctx context.Context, ip, reason string) error {
	if err := s.store.UpsertThreatIntelAllowIP(ctx, ip, reason); err != nil {
		return err
	}
	_, _ = s.RefreshThreatIntelSnapshot(ctx)
	return nil
}

func (s *Service) RemoveThreatIntelAllowIP(ctx context.Context, ip string) error {
	if err := s.store.RemoveThreatIntelAllowIP(ctx, ip); err != nil {
		return err
	}
	_, _ = s.RefreshThreatIntelSnapshot(ctx)
	return nil
}

func (s *Service) StartThreatIntelSync(ctx context.Context) {
	s.ensureThreatSignaturesLoaded(ctx)
	syncTicker := time.NewTicker(1 * time.Hour)
	decayTicker := time.NewTicker(5 * time.Minute)
	firewallTicker := time.NewTicker(1 * time.Minute)
	defer syncTicker.Stop()
	defer decayTicker.Stop()
	defer firewallTicker.Stop()
	if err := s.reconcileOSFirewall(ctx); err != nil {
		s.log.Warn("threat intel os firewall reconcile failed", map[string]any{"err": err.Error()})
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-decayTicker.C:
			rehab, err := s.ReconcileThreatIntelDecay(ctx)
			if err != nil {
				s.log.Warn("threat intel decay reconcile failed", map[string]any{"err": err.Error()})
				continue
			}
			if rehab > 0 {
				_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
					Actor:  "system",
					Action: "threatintel.rehabilitated.cleanup",
					Target: "threat-intel",
					Meta:   "count=" + strconv.Itoa(rehab),
				})
			}
		case <-syncTicker.C:
			cfg, err := s.store.GetThreatIntelConfig(ctx)
			if err != nil || !cfg.Enabled {
				if err := s.syncThreatSignatures(ctx, false); err != nil {
					s.log.Warn("threat signature scheduled sync failed", map[string]any{"err": err.Error()})
				}
				continue
			}
			if err := s.syncThreatSignatures(ctx, false); err != nil {
				s.log.Warn("threat signature scheduled sync failed", map[string]any{"err": err.Error()})
			}
			feeds, err := s.store.ListThreatIntelFeeds(ctx)
			if err != nil {
				continue
			}
			due := false
			cutoff := time.Now().UTC().Add(-time.Duration(cfg.SyncHours) * time.Hour)
			for _, f := range feeds {
				if !f.Enabled {
					continue
				}
				if f.LastSyncAt.IsZero() || f.LastSyncAt.Before(cutoff) {
					due = true
					break
				}
			}
			if !due {
				continue
			}
			if _, err := s.SyncThreatIntelFeeds(ctx); err != nil {
				s.log.Warn("threat intel scheduled sync failed", map[string]any{"err": err.Error()})
			}
		case <-firewallTicker.C:
			if err := s.reconcileOSFirewall(ctx); err != nil {
				s.log.Warn("threat intel os firewall reconcile failed", map[string]any{"err": err.Error()})
			}
		}
	}
}

func (s *Service) reconcileOSFirewall(ctx context.Context) error {
	if s.nft == nil {
		return nil
	}
	cfg, err := s.store.GetThreatIntelConfig(ctx)
	if err != nil {
		return err
	}
	if !cfg.OSFirewall {
		return s.nft.Disable(ctx)
	}
	mode := strings.TrimSpace(strings.ToLower(cfg.OSFirewallMode))
	if mode == "" {
		mode = "hard_only"
	}
	hardByIP := map[string]bool{}
	if mode == "hard_only" {
		states, stErr := s.store.ListThreatIntelIPStates(ctx, 50000)
		if stErr != nil {
			return stErr
		}
		for _, st := range states {
			ip := strings.TrimSpace(st.IP)
			if ip == "" {
				continue
			}
			rs := strings.ToLower(strings.TrimSpace(st.RiskState))
			if st.PermBlocked || rs == "hardblock" || st.Level >= cfg.HardLevel {
				hardByIP[ip] = true
			}
		}
	}
	blocked, err := s.store.ListBlockedIPs(ctx, 200000)
	if err != nil {
		return err
	}
	set4 := map[string]bool{}
	set6 := map[string]bool{}
	for _, b := range blocked {
		ip := strings.TrimSpace(b.IP)
		if ip == "" {
			continue
		}
		if mode == "hard_only" {
			if !hardByIP[ip] && !strings.Contains(strings.ToLower(strings.TrimSpace(b.Reason)), "hard") {
				continue
			}
		}
		if isPublicIPv4(ip) {
			set4[ip] = true
			continue
		}
		if isPublicIPv6(ip) {
			set6[ip] = true
		}
	}
	ips4 := make([]string, 0, len(set4))
	for ip := range set4 {
		ips4 = append(ips4, ip)
	}
	ips6 := make([]string, 0, len(set6))
	for ip := range set6 {
		ips6 = append(ips6, ip)
	}
	sort.Strings(ips4)
	sort.Strings(ips6)
	return s.nft.Replace(ctx, ips4, ips6)
}

func isPublicIPv4(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalMulticast() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
		return false
	}
	switch {
	case v4[0] == 0:
		return false
	case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
		return false
	case v4[0] == 169 && v4[1] == 254:
		return false
	case v4[0] >= 224:
		return false
	}
	return true
}

func isPublicIPv6(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// ULA fc00::/7 and documentation prefix 2001:db8::/32 should never be enforced.
	if strings.HasPrefix(strings.ToLower(ip.String()), "fc") || strings.HasPrefix(strings.ToLower(ip.String()), "fd") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(ip.String()), "2001:db8:") {
		return false
	}
	return true
}

func (s *Service) RunRetentionPurge(ctx context.Context) (RetentionPurgeResult, error) {
	policy := s.getRetentionPolicy(ctx)
	now := time.Now().UTC()
	var out RetentionPurgeResult
	var err error
	if out.AuditEvents, err = s.store.PurgeAuditEventsBefore(ctx, now.AddDate(0, 0, -policy.AuditDays)); err != nil {
		return out, err
	}
	if out.TrafficBuckets, err = s.store.PurgeTrafficBucketsBefore(ctx, now.AddDate(0, 0, -policy.TrafficDays)); err != nil {
		return out, err
	}
	if out.VisitorHashes, err = s.store.PurgeVisitorHashesBeforeDay(ctx, now.AddDate(0, 0, -policy.VisitorsDays)); err != nil {
		return out, err
	}
	if out.ThreatMatches, err = s.store.PurgeThreatIntelMatchesBefore(ctx, now.AddDate(0, 0, -policy.ThreatDays)); err != nil {
		return out, err
	}
	if out.ThreatStates, err = s.store.PurgeThreatIntelStateBefore(ctx, now.AddDate(0, 0, -policy.ThreatDays)); err != nil {
		return out, err
	}
	if out.BlockedIPs, err = s.store.PurgeBlockedIPsBefore(ctx, now.AddDate(0, 0, -policy.BlockedDays)); err != nil {
		return out, err
	}
	if out.LoginAttempts, err = s.store.PurgeLoginAttemptsBefore(ctx, now.AddDate(0, 0, -policy.LoginAttemptDays)); err != nil {
		return out, err
	}
	if out.PasswordResetTokens, err = s.store.PurgePasswordResetTokensBefore(ctx, now.AddDate(0, 0, -policy.PasswordResetDays)); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) StartRetentionWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	lastRunDay := ""
	run := func() {
		result, err := s.RunRetentionPurge(ctx)
		if err != nil {
			s.log.Warn("retention purge failed", map[string]any{"err": err.Error()})
			return
		}
		total := result.Total()
		if total <= 0 {
			return
		}
		meta := "audit=" + strconv.FormatInt(result.AuditEvents, 10) +
			";traffic=" + strconv.FormatInt(result.TrafficBuckets, 10) +
			";visitors=" + strconv.FormatInt(result.VisitorHashes, 10) +
			";threat_matches=" + strconv.FormatInt(result.ThreatMatches, 10) +
			";threat_states=" + strconv.FormatInt(result.ThreatStates, 10) +
			";blocked=" + strconv.FormatInt(result.BlockedIPs, 10) +
			";login_attempts=" + strconv.FormatInt(result.LoginAttempts, 10) +
			";password_reset_tokens=" + strconv.FormatInt(result.PasswordResetTokens, 10) +
			";total=" + strconv.FormatInt(total, 10)
		_ = s.store.AddAuditEvent(ctx, model.AuditEvent{
			Actor:  "system",
			Action: "retention.purge",
			Target: "runtime",
			Meta:   meta,
		})
	}
	run()
	lastRunDay = time.Now().UTC().Format("2006-01-02")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			day := time.Now().UTC().Format("2006-01-02")
			if day == lastRunDay {
				continue
			}
			lastRunDay = day
			run()
		}
	}
}

func (s *Service) ReconcileThreatIntelDecay(ctx context.Context) (int, error) {
	cfg, cfgErr := s.store.GetThreatIntelConfig(ctx)
	softMinLevel := defaultTISoftMinLevel
	hardLevel := defaultTIHardLevel
	if cfgErr == nil {
		if cfg.SoftMinLevel > 0 {
			softMinLevel = cfg.SoftMinLevel
		}
		if cfg.HardLevel > 0 {
			hardLevel = cfg.HardLevel
		}
	}
	// Global safety net: enforce hard-level states into blocked IPs regularly.
	if _, err := s.store.PromoteThreatIntelHardBlocks(ctx, hardLevel); err != nil {
		s.log.Warn("threat intel hardblock promotion failed", map[string]any{"err": err.Error()})
	}
	_ = s.store.SyncThreatIntelBanHistoryOpen(ctx)
	states, err := s.store.ListThreatIntelIPStates(ctx, 20000)
	if err != nil {
		return 0, err
	}
	allowEntries, err := s.store.ListThreatIntelAllowIPs(ctx)
	if err != nil {
		return 0, err
	}
	allow := map[string]bool{}
	for _, a := range allowEntries {
		allow[strings.TrimSpace(a.IP)] = true
	}
	now := time.Now().UTC()
	rehab := 0
	for _, st := range states {
		if st.IP == "" {
			continue
		}
		idle := now.Sub(st.LastSeenAt)
		// Lifecycle downgrade: long-lived hard blocks become watch entries, not infinite database growth.
		if st.PermBlocked && idle >= time.Duration(defaultTIHardToWatchDays)*24*time.Hour {
			st.PermBlocked = false
			st.BanUntil = time.Time{}
			st.RiskState = "watch"
			st.Level = defaultTIWatchLevel
			st.XP = threatLevelThreshold(defaultTIWatchLevel)
			st.LastSeenAt = now
			idle = 0
			_ = s.removeBlockedIPTracked(ctx, st.IP, false)
		}
		decayThreatState(&st, now)
		if !st.BanUntil.IsZero() && !st.BanUntil.After(now) {
			_ = s.store.RecordThreatIntelRehabEvent(ctx, st.IP, true, "soft_ban_expired")
			_ = s.store.CloseThreatIntelBanHistory(ctx, st.IP, "soft", false)
			st.BanUntil = time.Time{}
		}
		if st.RiskState != "watch" {
			st.RiskState = threatRiskState(st.Level, softMinLevel, hardLevel)
		} else if st.Level <= 0 && st.XP <= 0 {
			st.RiskState = "monitoring"
		}
		// If an IP has fully cooled down for a sustained period, drop it from active state/history.
		idle = now.Sub(st.LastSeenAt)
		if st.XP <= 0 && st.Level <= 0 && idle >= 72*time.Hour && !st.PermBlocked && st.BanUntil.IsZero() {
			st.XP = 0
			st.Level = 0
			st.RiskState = "monitoring"
			st.TempBlockCount = 0
			if !allow[st.IP] {
				_ = s.store.RecordThreatIntelRehabEvent(ctx, st.IP, false, "monitor_decay_cleanup")
				_ = s.store.DeleteThreatIntelMatchesByIP(ctx, st.IP)
				_ = s.store.DeleteThreatIntelState(ctx, st.IP)
				rehab++
				continue
			}
		}
		if err := s.store.UpsertThreatIntelIPState(ctx, st); err != nil {
			s.log.Warn("threat intel state reconcile failed", map[string]any{"ip": st.IP, "err": err.Error()})
		}
	}
	return rehab, nil
}

func (s *Service) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	return s.store.IsIPBlocked(ctx, ip)
}

func (s *Service) UpsertBlockedIP(ctx context.Context, ip, reason string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed != nil && parsed.IsLoopback() {
		return fmt.Errorf("loopback addresses cannot be blocked")
	}
	if err := s.store.UpsertBlockedIP(ctx, ip, reason); err != nil {
		return err
	}
	_ = s.store.EnsureThreatIntelBanHistoryForIP(ctx, ip, reason, "hard")
	_ = s.reconcileOSFirewall(ctx)
	return nil
}

func (s *Service) removeBlockedIPTracked(ctx context.Context, ip string, falsePositive bool) error {
	if err := s.store.RemoveBlockedIP(ctx, ip); err != nil {
		return err
	}
	_ = s.store.RecordThreatIntelRehabEvent(ctx, ip, true, "blocked_ip_removed")
	_ = s.store.CloseThreatIntelBanHistory(ctx, ip, "hard", falsePositive)
	_ = s.reconcileOSFirewall(ctx)
	return nil
}

func (s *Service) RemoveBlockedIP(ctx context.Context, ip string) error {
	return s.removeBlockedIPTracked(ctx, ip, false)
}

func (s *Service) RemoveBlockedIPFalsePositive(ctx context.Context, ip string) error {
	return s.removeBlockedIPTracked(ctx, ip, true)
}

func (s *Service) geoIPSourcesDir() string {
	return filepath.Join(s.cfg.DataDir, "geoip-sources")
}

func (s *Service) ListGeoIPSources(_ context.Context) ([]GeoIPSourceFile, error) {
	dir := s.geoIPSourcesDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]GeoIPSourceFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.TrimSpace(e.Name())
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".mmdb" && ext != ".csv" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, GeoIPSourceFile{
			Name:    name,
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out, nil
}

func (s *Service) UploadGeoIPSource(_ context.Context, filename string, in io.Reader) (GeoIPSourceFile, error) {
	origName := filepath.Base(strings.TrimSpace(filename))
	if origName == "" || origName == "." || origName == ".." {
		return GeoIPSourceFile{}, fmt.Errorf("invalid filename")
	}
	dir := s.geoIPSourcesDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return GeoIPSourceFile{}, err
	}
	name := origName
	src := in
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".zip" {
		const maxZipUpload int64 = 1 << 30 // 1 GiB compressed archive
		zipTmp := filepath.Join(dir, fmt.Sprintf(".geoip-upload-%d.zip", time.Now().UnixNano()))
		defer os.Remove(zipTmp)
		zf, err := os.OpenFile(zipTmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return GeoIPSourceFile{}, err
		}
		written, copyErr := io.Copy(zf, io.LimitReader(in, maxZipUpload+1))
		closeErr := zf.Close()
		if copyErr != nil {
			return GeoIPSourceFile{}, copyErr
		}
		if closeErr != nil {
			return GeoIPSourceFile{}, closeErr
		}
		if written <= 0 || written > maxZipUpload {
			return GeoIPSourceFile{}, fmt.Errorf("invalid zip upload size")
		}
		zr, err := zip.OpenReader(zipTmp)
		if err != nil {
			return GeoIPSourceFile{}, fmt.Errorf("invalid zip file")
		}
		defer zr.Close()
		var selected *zip.File
		for _, zentry := range zr.File {
			if zentry.FileInfo().IsDir() {
				continue
			}
			base := filepath.Base(strings.TrimSpace(zentry.Name))
			if base == "" || base == "." || base == ".." {
				continue
			}
			e := strings.ToLower(filepath.Ext(base))
			if e != ".mmdb" && e != ".csv" {
				continue
			}
			if selected != nil {
				return GeoIPSourceFile{}, fmt.Errorf("zip must contain exactly one .mmdb or .csv file")
			}
			selected = zentry
		}
		if selected == nil {
			return GeoIPSourceFile{}, fmt.Errorf("zip must contain one .mmdb or .csv file")
		}
		zsrc, err := selected.Open()
		if err != nil {
			return GeoIPSourceFile{}, err
		}
		defer zsrc.Close()
		name = filepath.Base(selected.Name)
		src = zsrc
		ext = strings.ToLower(filepath.Ext(name))
	}
	if ext == ".gz" {
		base := strings.TrimSuffix(name, filepath.Ext(name))
		baseExt := strings.ToLower(filepath.Ext(base))
		if baseExt != ".mmdb" && baseExt != ".csv" {
			return GeoIPSourceFile{}, fmt.Errorf("gzip must contain a .mmdb or .csv file")
		}
		gz, err := gzip.NewReader(in)
		if err != nil {
			return GeoIPSourceFile{}, fmt.Errorf("invalid gzip file")
		}
		defer gz.Close()
		name = filepath.Base(base)
		src = gz
		ext = baseExt
	}
	if ext != ".mmdb" && ext != ".csv" {
		return GeoIPSourceFile{}, fmt.Errorf("only .mmdb, .csv, .mmdb.gz, .csv.gz or .zip are allowed")
	}
	dst := filepath.Join(dir, name)
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return GeoIPSourceFile{}, err
	}
	const maxUpload int64 = 2 << 30 // 2 GiB (decompressed payload limit)
	written, copyErr := io.Copy(f, io.LimitReader(src, maxUpload+1))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return GeoIPSourceFile{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return GeoIPSourceFile{}, closeErr
	}
	if written <= 0 || written > maxUpload {
		_ = os.Remove(tmp)
		return GeoIPSourceFile{}, fmt.Errorf("invalid upload size")
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return GeoIPSourceFile{}, err
	}
	st, err := os.Stat(dst)
	if err != nil {
		return GeoIPSourceFile{}, err
	}
	out := GeoIPSourceFile{
		Name:    name,
		Size:    st.Size(),
		ModTime: st.ModTime().UTC(),
	}
	if _, err := s.CompileGeoIPSources(context.Background(), false); err != nil {
		s.log.Warn("geoip compile after upload failed", map[string]any{"err": err.Error()})
	}
	return out, nil
}

func (s *Service) GeoIPSourceStats(ctx context.Context) (GeoIPStats, error) {
	items, err := s.ListGeoIPSources(ctx)
	if err != nil {
		return GeoIPStats{}, err
	}
	out := GeoIPStats{
		SourceFiles:  len(items),
		CompiledPath: s.geoIPCompiledMMDBPath(),
	}
	for _, it := range items {
		out.SourceBytes += it.Size
		switch strings.ToLower(filepath.Ext(it.Name)) {
		case ".csv":
			out.SourceCSVFiles++
		case ".mmdb":
			out.SourceMMDBFiles++
		}
	}
	if st, err := os.Stat(out.CompiledPath); err == nil {
		out.CompiledExists = true
		out.CompiledSize = st.Size()
		out.CompiledModTime = st.ModTime().UTC()
	}
	events, err := s.store.ListAuditEvents(ctx, 1000)
	if err == nil {
		for _, ev := range events {
			if out.LastCompileAt.IsZero() && ev.Action == "geoip.compile.success" {
				out.LastCompileAt = ev.CreatedAt.UTC()
				for _, part := range strings.Split(ev.Meta, ";") {
					p := strings.TrimSpace(part)
					if strings.HasPrefix(p, "sources=") {
						out.LastCompileSources, _ = strconv.Atoi(strings.TrimPrefix(p, "sources="))
					}
					if strings.HasPrefix(p, "records=") {
						out.LastCompileRecords, _ = strconv.Atoi(strings.TrimPrefix(p, "records="))
					}
				}
			}
			if out.LastUploadAt.IsZero() && ev.Action == "geoip.source.upload" {
				out.LastUploadAt = ev.CreatedAt.UTC()
				out.LastUploadFile = strings.TrimSpace(ev.Target)
			}
			if !out.LastCompileAt.IsZero() && !out.LastUploadAt.IsZero() {
				break
			}
		}
	}
	return out, nil
}
