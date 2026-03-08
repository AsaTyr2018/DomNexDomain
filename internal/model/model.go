package model

import "time"

type Role string

const (
	RoleAdmin       Role = "admin"
	RoleDomainAdmin Role = "domain-admin"
	RoleOperator    Role = "operator"
	RoleReadOnly    Role = "read-only"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	AuthProvider string    `json:"authProvider,omitempty"`
	AllowedCIDRs string    `json:"allowedCidrs"`
	IPCheckOff   bool      `json:"ipCheckOff"`
	MFAEnabled   bool      `json:"mfaEnabled"`
	MFASecretEnc string    `json:"-"`
	MFAEnrolled  time.Time `json:"mfaEnrolledAt"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type PermissionGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Template    string    `json:"template"`
	System      bool      `json:"system"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type PermissionGroupEntry struct {
	GroupID    int64     `json:"groupId"`
	Permission string    `json:"permission"`
	CreatedAt  time.Time `json:"createdAt"`
}

type UserGroupMembership struct {
	UserID     int64     `json:"userId"`
	GroupID    int64     `json:"groupId"`
	Priority   int       `json:"priority"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	GroupName  string    `json:"groupName,omitempty"`
	IsTemplate bool      `json:"isTemplate,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    int64     `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type APIToken struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	TokenPrefix string    `json:"tokenPrefix"`
	TokenHash   string    `json:"-"`
	Scopes      string    `json:"scopes"`
	Role        Role      `json:"role"`
	DomainIDs   []int64   `json:"domainIds,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt"`
	CreatedAt   time.Time `json:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt"`
}

type Domain struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	DNSMode   string    `json:"dnsMode"`
	CertMode  string    `json:"certMode"`
	Provider  string    `json:"provider"`
	ZoneID    string    `json:"zoneId"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Host struct {
	ID                int64       `json:"id"`
	DomainID          int64       `json:"domainId"`
	Subdomain         string      `json:"subdomain"`
	FQDN              string      `json:"fqdn"`
	ConnectionProfile string      `json:"connectionProfile"`
	UpstreamURL       string      `json:"upstreamUrl"`
	InsecureTLS       bool        `json:"insecureTls"`
	HAEnabled         bool        `json:"haEnabled"`
	HAMode            string      `json:"haMode,omitempty"`
	HABackends        []HABackend `json:"haBackends,omitempty"`
	AuthEnabled       bool        `json:"authEnabled"`
	AuthUser          string      `json:"authUser,omitempty"`
	AuthPassHash      string      `json:"-"`
	GeoMode           string      `json:"geoMode,omitempty"`
	GeoCountries      []string    `json:"geoCountries,omitempty"`
	State             string      `json:"state"`
	ErrorReason       string      `json:"errorReason,omitempty"`
	CreatedAt         time.Time   `json:"createdAt"`
	UpdatedAt         time.Time   `json:"updatedAt"`
}

type HABackend struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type AuditEvent struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Meta      string    `json:"meta"`
	SourceIP  string    `json:"sourceIp,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SSHBastionRoute struct {
	ID         int64     `json:"id"`
	FQDN       string    `json:"fqdn"`
	TargetHost string    `json:"targetHost"`
	TargetPort int       `json:"targetPort"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type SSHBastionKey struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"publicKey"`
	Fingerprint string    `json:"fingerprint"`
	Enabled     bool      `json:"enabled"`
	RouteIDs    []int64   `json:"routeIds"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type SSHBastionKeyAuth struct {
	Key    SSHBastionKey
	Routes []SSHBastionRoute
}

type ThreatIntelConfig struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`
	OSFirewall       bool   `json:"osFirewall"`
	OSFirewallMode   string `json:"osFirewallMode"`
	SyncHours        int    `json:"syncHours"`
	EventMinHits     int    `json:"eventMinHits"`
	OffenderMinHits  int    `json:"offenderMinHits"`
	MonitorMaxLevel  int    `json:"monitorMaxLevel"`
	SoftMinLevel     int    `json:"softMinLevel"`
	HardLevel        int    `json:"hardLevel"`
	SoftBlockMinutes int    `json:"softBlockMinutes"`
}

type ThreatIntelFeed struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Enabled    bool      `json:"enabled"`
	IsDefault  bool      `json:"isDefault"`
	EntryCount int64     `json:"entryCount"`
	LastSyncAt time.Time `json:"lastSyncAt"`
	LastError  string    `json:"lastError"`
	LastHash   string    `json:"lastHash"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type ThreatIntelSnapshot struct {
	Enabled          bool
	Mode             string
	EventMinHits     int
	OffenderMinHits  int
	MonitorMaxLevel  int
	SoftMinLevel     int
	HardLevel        int
	SoftBlockMinutes int
	Allowlist        map[string]bool
	FeedByIP         map[string][]string
}

type ThreatIntelMatchEvent struct {
	IP          string
	Feed        string
	Host        string
	Path        string
	Country     string
	Mode        string
	Decision    string
	TraceID     string
	SourceScope string
	XPDelta     int
	XPAfter     int
	LevelAfter  int
	TierAfter   string
}

type ThreatIntelMatch struct {
	ID          int64     `json:"id"`
	IP          string    `json:"ip"`
	Feed        string    `json:"feed"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	TargetCount int64     `json:"targetCount"`
	Country     string    `json:"country"`
	Mode        string    `json:"mode"`
	Decision    string    `json:"decision"`
	Hits        int64     `json:"hits"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	LastTraceID string    `json:"lastTraceId"`
	SourceScope string    `json:"sourceScope"`
	XP          int       `json:"xp"`
	Level       int       `json:"level"`
	Tier        string    `json:"tier"`
	RiskState   string    `json:"riskState"`
}

type ThreatIntelTarget struct {
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Feed       string    `json:"feed"`
	Decision   string    `json:"decision"`
	Hits       int64     `json:"hits"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

type ThreatIntelOffender struct {
	IP            string    `json:"ip"`
	TotalHits     int64     `json:"totalHits"`
	DistinctFeeds int64     `json:"distinctFeeds"`
	DistinctHosts int64     `json:"distinctHosts"`
	FeedSummary   string    `json:"feedSummary"`
	Decisions     string    `json:"decisions"`
	LastSeenAt    time.Time `json:"lastSeenAt"`
	Blocked       bool      `json:"blocked"`
	Allowlisted   bool      `json:"allowlisted"`
	XP            int       `json:"xp"`
	Level         int       `json:"level"`
	Tier          string    `json:"tier"`
	RiskState     string    `json:"riskState"`
}

type ThreatIntelBlocked struct {
	IP            string    `json:"ip"`
	Reason        string    `json:"reason"`
	History       string    `json:"history"`
	BlockedOn     time.Time `json:"blockedOn"`
	BlockedUntil  time.Time `json:"blockedUntil"`
	UpdatedAt     time.Time `json:"updatedAt"`
	TotalHits     int64     `json:"totalHits"`
	DistinctFeeds int64     `json:"distinctFeeds"`
	DistinctHosts int64     `json:"distinctHosts"`
	LastSeenAt    time.Time `json:"lastSeenAt"`
	XP            int       `json:"xp"`
	Level         int       `json:"level"`
	Tier          string    `json:"tier"`
	RiskState     string    `json:"riskState"`
}

type ThreatIntelGeoPoint struct {
	Country string `json:"country"`
	State   string `json:"state"` // monitor | soft | hard
	IPs     int64  `json:"ips"`
	Hits    int64  `json:"hits"`
}

type ThreatIntelMetaDashboard struct {
	TotalBannedIPs             int64   `json:"totalBannedIps"`
	AverageEscalationSeconds   float64 `json:"averageEscalationSeconds"`
	AverageXPBeforeBan         float64 `json:"averageXpBeforeBan"`
	AverageRehabSeconds        float64 `json:"averageRehabSeconds"`
	FalsePositiveRehabSharePct float64 `json:"falsePositiveRehabSharePct"`
	RehabCount                 int64   `json:"rehabCount"`
	FalsePositiveRehabCount    int64   `json:"falsePositiveRehabCount"`
	SoftBanCount               int64   `json:"softBanCount"`
	HardBanCount               int64   `json:"hardBanCount"`
	SoftBanAvgDecaySeconds     float64 `json:"softBanAvgDecaySeconds"`
	HardBanAvgDecaySeconds     float64 `json:"hardBanAvgDecaySeconds"`
}

type ThreatIntelIPState struct {
	IP             string
	XP             int
	Level          int
	RiskState      string
	BanUntil       time.Time
	PermBlocked    bool
	TempBlockCount int
	LastSeenAt     time.Time
	TopSignal      string
	SignalCounts   map[string]int
}

type BackupArchive struct {
	ID        int64     `json:"id"`
	FileName  string    `json:"fileName"`
	Storage   string    `json:"storage"` // local | ftp
	Location  string    `json:"location"`
	SizeBytes int64     `json:"sizeBytes"`
	SHA256    string    `json:"sha256"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

type ThreatIntelEventInput struct {
	IP          string
	Host        string
	Path        string
	UserAgent   string
	Country     string
	SourceScope string
	TraceID     string
	Signals     []string
	Mode        string
}

type ThreatIntelEventResult struct {
	Decision  string
	Blocked   bool
	HardBlock bool
	BanUntil  time.Time
	XPDelta   int
	XPAfter   int
	Level     int
	Tier      string
	RiskState string
}
