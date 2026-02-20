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
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
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
	ID           int64       `json:"id"`
	DomainID     int64       `json:"domainId"`
	Subdomain    string      `json:"subdomain"`
	FQDN         string      `json:"fqdn"`
	UpstreamURL  string      `json:"upstreamUrl"`
	InsecureTLS  bool        `json:"insecureTls"`
	HAEnabled    bool        `json:"haEnabled"`
	HAMode       string      `json:"haMode,omitempty"`
	HABackends   []HABackend `json:"haBackends,omitempty"`
	AuthEnabled  bool        `json:"authEnabled"`
	AuthUser     string      `json:"authUser,omitempty"`
	AuthPassHash string      `json:"-"`
	GeoMode      string      `json:"geoMode,omitempty"`
	GeoCountries []string    `json:"geoCountries,omitempty"`
	State        string      `json:"state"`
	ErrorReason  string      `json:"errorReason,omitempty"`
	CreatedAt    time.Time   `json:"createdAt"`
	UpdatedAt    time.Time   `json:"updatedAt"`
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
	CreatedAt time.Time `json:"createdAt"`
}
