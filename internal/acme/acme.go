package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	certcrypto "github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	cfdns "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type HostProvider interface {
	ListFQDNs(ctx context.Context) ([]string, error)
	ListCatchAllDomains(ctx context.Context) ([]string, error)
	ListWildcardDomains(ctx context.Context) ([]string, error)
	GetCloudflareToken(ctx context.Context) (string, error)
}

type Manager struct {
	auto         *autocert.Manager
	hostProvider HostProvider
	cacheDir     string
	email        string
	staging      bool

	refreshMu sync.Mutex
	mu        sync.RWMutex
	wildcards map[string]*tls.Certificate
}

const cloudflareDNS01SettleDelay = 5 * time.Minute

func New(cacheDir, email string, staging bool, hostProvider HostProvider) *Manager {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		Email:  email,
	}
	m.HostPolicy = func(ctx context.Context, host string) error {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		list, err := hostProvider.ListFQDNs(ctx)
		if err != nil {
			return err
		}
		for _, fqdn := range list {
			if strings.EqualFold(host, fqdn) {
				return nil
			}
		}
		catchAllDomains, err := hostProvider.ListCatchAllDomains(ctx)
		if err != nil {
			return err
		}
		for _, d := range catchAllDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if host != d && strings.HasSuffix(host, "."+d) {
				return nil
			}
		}
		return autocert.ErrCacheMiss
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	return &Manager{
		auto:         m,
		hostProvider: hostProvider,
		cacheDir:     cacheDir,
		email:        strings.TrimSpace(email),
		staging:      staging,
		wildcards:    map[string]*tls.Certificate{},
	}
}

func (m *Manager) HTTPHandler(next http.Handler) http.Handler {
	return m.auto.HTTPHandler(next)
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
}

func (m *Manager) StartRefresher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.RefreshWildcardCertificates(ctx)
		}
	}
}

func (m *Manager) RefreshWildcardCertificates(ctx context.Context) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	token, err := m.hostProvider.GetCloudflareToken(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return nil
	}
	domains, err := m.hostProvider.ListWildcardDomains(ctx)
	if err != nil {
		return err
	}
	var errs []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if err := m.ensureWildcardCert(ctx, d, strings.TrimSpace(token)); err != nil {
			errs = append(errs, d+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("wildcard refresh errors: %s", strings.Join(errs, " | "))
	}
	return nil
}

func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))
	if host != "" {
		if cert := m.findWildcardForHost(host); cert != nil {
			return cert, nil
		}
	}
	return m.auto.GetCertificate(hello)
}

func (m *Manager) findWildcardForHost(host string) *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.wildcards) == 0 {
		return nil
	}
	type match struct {
		domain string
		cert   *tls.Certificate
	}
	candidates := make([]match, 0, len(m.wildcards))
	for d, cert := range m.wildcards {
		if host == d || strings.HasSuffix(host, "."+d) {
			candidates = append(candidates, match{domain: d, cert: cert})
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return len(candidates[i].domain) > len(candidates[j].domain) })
	return candidates[0].cert
}

func (m *Manager) ensureWildcardCert(_ context.Context, domain, token string) error {
	if cert := m.findWildcardForHost(domain); cert != nil {
		if leaf := cert.Leaf; leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
			return nil
		}
	}
	crtPath, keyPath := m.wildcardPaths(domain)
	if cert, err := loadTLSKeyPair(crtPath, keyPath); err == nil {
		if leaf := cert.Leaf; leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
			m.mu.Lock()
			m.wildcards[domain] = cert
			m.mu.Unlock()
			return nil
		}
	}

	res, err := m.obtainWildcardCert(domain, token)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(crtPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(crtPath, res.Certificate, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, res.PrivateKey, 0o600); err != nil {
		return err
	}
	cert, err := loadTLSKeyPair(crtPath, keyPath)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.wildcards[domain] = cert
	m.mu.Unlock()
	return nil
}

func (m *Manager) wildcardPaths(domain string) (string, string) {
	base := filepath.Join(m.cacheDir, "wildcard")
	name := strings.ReplaceAll(domain, "*", "wild")
	return filepath.Join(base, name+".crt.pem"), filepath.Join(base, name+".key.pem")
}

func loadTLSKeyPair(crtPath, keyPath string) (*tls.Certificate, error) {
	crt, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
			pair.Leaf = leaf
		}
	}
	return &pair, nil
}

func (m *Manager) obtainWildcardCert(domain, token string) (*certificate.Resource, error) {
	user, err := m.loadOrCreateAccount()
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(user)
	if m.staging {
		cfg.CADirURL = lego.LEDirectoryStaging
	}
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	if reg, err := client.Registration.ResolveAccountByKey(); err == nil {
		user.Registration = reg
	} else {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		user.Registration = reg
	}

	cfCfg := cfdns.NewDefaultConfig()
	cfCfg.AuthToken = token
	provider, err := cfdns.NewDNSProviderConfig(cfCfg)
	if err != nil {
		return nil, err
	}
	err = client.Challenge.SetDNS01Provider(
		provider,
		// Cloudflare propagation can lag; enforce a fixed settle window before LE validation.
		dns01.PropagationWait(cloudflareDNS01SettleDelay, true),
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
		dns01.DisableAuthoritativeNssPropagationRequirement(),
	)
	if err != nil {
		return nil, err
	}

	req := certificate.ObtainRequest{
		Domains: []string{domain, "*." + domain},
		Bundle:  true,
	}
	return client.Certificate.Obtain(req)
}

func (m *Manager) loadOrCreateAccount() (*legoUser, error) {
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(m.cacheDir, "lego_account.key")
	if key, err := readPrivateKeyPEM(keyPath); err == nil {
		return &legoUser{Email: m.email, key: key}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writePrivateKeyPEM(keyPath, key); err != nil {
		return nil, err
	}
	return &legoUser{Email: m.email, key: key}, nil
}

func readPrivateKeyPEM(path string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid account key pem")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	anyKey, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 != nil {
		return nil, err
	}
	return anyKey, nil
}

func writePrivateKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o600)
}

type legoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *legoUser) GetEmail() string {
	return u.Email
}

func (u *legoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *legoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
