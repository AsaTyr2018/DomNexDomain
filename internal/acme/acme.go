package acme

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type HostProvider interface {
	ListFQDNs(ctx context.Context) ([]string, error)
}

type Manager struct {
	manager *autocert.Manager
}

func New(cacheDir, email string, staging bool, hostProvider HostProvider) *Manager {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		Email:  email,
	}
	m.HostPolicy = func(ctx context.Context, host string) error {
		host = strings.ToLower(host)
		list, err := hostProvider.ListFQDNs(ctx)
		if err != nil {
			return err
		}
		for _, fqdn := range list {
			if strings.EqualFold(host, fqdn) {
				return nil
			}
		}
		return autocert.ErrCacheMiss
	}
	if staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	return &Manager{manager: m}
}

func (m *Manager) HTTPHandler(next http.Handler) http.Handler {
	return m.manager.HTTPHandler(next)
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
}
