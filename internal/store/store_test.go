package store

import (
	"context"
	"testing"

	"github.com/domnexdomain/domnexdomain/internal/model"
)

func TestHostStateTransitions(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	d, err := s.UpsertDomain(ctx, model.Domain{Name: "example.com", DNSMode: "manual", CertMode: "letsencrypt", Provider: "manual", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.CreateHost(ctx, d.ID, "app", "app.example.com", "http", "http://127.0.0.1:3000", false, false, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostState(ctx, h.ID, "dns_pending", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostState(ctx, h.ID, "cert_pending", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostState(ctx, h.ID, "active", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostState(ctx, h.ID, "created", "invalid"); err == nil {
		t.Fatal("expected invalid transition to fail")
	}
}
