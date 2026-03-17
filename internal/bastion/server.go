package bastion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/domnexdomain/domnexdomain/internal/logx"
	"github.com/domnexdomain/domnexdomain/internal/model"
	"golang.org/x/crypto/ssh"
)

type AuthSource interface {
	GetSSHBastionAuthByFingerprint(ctx context.Context, fingerprint string) (model.SSHBastionKeyAuth, error)
	AddAuditEvent(ctx context.Context, e model.AuditEvent) error
	AddTraceEvent(ctx context.Context, e model.TraceEvent) error
	ApplyThreatIntelEvent(ctx context.Context, in model.ThreatIntelEventInput) (model.ThreatIntelEventResult, error)
	IsSourceBlocked(ctx context.Context, ip string) (bool, bool, time.Time, string, error)
}

type Server struct {
	addr        string
	hostKeyPath string
	src         AuthSource
	log         *logx.Logger
}

func New(addr, hostKeyPath string, src AuthSource, log *logx.Logger) *Server {
	return &Server{
		addr:        strings.TrimSpace(addr),
		hostKeyPath: strings.TrimSpace(hostKeyPath),
		src:         src,
		log:         log,
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.addr == "" {
		return fmt.Errorf("ssh bastion addr empty")
	}
	signer, err := ensureHostSigner(s.hostKeyPath)
	if err != nil {
		return err
	}
	cfg := &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			sourceIP := addrIP(meta.RemoteAddr())
			if blocked, hard, until, why, err := s.src.IsSourceBlocked(context.Background(), sourceIP); err == nil && blocked {
				traceID := sshTraceID(sourceIP, meta.User(), "auth_blocked")
				blockReason := strings.TrimSpace(why)
				if blockReason == "" {
					if hard {
						blockReason = "threat_intel_hardblock"
					} else {
						blockReason = "threat_intel_softblock"
					}
				}
				metaBits := "source=" + sourceIP + ";user=" + meta.User() + ";reason=" + blockReason + ";trace=" + traceID
				if !until.IsZero() {
					metaBits += ";until=" + until.UTC().Format(time.RFC3339)
				}
				_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
					TraceID:     traceID,
					Kind:        "flow",
					Actor:       "ssh-bastion",
					Action:      "auth.blocked",
					Target:      meta.User(),
					SourceIP:    sourceIP,
					IP:          sourceIP,
					Host:        "ssh-bastion",
					Path:        "auth",
					Decision:    blockReason,
					SourceScope: sourceScopeFromIP(sourceIP),
					Summary:     "SSH bastion rejected a blocked source before key evaluation",
				})
				_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
					Actor:  "ssh-bastion",
					Action: "ssh.bastion.auth.blocked",
					Target: sourceIP,
					Meta:   metaBits,
				})
				return nil, fmt.Errorf("source blocked")
			}
			fp := ssh.FingerprintSHA256(key)
			auth, err := s.src.GetSSHBastionAuthByFingerprint(context.Background(), fp)
			if err != nil || !auth.Key.Enabled {
				traceID := sshTraceID(sourceIP, meta.User(), "auth_denied")
				_, _ = s.src.ApplyThreatIntelEvent(context.Background(), model.ThreatIntelEventInput{
					IP:          sourceIP,
					Host:        "ssh-bastion",
					Path:        "auth",
					Country:     "ZZ",
					SourceScope: sourceScopeFromIP(sourceIP),
					TraceID:     traceID,
					Signals:     []string{"behavior.auth_failed", "protocol.ssh.auth_denied"},
					Mode:        "auto_mode",
				})
				_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
					TraceID:     traceID,
					Kind:        "flow",
					Actor:       "ssh-bastion",
					Action:      "auth.denied",
					Target:      meta.User(),
					SourceIP:    sourceIP,
					IP:          sourceIP,
					Host:        "ssh-bastion",
					Path:        "auth",
					Decision:    "publickey_denied",
					SourceScope: sourceScopeFromIP(sourceIP),
					Summary:     "SSH bastion rejected presented public key",
				})
				_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
					Actor:  "ssh-bastion",
					Action: "ssh.bastion.auth.denied",
					Target: meta.RemoteAddr().String(),
					Meta:   "fingerprint=" + fp + ";user=" + meta.User() + ";source=" + sourceIP + ";trace=" + traceID,
				})
				return nil, fmt.Errorf("unknown key")
			}
			traceID := sshTraceID(sourceIP, meta.User(), "auth_ok")
			_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
				TraceID:     traceID,
				Kind:        "flow",
				Actor:       "ssh-bastion",
				Action:      "auth.ok",
				Target:      auth.Key.Name,
				SourceIP:    sourceIP,
				IP:          sourceIP,
				Host:        "ssh-bastion",
				Path:        "auth",
				Decision:    "publickey_ok",
				SourceScope: sourceScopeFromIP(sourceIP),
				Summary:     "SSH bastion accepted public key",
			})
			_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
				Actor:  "ssh-bastion",
				Action: "ssh.bastion.auth.ok",
				Target: auth.Key.Name,
				Meta:   "fingerprint=" + fp + ";user=" + meta.User() + ";source=" + addrIP(meta.RemoteAddr()) + ";trace=" + traceID,
			})
			return &ssh.Permissions{Extensions: map[string]string{
				"key_fingerprint": fp,
				"principal":       auth.Key.Name,
			}}, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	s.log.Info("ssh bastion listening", map[string]any{"addr": s.addr})
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go s.handleConn(conn, cfg)
	}
}

func (s *Server) handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	serverConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "direct-tcpip" {
			_ = ch.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		var d struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(ch.ExtraData(), &d); err != nil {
			_ = ch.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
			continue
		}
		fp := serverConn.Permissions.Extensions["key_fingerprint"]
		auth, err := s.src.GetSSHBastionAuthByFingerprint(context.Background(), fp)
		if err != nil || !auth.Key.Enabled {
			_ = ch.Reject(ssh.Prohibited, "unauthorized key")
			continue
		}
		targetHost := strings.TrimSpace(d.DestAddr)
		targetPort := int(d.DestPort)
		allowed := false
		for _, rt := range auth.Routes {
			if !rt.Enabled {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(rt.TargetHost), targetHost) && rt.TargetPort == targetPort {
				allowed = true
				break
			}
		}
		if !allowed {
			sourceIP := addrIP(serverConn.RemoteAddr())
			traceID := sshTraceID(sourceIP, auth.Key.Name, "forward_denied")
			_, _ = s.src.ApplyThreatIntelEvent(context.Background(), model.ThreatIntelEventInput{
				IP:          sourceIP,
				Host:        "ssh-bastion",
				Path:        "forward",
				Country:     "ZZ",
				SourceScope: sourceScopeFromIP(sourceIP),
				TraceID:     traceID,
				Signals:     []string{"behavior.auth_failed", "protocol.ssh.forward_denied"},
				Mode:        "auto_mode",
			})
			_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
				TraceID:     traceID,
				Kind:        "flow",
				Actor:       auth.Key.Name,
				Action:      "forward.denied",
				Target:      fmt.Sprintf("%s:%d", targetHost, targetPort),
				SourceIP:    sourceIP,
				IP:          sourceIP,
				Host:        "ssh-bastion",
				Path:        "forward",
				Decision:    "target_not_allowed",
				SourceScope: sourceScopeFromIP(sourceIP),
				Summary:     "SSH bastion denied forwarding target",
			})
			_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
				Actor:  auth.Key.Name,
				Action: "ssh.bastion.forward.denied",
				Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
				Meta:   "source=" + sourceIP + ";fingerprint=" + fp + ";trace=" + traceID,
			})
			_ = ch.Reject(ssh.Prohibited, "target not allowed")
			continue
		}
		upstream, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)), 8*time.Second)
		if err != nil {
			traceID := sshTraceID(addrIP(serverConn.RemoteAddr()), auth.Key.Name, "forward_error")
			_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
				TraceID:     traceID,
				Kind:        "flow",
				Actor:       auth.Key.Name,
				Action:      "forward.error",
				Target:      fmt.Sprintf("%s:%d", targetHost, targetPort),
				SourceIP:    addrIP(serverConn.RemoteAddr()),
				IP:          addrIP(serverConn.RemoteAddr()),
				Host:        "ssh-bastion",
				Path:        "forward",
				Decision:    "target_unreachable",
				SourceScope: sourceScopeFromIP(addrIP(serverConn.RemoteAddr())),
				Summary:     "SSH bastion could not reach configured target",
				Meta:        "err=" + err.Error(),
			})
			_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
				Actor:  auth.Key.Name,
				Action: "ssh.bastion.forward.error",
				Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
				Meta:   "source=" + addrIP(serverConn.RemoteAddr()) + ";err=" + err.Error() + ";trace=" + traceID,
			})
			_ = ch.Reject(ssh.ConnectionFailed, "target unreachable")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			_ = upstream.Close()
			continue
		}
		go ssh.DiscardRequests(requests)
		traceID := sshTraceID(addrIP(serverConn.RemoteAddr()), auth.Key.Name, "forward_ok")
		_ = s.src.AddTraceEvent(context.Background(), model.TraceEvent{
			TraceID:     traceID,
			Kind:        "flow",
			Actor:       auth.Key.Name,
			Action:      "forward.ok",
			Target:      fmt.Sprintf("%s:%d", targetHost, targetPort),
			SourceIP:    addrIP(serverConn.RemoteAddr()),
			IP:          addrIP(serverConn.RemoteAddr()),
			Host:        "ssh-bastion",
			Path:        "forward",
			Decision:    "forward_opened",
			SourceScope: sourceScopeFromIP(addrIP(serverConn.RemoteAddr())),
			Summary:     "SSH bastion opened forwarding channel",
		})
		_ = s.src.AddAuditEvent(context.Background(), model.AuditEvent{
			Actor:  auth.Key.Name,
			Action: "ssh.bastion.forward.ok",
			Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
			Meta:   "source=" + addrIP(serverConn.RemoteAddr()) + ";fingerprint=" + fp + ";trace=" + traceID,
		})
		pipeConn(channel, upstream)
	}
}

type rwc interface {
	io.Reader
	io.Writer
	io.Closer
}

func pipeConn(a, b rwc) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if c, ok := a.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if c, ok := b.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func ensureHostSigner(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(raw)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}

func addrIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(a.String()))
	if err != nil {
		return strings.TrimSpace(a.String())
	}
	return strings.TrimSpace(host)
}

func sourceScopeFromIP(ip string) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return "external"
	}
	if p.IsLoopback() || p.IsPrivate() {
		return "internal"
	}
	return "external"
}

func sshTraceID(ip, user, reason string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(ip)))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strings.TrimSpace(user)))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strings.TrimSpace(reason)))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return fmt.Sprintf("%016x", h.Sum64())
}
