# DomNexDomain

Security-first edge control plane for self-hosters and operators who want one hardened Linux binary instead of a pile of moving parts.

DomNexDomain combines reverse proxying, TLS automation, DNS automation, RBAC, API tokens, audit logging, and Web UI/API management in a single process.

<img width="1906" height="814" alt="grafik" src="https://github.com/user-attachments/assets/8b9b1547-dc8d-4b60-a21c-c1f4562cbdc7" />

## Why DomNexDomain

- Single statically linked Go binary
- Linux-focused runtime model (`systemd`, Debian/Ubuntu LTS first)
- Built-in control plane UI + API (no extra dashboard stack)
- Built-in certificate lifecycle flow (Let's Encrypt, staging toggle, retries/backoff)
- Built-in DNS provider automation (Cloudflare first, provider abstraction ready)
- SQLite persistence with encrypted secrets
- Security-oriented defaults (network gating, auth, CSRF, audit)

## Feature Highlights

- Reverse proxy engine:
  - Host-based HTTP/HTTPS routing
    - Routes traffic by requested hostname, so each subdomain maps cleanly to its own upstream service.
  - WebSocket support
    - Supports long-lived upgraded connections for apps like streaming, realtime dashboards, and game backends.
  - HTTP/2 support
    - Improves client connection behavior and latency under modern browsers and TLS endpoints.
  - Optional HA per subdomain (failover / round-robin)
    - `failover`: prioritizes a primary backend and switches to secondary targets when reachability checks fail.
    - `round_robin`: distributes requests across multiple healthy targets for load spreading.
    - Health state is visible in the UI (`Hosts Online x/x`) with explicit offline backend names.
- ACME:
  - Let's Encrypt production + staging
    - Switch between staging and production ACME endpoints without changing deployment architecture.
  - Certificate diagnostics and status visibility in UI
    - Shows DNS/HTTP/HTTPS/TLS checks and certificate lifetime status per host.
  - Backoff-aware retry handling
    - Detects transient issuance problems and retries with controlled backoff to avoid noisy failure loops.
- DNS:
  - Cloudflare API integration
    - Can provision and update required A records directly via API for managed domains/subdomains.
  - Per-domain Zone ID support
    - Avoids global zone assumptions and keeps multi-domain/multi-zone setups explicit and safe.
  - Live checks for DNS and reachability
    - Verifies DNS resolution, target matching, and endpoint reachability from the control plane perspective.
- Access control:
  - Roles: `admin`, `domain-admin`, `operator`, `read-only`
    - Supports global administration and domain-scoped delegation for multi-tenant or team-based operations.
  - API tokens with scoped permissions and optional domain scoping
    - Enables automation clients with least-privilege access instead of sharing admin session credentials.
- Security and operations:
  - Argon2id password hashing
    - Hardened password storage with memory-hard hashing suitable for exposed admin surfaces.
  - Session + CSRF protections
    - Protects state-changing UI/API operations against common browser-side attack vectors.
  - Audit event logging (including failed auth events)
    - Captures login failures and high-impact configuration actions for forensic traceability.
  - Prometheus metrics endpoint
    - Exposes operational telemetry for alerting and dashboard integration.

## DomNexDomain vs Nginx/Caddy/Traefik

DomNexDomain is not trying to be "just another proxy process". It is a security-focused control plane with an integrated operations model.

- Compared to Nginx:
  - Nginx is an excellent data-plane server, but control-plane workflows (RBAC, API tokens, UI, audit, DNS/ACME automation) are usually assembled externally.
  - DomNexDomain ships these workflows in one package.
- Compared to Caddy:
  - Caddy has great certificate ergonomics out of the box.
  - DomNexDomain adds integrated role-based administration, domain-scoped permissions, API token governance, and built-in auditability.
- Compared to Traefik:
  - Traefik is strong in dynamic/service-discovery ecosystems.
  - DomNexDomain targets lean Linux single-node and small-cluster operators who want minimal runtime dependencies and an integrated control plane.

If you want raw proxy flexibility first, classic proxies are great.  
If you want security-conscious operational governance with fewer external components, DomNexDomain is the point.

## Requirements

- Linux only (x86_64, ARM64)
- Debian/Ubuntu LTS recommended
- `systemd`
- Open inbound ports `80/tcp` and `443/tcp` to the host
- Go 1.24+ (build from source)
- Node.js + npm (build UI from source only; not required at runtime)

## Deployment Scope (Current)

DomNexDomain currently targets bare-metal Linux deployments with `systemd`.

Containerized deployment (Docker/Compose/Kubernetes) is intentionally deferred until the current development phase is complete.  
This keeps the v1 operational model focused, auditable, and predictable.

## Install (Production, systemd)

### 1. Build binary

```bash
git clone https://github.com/MythosMachina/DomNexDomain /opt/domnexdomain
cd /opt/domnexdomain
go mod tidy
go build -o build/domnexdomain ./cmd/domnexdomain
```

### 2. Build UI assets (if needed)

If `web/dist` is already present and up to date, you can skip this.

```bash
cd /opt/domnexdomain/ui
npm install
npm run build
```

### 3. Install filesystem layout

```bash
sudo useradd --system --home /var/lib/domnexdomain --shell /usr/sbin/nologin domnexdomain || true
sudo mkdir -p /etc/domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
sudo chown -R domnexdomain:domnexdomain /var/lib/domnexdomain /var/log/domnexdomain
sudo install -m 0755 /opt/domnexdomain/build/domnexdomain /usr/bin/domnexdomain
```

### 4. Configure environment

Start from the template:

```bash
sudo cp /opt/domnexdomain/config/domnexdomain.env.example /etc/domnexdomain/domnexdomain.env
sudo nano /etc/domnexdomain/domnexdomain.env
```

Minimum important values:

- `DOMNEX_BOOTSTRAP_USER=admin`
- `DOMNEX_BOOTSTRAP_PASSWORD=<strong-password>`
- `DOMNEX_HTTP_ADDR=:80`
- `DOMNEX_HTTPS_ADDR=:443`
- `DOMNEX_ADMIN_BIND=0.0.0.0:8443` (or restricted bind IP)
- `DOMNEX_ACME_EMAIL=<you@example.com>`

`DOMNEX_DOMAIN` is optional. Leaving it empty starts with no preloaded master domain.

### 5. Install and start service

```bash
sudo cp /opt/domnexdomain/deploy/systemd/domnexdomain.service /etc/systemd/system/domnexdomain.service
sudo systemctl daemon-reload
sudo systemctl enable --now domnexdomain
sudo systemctl status domnexdomain
```

## First Admin Account (Bootstrap)

On first startup, DomNexDomain creates the bootstrap admin from:

- `DOMNEX_BOOTSTRAP_USER`
- `DOMNEX_BOOTSTRAP_PASSWORD`

Login with those credentials in the Web UI.

After first login:

1. Rotate bootstrap password to a long random value.
2. Create additional admin/domain-admin accounts as needed.
3. Store Cloudflare token in Settings if you use Cloudflare automation.

## Runtime Layout

- Binary: `/usr/bin/domnexdomain`
- Config: `/etc/domnexdomain/domnexdomain.env`
- Data: `/var/lib/domnexdomain/`
- Logs: `/var/log/domnexdomain/`

## Observability

- JSON logs on stdout (optional file logs in runtime log dir)
- Prometheus metrics endpoint via `DOMNEX_METRICS_ADDR` (default `127.0.0.1:9108`) at `/metrics`

## Security Baseline

- Admin network allowlist before auth checks
- Mandatory authentication for control-plane actions
- API token scope enforcement
- Argon2id password hashing
- Session cookie + CSRF protections for state-changing requests
- Audit trail for security-relevant actions
