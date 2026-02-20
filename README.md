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
  - Per-subdomain traffic gating modes
    - `active`: normal external + internal access.
    - `maintenance`: external traffic gets a maintenance page, LAN/hairpin clients can still access the upstream.
    - `disabled`: all traffic receives a host-disabled page.
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
  - User account roles: `admin`, `domain-admin`
    - Supports global administration and domain-scoped delegation for multi-tenant or team-based operations.
  - API token roles: `admin`, `operator`, `read-only`
    - Enables scoped automation identities separate from human UI users.
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
  - Per-subdomain GeoIP policy (allow/deny country lists)
    - Evaluates client IP to ISO country code and enforces optional country-based access rules before proxy upstream/auth flow.
  - Destructive action confirmation for host deletion
    - Subdomain delete requires explicit `Remove` text confirmation in the UI.

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

GeoIP implementation note:
- Country detection is IP-based and mapped to ISO-3166-1 alpha-2 codes.
- UI presets (for example `EU`, `DACH`, `North America`) are static code lists for predictable behavior.
- Local/private client addresses are treated as `LOCAL` and are not blocked by Geo policy.

## API Overview (Technical)

Base path: `/api/v1`

### Authentication Modes

- Session auth (Web UI style):
  - `GET /api/v1/csrf`
  - `POST /api/v1/login`
  - include `X-CSRF-Token` for state-changing requests when using cookie sessions
- Bearer token auth (automation):
  - `Authorization: Bearer <token>`
  - no CSRF token required for token-based requests
  - tokens are created in the Web UI under `API Mgmt` (admin role)
  - generated token values are shown once at creation time

Example:

```bash
BASE="https://admin.example.com"
TOKEN="dnx_xxx"
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/me"
```

### Core Endpoint Groups

- Auth/session:
  - `GET /csrf`
  - `POST /login`
  - `POST /logout`
  - `GET /me`
- Domains:
  - `GET /domains`
  - `POST /domains/preflight`
  - `POST /domains`
  - `GET /domains/{id}/live-check`
  - `DELETE /domains/{id}`
- Hosts/Subdomains:
  - `GET /hosts`
  - `GET /hosts/diagnostics`
  - `POST /hosts/preflight`
  - `POST /hosts`
  - `PUT /hosts/{id}`
  - `PUT /hosts/{id}/auth`
  - `PUT /hosts/{id}/geo`
  - `POST /hosts/{id}/disable`
  - `POST /hosts/{id}/maintenance`
  - `POST /hosts/{id}/retry`
  - `DELETE /hosts/{id}`
- Settings/system:
  - `GET /settings`
  - `POST /settings`
  - `POST /reload`
  - `GET /audit`
- Tokens/users:
  - `GET /tokens`
  - `POST /tokens`
  - `DELETE /tokens/{id}`
  - `GET /users`
  - `POST /users`
  - `PUT /users/{id}/domains`
  - `DELETE /users/{id}`

### In-App API Documentation

DomNexDomain includes an internal API reference page in the Web UI (`API Docs` menu).  
Use it for endpoint descriptions, permission context, and ready-to-run request examples.

### Role + Scope Model

- User roles (Web UI accounts): `admin`, `domain-admin`
- API token roles: `admin`, `operator`, `read-only`
- Current UI behavior:
  - User creation in the Web UI currently offers `admin` and `domain-admin`.
  - `operator` and `read-only` are currently available through API token role selection.
- Tokens can be constrained by:
  - scope strings (e.g. `hosts:write`, `domains:write`, `users:write`)
  - optional domain scoping (`domainIds`)
- Principle of use:
  - prefer least privilege for automation tokens
  - reserve global write scopes for tightly controlled CI/CD paths

### HA Payload Example

```json
{
  "domain": "example.com",
  "subdomain": "app-ha",
  "insecureTls": true,
  "haEnabled": true,
  "haMode": "failover",
  "haBackends": [
    { "name": "Server1", "url": "http://127.0.0.1:18081" },
    { "name": "Server2", "url": "http://127.0.0.1:18082" }
  ]
}
```
