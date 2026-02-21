<img width="999" height="442" alt="logo" src="https://github.com/user-attachments/assets/71b5ed38-e6c8-4e2a-a9b5-dac75e1144c9" />

Build and run secure public self-hosting with one hardened edge control plane: proxy, TLS, DNS automation, access control, and observability in a single Linux service.

DomNexDomain combines reverse proxying, TLS automation, DNS automation, RBAC, API tokens, audit logging, and Web UI/API management in a single process.

## Why DomNexDomain

- Single statically linked Go binary
- Linux-focused runtime model (`systemd`, Debian/Ubuntu LTS first)
- Built-in control plane UI + API (no extra dashboard stack)
- Built-in certificate lifecycle flow (Let's Encrypt, staging toggle, retries/backoff)
- Built-in DNS provider automation (Cloudflare first, provider abstraction ready)
- SQLite persistence with encrypted secrets
- Security-oriented defaults (network gating, auth, CSRF, audit)

## Feature Highlights

- Operator-focused UI and branding:
  - Style system with `Monolith`, `CyberMonolith`, and `Custom` profiles
    - One profile switch applies consistently to Dashboard, MetricCenter, LogCenter, login pages, and edge error pages.
  - Unified DomNexDomain branding
    - Dedicated logo integration across sidebar, login overlays, and smart error surfaces for consistent operator/user-facing identity.

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
  - Optional SSH Bastion listener (single public TCP port)
    - Dedicated SSH bastion mode on one configurable port (for example `2222`) without changing HTTP/HTTPS routing.
    - Subdomain wizard integration: mark a subdomain as `SSH Bastion` to auto-bind upstream handling and auto-register its SSH bastion route.
    - Public-key authentication with per-key target allowlists.
    - Forwarding decisions are audited (`ssh.bastion.*` events).
- ACME:
  - Let's Encrypt production + staging
    - Switch between staging and production ACME endpoints without changing deployment architecture.
  - Deterministic Cloudflare DNS-01 flow for wildcard certs
    - DomNexDomain creates/updates `_acme-challenge` TXT records via Cloudflare API, then waits 5 minutes before validation to absorb DNS propagation delay.
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
  - User account roles: `admin`, `domain-admin`, `read-only`
    - `admin`: full control across domains, users, settings, and system operations.
    - `domain-admin`: write access for assigned domains/subdomains only.
    - `read-only`: observer mode, read access only (no create/update/delete).
  - API token roles: `admin`, `operator`, `read-only`
    - Enables scoped automation identities separate from human UI users.
  - API tokens with scoped permissions and optional domain scoping
    - Enables automation clients with least-privilege access instead of sharing admin session credentials.
- Security and operations:
  - Threat Intel management (allowlist-first, 2-mode model)
    - `monitor_only`: detect, score, and audit only (no automatic blocking).
    - `auto_mode`: applies temporary soft blocks and escalates hard-risk sources to permanent hard block.
    - Allowlist always takes precedence, even in auto mode.
  - Hard-block edge drop behavior
    - Hard-blocked source IPs are dropped at app edge level (connection close) instead of receiving a rendered error page.
    - This reduces response surface for hostile scanners while preserving audit visibility (`proxy.block.hard_drop`).
  - Argon2id password hashing
    - Hardened password storage with memory-hard hashing suitable for exposed admin surfaces.
  - Session + CSRF protections
    - Protects state-changing UI/API operations against common browser-side attack vectors.
  - Audit event logging (including failed auth events)
    - Captures login failures and high-impact configuration actions for forensic traceability.
  - Smart Edge Error Pages with Trace ID
    - DomNexDomain serves branded error pages for policy/origin/routing failures with a trace ID shown to the user.
    - The same trace ID is written into audit events (`proxy.error.*`) so operators can search and correlate quickly in the Logs UI.
  - Built-in WAF baseline with temporary auto-block
    - Unknown-host flood traffic is detected at the edge and auto-blocked per source IP for 15 minutes.
    - Blocks are intentionally temporary (no permanent auto-ban), reducing lockout risk while still damping scanner noise.
    - WAF decisions are audited (`proxy.waf.temp_block.set` / `proxy.waf.temp_block.hit`).
  - Prometheus metrics endpoint
    - Exposes operational telemetry for alerting and dashboard integration.
  - MetricCenter traffic analytics
    - Global or per-subdomain request analysis with selectable windows (`1h`, `6h`, `24h`, `7d`), country heat map, and country-level status breakdown.
    - Includes unknown-country (`ZZ`) breakdown by subdomain to identify noisy or unresolved traffic sources quickly.
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

Safe local publish (recommended):

```bash
cd /opt/domnexdomain
make publish-local
```

`publish-local` enforces serial build order (`UI -> Go binary -> service restart`) and verifies the live served UI asset hash to prevent stale deploys.

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
- Optional SSH bastion:
  - `DOMNEX_SSH_BASTION_ENABLED=true`
  - `DOMNEX_SSH_BASTION_ADDR=:2222`
  - `DOMNEX_SSH_BASTION_HOST_KEY=/var/lib/domnexdomain/ssh_bastion_host_key.pem`

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
2. Create additional `admin`, `domain-admin`, or `read-only` accounts as needed.
3. Store Cloudflare token in Settings if you use Cloudflare automation.

## Runtime Layout

- Binary: `/usr/bin/domnexdomain`
- Config: `/etc/domnexdomain/domnexdomain.env`
- Data: `/var/lib/domnexdomain/`
- Logs: `/var/log/domnexdomain/`

## Observability

- JSON logs on stdout (optional file logs in runtime log dir)
- Prometheus metrics endpoint via `DOMNEX_METRICS_ADDR` (default `127.0.0.1:9108`) at `/metrics`
- `LogCenter` is a tabular audit view for high-volume operation:
  - dynamic filters for time window, level, namespace, action, actor, source IP/scope, target, and free-text
  - trace-ID lookup for direct smart-error correlation
  - source-IP quick actions (for example temporary/manual block workflows)
- Security and status operational widgets are consolidated in `MetricCenter` to keep `LogCenter` focused on investigation workflows.

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

GeoIP database setup (recommended):
- Source: `https://download.ip2location.com/lite/`
- Download: `IP2LOCATION-LITE-DB1.MMDB.ZIP`
- Target directory on server: `/var/lib/domnexdomain/geoip/`
- Required runtime file path: `/var/lib/domnexdomain/geoip/IP2LOCATION-LITE-DB1.MMDB`
- The MMDB file is runtime data and must not be committed to git.

## Support

- Open a GitHub issue for bugs, feature requests, or regressions.
- Join the community Discord for setup help and operator discussion:
  - https://discord.gg/GnAUmXhfeG

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
- Threat Intel:
  - `GET /threat-intel/config`
  - `POST /threat-intel/config`
  - `GET /threat-intel/feeds`
  - `POST /threat-intel/feeds`
  - `DELETE /threat-intel/feeds/{id}`
  - `POST /threat-intel/sync`
  - `GET /threat-intel/matches`
  - `GET /threat-intel/offenders`
  - `GET /threat-intel/targets`
  - `GET /threat-intel/blocked`
  - `GET /threat-intel/allowlist`
  - `POST /threat-intel/allowlist`
  - `DELETE /threat-intel/allowlist/{ip}`
- SSH bastion (admin):
  - `GET /ssh/routes`
  - `POST /ssh/routes`
  - `DELETE /ssh/routes/{id}`
  - `GET /ssh/keys`
  - `POST /ssh/keys/import`
  - `POST /ssh/keys/generate`
  - `DELETE /ssh/keys/{id}`

### In-App API Documentation

DomNexDomain includes an internal API reference page in the Web UI (`API Docs` menu).  
Use it for endpoint descriptions, permission context, and ready-to-run request examples.

### Role + Scope Model

- User roles (Web UI accounts): `admin`, `domain-admin`, `read-only`
- API token roles: `admin`, `operator`, `read-only`
- Current UI behavior:
  - User creation in the Web UI offers `admin`, `domain-admin`, and `read-only`.
  - `operator` is intended for API token automation use.
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

## Screenshots

<img width="1900" height="840" alt="grafik" src="https://github.com/user-attachments/assets/cbf69637-7f7c-4306-8853-ee10099a4898" />
<img width="1905" height="882" alt="grafik" src="https://github.com/user-attachments/assets/c2548fa2-4cf7-485f-b562-e9bf0dd1fd82" />
<img width="1910" height="782" alt="grafik" src="https://github.com/user-attachments/assets/7bea719c-811b-4ee0-a235-2d32cb9ab173" />
<img width="1904" height="825" alt="grafik" src="https://github.com/user-attachments/assets/835b045c-4019-4150-982f-9582538612d3" />
