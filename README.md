<img width="999" height="442" alt="DomNexDomain" src="https://github.com/user-attachments/assets/71b5ed38-e6c8-4e2a-a9b5-dac75e1144c9" />

# DomNexDomain

**From lean reverse proxy to full edge control plane for secure self-hosting.**

DomNexDomain started as a focused routing layer.  
It has evolved into an integrated edge platform that combines routing, DNS and certificate automation, threat-aware policy enforcement, observability, and day-2 operations in one Linux-native service.

## Product Positioning

DomNexDomain is a **self-hosted Edge Control Plane**:

- expose internal services safely
- enforce security posture at the edge
- operate everything from one UI/API
- keep runtime simple (single Go binary, systemd-first)

## Connectivity Prerequisite

DomNexDomain is the gatekeeper, not the connectivity provider.

It assumes your edge is reachable from the internet on the intended entry points. Provider constraints (CGNAT, IPv6-only edge gaps, tunnel strategy) are currently out of product scope and tracked separately in roadmap guidance (`P11`).

## Why DomNexDomain

- **Integrated edge stack**: reverse proxy, DNS automation, ACME, authn/authz, threat controls, metrics, logs.
- **Security-first flow**: Threat Intel + WAF baseline + geo policy + traceable edge error handling.
- **Operational clarity**: Strategic Intel unifies events, telemetry, geo, and investigations for fast operator workflows.
- **Resilience after WAN drops**: automatic public-IP reconciliation and Cloudflare DNS self-heal.
- **Linux-native runtime**: statically linked Go binary, systemd deployment, no Node.js requirement in production.
- **Pragmatic persistence**: SQLite + encrypted secrets for v1 simplicity.

## Core Capabilities

- Host-based HTTP/HTTPS routing with WebSocket and HTTP/2 support
- Optional HA per subdomain (`failover` / `round-robin`)
- SSH Bastion gateway mode
- Automated DNS + certificate workflows (Cloudflare-first)
- Automated WAN-IP drift handling with Cloudflare reconciliation
- 1-minute DNS maintenance loop for apex + subdomain reachability transitions
- In-house MFA/2FA (TOTP) with per-role enforcement and recovery flow
- Login hardening with staged auth flow and anti-enumeration behavior
- Smart branded edge error pages with trace ID correlation
- Threat Intel modes (`Monitor only` / `Auto mode`) with allowlist-first policy
- Edge hard-drop enforcement for hard-blocked sources
- GeoIP multi-source ingestion (`.mmdb`, `.csv`, `.gz`, `.zip`) with compiled source-of-truth MMDB
- GeoIP source stats and upload progress in Web UI
- Role model: `admin`, `domain-admin`, `read-only`
- Scoped API tokens (global/domain/system)
- Data retention controls + daily purge jobs
- Encrypted backup/restore pipeline with scheduled jobs and post-restore checks
- Audit events for resilience operations (`network.public_ip.changed.auto`, `maintenance.reachability.changed`, `maintenance.cloudflare.domain_updated`)
- Setup Assistant with OTS unlock and restore-first onboarding
- UI style profiles (`Monolith`, `CyberMonolith`, `Custom`)

## Built For

- security-focused homelabs
- small infra teams and operators
- self-hosters who want fewer moving parts than stitching Nginx/Caddy + scripts + extra tooling

## Documentation

Detailed setup and operations are maintained in the wiki:

For appliance-style onboarding:

```bash
sudo ./deploy/systemd/setup-appliance.sh
```

- **Wiki Home:** https://github.com/AsaTyr2018/DomNexDomain/wiki
- **Quick Start:** https://github.com/AsaTyr2018/DomNexDomain/wiki/00-Quick-Start
- **Installation (Bare Metal):** https://github.com/AsaTyr2018/DomNexDomain/wiki/01-Installation-Bare-Metal
- **Initial Setup Assistant and OTS:** https://github.com/AsaTyr2018/DomNexDomain/wiki/23-Initial-Setup-Assistant-and-OTS
- **Backup and Restore:** https://github.com/AsaTyr2018/DomNexDomain/wiki/10-Backup-and-Restore
- **Users, Roles, and MFA:** https://github.com/AsaTyr2018/DomNexDomain/wiki/06-Users-and-Roles
- **Threat Intel Operations:** https://github.com/AsaTyr2018/DomNexDomain/wiki/18-Threat-Intel-Operations
- **API Usage Guide:** https://github.com/AsaTyr2018/DomNexDomain/wiki/13-API-Usage-Guide

## Operating Profiles

- `Quickstart Gate` (default): strong baseline with minimal friction
- `Warden Gate` (hardening): stricter security posture for exposed production edges

Profile guidance is documented in the wiki.

## Compliance Notice

- IP addresses are treated as operational security data and are subject to retention limits.
- DomNexDomain does not automatically ensure legal compliance. Operators remain responsible for lawful use.

## Support

- GitHub Issues: https://github.com/AsaTyr2018/DomNexDomain/issues
- Discord: https://discord.gg/GnAUmXhfeG

## Screenshots

<img width="1900" height="840" alt="grafik" src="https://github.com/user-attachments/assets/cbf69637-7f7c-4306-8853-ee10099a4898" />
<img width="1905" height="882" alt="grafik" src="https://github.com/user-attachments/assets/c2548fa2-4cf7-485f-b562-e9bf0dd1fd82" />
<img width="1910" height="782" alt="grafik" src="https://github.com/user-attachments/assets/7bea719c-811b-4ee0-a235-2d32cb9ab173" />
<img width="1904" height="825" alt="grafik" src="https://github.com/user-attachments/assets/835b045c-4019-4150-982f-9582538612d3" />
