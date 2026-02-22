<img width="999" height="442" alt="DomNexDomain" src="https://github.com/user-attachments/assets/71b5ed38-e6c8-4e2a-a9b5-dac75e1144c9" />

# DomNexDomain

**All-in-one edge control plane for secure public self-hosting.**

DomNexDomain combines reverse proxy, TLS automation, DNS automation, access control, observability, and security policy in one Linux-native service.

## Connectivity Prerequisite

DomNexDomain is the gatekeeper, not the connectivity provider.

It assumes your edge is reachable from the internet on the intended entry points. Provider constraints (CGNAT, IPv6-only edge gaps, tunnel strategy) are currently out of product scope and tracked separately in roadmap guidance (`P11`).

## Why It Stands Out

- One statically linked Go binary
- Linux + systemd first (Debian/Ubuntu LTS)
- Integrated Web UI + API control plane
- ACME + DNS automation with Cloudflare-first provider model
- Built-in Threat Intel, WAF baseline, and audit visibility
- HA routing and SSH Bastion in the same platform
- SQLite persistence with encrypted secrets

## Operating Profiles

Two official operations profiles help teams ramp from simple to hardened setups:

- `Quickstart Gate` (default): TLS, per-user admin IP policy, baseline threat controls, single upstream, logs enabled.
- `Warden Gate` (hardening): Threat Intel auto mode, geo policy, HA routing, external SIEM, stricter admin/API posture.

Details and rollout guidance are documented in the wiki.

## Built For

- Security-focused homelab operators
- Small teams running multiple internal services
- Anyone who wants fewer moving parts than classic proxy stacks

## Key Product Capabilities

- Reverse proxy with host-based routing, WebSocket, HTTP/2
- Optional per-subdomain HA (failover or round-robin)
- Smart edge error pages with trace IDs and LogCenter correlation
- Role-based access (`admin`, `domain-admin`, `read-only`)
- API tokens with scopes and domain boundaries
- MetricCenter + LogCenter for operations and investigations
- Retention policy controls with automatic daily data purge
- Style profiles (`Monolith`, `CyberMonolith`, `Custom`) across UI, login, and edge pages

## Documentation

Technical setup and operations are maintained in the wiki:

- **Wiki Home:** https://github.com/AsaTyr2018/DomNexDomain/wiki
- **Quick Start:** https://github.com/AsaTyr2018/DomNexDomain/wiki/00-Quick-Start
- **Installation (Bare Metal):** https://github.com/AsaTyr2018/DomNexDomain/wiki/01-Installation-Bare-Metal
- **API Usage Guide:** https://github.com/AsaTyr2018/DomNexDomain/wiki/13-API-Usage-Guide

## Support

- GitHub Issues: https://github.com/AsaTyr2018/DomNexDomain/issues
- Discord: https://discord.gg/GnAUmXhfeG

## Screenshots

<img width="1900" height="840" alt="grafik" src="https://github.com/user-attachments/assets/cbf69637-7f7c-4306-8853-ee10099a4898" />
<img width="1905" height="882" alt="grafik" src="https://github.com/user-attachments/assets/c2548fa2-4cf7-485f-b562-e9bf0dd1fd82" />
<img width="1910" height="782" alt="grafik" src="https://github.com/user-attachments/assets/7bea719c-811b-4ee0-a235-2d32cb9ab173" />
<img width="1904" height="825" alt="grafik" src="https://github.com/user-attachments/assets/835b045c-4019-4150-982f-9582538612d3" />
