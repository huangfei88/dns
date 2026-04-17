# Enterprise-Grade Unbound Public DNS Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Enterprise-grade Unbound DNS server installation script for **Debian 13 (Trixie)** on **Azure Standard_B2ats_v2** virtual machines. Designed for public DNS service with maximum security, performance, and compliance.

## Features

### Security
- **DNSSEC** validation with automatic root trust-anchor management
- **DNS-over-TLS (DoT)** on port 853 with TLS 1.2+ (PCI-DSS 3.2.1)
- **DNS-over-HTTPS (DoH)** on port 443
- **QNAME minimisation** (RFC 7816) for upstream privacy
- **0x20 query randomisation** to prevent spoofing
- **Rate limiting** (per-IP and global) with automatic blocking
- **nftables firewall** with connection tracking and anti-DDoS rules
- **Fail2Ban** integration for DNS abuse protection
- **Systemd sandboxing** (ProtectSystem, NoNewPrivileges, MemoryDenyWriteExecute, etc.)
- **deny-any** to prevent amplification attacks
- **Minimal responses** to reduce attack surface
- Server identity and version hidden

### Performance
- Optimized for **2 vCPU / 1 GiB RAM** (Azure Standard_B2ats_v2)
- **2 threads** with `SO_REUSEPORT` for load distribution
- **Aggressive cache prefetching** for popular domains
- **Serve-expired** responses while refreshing (zero-downtime cache)
- **Aggressive NSEC** (RFC 8198) to reduce upstream queries
- Tuned socket buffers and connection limits
- Conservative cache sizes for low-memory environments

### Compliance
- **CIS Benchmark** hardening (kernel, SSH, filesystem, services)
- **PCI-DSS** compliance (TLS 1.2+, audit logging, 90-day log retention, access control)
- Comprehensive audit logging
- Login banners and access restrictions
- Disabled unnecessary services

### Monitoring & Maintenance
- Health check script (`/usr/local/bin/unbound-health-check`)
- Statistics collection (`/usr/local/bin/unbound-stats`)
- Automatic root hints updates (monthly)
- Automatic DNSSEC trust anchor updates (weekly)
- Automatic TLS certificate renewal (Let's Encrypt)
- Log rotation with 90-day retention

## Requirements

- **OS**: Debian 13 (Trixie)
- **VM**: Azure Standard_B2ats_v2 (2 vCPU Arm64, 1 GiB RAM) or similar
- **Network**: Public IP address with ports 53, 443, 853 open
- **DNS**: A domain name pointing to the server's public IP (for TLS certificates)
- **Privileges**: Root access (sudo)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/huangfei88/dns.git
cd dns

# Make the script executable
chmod +x install_unbound.sh

# Run with Let's Encrypt certificate
sudo ./install_unbound.sh --domain dns.example.com --email admin@example.com

# Or run with self-signed certificate (for testing)
sudo ./install_unbound.sh --domain dns.example.com --skip-certbot
```

## Usage

```
Usage: sudo install_unbound.sh [OPTIONS]

Required:
  --domain <FQDN>      Domain name for TLS certificates (e.g., dns.example.com)
  --email  <EMAIL>      Email for Let's Encrypt certificate notifications

Optional:
  --skip-certbot        Skip Let's Encrypt certificate provisioning (use self-signed)
  --dry-run             Show what would be done without making changes
  -h, --help            Show this help message
  -v, --version         Show script version
```

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Internet Clients           │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │     nftables Firewall + Rate Limit   │
                    │   (Connection tracking, Anti-DDoS)   │
                    └─────────────┬───────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
     ┌────────▼──────┐  ┌────────▼──────┐  ┌────────▼──────┐
     │  Port 53      │  │  Port 853     │  │  Port 443     │
     │  DNS (UDP/TCP)│  │  DoT (TLS)    │  │  DoH (HTTPS)  │
     └────────┬──────┘  └────────┬──────┘  └────────┬──────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │         Unbound DNS Server           │
                    │  ┌─────────────────────────────────┐ │
                    │  │  DNSSEC Validation               │ │
                    │  │  Cache (32MB msg + 64MB rrset)   │ │
                    │  │  Rate Limiting                   │ │
                    │  │  QNAME Minimisation              │ │
                    │  │  Aggressive NSEC                 │ │
                    │  │  Response Policy (Blocklist)     │ │
                    │  └─────────────────────────────────┘ │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │       Root DNS Servers               │
                    │       (via root.hints)               │
                    └─────────────────────────────────────┘
```

## Configuration Files

| File | Description |
|------|-------------|
| `/etc/unbound/unbound.conf` | Main configuration (includes modular configs) |
| `/etc/unbound/unbound.conf.d/01-server.conf` | Core server settings, performance, security |
| `/etc/unbound/unbound.conf.d/02-remote-control.conf` | Remote control (localhost only) |
| `/etc/unbound/unbound.conf.d/03-doh.conf` | DNS-over-HTTPS configuration |
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | Response policy / domain blocklist |
| `/etc/unbound/blocklist.conf` | Custom domain blocklist entries |
| `/etc/nftables.conf` | Firewall rules |
| `/etc/sysctl.d/99-unbound-dns.conf` | Kernel tuning parameters |

## Management Commands

```bash
# Service management
sudo systemctl status unbound
sudo systemctl restart unbound
sudo systemctl reload unbound

# Health check
sudo /usr/local/bin/unbound-health-check -v

# View statistics
sudo /usr/local/bin/unbound-stats

# View logs
sudo tail -f /var/log/unbound/unbound.log

# Flush DNS cache
sudo unbound-control flush_zone .

# Check configuration
sudo unbound-checkconf

# View cache dump
sudo unbound-control dump_cache

# View firewall rules
sudo nft list ruleset
```

## Testing

```bash
# Test DNS resolution
dig @<server-ip> example.com A

# Test DNSSEC validation
dig @<server-ip> +dnssec example.com A

# Test DNS-over-TLS (requires kdig from knot-dnsutils)
kdig @<server-ip> +tls example.com A

# Test DNS-over-HTTPS
curl -H 'accept: application/dns-json' \
  'https://dns.example.com/dns-query?name=example.com&type=A'

# Verify DNSSEC rejects invalid signatures
dig @<server-ip> dnssec-failed.org A  # Should return SERVFAIL
```

## Security Hardening Summary

### CIS Benchmark Controls
- [x] Kernel hardening (IP forwarding, source routing, ICMP redirects)
- [x] Core dump restrictions
- [x] SSH hardening (Protocol 2, MaxAuthTries, no root login)
- [x] File permission hardening
- [x] Unnecessary services disabled
- [x] Login banners
- [x] ASLR enabled

### PCI-DSS Requirements
- [x] TLS 1.2+ for encrypted DNS (Requirement 4.1)
- [x] Strong cipher suites only
- [x] Comprehensive audit logging (Requirement 10)
- [x] 90-day log retention (Requirement 10.7)
- [x] Firewall with default-deny policy (Requirement 1)
- [x] System hardening (Requirement 2)
- [x] Access control (Requirement 7)

## Azure NSG Configuration

Remember to configure your Azure Network Security Group (NSG) to allow:

| Priority | Port | Protocol | Source | Description |
|----------|------|----------|--------|-------------|
| 100 | 53 | UDP | Any | DNS queries |
| 110 | 53 | TCP | Any | DNS queries (TCP) |
| 120 | 853 | TCP | Any | DNS-over-TLS |
| 130 | 443 | TCP | Any | DNS-over-HTTPS |
| 140 | 22 | TCP | Your IP | SSH management |

## Troubleshooting

```bash
# Check service status and recent logs
sudo systemctl status unbound
sudo journalctl -u unbound -n 50 --no-pager

# Verify configuration syntax
sudo unbound-checkconf

# Check listening ports
sudo ss -tlnp | grep -E ':(53|853|443)\s'
sudo ss -ulnp | grep ':53\s'

# Test with verbose output
dig @127.0.0.1 +trace example.com

# Check firewall rules
sudo nft list ruleset

# Check Fail2Ban status
sudo fail2ban-client status unbound-dns-abuse
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.