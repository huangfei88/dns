# Enterprise-Grade Unbound Public DNS Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Enterprise-grade Unbound DNS server installation script for **Debian 13 (Trixie)** on **Azure Standard_B2ats_v2** virtual machines. Designed for public DNS service with maximum security, performance, and compliance.

## Features

### Security
- **DNSSEC** validation with automatic root trust-anchor management
- **QNAME minimisation** (RFC 7816) for upstream privacy
- **0x20 query randomisation** to prevent spoofing
- **Rate limiting** (per-IP and global) with automatic blocking
- **UFW firewall** (nftables backend) with default-deny policy and rate-limited SSH
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
- **CIS Benchmark** hardening (kernel, SSH, filesystem, services, login banners, core dump restrictions)
- **PCI-DSS** compliance (TLS 1.2+, audit logging, 90-day log retention, access control)
- Comprehensive audit logging
- Login banners and access restrictions
- Disabled unnecessary services

### Monitoring & Maintenance
- Health check script (`/usr/local/bin/unbound-health-check`)
- Statistics collection (`/usr/local/bin/unbound-stats`)
- Automatic root hints updates (monthly via systemd timer)
- Automatic DNSSEC trust anchor updates (weekly via systemd timer)
- Log rotation with 90-day retention

## Requirements

- **OS**: Debian 13 (Trixie)
- **VM**: Azure Standard_B2ats_v2 (2 vCPU Arm64, 1 GiB RAM) or similar
- **Network**: Public IP address with port 53 open (ports 443/853 needed if NGINX proxy is used for DoT/DoH)
- **Privileges**: Root access (sudo)

> **Note**: DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443) are handled by a separately installed NGINX reverse proxy. TLS certificates are provisioned during the NGINX installation. This script only configures Unbound as a recursive DNS resolver on port 53.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/huangfei88/dns.git
cd dns

# Make the script executable
chmod +x install_unbound.sh

# Run the installation
sudo ./install_unbound.sh

# Or preview what would be done (dry run)
sudo ./install_unbound.sh --dry-run
```

## Usage

```
Usage: sudo install_unbound.sh [OPTIONS]

Optional:
  --dry-run             Show what would be done without making changes
  -h, --help            Show this help message
  -v, --version         Show script version

Note:
  DoT (DNS-over-TLS) and DoH (DNS-over-HTTPS) are handled by a separately
  installed NGINX reverse proxy. TLS certificates are provisioned during NGINX
  installation. This script only configures Unbound as a recursive DNS resolver
  on port 53.
```

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Internet Clients           │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────┐
                    │       UFW Firewall + Rate Limit      │
                    │   (nftables backend, Default-Deny)   │
                    └─────────────┬───────────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
     ┌────────▼──────┐  ┌────────▼──────┐  ┌────────▼──────┐
     │  Port 53      │  │  Port 853     │  │  Port 443     │
     │  DNS (UDP/TCP)│  │  DoT (TLS)    │  │  DoH (HTTPS)  │
     └────────┬──────┘  └────────┬──────┘  └────────┬──────┘
              │                   │                   │
              │           ┌──────┴──────────────┐     │
              │           │  NGINX Reverse Proxy │     │
              │           │  (separate install)  │     │
              │           └──────┬──────────────┘     │
              │                  │   (proxy to 53)    │
              └──────────────────┼────────────────────┘
                                 │
                    ┌────────────▼────────────────────────┐
                    │         Unbound DNS Server           │
                    │         (Port 53 only)               │
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
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | Response policy / domain blocklist |
| `/etc/unbound/blocklist.conf` | Custom domain blocklist entries |
| `/etc/sysctl.d/99-unbound-dns.conf` | DNS performance + CIS kernel security tuning |
| `/etc/ssh/sshd_config.d/99-cis-hardening.conf` | SSH CIS hardening configuration |
| `/etc/security/limits.d/99-disable-coredumps.conf` | Core dump restrictions |

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
sudo ufw status verbose
```

## Testing

```bash
# Test DNS resolution
dig @<server-ip> example.com A

# Test DNSSEC validation
dig @<server-ip> +dnssec example.com A

# Test DNS-over-TLS (requires NGINX proxy and kdig from knot-dnsutils)
kdig @<server-ip> +tls example.com A

# Test DNS-over-HTTPS (requires NGINX proxy)
curl -H 'accept: application/dns-json' \
  'https://dns.example.com/dns-query?name=example.com&type=A'

# Verify DNSSEC rejects invalid signatures
dig @<server-ip> dnssec-failed.org A  # Should return SERVFAIL
```

## Security Hardening Summary

### CIS Benchmark Controls
- [x] Kernel hardening (IP forwarding, source routing, ICMP redirects, SYN cookies)
- [x] Core dump restrictions
- [x] SSH hardening (MaxAuthTries, strong ciphers, no X11 forwarding, login banner)
- [x] File permission hardening
- [x] Unnecessary services disabled (avahi, cups, rpcbind, etc.)
- [x] Login banners (pre-login and post-login)
- [x] ASLR enabled
- [x] BPF and ptrace restrictions

### PCI-DSS Requirements
- [x] TLS 1.2+ for encrypted DNS via NGINX proxy (Requirement 4.1)
- [x] Strong cipher suites (SSH and DNS transport)
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

# Check listening ports (Unbound listens on port 53 only; 853/443 are via NGINX)
sudo ss -tlnp | grep ':53\s'
sudo ss -ulnp | grep ':53\s'

# Test with verbose output
dig @127.0.0.1 +trace example.com

# Check firewall rules
sudo ufw status verbose

# Check Fail2Ban status
sudo fail2ban-client status unbound-dns-abuse
```

## Detailed Deployment Guide / 详细部署教程

### Step 1: Create Azure VM / 创建 Azure 虚拟机

1. Log into [Azure Portal](https://portal.azure.com)
2. Create a new VM with these settings:
   - **Image**: Debian 13 (Trixie) ARM64
   - **Size**: Standard_B2ats_v2 (2 vCPU Arm64, 1 GiB RAM)
   - **Authentication**: SSH public key (recommended) or password
   - **Public IP**: Static (required for DNS service)
   - **OS Disk**: 30 GB Standard SSD (P4)

3. Configure **Network Security Group (NSG)**:

| Priority | Port | Protocol | Source | Description |
|----------|------|----------|--------|-------------|
| 100 | 53 | UDP | Any | DNS queries |
| 110 | 53 | TCP | Any | DNS queries (TCP) |
| 120 | 853 | TCP | Any | DNS-over-TLS (for NGINX) |
| 130 | 443 | TCP | Any | DNS-over-HTTPS (for NGINX) |
| 140 | 22 | TCP | Your IP only | SSH management |

### Step 2: Initial Server Setup / 初始服务器配置

```bash
# SSH into the server
ssh <username>@<server-public-ip>

# Update the system
sudo apt-get update && sudo apt-get upgrade -y

# Install git (if not present)
sudo apt-get install -y git
```

### Step 3: Clone and Run / 克隆并运行

```bash
# Clone the repository
git clone https://github.com/huangfei88/dns.git
cd dns

# Make the script executable
chmod +x install_unbound.sh

# (Optional) Preview what will be done
sudo ./install_unbound.sh --dry-run

# Run the installation
sudo ./install_unbound.sh
```

The script will automatically:
1. Install all required packages (Unbound, Fail2Ban, UFW, etc.)
2. Apply kernel security hardening (CIS Benchmark + DNS performance tuning)
3. Configure DNSSEC with automatic root trust-anchor management
4. Set up Unbound with optimized configuration for the VM size
5. Configure UFW firewall with default-deny policy
6. Set up Fail2Ban for DNS abuse protection
7. Apply systemd sandboxing and SSH hardening
8. Create monitoring scripts and maintenance timers
9. Validate configuration and start the service
10. Run post-installation health checks

### Step 4: Verify Installation / 验证安装

```bash
# Run the built-in health check
sudo /usr/local/bin/unbound-health-check -v

# Test DNS resolution from the server itself
dig @127.0.0.1 example.com A

# Test DNSSEC validation
dig @127.0.0.1 +dnssec example.com A

# Verify DNSSEC rejects bad signatures (should return SERVFAIL)
dig @127.0.0.1 dnssec-failed.org A

# Check service status
sudo systemctl status unbound
sudo ufw status verbose
sudo fail2ban-client status unbound-dns-abuse

# View statistics
sudo /usr/local/bin/unbound-stats
```

### Step 5: Test from External Client / 从外部客户端测试

```bash
# Replace <server-ip> with your VM's public IP
dig @<server-ip> example.com A
dig @<server-ip> +dnssec google.com A
dig @<server-ip> +tcp example.com AAAA
```

### Step 6: (Optional) Set Up DNS-over-TLS/HTTPS / 配置 DoT/DoH

DNS-over-TLS (port 853) and DNS-over-HTTPS (port 443) are handled by a separately installed NGINX reverse proxy. Install and configure NGINX with TLS certificates after Unbound is running:

1. Point a domain name (e.g., `dns.example.com`) to your server's public IP
2. Install NGINX and certbot
3. Configure NGINX to proxy DoT (port 853) and DoH (port 443) to Unbound (port 53)
4. Obtain TLS certificates via Let's Encrypt

### Step 7: Configure DNS Records / 配置 DNS 记录

If you want clients to use your server by domain name, create DNS records:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| A | dns.example.com | `<server-ip>` | Server address |
| AAAA | dns.example.com | `<server-ipv6>` | Server IPv6 address |

### Maintenance / 日常维护

```bash
# View logs
sudo tail -f /var/log/unbound/unbound.log

# View statistics
sudo /usr/local/bin/unbound-stats

# Flush DNS cache
sudo unbound-control flush_zone .

# Reload configuration after changes
sudo unbound-control reload

# Verify configuration syntax
sudo unbound-checkconf

# Check automatic update timers
systemctl list-timers --all | grep -E 'root-hints|trust-anchor'
```

Root hints are updated automatically (monthly) and DNSSEC trust anchors are updated weekly via systemd timers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.