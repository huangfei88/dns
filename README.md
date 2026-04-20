**English** | [中文](README.zh-CN.md)

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
- **CIS Benchmark** hardening (kernel, filesystem, services, login banners, core dump restrictions)
- **PCI-DSS** compliance (TLS 1.2+, audit logging, 365-day log retention, access control)
- Comprehensive audit logging
- Login banners and access restrictions
- Disabled unnecessary services

### Monitoring & Maintenance
- Health check script (`/usr/local/bin/unbound-health-check`)
- Statistics collection (`/usr/local/bin/unbound-stats`)
- Automatic root hints updates (monthly via systemd timer)
- Automatic DNSSEC trust anchor updates (weekly via systemd timer)
- Log rotation with 365-day retention

## Requirements

- **OS**: Debian 13 (Trixie)
- **VM**: Azure Standard_B2ats_v2 (2 vCPU Arm64, 1 GiB RAM) or similar
- **Network**: Public IP address with ports 53/443/853 open
- **Privileges**: Root access (sudo)

> **Note**: DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443) are natively supported by Unbound (requires libnghttp2 compile-time support). The install script automatically generates self-signed TLS certificates for initial use. For production, replace them with certificates from a trusted CA such as Let's Encrypt.

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
Usage: sudo install_unbound.sh [COMMAND] [OPTIONS]

Commands:
  install               Install and configure Unbound DNS server (default)
  uninstall             Uninstall Unbound DNS server and clean up all configurations
  update                Update Unbound packages, root hints, and trust anchor

Options:
  --dry-run             Show what would be done without making changes
  -h, --help            Show this help message
  -v, --version         Show script version

Note:
  DoT (DNS-over-TLS, port 853) and DoH (DNS-over-HTTPS, port 443) are
  natively supported by Unbound (requires libnghttp2 compile-time support).
  Self-signed TLS certificates are generated during installation.
  For production, replace with certificates from a trusted CA.

Examples:
  sudo ./install_unbound.sh                 # Default: install
  sudo ./install_unbound.sh install         # Install Unbound
  sudo ./install_unbound.sh uninstall       # Uninstall Unbound
  sudo ./install_unbound.sh update          # Update Unbound
  sudo ./install_unbound.sh install --dry-run
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
              │                  │                   │
              └──────────────────┼───────────────────┘
                                 │
                    ┌────────────▼────────────────────────┐
                    │         Unbound DNS Server           │
                    │  Port 53 (DNS) + 853 (DoT) +        │
                    │  443 (DoH, native libnghttp2)       │
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
| `/etc/unbound/unbound.conf.d/01-server.conf` | Core server settings, performance, security, DoT/DoH |
| `/etc/unbound/unbound.conf.d/02-remote-control.conf` | Remote control (localhost only) |
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | Response policy / domain blocklist |
| `/etc/unbound/tls/server.pem` | DoT/DoH TLS certificate (self-signed by default) |
| `/etc/unbound/tls/server.key` | DoT/DoH TLS private key |
| `/etc/unbound/blocklist.conf` | Custom domain blocklist entries |
| `/etc/sysctl.d/99-unbound-dns.conf` | DNS performance + CIS kernel security tuning |
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

# Test DNS-over-TLS (requires kdig from knot-dnsutils)
kdig @<server-ip> +tls example.com A

# Test DNS-over-HTTPS (RFC 8484 wire format)
# Note: Unbound's DoH only supports application/dns-message (wire format),
# NOT application/dns-json. Use base64url-encoded DNS query:
# Use -k flag to skip certificate verification with self-signed certs
curl -ksSf 'https://<server-ip>/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# Verify DNSSEC rejects invalid signatures
dig @<server-ip> dnssec-failed.org A  # Should return SERVFAIL
```

## Security Hardening Summary

### CIS Benchmark Controls
- [x] Kernel hardening (IP forwarding, source routing, ICMP redirects, SYN cookies)
- [x] Core dump restrictions
- [x] File permission hardening
- [x] Unnecessary services disabled (avahi, cups, rpcbind, etc.)
- [x] Login banners (pre-login and post-login)
- [x] ASLR enabled
- [x] BPF and ptrace restrictions

### PCI-DSS Requirements
- [x] TLS 1.2+ for encrypted DNS via native Unbound DoT/DoH (Requirement 4.1)
- [x] Strong cipher suites (DNS transport)
- [x] Comprehensive audit logging (Requirement 10)
- [x] 365-day log retention (PCI-DSS v4.0 Requirement 10.7.1)
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

# Check listening ports (Unbound listens on ports 53, 853, and 443)
sudo ss -tlnp | grep -E ':(53|853|443)\s'
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

> ⚠️ **Security Warning**: Always restrict SSH (port 22) access to your own IP address only. Never open SSH to `Any`.

| Priority | Port | Protocol | Source | Description |
|----------|------|----------|--------|-------------|
| 100 | 53 | UDP | Any | DNS queries |
| 110 | 53 | TCP | Any | DNS queries (TCP) |
| 120 | 853 | TCP | Any | DNS-over-TLS |
| 130 | 443 | TCP | Any | DNS-over-HTTPS |
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
7. Apply systemd sandboxing
8. Create monitoring scripts and maintenance timers
9. Validate configuration and start the service
10. Run post-installation health checks

> **Tip**: The installation log is saved to `/var/log/unbound-install.log`. If anything goes wrong, check this file first.

### Step 4: Verify Installation / 验证安装

```bash
# Run the built-in health check (shows all check results)
sudo /usr/local/bin/unbound-health-check -v

# Test DNS resolution from the server itself
dig @127.0.0.1 example.com A

# Test DNSSEC validation (look for "ad" flag in the response)
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

**Expected results:**
- `dig` should return an IP address for `example.com`
- The `+dnssec` query should show `flags: ... ad;` (Authenticated Data)
- `dnssec-failed.org` should return `SERVFAIL` (proving DNSSEC validation works)
- All health checks should show `[通过]` (PASS)

### Step 5: Test from External Client / 从外部客户端测试

```bash
# Replace <server-ip> with your VM's public IP address

# Basic DNS query
dig @<server-ip> example.com A

# DNSSEC-enabled query
dig @<server-ip> +dnssec google.com A

# TCP query
dig @<server-ip> +tcp example.com AAAA

# Reverse DNS lookup
dig @<server-ip> -x 8.8.8.8

# Query response time benchmark
dig @<server-ip> example.com A | grep "Query time"
```

> If external queries fail, verify: (1) Azure NSG allows port 53 inbound, (2) UFW is not blocking traffic (`sudo ufw status verbose`), (3) Unbound is listening on all interfaces (`ss -ulnp | grep :53`).

### Step 6: Verify DNS-over-TLS & DNS-over-HTTPS / 验证 DoT 和 DoH

The install script automatically configures Unbound's native DoT (port 853) and DoH (port 443) support, and generates self-signed TLS certificates.

#### 6.1 Verify DoT/DoH Port Listening / 验证端口监听

```bash
# Verify Unbound is listening on DoT and DoH ports
sudo ss -tlnp | grep -E ':(53|853|443)\s'
# Should show Unbound listening on ports 53, 853, and 443
```

#### 6.2 Test DNS-over-TLS (DoT) / 测试 DoT

```bash
# Install kdig (part of knot-dnsutils) for DoT testing
sudo apt-get install -y knot-dnsutils

# Test DoT from the server itself
kdig @127.0.0.1 +tls -p 853 example.com A

# Test DoT from an external machine (replace with your domain or IP)
kdig @dns.example.com +tls -p 853 example.com A
```

#### 6.3 Test DNS-over-HTTPS (DoH) / 测试 DoH

```bash
# Test DoH using curl (GET method, RFC 8484 wire format)
# Use -k to skip certificate verification with self-signed certs
curl -ksSf 'https://127.0.0.1/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# Test DoH using curl (POST method, RFC 8484 wire format)
curl -ksSf -X POST https://127.0.0.1/dns-query \
    -H 'Content-Type: application/dns-message' \
    --data-binary @<(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01') | \
    od -A x -t x1

# Note: Unbound's DoH only supports RFC 8484 wire format (application/dns-message).
# JSON format (application/dns-json) is NOT supported.
```

#### 6.4 Replace with Production TLS Certificates / 替换正式证书

The install script generates self-signed certificates by default. For production, use certificates from a trusted CA such as Let's Encrypt:

```bash
# Install certbot
sudo apt-get install -y certbot

# Stop Unbound to free port 443 (certbot standalone mode needs it)
sudo systemctl stop unbound

# Obtain certificate (replace with your domain and email)
sudo certbot certonly --standalone \
    -d dns.example.com \
    --agree-tos \
    --email admin@example.com \
    --non-interactive

# Replace Unbound's TLS certificate
sudo cp /etc/letsencrypt/live/dns.example.com/fullchain.pem /etc/unbound/tls/server.pem
sudo cp /etc/letsencrypt/live/dns.example.com/privkey.pem /etc/unbound/tls/server.key
sudo chown root:unbound /etc/unbound/tls/server.pem /etc/unbound/tls/server.key
sudo chmod 644 /etc/unbound/tls/server.pem
sudo chmod 640 /etc/unbound/tls/server.key

# Restart Unbound
sudo systemctl start unbound

# Set up automatic renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Create post-renewal hook to reload Unbound after certificate renewal
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post
cat <<'HOOK' | sudo tee /etc/letsencrypt/renewal-hooks/post/reload-unbound.sh
#!/bin/bash
cp /etc/letsencrypt/live/dns.example.com/fullchain.pem /etc/unbound/tls/server.pem
cp /etc/letsencrypt/live/dns.example.com/privkey.pem /etc/unbound/tls/server.key
chown root:unbound /etc/unbound/tls/server.pem /etc/unbound/tls/server.key
chmod 644 /etc/unbound/tls/server.pem
chmod 640 /etc/unbound/tls/server.key
systemctl reload unbound 2>/dev/null || true
HOOK
sudo chmod 755 /etc/letsencrypt/renewal-hooks/post/reload-unbound.sh
```

#### 6.5 Encrypted DNS Client Configuration / 客户端加密 DNS 配置

**Android 9+ (Private DNS / DoT):**
1. Settings → Network & Internet → Private DNS
2. Select "Private DNS provider hostname"
3. Enter `dns.example.com`

**iOS 14+ / macOS (DoH):**

Create a `.mobileconfig` profile and install it on the device:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://dns.example.com/dns-query</string>
            </dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.example.dns.doh</string>
            <key>PayloadUUID</key>
            <string>YOUR-UUID-HERE</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.example.dns</string>
    <key>PayloadUUID</key>
    <string>YOUR-UUID-HERE</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadDisplayName</key>
    <string>Custom DNS (DoH)</string>
</dict>
</plist>
```

**Windows 11 (DoH):**
1. Settings → Network & Internet → Advanced network settings → More network adapter options
2. Edit DNS settings, add `https://dns.example.com/dns-query`

**Firefox (DoH):**
1. Settings → Privacy & Security → DNS over HTTPS → Max Protection
2. Custom provider: `https://dns.example.com/dns-query`

#### 6.6 DoT/DoH Troubleshooting / 故障排查

```bash
# Check if Unbound is listening on ports 853 and 443
sudo ss -tlnp | grep -E ':(443|853)\s'

# Check Unbound logs
sudo tail -20 /var/log/unbound/unbound.log

# Verify Unbound configuration
sudo unbound-checkconf

# Check firewall allows traffic
sudo ufw status | grep -E '(443|853)'

# Verbose DoT debugging
kdig @dns.example.com +tls +tls-host=dns.example.com -d example.com A
```

**Common issues:**
- **"Connection refused" on port 853/443**: Ensure Unbound is running. Run `systemctl status unbound` to check.
- **Empty reply on DoH**: Ensure Unbound was compiled with `--with-libnghttp2` support. Run `unbound -V` to check if Linked libs includes libnghttp2, or run `ldd $(which unbound) | grep nghttp2`.
- **Certificate errors**: Check certificate file paths and permissions. Run `openssl x509 -in /etc/unbound/tls/server.pem -noout -subject -dates` to verify.
- **"SSL handshake failed"**: Verify the TLS certificate is valid and the client trusts it (self-signed certs require skipping verification on the client side).

> **Note**: Unbound's native DoH endpoint only supports RFC 8484 wire format (`application/dns-message`). JSON format (`application/dns-json`) is **not** supported.

### Step 7: Configure DNS Records / 配置 DNS 记录

If you want clients to use your server by domain name, create DNS records:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| A | dns.example.com | `<server-ip>` | Server address |
| AAAA | dns.example.com | `<server-ipv6>` | Server IPv6 address |

### Step 8: Managing the Domain Blocklist / 管理域名黑名单

Add malicious or unwanted domains to the blocklist:

```bash
# Edit the blocklist file
sudo nano /etc/unbound/blocklist.conf

# Add entries in this format (one per line):
# local-zone: "malware-domain.com." always_refuse
# local-zone: "tracking-site.net." always_refuse

# After editing, verify the configuration syntax
sudo unbound-checkconf

# Reload Unbound to apply changes (no restart needed)
sudo unbound-control reload
```

### Step 9: Client Configuration / 客户端配置

Configure your devices to use the new DNS server:

**Linux/macOS:**
```bash
# Temporarily test
dig @<server-ip> example.com

# Permanently set DNS (varies by distribution)
# For systemd-resolved systems, edit /etc/systemd/resolved.conf:
#   [Resolve]
#   DNS=<server-ip>
```

**Windows:**
1. Open Network & Internet Settings → Change adapter options
2. Right-click your connection → Properties → IPv4 → Properties
3. Set Preferred DNS server to `<server-ip>`

**Android (Private DNS):**
1. Settings → Network & Internet → Private DNS
2. Select "Private DNS provider hostname"
3. Enter `dns.example.com` (requires valid TLS certificate)

**iOS:**
1. Settings → Wi-Fi → tap your network → Configure DNS → Manual
2. Add `<server-ip>` as DNS server

### Maintenance / 日常维护

```bash
# View real-time logs
sudo tail -f /var/log/unbound/unbound.log

# View statistics
sudo /usr/local/bin/unbound-stats

# Run health check
sudo /usr/local/bin/unbound-health-check -v

# Flush entire DNS cache
sudo unbound-control flush_zone .

# Flush a specific domain from cache
sudo unbound-control flush example.com

# Reload configuration after changes (no downtime)
sudo unbound-control reload

# Full restart (brief downtime)
sudo systemctl restart unbound

# Verify configuration syntax before reloading
sudo unbound-checkconf

# Check automatic update timers
systemctl list-timers --all | grep -E 'root-hints|trust-anchor'

# Check Fail2Ban banned IPs
sudo fail2ban-client status unbound-dns-abuse

# Unban a specific IP from Fail2Ban
sudo fail2ban-client set unbound-dns-abuse unbanip <ip-address>

# View firewall rules
sudo ufw status numbered
```

Root hints are updated automatically (monthly) and DNSSEC trust anchors are updated weekly via systemd timers.

### Backup and Restore / 备份与恢复

The installation script automatically creates a backup in `/var/backups/unbound-install-<timestamp>/` before making changes. To manually backup:

```bash
# Create a manual backup
sudo cp -a /etc/unbound /var/backups/unbound-manual-$(date +%Y%m%d)
sudo cp -a /etc/fail2ban/jail.d/unbound-dns.conf /var/backups/
sudo cp -a /etc/sysctl.d/99-unbound-dns.conf /var/backups/
```

To restore from backup:
```bash
# Stop Unbound
sudo systemctl stop unbound

# Restore configuration (replace <timestamp> with your backup timestamp)
sudo cp -a /var/backups/unbound-install-<timestamp>/etc_unbound/* /etc/unbound/

# Verify and restart
sudo unbound-checkconf
sudo systemctl start unbound
```

### Uninstallation / 卸载

**Recommended: Use the built-in uninstall command:**

```bash
# Preview what will be removed (dry run)
sudo ./install_unbound.sh uninstall --dry-run

# Perform full uninstallation
sudo ./install_unbound.sh uninstall
```

The built-in uninstall command automatically handles all cleanup steps including stopping services, removing configurations, cleaning up firewall rules, and restoring DNS settings.

<details>
<summary>Alternative: Manual uninstallation steps</summary>

To manually remove Unbound and all configurations:

```bash
# Stop and disable services
sudo systemctl stop unbound
sudo systemctl disable unbound
sudo systemctl stop fail2ban

# Remove immutable attribute from resolv.conf
sudo chattr -i /etc/resolv.conf

# Restore default DNS
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Remove packages
sudo apt-get purge -y unbound unbound-anchor unbound-host
sudo apt-get autoremove -y

# Remove configuration files
sudo rm -rf /etc/unbound
sudo rm -rf /var/log/unbound
sudo rm -rf /var/lib/unbound
sudo rm -f /etc/sysctl.d/99-unbound-dns.conf
sudo rm -f /etc/security/limits.d/99-disable-coredumps.conf
sudo rm -f /etc/systemd/coredump.conf.d/99-disable-coredumps.conf
sudo rm -f /etc/fail2ban/jail.d/unbound-dns.conf
sudo rm -f /etc/fail2ban/filter.d/unbound-dns-abuse.conf
sudo rm -rf /etc/systemd/system/unbound.service.d
sudo rm -f /etc/systemd/system/update-root-hints.*
sudo rm -f /etc/systemd/system/update-trust-anchor.*
sudo rm -f /etc/tmpfiles.d/unbound.conf
sudo rm -f /usr/local/bin/unbound-health-check
sudo rm -f /usr/local/bin/unbound-stats
sudo rm -f /usr/local/bin/update-root-hints
sudo rm -f /usr/local/bin/update-trust-anchor
sudo rm -f /etc/logrotate.d/unbound
sudo rm -f /etc/audit/rules.d/99-pci-dss-cis.rules

# Reload systemd
sudo systemctl daemon-reload

# Re-apply sysctl defaults
sudo sysctl --system
```

</details>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.