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
- **UFW firewall** (nftables backend) with default-deny policy
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
- **PCI-DSS** compliance (TLS 1.2+ via NGINX proxy, audit logging, 365-day log retention, access control)
- Comprehensive audit logging (Unbound DNS-specific auditd rules)
- DNS configuration and DNSSEC change monitoring

> **Note**: CIS Benchmark system-level hardening (kernel parameters, login banners, core dump restrictions, disabling unnecessary services, etc.) is assumed to be managed separately by the system administrator. This script focuses solely on Unbound DNS components.

### Monitoring & Maintenance
- Health check script (`/usr/local/bin/unbound-health-check`)
- Statistics collection (`/usr/local/bin/unbound-stats`)
- Automatic root hints updates (monthly via systemd timer)
- Automatic DNSSEC trust anchor updates (weekly via systemd timer)
- Log rotation with 365-day retention

## Requirements

- **OS**: Debian 13 (Trixie)
- **VM**: Azure Standard_B2ats_v2 (2 vCPU Arm64, 1 GiB RAM) or similar
- **Network**: Public IP address with port 53 open (ports 443/853 needed if NGINX proxy is used for DoT/DoH)
- **Privileges**: Root access (sudo)

> **Note**: DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443) are handled by a separately installed NGINX reverse proxy. TLS certificates are provisioned during the NGINX installation. This script configures Unbound as a recursive DNS resolver on port 53 and opens the DoT firewall port (853). The DoH port (443) is opened by the NGINX install script.

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
  DoT (DNS-over-TLS, port 853) firewall port is opened by this script.
  DoH (DNS-over-HTTPS, port 443) is opened by the separate NGINX install script.
  TLS certificates are provisioned during NGINX installation.
  This script configures Unbound as a recursive DNS resolver on port 53.

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
              │           ┌──────┴───────────────────┘
              │           │  NGINX Reverse Proxy
              │           │  ┌─ stream:853 → TCP proxy ─┐
              │           │  └─ http:443 → grpc_pass h2c ──┘
              │           └──────┬──────────────┘
              │                  │
              └──────────────────┤
                                 │
                    ┌────────────▼────────────────────────┐
                    │         Unbound DNS Server           │
                    │  Port 53 (DNS) + 8443 (DoH backend) │
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
| `/etc/unbound/unbound.conf.d/03-doh.conf` | DoH backend (localhost:8443, added with NGINX) |
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | Response policy / domain blocklist |
| `/etc/unbound/blocklist.conf` | Custom domain blocklist entries |
| `/etc/sysctl.d/99-unbound-dns.conf` | DNS server network performance tuning |

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

# Test DNS-over-HTTPS (requires NGINX proxy, RFC 8484 wire format)
# Note: Unbound's DoH only supports application/dns-message (wire format),
# NOT application/dns-json. Use base64url-encoded DNS query:
curl -sSf 'https://dns.example.com/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# Verify DNSSEC rejects invalid signatures
dig @<server-ip> dnssec-failed.org A  # Should return SERVFAIL
```

## Security Hardening Summary

### DNS-Specific Security (Managed by This Script)
- [x] DNSSEC validation with automatic trust anchor management
- [x] Rate limiting (per-IP and global) with Fail2Ban integration
- [x] UFW firewall DNS rules (default-deny, incremental, preserves existing rules)
- [x] Systemd sandboxing (ProtectSystem, NoNewPrivileges, MemoryDenyWriteExecute, etc.)
- [x] Server identity and version hidden
- [x] QNAME minimisation (RFC 7816)
- [x] 0x20 query randomisation
- [x] deny-any to prevent amplification attacks
- [x] Minimal responses to reduce attack surface
- [x] File permission hardening (config files, keys, logs)
- [x] Unbound DNS-specific auditd rules
- [x] 365-day log retention (PCI-DSS v4.0 Requirement 10.7.1)

### System-Level Hardening (Managed Separately by System Administrator)
- [ ] Kernel hardening (IP forwarding, source routing, ICMP redirects, SYN cookies, ASLR)
- [ ] Core dump restrictions
- [ ] Unnecessary services disabled (avahi, cups, rpcbind, etc.)
- [ ] Login banners (pre-login and post-login)
- [ ] BPF and ptrace restrictions
- [ ] SSH hardening and access control

### PCI-DSS Requirements
- [x] TLS 1.2+ for encrypted DNS via NGINX proxy (Requirement 4.1)
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

> ⚠️ **Security Warning**: Always restrict SSH (port 22) access to your own IP address only. Never open SSH to `Any`.

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
2. Apply DNS server network performance tuning (sysctl)
3. Configure DNSSEC with automatic root trust-anchor management
4. Set up Unbound with optimized configuration for the VM size
5. Configure UFW firewall with default-deny policy (DNS rules only, preserves existing rules)
6. Set up Fail2Ban for DNS abuse protection
7. Apply systemd sandboxing
8. Create monitoring scripts and maintenance timers
9. Configure Unbound DNS-specific auditd rules
10. Validate configuration and start the service
11. Run post-installation health checks

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

### Step 6: Set Up DNS-over-TLS & DNS-over-HTTPS / 配置 DoT 和 DoH

DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443) are provided by NGINX as a reverse proxy in front of Unbound. This section provides complete, production-ready configuration.

> The install script already opens port 853 (DoT) in the firewall. Only port 443 (DoH) needs to be opened separately before starting NGINX:
> ```bash
> sudo ufw allow 443/tcp
> ```

#### 6.1 Prerequisites / 前置条件

1. **Unbound is running** — Complete Steps 1–5 first and verify DNS works on port 53
2. **Domain name** — Point a domain (e.g., `dns.example.com`) to your server's public IP via A/AAAA records
3. **DNS propagation** — Wait for DNS records to propagate (check with `dig dns.example.com`)

#### 6.2 Install NGINX and Certbot / 安装 NGINX 和 Certbot

```bash
# Install NGINX (nginx-full includes the stream module needed for DoT)
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx

# Verify NGINX stream module is available
nginx -V 2>&1 | grep -o with-stream
# Should output: with-stream

# Stop NGINX temporarily for certificate issuance
sudo systemctl stop nginx
```

#### 6.3 Obtain TLS Certificate / 获取 TLS 证书

```bash
# Obtain certificate using standalone mode (NGINX must be stopped)
# Replace dns.example.com with your actual domain
sudo certbot certonly --standalone \
    -d dns.example.com \
    --agree-tos \
    --email admin@example.com \
    --non-interactive

# Verify the certificate files exist
ls -la /etc/letsencrypt/live/dns.example.com/
# Should show: fullchain.pem, privkey.pem, cert.pem, chain.pem

# Set up automatic renewal (certbot auto-renews via systemd timer)
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Create a post-renewal hook to reload NGINX after certificate renewal
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post
cat <<'HOOK' | sudo tee /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
#!/bin/bash
systemctl reload nginx 2>/dev/null || true
HOOK
sudo chmod 755 /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
```

#### 6.4 Configure NGINX for DoT (DNS-over-TLS) / 配置 DoT

DoT uses NGINX's `stream` module to terminate TLS on port 853 and proxy raw TCP DNS traffic to Unbound on port 53.

**Step 1: Enable stream module in NGINX main config**

```bash
# Check if stream block loading is already present
grep -q 'stream' /etc/nginx/nginx.conf && echo "stream found" || echo "need to add stream"

# Edit nginx.conf to include stream configuration
# The stream block must be at the TOP LEVEL (same level as 'http'), NOT inside 'http {}'
sudo nano /etc/nginx/nginx.conf
```

Add the following line **before** the `http {` block in `/etc/nginx/nginx.conf`:

```nginx
# Load stream configuration for DNS-over-TLS (DoT)
include /etc/nginx/stream.conf.d/*.conf;
```

The final structure of `nginx.conf` should look like:

```nginx
# ... (existing worker_processes, events, etc.)

# DoT stream configuration (MUST be outside http block)
include /etc/nginx/stream.conf.d/*.conf;

http {
    # ... (existing http configuration)
}
```

**Step 2: Create DoT stream configuration**

```bash
# Create stream config directory
sudo mkdir -p /etc/nginx/stream.conf.d

# Create DoT configuration
# Replace dns.example.com with your actual domain
cat <<'DOTCONF' | sudo tee /etc/nginx/stream.conf.d/dns-over-tls.conf
# =============================================================================
# DNS-over-TLS (DoT) - NGINX Stream Proxy
# Terminates TLS on port 853 and proxies to Unbound on TCP port 53
# =============================================================================
stream {
    # Upstream: Unbound DNS server (TCP)
    upstream unbound_tcp {
        server 127.0.0.1:53;
    }

    # DoT server on port 853
    server {
        listen 853 ssl;
        listen [::]:853 ssl;

        # TLS certificate (Let's Encrypt)
        ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;

        # TLS security settings (PCI-DSS compliant)
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:DoT_SSL:10m;
        ssl_session_timeout 1h;
        ssl_session_tickets off;

        # Proxy to Unbound
        proxy_pass unbound_tcp;

        # Timeouts
        proxy_timeout 10s;
        proxy_connect_timeout 5s;
    }
}
DOTCONF

# IMPORTANT: Replace YOUR_ACTUAL_DOMAIN below with your real domain, then run:
# Example: sudo sed -i 's/dns.example.com/dns.myserver.com/g' /etc/nginx/stream.conf.d/dns-over-tls.conf
sudo sed -i 's/dns.example.com/YOUR_ACTUAL_DOMAIN/g' /etc/nginx/stream.conf.d/dns-over-tls.conf
```

#### 6.5 Configure NGINX for DoH (DNS-over-HTTPS) / 配置 DoH

DoH uses NGINX's `http` module to terminate HTTPS on port 443 and proxy requests to Unbound's built-in HTTP/2 endpoint. Since Unbound's DoH module (based on libnghttp2) **strictly requires HTTP/2** and will reject HTTP/1.1 connections, we use NGINX's `grpc_pass` directive which establishes HTTP/2 cleartext (h2c) connections to the backend.

**Step 1: Enable Unbound's DoH backend**

Create an additional Unbound configuration file for the local DoH listener:

```bash
cat <<'DOHCONF' | sudo tee /etc/unbound/unbound.conf.d/03-doh.conf
# =============================================================================
# DNS-over-HTTPS (DoH) 本地后端配置
# Unbound 在本地 127.0.0.1:8443 提供 HTTP DoH 接口
# NGINX 负责公网 TLS 终止，然后将请求转发到此接口
# =============================================================================
server:
    # 仅监听本地回环地址（NGINX 反向代理访问）
    interface: 127.0.0.1@8443

    # 启用 HTTPS/DoH 端口
    https-port: 8443

    # DoH 端点路径（RFC 8484 标准）
    http-endpoint: "/dns-query"

    # 允许不加密的下游连接（因为 NGINX 已处理 TLS）
    http-notls-downstream: yes
DOHCONF

# Verify configuration is valid
sudo unbound-checkconf

# Reload Unbound to apply DoH backend
sudo unbound-control reload
# Or restart if reload fails:
# sudo systemctl restart unbound

# Verify Unbound is listening on port 8443
ss -tlnp | grep 8443
```

> **Note**: The `http-notls-downstream: yes` option requires Unbound 1.17.0+. Debian 13 (Trixie) ships Unbound 1.19+ which supports this. If you encounter an error, check your Unbound version with `unbound -V`.

**Step 2: Create NGINX HTTP configuration for DoH**

```bash
# Create DoH site configuration
# Replace dns.example.com with your actual domain
cat <<'DOHSITE' | sudo tee /etc/nginx/sites-available/dns-over-https
# =============================================================================
# DNS-over-HTTPS (DoH) - NGINX HTTP Reverse Proxy
# Terminates TLS on port 443, proxies /dns-query to Unbound's DoH backend
# =============================================================================
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name dns.example.com;

    # TLS certificate (Let's Encrypt)
    ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;

    # TLS security settings (PCI-DSS compliant)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:DoH_SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets off;

    # HSTS (Strict Transport Security)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # DoH endpoint (RFC 8484)
    location /dns-query {
        # Use grpc_pass for HTTP/2 cleartext (h2c) to Unbound's DoH backend.
        # Unbound's DoH module (libnghttp2) strictly requires HTTP/2 and will
        # reject HTTP/1.1 connections. NGINX's proxy_pass only supports HTTP/1.x,
        # so grpc_pass is used to establish an h2c connection to the backend.
        grpc_pass grpc://127.0.0.1:8443;

        # Override default gRPC Content-Type (application/grpc) to preserve
        # the client's original Content-Type for DoH (application/dns-message)
        grpc_set_header Content-Type $content_type;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;

        # Timeout settings
        grpc_connect_timeout 5s;
        grpc_send_timeout 10s;
        grpc_read_timeout 10s;

        # Limit request body size (DNS messages are small, max 512 bytes typical)
        client_max_body_size 4k;
    }

    # Health check endpoint (optional, for monitoring)
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }

    # Deny all other paths
    location / {
        return 404;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name dns.example.com;
    return 301 https://$host$request_uri;
}
DOHSITE

# IMPORTANT: Replace YOUR_ACTUAL_DOMAIN below with your real domain, then run:
# Example: sudo sed -i 's/dns.example.com/dns.myserver.com/g' /etc/nginx/sites-available/dns-over-https
sudo sed -i 's/dns.example.com/YOUR_ACTUAL_DOMAIN/g' /etc/nginx/sites-available/dns-over-https

# Enable the site
sudo ln -sf /etc/nginx/sites-available/dns-over-https /etc/nginx/sites-enabled/

# Remove default NGINX site (optional but recommended)
sudo rm -f /etc/nginx/sites-enabled/default
```

#### 6.6 Start NGINX / 启动 NGINX

```bash
# Test NGINX configuration syntax
sudo nginx -t

# If the test passes, start NGINX
sudo systemctl enable nginx
sudo systemctl start nginx

# Verify NGINX is running and listening on the correct ports
sudo ss -tlnp | grep -E ':(443|853)\s'
# Should show NGINX listening on both 443 and 853
```

#### 6.7 Test DoT and DoH / 测试 DoT 和 DoH

**Test DNS-over-TLS (DoT):**

```bash
# Install kdig (part of knot-dnsutils) for DoT testing
sudo apt-get install -y knot-dnsutils

# Test DoT from the server itself
kdig @127.0.0.1 +tls -p 853 example.com A

# Test DoT from an external machine (replace with your domain or IP)
kdig @dns.example.com +tls example.com A

# Test with specific TLS hostname verification
kdig @<server-ip> +tls-host=dns.example.com +tls example.com A

# Verify TLS certificate
echo | openssl s_client -connect dns.example.com:853 -servername dns.example.com 2>/dev/null | openssl x509 -noout -subject -dates
```

**Test DNS-over-HTTPS (DoH):**

```bash
# Test DoH with curl (POST method, RFC 8484 wire format)
echo -n 'q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=' | base64 -d | \
    curl -sSf -H 'content-type: application/dns-message' \
    --data-binary @- \
    'https://dns.example.com/dns-query' | \
    od -A x -t x1

# Test DoH with curl (wire format via GET with base64url dns parameter)
# This queries example.com A record
curl -sSf 'https://dns.example.com/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# Note: Unbound's DoH supports RFC 8484 wire format (application/dns-message) only.
# JSON format (application/dns-json) is NOT supported by Unbound's native DoH endpoint.

# Test health endpoint
curl -sSf https://dns.example.com/health

# Verify TLS certificate for port 443
echo | openssl s_client -connect dns.example.com:443 -servername dns.example.com 2>/dev/null | openssl x509 -noout -subject -dates
```

**Expected results:**
- DoT queries via `kdig` should return valid DNS responses
- DoH POST/GET requests should return binary DNS response data (wire format per RFC 8484)
- TLS certificates should show your domain name and valid dates

> **Note**: Unbound's native DoH endpoint only supports RFC 8484 wire format (`application/dns-message`). JSON format (`application/dns-json`) is **not** supported.

#### 6.8 Configure Android / iOS Private DNS / 配置客户端私有 DNS

**Android 9+ (Private DNS / DoT):**
1. Settings → Network & Internet → Private DNS
2. Select "Private DNS provider hostname"
3. Enter: `dns.example.com`

**iOS 14+ / macOS (DoH):**

Create and install a DNS configuration profile (`.mobileconfig`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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
            <string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.example.dns</string>
    <key>PayloadUUID</key>
    <string>F1E2D3C4-B5A6-7890-FEDC-BA0987654321</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadDisplayName</key>
    <string>Custom DNS (DoH)</string>
</dict>
</plist>
```

**Windows 11 (DoH):**
1. Settings → Network & Internet → Wi-Fi / Ethernet → DNS
2. Set DNS to Manual
3. Enter server IP and enable "DNS over HTTPS"
4. Template: `https://dns.example.com/dns-query`

**Firefox (DoH):**
1. Settings → Privacy & Security → DNS over HTTPS
2. Select "Custom" and enter: `https://dns.example.com/dns-query`

#### 6.9 Troubleshooting DoT/DoH / DoT/DoH 故障排查

```bash
# Check NGINX error logs
sudo tail -20 /var/log/nginx/error.log

# Check if NGINX is listening on 853 and 443
sudo ss -tlnp | grep -E ':(443|853)\s'

# Check if Unbound DoH backend is listening on 8443
sudo ss -tlnp | grep ':8443\s'

# Test Unbound DoH backend directly (bypassing NGINX, wire format GET, queries example.com A)
# Note: --http2-prior-knowledge is required because Unbound's DoH only accepts HTTP/2 (h2c)
curl --http2-prior-knowledge -sSf 'http://127.0.0.1:8443/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# Check TLS certificate validity
sudo certbot certificates

# Renew certificate manually if needed
sudo certbot renew --dry-run

# Check NGINX configuration for errors
sudo nginx -t

# Verify Unbound configuration including DoH
sudo unbound-checkconf

# Check firewall allows traffic
sudo ufw status | grep -E '(443|853)'

# Debug DoT with verbose output
kdig @dns.example.com +tls +tls-host=dns.example.com -d example.com A
```

**Common issues:**
- **"Connection refused" on port 853**: Ensure NGINX is running and the stream config is loaded. Check that the `include stream.conf.d/*.conf;` line is OUTSIDE the `http {}` block.
- **"502 Bad Gateway" on DoH**: Ensure Unbound is listening on port 8443. Run `unbound-checkconf` and check for `https-port` errors. If `http-notls-downstream` is not recognized, your Unbound version may be too old.
- **DoH direct test fails with "curl: (56) Recv failure"**: Unbound's DoH module (libnghttp2) strictly requires HTTP/2. When testing directly (bypassing NGINX), you must use `curl --http2-prior-knowledge`. Standard `curl` uses HTTP/1.1 which Unbound will immediately reject.
- **Certificate errors**: Run `sudo certbot certificates` to check certificate status. Ensure the domain matches.
- **"SSL handshake failed"**: Check that `ssl_protocols` and `ssl_ciphers` in NGINX match what the client supports.

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
3. Enter `dns.example.com` (requires DoT via NGINX)

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
sudo rm -f /etc/audit/rules.d/50-unbound.rules

# Reload systemd
sudo systemctl daemon-reload

# Re-apply sysctl defaults
sudo sysctl --system
```

</details>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.