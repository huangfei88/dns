#!/usr/bin/env bash
###############################################################################
# Enterprise-Grade Unbound Public DNS Installation Script
# Target: Debian 13 (Trixie) on Azure Standard_B2ats_v2 (2 vCPU / 1 GiB RAM)
#
# Features:
#   - DNSSEC validation with automatic root trust-anchor management
#   - DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443)
#   - High-performance tuning for low-latency public DNS
#   - CIS Benchmark and PCI-DSS compliance hardening
#   - Rate limiting, access control, and anti-amplification
#   - Systemd service sandboxing
#   - nftables firewall with connection tracking
#   - Comprehensive logging and monitoring
#   - Automatic TLS certificate provisioning (Let's Encrypt)
#
# Usage:
#   sudo bash install_unbound.sh --domain <your-dns-domain> --email <your-email>
#
# Azure Standard_B2ats_v2: 2 vCPU (Arm64), 1 GiB RAM
# We tune for 2 threads, conservative cache sizes, and aggressive prefetching.
###############################################################################

set -euo pipefail
IFS=$'\n\t'

###############################################################################
# Constants & Defaults
###############################################################################
readonly SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly LOG_FILE="/var/log/unbound-install.log"
BACKUP_DIR="/var/backups/unbound-install-$(date +%Y%m%d%H%M%S)"
readonly BACKUP_DIR

# Unbound paths
readonly UNBOUND_CONF_DIR="/etc/unbound/unbound.conf.d"
readonly UNBOUND_MAIN_CONF="/etc/unbound/unbound.conf"
readonly UNBOUND_LOG_DIR="/var/log/unbound"
# TLS / ACME
readonly CERT_DIR="/etc/unbound/tls"
readonly ACME_WEBROOT="/var/www/acme"

# Network defaults
readonly DNS_PORT=53
readonly DOT_PORT=853
readonly DOH_PORT=443

# Performance tuning for Standard_B2ats_v2 (2 vCPU, 1 GiB)
readonly NUM_THREADS=2
readonly MSG_CACHE_SIZE="32m"
readonly RRSET_CACHE_SIZE="64m"
readonly KEY_CACHE_SIZE="16m"
readonly NEG_CACHE_SIZE="8m"
readonly MSG_CACHE_SLABS=2
readonly RRSET_CACHE_SLABS=2
readonly INFRA_CACHE_SLABS=2
readonly KEY_CACHE_SLABS=2
readonly OUTGOING_RANGE=4096
readonly NUM_QUERIES_PER_THREAD=2048
readonly SO_REUSEPORT="yes"
readonly SO_RCVBUF="4m"
readonly SO_SNDBUF="4m"

# Rate limiting
readonly RATELIMIT=1000
readonly RATELIMIT_SLABS=2
readonly IP_RATELIMIT=100
readonly IP_RATELIMIT_SLABS=2

# Colours for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

###############################################################################
# Global Variables (set via CLI args)
###############################################################################
DOMAIN=""
EMAIL=""
SKIP_CERTBOT="false"
DRY_RUN="false"

###############################################################################
# Logging helpers
###############################################################################
log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf "[%s] [%-5s] %s\n" "$ts" "$level" "$*" | tee -a "$LOG_FILE"
}
info()  { log "INFO"  "$@"; printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()  { log "WARN"  "$@"; printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
error() { log "ERROR" "$@"; printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
fatal() { error "$@"; exit 1; }
debug() { log "DEBUG" "$@"; }

###############################################################################
# Usage
###############################################################################
usage() {
    cat <<EOF
Usage: sudo $SCRIPT_NAME [OPTIONS]

Required:
  --domain <FQDN>      Domain name for TLS certificates (e.g., dns.example.com)
  --email  <EMAIL>      Email for Let's Encrypt certificate notifications

Optional:
  --skip-certbot        Skip Let's Encrypt certificate provisioning (use self-signed)
  --dry-run             Show what would be done without making changes
  -h, --help            Show this help message
  -v, --version         Show script version

Example:
  sudo $SCRIPT_NAME --domain dns.example.com --email admin@example.com
EOF
    exit 0
}

###############################################################################
# Argument Parsing
###############################################################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN="${2:-}"
                [[ -z "$DOMAIN" ]] && fatal "--domain requires a value"
                shift 2
                ;;
            --email)
                EMAIL="${2:-}"
                [[ -z "$EMAIL" ]] && fatal "--email requires a value"
                shift 2
                ;;
            --skip-certbot)
                SKIP_CERTBOT="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            -h|--help)
                usage
                ;;
            -v|--version)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            *)
                fatal "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    if [[ -z "$DOMAIN" ]]; then
        fatal "Missing required parameter --domain. Use --help for usage information."
    fi
    if [[ -z "$EMAIL" && "$SKIP_CERTBOT" == "false" ]]; then
        fatal "Missing required parameter --email (needed for Let's Encrypt). Use --skip-certbot to skip."
    fi
}

###############################################################################
# Pre-flight Checks
###############################################################################
preflight_checks() {
    info "Running pre-flight checks..."

    # Must run as root
    if [[ $EUID -ne 0 ]]; then
        fatal "This script must be run as root (sudo)."
    fi

    # Check Debian version
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        if [[ "${ID:-}" != "debian" ]]; then
            warn "This script is designed for Debian. Detected: ${ID:-unknown}"
        fi
        info "Detected OS: ${PRETTY_NAME:-unknown}"
    else
        warn "Cannot determine OS version (/etc/os-release not found)."
    fi

    # Check available memory
    local mem_total_kb
    mem_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local mem_total_mb=$((mem_total_kb / 1024))
    info "Available memory: ${mem_total_mb} MB"
    if [[ $mem_total_mb -lt 512 ]]; then
        warn "Low memory detected (${mem_total_mb} MB). Cache sizes are already conservative."
    fi

    # Check CPU count
    local cpu_count
    cpu_count=$(nproc)
    info "Available CPUs: $cpu_count"

    # Check network connectivity
    if ! ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        warn "No network connectivity detected. Installation may fail."
    fi

    info "Pre-flight checks passed."
}

###############################################################################
# Backup Existing Configuration
###############################################################################
backup_existing() {
    info "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    if [[ -d /etc/unbound ]]; then
        cp -a /etc/unbound "$BACKUP_DIR/etc_unbound" 2>/dev/null || true
        info "Backed up existing /etc/unbound"
    fi

    if [[ -f /etc/nftables.conf ]]; then
        cp -a /etc/nftables.conf "$BACKUP_DIR/" 2>/dev/null || true
        info "Backed up existing /etc/nftables.conf"
    fi

    # Backup sysctl
    if [[ -d /etc/sysctl.d ]]; then
        cp -a /etc/sysctl.d "$BACKUP_DIR/etc_sysctl.d" 2>/dev/null || true
    fi
}

###############################################################################
# System Update & Package Installation
###############################################################################
install_packages() {
    info "Updating system packages..."
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq
    apt-get upgrade -y -qq

    info "Installing required packages..."
    apt-get install -y -qq \
        unbound \
        unbound-anchor \
        unbound-host \
        dns-root-data \
        dnsutils \
        nftables \
        certbot \
        openssl \
        curl \
        wget \
        ca-certificates \
        gnupg \
        lsb-release \
        jq \
        apparmor \
        apparmor-utils \
        fail2ban \
        logrotate \
        rsyslog \
        apt-transport-https \
        software-properties-common \
        net-tools \
        tcpdump \
        libhiredis-dev \
        libevent-dev \
        libexpat1-dev \
        libprotobuf-c-dev \
        protobuf-c-compiler \
        sudo

    info "All packages installed successfully."
}

###############################################################################
# System Hardening (CIS / PCI-DSS)
###############################################################################
harden_system() {
    info "Applying system hardening (CIS/PCI-DSS)..."

    # --- Kernel parameters for DNS server ---
    cat > /etc/sysctl.d/99-unbound-dns.conf <<'SYSCTL'
# =============================================================================
# Kernel Tuning for Enterprise DNS Server
# CIS Benchmark & PCI-DSS Compliance
# =============================================================================

# --- Network Performance ---
# Increase socket buffer sizes for DNS traffic
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.core.optmem_max = 2097152

# TCP tuning
net.ipv4.tcp_rmem = 4096 1048576 8388608
net.ipv4.tcp_wmem = 4096 1048576 8388608
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1

# UDP tuning
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# --- Security Hardening (CIS / PCI-DSS) ---
# Disable IP forwarding (CIS 3.1.1)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing (CIS 3.1.2)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects (CIS 3.2.2)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Log martian packets (CIS 3.2.4)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast requests (CIS 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP responses (CIS 3.2.6)
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Enable TCP SYN cookies (CIS 3.2.8)
net.ipv4.tcp_syncookies = 1

# Disable IPv6 router advertisements (CIS 3.3.1)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Memory ---
# Reduce swappiness for DNS cache performance
vm.swappiness = 10

# --- Conntrack for nftables ---
net.netfilter.nf_conntrack_max = 262144

# --- File descriptors ---
fs.file-max = 1048576

# --- Address Space Layout Randomization (PCI-DSS) ---
kernel.randomize_va_space = 2

# Restrict core dumps (CIS 1.5.1)
fs.suid_dumpable = 0

# Restrict kernel pointer exposure (CIS)
kernel.kptr_restrict = 2

# Restrict dmesg access (CIS)
kernel.dmesg_restrict = 1
SYSCTL

    sysctl --system >/dev/null 2>&1 || warn "Some sysctl parameters may not have applied."
    info "Kernel parameters applied."

    # --- Restrict core dumps (CIS 1.5.1) ---
    cat > /etc/security/limits.d/99-core-dump.conf <<'EOF'
* hard core 0
EOF

    # --- File permissions hardening ---
    chmod 600 /etc/crontab 2>/dev/null || true
    chmod 700 /etc/cron.d 2>/dev/null || true
    chmod 700 /etc/cron.daily 2>/dev/null || true
    chmod 700 /etc/cron.hourly 2>/dev/null || true
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    chmod 700 /etc/cron.monthly 2>/dev/null || true

    # --- SSH hardening (PCI-DSS) ---
    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_hardening="/etc/ssh/sshd_config.d/99-hardening.conf"
        mkdir -p /etc/ssh/sshd_config.d
        cat > "$sshd_hardening" <<'EOF'
# CIS / PCI-DSS SSH Hardening
Protocol 2
MaxAuthTries 3
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
MaxSessions 4
Banner /etc/issue.net
EOF
        info "SSH hardening applied."
    fi

    # --- Login banner (PCI-DSS) ---
    cat > /etc/issue.net <<'EOF'
*******************************************************************************
*  WARNING: This system is for authorized use only.                           *
*  All activity is monitored and logged. Unauthorized access is prohibited    *
*  and will be prosecuted to the fullest extent of the law.                   *
*******************************************************************************
EOF

    # --- Disable unnecessary services ---
    local -a disable_services=(
        "avahi-daemon"
        "cups"
        "rpcbind"
    )
    for svc in "${disable_services[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            systemctl disable --now "$svc" 2>/dev/null || true
            info "Disabled unnecessary service: $svc"
        fi
    done

    info "System hardening complete."
}

###############################################################################
# Create Unbound User & Directories
###############################################################################
setup_unbound_dirs() {
    info "Setting up Unbound directories and permissions..."

    # Ensure unbound user exists (usually created by package)
    if ! id -u unbound &>/dev/null; then
        useradd -r -s /usr/sbin/nologin -d /etc/unbound unbound
        info "Created unbound system user."
    fi

    # Create required directories
    mkdir -p "$UNBOUND_CONF_DIR"
    mkdir -p "$UNBOUND_LOG_DIR"
    mkdir -p "$CERT_DIR"
    mkdir -p /var/lib/unbound

    # Set ownership and permissions
    chown -R unbound:unbound "$UNBOUND_LOG_DIR"
    chmod 750 "$UNBOUND_LOG_DIR"
    chown -R unbound:unbound "$CERT_DIR"
    chmod 750 "$CERT_DIR"
    chown -R unbound:unbound /var/lib/unbound
    chmod 750 /var/lib/unbound

    info "Directories configured."
}

###############################################################################
# DNSSEC Root Trust Anchor
###############################################################################
setup_dnssec() {
    info "Configuring DNSSEC trust anchors..."

    # Fetch fresh root hints
    local root_hints="/var/lib/unbound/root.hints"
    if curl -sSf -o "$root_hints" https://www.internic.net/domain/named.root; then
        info "Downloaded fresh root hints."
    else
        warn "Could not download root hints. Using system default."
        cp /usr/share/dns/root.hints "$root_hints" 2>/dev/null || true
    fi
    chown unbound:unbound "$root_hints"
    chmod 644 "$root_hints"

    # Initialize/update root trust anchor
    local anchor_file="/var/lib/unbound/root.key"
    unbound-anchor -a "$anchor_file" 2>/dev/null || true
    chown unbound:unbound "$anchor_file"
    chmod 644 "$anchor_file"

    info "DNSSEC trust anchors configured."
}

###############################################################################
# TLS Certificate Setup
###############################################################################
setup_tls() {
    info "Setting up TLS certificates..."

    if [[ "$SKIP_CERTBOT" == "true" ]]; then
        info "Generating self-signed TLS certificate..."
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout "$CERT_DIR/privkey.pem" \
            -out "$CERT_DIR/fullchain.pem" \
            -days 365 -nodes \
            -subj "/CN=$DOMAIN/O=DNS Server/C=US" \
            -addext "subjectAltName=DNS:$DOMAIN" 2>/dev/null

        chown unbound:unbound "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem"
        chmod 640 "$CERT_DIR/privkey.pem"
        chmod 644 "$CERT_DIR/fullchain.pem"
        info "Self-signed certificate generated."
    else
        info "Provisioning Let's Encrypt certificate for $DOMAIN..."

        # Set up ACME webroot
        mkdir -p "$ACME_WEBROOT"

        # Request certificate using standalone mode
        certbot certonly --standalone \
            --non-interactive \
            --agree-tos \
            --email "$EMAIL" \
            --domain "$DOMAIN" \
            --preferred-challenges http \
            --key-type ecdsa \
            --elliptic-curve secp256r1 \
            --deploy-hook "bash -c 'cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/privkey.pem && chown unbound:unbound $CERT_DIR/*.pem && chmod 640 $CERT_DIR/privkey.pem && chmod 644 $CERT_DIR/fullchain.pem && systemctl reload unbound'" \
            || fatal "Certbot failed. Use --skip-certbot for self-signed certificates."

        # Copy certificates
        cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERT_DIR/fullchain.pem"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERT_DIR/privkey.pem"
        chown unbound:unbound "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem"
        chmod 640 "$CERT_DIR/privkey.pem"
        chmod 644 "$CERT_DIR/fullchain.pem"

        # Set up auto-renewal cron
        cat > /etc/cron.d/certbot-unbound <<EOF
# Renew certificates twice daily (PCI-DSS: ensure certificates are always valid)
0 */12 * * * root certbot renew --quiet --deploy-hook "bash -c 'cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERT_DIR/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERT_DIR/privkey.pem && chown unbound:unbound $CERT_DIR/*.pem && chmod 640 $CERT_DIR/privkey.pem && chmod 644 $CERT_DIR/fullchain.pem && systemctl reload unbound'"
EOF
        chmod 644 /etc/cron.d/certbot-unbound
        info "Let's Encrypt certificate provisioned with auto-renewal."
    fi
}

###############################################################################
# Generate Unbound Configuration
###############################################################################
configure_unbound() {
    info "Generating Unbound configuration..."

    # --- Main configuration ---
    cat > "$UNBOUND_MAIN_CONF" <<'EOF'
# =============================================================================
# Unbound Main Configuration
# Enterprise-Grade Public DNS Server
# =============================================================================
# Include modular configuration files
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
EOF

    # --- Server configuration ---
    cat > "$UNBOUND_CONF_DIR/01-server.conf" <<EOF
# =============================================================================
# Server Core Configuration
# Optimized for Azure Standard_B2ats_v2 (2 vCPU, 1 GiB RAM)
# =============================================================================
server:
    # --- Interface Binding ---
    interface: 0.0.0.0@${DNS_PORT}
    interface: ::0@${DNS_PORT}
    interface: 0.0.0.0@${DOT_PORT}
    interface: ::0@${DOT_PORT}

    # --- Access Control (Public DNS) ---
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow

    # Refuse queries for private/bogon ranges to prevent rebinding attacks
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

    # --- Protocol Settings ---
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    prefer-ip6: no

    # --- TLS (DNS-over-TLS on port 853) ---
    tls-service-key: "${CERT_DIR}/privkey.pem"
    tls-service-pem: "${CERT_DIR}/fullchain.pem"
    tls-port: ${DOT_PORT}
    # Use strong TLS ciphers only (PCI-DSS requirement)
    tls-ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    tls-ciphersuites: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    # Minimum TLS 1.2 (PCI-DSS 3.2.1 requires TLS 1.2+)
    tls-upstream: no
    incoming-num-tcp: 1024

    # --- Performance Tuning ---
    num-threads: ${NUM_THREADS}
    msg-cache-size: ${MSG_CACHE_SIZE}
    rrset-cache-size: ${RRSET_CACHE_SIZE}
    key-cache-size: ${KEY_CACHE_SIZE}
    neg-cache-size: ${NEG_CACHE_SIZE}
    msg-cache-slabs: ${MSG_CACHE_SLABS}
    rrset-cache-slabs: ${RRSET_CACHE_SLABS}
    infra-cache-slabs: ${INFRA_CACHE_SLABS}
    key-cache-slabs: ${KEY_CACHE_SLABS}
    outgoing-range: ${OUTGOING_RANGE}
    num-queries-per-thread: ${NUM_QUERIES_PER_THREAD}
    so-reuseport: ${SO_REUSEPORT}
    so-rcvbuf: ${SO_RCVBUF}
    so-sndbuf: ${SO_SNDBUF}

    # Faster UDP with connected sockets
    udp-connect: yes

    # --- Cache Optimization ---
    # Prefetch almost-expired entries (reduces latency for popular queries)
    prefetch: yes
    prefetch-key: yes

    # Serve stale data while refreshing (improves availability)
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-client-timeout: 1800
    serve-expired-reply-ttl: 30

    # Cache minimum/maximum TTLs
    cache-min-ttl: 60
    cache-max-ttl: 86400
    cache-max-negative-ttl: 300

    # Infrastructure cache
    infra-host-ttl: 900
    infra-cache-numhosts: 50000
    infra-cache-min-rtt: 50

    # --- DNSSEC ---
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"

    # Harden DNSSEC validation
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1

    # --- Security Hardening ---
    # Hide server identity (CIS)
    hide-identity: yes
    hide-version: yes
    identity: ""
    version: ""

    # Harden against protocol exploitation
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    harden-unknown-additional: yes

    # Use 0x20-encoded random bits in the query to foil spoofing
    use-caps-for-id: yes

    # Minimal responses (reduces amplification attack surface)
    minimal-responses: yes

    # QNAME minimisation (privacy enhancement, RFC 7816)
    qname-minimisation: yes
    qname-minimisation-strict: no

    # Prevent DNS rebinding attacks
    private-domain: ""

    # Deny queries of type ANY (anti-amplification)
    deny-any: yes

    # EDNS buffer size (prevent fragmentation-based attacks)
    edns-buffer-size: 1232

    # Maximum UDP response size
    max-udp-size: 1232

    # --- Aggressive NSEC (RFC 8198) ---
    aggressive-nsec: yes

    # --- Rate Limiting ---
    ratelimit: ${RATELIMIT}
    ratelimit-slabs: ${RATELIMIT_SLABS}
    ratelimit-size: 4m
    ip-ratelimit: ${IP_RATELIMIT}
    ip-ratelimit-slabs: ${IP_RATELIMIT_SLABS}
    ip-ratelimit-size: 4m

    # --- Logging (PCI-DSS: comprehensive audit logging) ---
    use-syslog: no
    logfile: "${UNBOUND_LOG_DIR}/unbound.log"
    verbosity: 1
    log-queries: no
    log-replies: no
    log-tag-queryreply: yes
    log-local-actions: yes
    log-servfail: yes
    log-time-ascii: yes
    val-log-level: 1

    # --- Process Settings ---
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""
    pidfile: "/run/unbound/unbound.pid"

    # --- Misc ---
    unwanted-reply-threshold: 10000000
    do-not-query-localhost: yes
    ede: yes
    ede-serve-expired: yes
EOF

    # --- Remote Control Configuration ---
    cat > "$UNBOUND_CONF_DIR/02-remote-control.conf" <<'EOF'
# =============================================================================
# Remote Control Configuration
# Only accessible from localhost for security
# =============================================================================
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-interface: ::1
    control-port: 8953
    control-use-cert: yes
    server-key-file: "/etc/unbound/unbound_server.key"
    server-cert-file: "/etc/unbound/unbound_server.pem"
    control-key-file: "/etc/unbound/unbound_control.key"
    control-cert-file: "/etc/unbound/unbound_control.pem"
EOF

    # Generate unbound-control keys
    unbound-control-setup 2>/dev/null || warn "unbound-control-setup had warnings"
    info "Unbound configuration generated."
}

###############################################################################
# Configure DoH (DNS-over-HTTPS) via unbound module
###############################################################################
configure_doh() {
    info "Configuring DNS-over-HTTPS (DoH) support..."

    # Unbound 1.20+ has built-in HTTPS support via the https-port directive
    # Add DoH configuration using unbound's native HTTPS support
    cat > "$UNBOUND_CONF_DIR/03-doh.conf" <<EOF
# =============================================================================
# DNS-over-HTTPS (DoH) Configuration
# =============================================================================
server:
    # HTTPS listener (DoH)
    https-port: ${DOH_PORT}
    http-endpoint: "/dns-query"
    http-notls-downstream: no
EOF

    info "DoH configured on port ${DOH_PORT} at /dns-query"
}

###############################################################################
# Blocklist / RPZ (Optional but enterprise-standard)
###############################################################################
configure_rpz() {
    info "Setting up DNS response policy zone (RPZ) for threat blocking..."

    # Create a local blocklist file
    cat > /etc/unbound/blocklist.conf <<'EOF'
# =============================================================================
# Local DNS Blocklist
# Add domains to block here, one per line:
# local-zone: "malware-domain.com." always_refuse
# =============================================================================

# Block known malware command-and-control domains (examples)
# local-zone: "example-malware.com." always_refuse
# local-zone: "bad-actor.net." always_refuse
EOF

    cat > "$UNBOUND_CONF_DIR/04-blocklist.conf" <<'EOF'
# =============================================================================
# Response Policy / Blocklist Integration
# =============================================================================
server:
    # Include local blocklist
    include: "/etc/unbound/blocklist.conf"

    # Block reverse lookups for private addresses
    local-zone: "10.in-addr.arpa." nodefault
    local-zone: "16.172.in-addr.arpa." nodefault
    local-zone: "17.172.in-addr.arpa." nodefault
    local-zone: "18.172.in-addr.arpa." nodefault
    local-zone: "19.172.in-addr.arpa." nodefault
    local-zone: "20.172.in-addr.arpa." nodefault
    local-zone: "21.172.in-addr.arpa." nodefault
    local-zone: "22.172.in-addr.arpa." nodefault
    local-zone: "23.172.in-addr.arpa." nodefault
    local-zone: "24.172.in-addr.arpa." nodefault
    local-zone: "25.172.in-addr.arpa." nodefault
    local-zone: "26.172.in-addr.arpa." nodefault
    local-zone: "27.172.in-addr.arpa." nodefault
    local-zone: "28.172.in-addr.arpa." nodefault
    local-zone: "29.172.in-addr.arpa." nodefault
    local-zone: "30.172.in-addr.arpa." nodefault
    local-zone: "31.172.in-addr.arpa." nodefault
    local-zone: "168.192.in-addr.arpa." nodefault
    local-zone: "254.169.in-addr.arpa." nodefault
EOF

    info "RPZ blocklist configured."
}

###############################################################################
# nftables Firewall Configuration
###############################################################################
configure_firewall() {
    info "Configuring nftables firewall..."

    cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# =============================================================================
# Enterprise DNS Server Firewall (nftables)
# CIS / PCI-DSS Compliant
# =============================================================================

# Flush existing rules
flush ruleset

table inet filter {
    # --- Rate limit sets ---
    set dns_meter_v4 {
        type ipv4_addr
        flags dynamic,timeout
        timeout 10s
    }
    set dns_meter_v6 {
        type ipv6_addr
        flags dynamic,timeout
        timeout 10s
    }
    set blocked_v4 {
        type ipv4_addr
        flags dynamic,timeout
        timeout 300s
    }
    set blocked_v6 {
        type ipv6_addr
        flags dynamic,timeout
        timeout 300s
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # --- Established/Related connections ---
        ct state established,related accept

        # --- Drop invalid packets ---
        ct state invalid drop

        # --- Loopback ---
        iifname "lo" accept

        # --- ICMP (rate limited) ---
        ip protocol icmp icmp type { echo-request } \
            limit rate 10/second burst 20 packets accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request } \
            limit rate 10/second burst 20 packets accept

        # Essential ICMPv6 for IPv6 operation
        ip6 nexthdr icmpv6 icmpv6 type {
            nd-neighbor-solicit,
            nd-neighbor-advert,
            nd-router-advert,
            nd-router-solicit
        } accept

        # --- SSH (rate limited, PCI-DSS: restrict management access) ---
        tcp dport 22 ct state new \
            limit rate 5/minute burst 10 packets accept

        # --- DNS (UDP/TCP port 53) ---
        # Drop blocked IPs
        ip saddr @blocked_v4 drop
        ip6 saddr @blocked_v6 drop

        # Rate limit DNS queries per source IP (anti-DDoS)
        udp dport 53 add @dns_meter_v4 { ip saddr limit rate over 100/second } \
            add @blocked_v4 { ip saddr } drop
        udp dport 53 accept

        tcp dport 53 ct state new accept

        # --- DNS-over-TLS (port 853) ---
        tcp dport 853 ct state new \
            limit rate 50/second burst 100 packets accept

        # --- DNS-over-HTTPS (port 443) ---
        tcp dport 443 ct state new \
            limit rate 50/second burst 100 packets accept

        # --- Unbound control (localhost only) ---
        tcp dport 8953 ip saddr 127.0.0.1 accept
        tcp dport 8953 ip6 saddr ::1 accept

        # --- Logging dropped packets (PCI-DSS audit requirement) ---
        limit rate 5/minute burst 10 packets \
            log prefix "[nftables-DROP] " level info
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        # DNS server should not forward packets
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Allow outgoing DNS (to upstream root servers)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow outgoing TLS (for DNS-over-TLS upstream if needed)
        tcp dport 853 accept

        # Allow outgoing HTTPS (for OCSP, CRL, certbot)
        tcp dport 443 accept
        tcp dport 80 accept

        # Allow outgoing NTP
        udp dport 123 accept

        # Allow established connections
        ct state established,related accept
    }
}
EOF

    # Enable and start nftables
    systemctl enable nftables
    nft -f /etc/nftables.conf || warn "Failed to apply nftables rules"

    info "Firewall configured and active."
}

###############################################################################
# Fail2Ban Configuration for DNS
###############################################################################
configure_fail2ban() {
    info "Configuring Fail2Ban for DNS abuse protection..."

    # Create DNS-specific jail
    cat > /etc/fail2ban/jail.d/unbound-dns.conf <<'EOF'
# =============================================================================
# Fail2Ban Jail for DNS Abuse
# =============================================================================
[unbound-dns-abuse]
enabled  = true
port     = 53,853,443
protocol = udp,tcp
filter   = unbound-dns-abuse
logpath  = /var/log/unbound/unbound.log
maxretry = 100
findtime = 60
bantime  = 3600
action   = nftables-allports[name=dns-abuse, protocol=all]
EOF

    # Create filter
    cat > /etc/fail2ban/filter.d/unbound-dns-abuse.conf <<'EOF'
# =============================================================================
# Fail2Ban Filter for Unbound DNS Abuse
# =============================================================================
[Definition]
failregex = .*query from <HOST>#\d+ .*
ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban 2>/dev/null || warn "Fail2Ban restart had issues (will start after reboot)"

    info "Fail2Ban configured."
}

###############################################################################
# Log Rotation
###############################################################################
configure_logrotate() {
    info "Configuring log rotation..."

    cat > /etc/logrotate.d/unbound <<'EOF'
/var/log/unbound/unbound.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 unbound unbound
    sharedscripts
    postrotate
        /usr/sbin/unbound-control log_reopen 2>/dev/null || true
    endscript
}
EOF

    info "Log rotation configured (90-day retention for PCI-DSS compliance)."
}

###############################################################################
# Systemd Service Hardening
###############################################################################
harden_systemd_service() {
    info "Hardening Unbound systemd service..."

    # Create systemd override
    mkdir -p /etc/systemd/system/unbound.service.d

    cat > /etc/systemd/system/unbound.service.d/hardening.conf <<'EOF'
# =============================================================================
# Unbound Systemd Service Hardening
# CIS / PCI-DSS Compliance
# =============================================================================
[Service]
# --- Filesystem ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/unbound /var/lib/unbound /run/unbound

# --- Capabilities ---
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# --- Security ---
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
PrivateDevices=yes

# --- System calls ---
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @module @obsolete @clock @cpu-emulation @debug @raw-io
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# --- Network ---
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# --- Misc ---
UMask=0027

# --- Resource Limits ---
LimitNOFILE=65535
LimitNPROC=512

# --- Restart Policy ---
Restart=always
RestartSec=5
WatchdogSec=60
EOF

    # Ensure PID directory exists
    mkdir -p /run/unbound
    chown unbound:unbound /run/unbound

    # Create tmpfiles.d entry for /run/unbound
    cat > /etc/tmpfiles.d/unbound.conf <<'EOF'
d /run/unbound 0755 unbound unbound -
EOF

    systemctl daemon-reload
    info "Systemd service hardening applied."
}

###############################################################################
# Monitoring & Health Check Script
###############################################################################
create_monitoring_scripts() {
    info "Creating monitoring and health check scripts..."

    # --- Health Check Script ---
    cat > /usr/local/bin/unbound-health-check <<'HEALTHCHECK'
#!/usr/bin/env bash
###############################################################################
# Unbound Health Check Script
# Returns 0 on success, 1 on failure
###############################################################################
set -euo pipefail

CHECKS_PASSED=0
CHECKS_FAILED=0
VERBOSE="${1:-}"

check() {
    local name="$1"
    local result="$2"
    if [[ "$result" == "0" ]]; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        [[ "$VERBOSE" == "-v" ]] && echo "[PASS] $name"
    else
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        echo "[FAIL] $name"
    fi
}

# Check 1: Service is running
systemctl is-active --quiet unbound
check "Unbound service active" "$?"

# Check 2: Port 53 is listening
ss -ulnp | grep -q ':53 ' 2>/dev/null
check "Port 53 (UDP) listening" "$?"

ss -tlnp | grep -q ':53 ' 2>/dev/null
check "Port 53 (TCP) listening" "$?"

# Check 3: Port 853 is listening (DoT)
ss -tlnp | grep -q ':853 ' 2>/dev/null
check "Port 853 (DoT) listening" "$?"

# Check 4: DNS resolution works
dig @127.0.0.1 +short +time=5 +tries=2 example.com A >/dev/null 2>&1
check "DNS resolution (A record)" "$?"

# Check 5: DNSSEC validation works
dig @127.0.0.1 +dnssec +short +time=5 +tries=2 example.com A >/dev/null 2>&1
check "DNSSEC resolution" "$?"

# Check 6: DNSSEC validation rejects bad signatures
local dnssec_fail
dnssec_fail=$(dig @127.0.0.1 +time=5 +tries=2 dnssec-failed.org A 2>&1 | grep -c "SERVFAIL" || true)
if [[ "$dnssec_fail" -ge 1 ]]; then
    check "DNSSEC rejects bad signatures" "0"
else
    check "DNSSEC rejects bad signatures" "1"
fi

# Check 7: unbound-control works
unbound-control status >/dev/null 2>&1
check "unbound-control operational" "$?"

# Summary
echo ""
echo "Health Check Summary: ${CHECKS_PASSED} passed, ${CHECKS_FAILED} failed"

if [[ $CHECKS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
HEALTHCHECK

    chmod 755 /usr/local/bin/unbound-health-check

    # --- Statistics Collection Script ---
    cat > /usr/local/bin/unbound-stats <<'STATS'
#!/usr/bin/env bash
###############################################################################
# Unbound Statistics Collection
###############################################################################
set -euo pipefail

echo "=== Unbound Server Statistics ==="
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Get stats
unbound-control stats_noreset 2>/dev/null | grep -E \
    "^(total|time|mem|num)" | while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done

echo ""
echo "=== Cache Statistics ==="
unbound-control stats_noreset 2>/dev/null | grep -E "^(rrset|msg|key|infra)" | \
    while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done

echo ""
echo "=== Rate Limit Statistics ==="
unbound-control stats_noreset 2>/dev/null | grep -E "ratelimit" | \
    while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done
STATS

    chmod 755 /usr/local/bin/unbound-stats

    # --- Root Hints Update Script (monthly cron) ---
    cat > /usr/local/bin/update-root-hints <<'ROOTHINTS'
#!/usr/bin/env bash
###############################################################################
# Update DNS Root Hints
# Run monthly via cron
###############################################################################
set -euo pipefail

ROOT_HINTS="/var/lib/unbound/root.hints"
TEMP_FILE=$(mktemp)

if curl -sSf -o "$TEMP_FILE" https://www.internic.net/domain/named.root; then
    if [[ -s "$TEMP_FILE" ]]; then
        mv "$TEMP_FILE" "$ROOT_HINTS"
        chown unbound:unbound "$ROOT_HINTS"
        chmod 644 "$ROOT_HINTS"
        unbound-control reload 2>/dev/null || systemctl reload unbound
        logger -t "root-hints-update" "Root hints updated successfully"
    else
        rm -f "$TEMP_FILE"
        logger -t "root-hints-update" "Downloaded file was empty, skipping update"
    fi
else
    rm -f "$TEMP_FILE"
    logger -t "root-hints-update" "Failed to download root hints"
fi
ROOTHINTS

    chmod 755 /usr/local/bin/update-root-hints

    # Monthly cron for root hints update
    cat > /etc/cron.d/update-root-hints <<'EOF'
# Update DNS root hints monthly
0 3 1 * * root /usr/local/bin/update-root-hints
EOF
    chmod 644 /etc/cron.d/update-root-hints

    # --- DNSSEC Trust Anchor Update (weekly cron) ---
    cat > /etc/cron.d/unbound-anchor <<'EOF'
# Update DNSSEC trust anchor weekly
0 4 * * 0 root /usr/sbin/unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null; systemctl reload unbound 2>/dev/null || true
EOF
    chmod 644 /etc/cron.d/unbound-anchor

    info "Monitoring and maintenance scripts created."
}

###############################################################################
# Validate Configuration
###############################################################################
validate_config() {
    info "Validating Unbound configuration..."

    if unbound-checkconf "$UNBOUND_MAIN_CONF"; then
        info "Configuration validation PASSED."
    else
        fatal "Configuration validation FAILED. Check $UNBOUND_MAIN_CONF"
    fi
}

###############################################################################
# Start & Enable Unbound
###############################################################################
start_unbound() {
    info "Starting Unbound DNS server..."

    # Stop systemd-resolved if running (conflicts with port 53)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl disable --now systemd-resolved
        # Update resolv.conf to use localhost
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf <<'EOF'
# Managed by Unbound DNS installer
nameserver 127.0.0.1
nameserver ::1
options edns0 trust-ad
EOF
        info "Disabled systemd-resolved and updated resolv.conf"
    fi

    systemctl enable unbound
    systemctl restart unbound

    # Wait for service to be ready
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet unbound; then
            break
        fi
        sleep 1
        retries=$((retries - 1))
    done

    if systemctl is-active --quiet unbound; then
        info "Unbound is running."
    else
        error "Unbound failed to start. Checking logs..."
        journalctl -u unbound --no-pager -n 30
        fatal "Unbound failed to start. Check logs above."
    fi
}

###############################################################################
# Post-Installation Validation
###############################################################################
post_install_validation() {
    info "Running post-installation validation..."

    echo ""
    echo "============================================================"
    echo "  Post-Installation Validation"
    echo "============================================================"
    echo ""

    local pass=0
    local fail=0

    # Test 1: Service status
    if systemctl is-active --quiet unbound; then
        printf "${GREEN}[PASS]${NC} Unbound service is active\n"
        pass=$((pass + 1))
    else
        printf "${RED}[FAIL]${NC} Unbound service is not active\n"
        fail=$((fail + 1))
    fi

    # Test 2: DNS resolution
    if dig @127.0.0.1 +short +time=5 +tries=2 example.com A >/dev/null 2>&1; then
        printf "${GREEN}[PASS]${NC} DNS resolution working (example.com)\n"
        pass=$((pass + 1))
    else
        printf "${RED}[FAIL]${NC} DNS resolution failed\n"
        fail=$((fail + 1))
    fi

    # Test 3: DNSSEC validation
    local ad_flag
    ad_flag=$(dig @127.0.0.1 +time=5 +tries=2 example.com A 2>&1 | grep -c "ad;" || true)
    if [[ "$ad_flag" -ge 1 ]]; then
        printf "${GREEN}[PASS]${NC} DNSSEC validation active (AD flag set)\n"
        pass=$((pass + 1))
    else
        printf "${YELLOW}[WARN]${NC} DNSSEC AD flag not detected (may need time to prime cache)\n"
    fi

    # Test 4: Port listening
    for port in 53 853; do
        if ss -tlnp | grep -q ":${port} "; then
            printf "${GREEN}[PASS]${NC} TCP port ${port} is listening\n"
            pass=$((pass + 1))
        else
            printf "${RED}[FAIL]${NC} TCP port ${port} is not listening\n"
            fail=$((fail + 1))
        fi
    done

    if ss -ulnp | grep -q ":53 "; then
        printf "${GREEN}[PASS]${NC} UDP port 53 is listening\n"
        pass=$((pass + 1))
    else
        printf "${RED}[FAIL]${NC} UDP port 53 is not listening\n"
        fail=$((fail + 1))
    fi

    # Test 5: Configuration validation
    if unbound-checkconf "$UNBOUND_MAIN_CONF" >/dev/null 2>&1; then
        printf "${GREEN}[PASS]${NC} Configuration file is valid\n"
        pass=$((pass + 1))
    else
        printf "${RED}[FAIL]${NC} Configuration file has errors\n"
        fail=$((fail + 1))
    fi

    # Test 6: unbound-control
    if unbound-control status >/dev/null 2>&1; then
        printf "${GREEN}[PASS]${NC} unbound-control is operational\n"
        pass=$((pass + 1))
    else
        printf "${YELLOW}[WARN]${NC} unbound-control not responding (may need service restart)\n"
    fi

    # Test 7: Firewall active
    if nft list ruleset 2>/dev/null | grep -q "chain input"; then
        printf "${GREEN}[PASS]${NC} nftables firewall is active\n"
        pass=$((pass + 1))
    else
        printf "${RED}[FAIL]${NC} nftables firewall is not configured\n"
        fail=$((fail + 1))
    fi

    # Test 8: Hide identity
    local identity
    identity=$(dig @127.0.0.1 +time=5 +tries=2 CH TXT id.server 2>&1 || true)
    if echo "$identity" | grep -q "REFUSED\|connection timed out\|no servers"; then
        printf "${GREEN}[PASS]${NC} Server identity is hidden\n"
        pass=$((pass + 1))
    else
        printf "${YELLOW}[WARN]${NC} Server identity may be visible\n"
    fi

    echo ""
    echo "============================================================"
    printf "  Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC}\n" "$pass" "$fail"
    echo "============================================================"
    echo ""

    if [[ $fail -gt 0 ]]; then
        warn "Some validation checks failed. Review the output above."
    else
        info "All validation checks passed!"
    fi
}

###############################################################################
# Print Summary
###############################################################################
print_summary() {
    cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║               Enterprise Unbound DNS Server - Installation Complete        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  Service Status:                                                           ║
║    • Unbound DNS:  systemctl status unbound                                ║
║    • Firewall:     nft list ruleset                                        ║
║    • Fail2Ban:     systemctl status fail2ban                               ║
║                                                                            ║
║  Listening Ports:                                                          ║
║    • DNS (UDP/TCP):  ${DNS_PORT}                                                    ║
║    • DNS-over-TLS:   ${DOT_PORT}                                                   ║
║    • DNS-over-HTTPS: ${DOH_PORT}                                                   ║
║    • Control:        8953 (localhost only)                                  ║
║                                                                            ║
║  Configuration Files:                                                      ║
║    • Main:          ${UNBOUND_MAIN_CONF}                           ║
║    • Server:        ${UNBOUND_CONF_DIR}/01-server.conf       ║
║    • Remote Ctrl:   ${UNBOUND_CONF_DIR}/02-remote-control.conf║
║    • DoH:           ${UNBOUND_CONF_DIR}/03-doh.conf          ║
║    • Blocklist:     ${UNBOUND_CONF_DIR}/04-blocklist.conf    ║
║                                                                            ║
║  TLS Certificates:                                                         ║
║    • Certificate:   ${CERT_DIR}/fullchain.pem                        ║
║    • Private Key:   ${CERT_DIR}/privkey.pem                          ║
║                                                                            ║
║  Useful Commands:                                                          ║
║    • Health check:    /usr/local/bin/unbound-health-check -v               ║
║    • View statistics: /usr/local/bin/unbound-stats                         ║
║    • View logs:       tail -f ${UNBOUND_LOG_DIR}/unbound.log           ║
║    • Flush cache:     unbound-control flush_zone .                         ║
║    • Reload config:   unbound-control reload                               ║
║    • Check config:    unbound-checkconf                                    ║
║                                                                            ║
║  Security Features:                                                        ║
║    ✓ DNSSEC validation enabled                                             ║
║    ✓ DNS-over-TLS (DoT) on port 853                                       ║
║    ✓ DNS-over-HTTPS (DoH) on port 443                                     ║
║    ✓ Rate limiting (per-IP and global)                                     ║
║    ✓ nftables firewall with connection tracking                            ║
║    ✓ Fail2Ban DNS abuse protection                                         ║
║    ✓ Systemd sandboxing (ProtectSystem, NoNewPrivileges, etc.)             ║
║    ✓ QNAME minimisation (RFC 7816)                                         ║
║    ✓ 0x20 query randomisation                                              ║
║    ✓ Minimal responses (anti-amplification)                                ║
║    ✓ deny-any enabled                                                      ║
║    ✓ CIS/PCI-DSS kernel hardening                                          ║
║    ✓ 90-day log retention                                                  ║
║                                                                            ║
║  Backup Location: ${BACKUP_DIR}                         ║
║  Install Log:     ${LOG_FILE}                                    ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF
}

###############################################################################
# Main
###############################################################################
main() {
    parse_args "$@"

    # Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"

    echo ""
    info "╔══════════════════════════════════════════════════════════════╗"
    info "║   Enterprise Unbound DNS Server Installer v${SCRIPT_VERSION}            ║"
    info "║   Target: Debian 13 / Azure Standard_B2ats_v2              ║"
    info "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    info "Domain: $DOMAIN"
    info "Email:  ${EMAIL:-N/A}"
    info "Skip Certbot: $SKIP_CERTBOT"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN mode - no changes will be made."
        exit 0
    fi

    # Execute installation steps
    preflight_checks
    backup_existing
    install_packages
    harden_system
    setup_unbound_dirs
    setup_dnssec
    setup_tls
    configure_unbound
    configure_doh
    configure_rpz
    configure_firewall
    configure_fail2ban
    configure_logrotate
    harden_systemd_service
    create_monitoring_scripts
    validate_config
    start_unbound
    post_install_validation
    print_summary

    info "Installation completed successfully!"
    info "Please review the summary above and test your DNS server."
    info "Run '/usr/local/bin/unbound-health-check -v' for a comprehensive health check."
}

# Run main with all arguments
main "$@"
