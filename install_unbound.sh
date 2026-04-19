#!/usr/bin/env bash
###############################################################################
# 企业级 Unbound 公共 DNS 服务器安装脚本
# 目标环境: Debian 13 (Trixie) / Azure Standard_B2ats_v2 (2 vCPU / 1 GiB RAM)
#
# 功能特性:
#   - DNSSEC 验证及自动根信任锚管理
#   - 针对低延迟公共 DNS 的高性能调优（仅端口 53 UDP/TCP）
#   - CIS 基准和 PCI-DSS 合规加固（内核、SSH、文件系统、服务）
#   - 速率限制、访问控制和防放大攻击
#   - Systemd 服务沙箱隔离
#   - UFW 防火墙（基于 nftables 后端）
#   - 全面的日志记录和监控
#
# 注意: DOT (DNS-over-TLS, 端口 853) 和 DoH (DNS-over-HTTPS, 端口 443) 由
#       单独安装的 NGINX 反向代理实现，SSL 证书也在安装 NGINX 时申请。
#       本脚本仅配置 Unbound 作为纯 DNS 递归解析服务器（端口 53）。
#
# 用法:
#   sudo bash install_unbound.sh
#
# Azure Standard_B2ats_v2: 2 vCPU (Arm64), 1 GiB 内存
# 针对 2 线程、保守缓存大小和积极预取进行优化。
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# 常量和默认值
###############################################################################
readonly SCRIPT_VERSION="1.3.0"
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly LOG_FILE="/var/log/unbound-install.log"
BACKUP_DIR="/var/backups/unbound-install-$(date +%Y%m%d%H%M%S)"
readonly BACKUP_DIR

# Unbound 路径
readonly UNBOUND_CONF_DIR="/etc/unbound/unbound.conf.d"
readonly UNBOUND_MAIN_CONF="/etc/unbound/unbound.conf"
readonly UNBOUND_LOG_DIR="/var/log/unbound"

# 网络端口默认值（仅 DNS 端口 53，DOT/DoH 由 NGINX 处理）
readonly DNS_PORT=53

# 性能调优参数 (适配 Standard_B2ats_v2: 2 vCPU, 1 GiB 内存)
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

# 速率限制参数
readonly RATELIMIT=1000
readonly RATELIMIT_SLABS=2
readonly IP_RATELIMIT=100
readonly IP_RATELIMIT_SLABS=2

# 终端输出颜色
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

###############################################################################
# 全局变量（通过命令行参数设置）
###############################################################################
DRY_RUN="false"

###############################################################################
# 日志辅助函数
# log() 仅写入日志文件；终端输出由 info/warn/error 各自处理。
# 当日志文件不可写时（例如非 root 用户运行），静默忽略写入失败，
# 终端的彩色输出仍正常显示给用户。
###############################################################################
log() {
    local level="$1"; shift
    local IFS=' '
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf "[%s] [%-5s] %s\n" "$ts" "$level" "$*" >> "$LOG_FILE" 2>/dev/null || true
}
info()  { local IFS=' '; log "INFO"  "$@"; printf '%b[INFO]%b  %s\n' "${GREEN}" "${NC}" "$*"; }
warn()  { local IFS=' '; log "WARN"  "$@"; printf '%b[WARN]%b  %s\n' "${YELLOW}" "${NC}" "$*"; }
error() { local IFS=' '; log "ERROR" "$@"; printf '%b[ERROR]%b %s\n' "${RED}" "${NC}" "$*" >&2; }
fatal() { error "$@"; exit 1; }
debug() { log "DEBUG" "$@"; }

###############################################################################
# 错误处理和清理
# 当脚本因错误终止时，确保系统 DNS 可用并记录失败信息。
###############################################################################
cleanup_on_error() {
    local exit_code=$?
    local line_no="${1:-unknown}"
    error "安装在第 ${line_no} 行失败 (退出码: ${exit_code})。"
    error "备份文件位于: ${BACKUP_DIR:-/var/backups}"
    error "安装日志: ${LOG_FILE}"

    # 确保系统有可用的 DNS（如果 resolv.conf 被删除但 Unbound 未启动）
    if [[ ! -f /etc/resolv.conf ]] || ! grep -q "nameserver" /etc/resolv.conf 2>/dev/null; then
        # 移除不可变属性后再写入
        if [[ -f /etc/resolv.conf ]]; then
            chattr -i /etc/resolv.conf 2>/dev/null || true
        fi
        cat > /etc/resolv.conf <<'DNSEOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
DNSEOF
        warn "已恢复 resolv.conf 使用公共 DNS 以确保网络连通性。"
    fi

    error "请检查日志文件并手动排查问题。"
}

###############################################################################
# 使用说明
###############################################################################
usage() {
    cat <<EOF
用法: sudo $SCRIPT_NAME [选项]

可选参数:
  --dry-run             仅显示将要执行的操作，不做任何更改
  -h, --help            显示此帮助信息
  -v, --version         显示脚本版本

注意:
  DOT (DNS-over-TLS) 和 DoH (DNS-over-HTTPS) 由单独安装的 NGINX 实现。
  SSL 证书在安装 NGINX 时申请。本脚本仅配置 Unbound 纯 DNS 递归解析。

示例:
  sudo $SCRIPT_NAME
  sudo $SCRIPT_NAME --dry-run
EOF
    exit 0
}

###############################################################################
# 命令行参数解析
###############################################################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            -h|--help)
                usage
                ;;
            -v|--version)
                echo "$SCRIPT_NAME 版本 $SCRIPT_VERSION"
                exit 0
                ;;
            *)
                fatal "未知选项: $1。使用 --help 查看用法。"
                ;;
        esac
    done
}

###############################################################################
# 安装前环境检查
###############################################################################
preflight_checks() {
    info "正在执行安装前环境检查..."

    # 必须以 root 权限运行
    if [[ $EUID -ne 0 ]]; then
        fatal "此脚本必须以 root 权限运行 (sudo)。"
    fi

    # 检查 Debian 版本
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        if [[ "${ID:-}" != "debian" ]]; then
            warn "此脚本专为 Debian 设计。检测到: ${ID:-unknown}"
        fi
        info "检测到操作系统: ${PRETTY_NAME:-unknown}"
    else
        warn "无法确定操作系统版本（未找到 /etc/os-release）。"
    fi

    # 检查可用内存
    local mem_total_kb
    mem_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local mem_total_mb=$((mem_total_kb / 1024))
    info "可用内存: ${mem_total_mb} MB"
    if [[ $mem_total_mb -lt 512 ]]; then
        warn "检测到内存不足（${mem_total_mb} MB）。缓存大小已配置为保守值。"
    fi

    # 检查 CPU 数量
    local cpu_count
    cpu_count=$(nproc)
    info "可用 CPU 核心数: $cpu_count"

    # 检查网络连通性
    if ! ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        warn "未检测到网络连接。安装可能会失败。"
    fi

    info "安装前环境检查通过。"
}

###############################################################################
# 备份现有配置
###############################################################################
backup_existing() {
    info "正在创建备份目录: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    if [[ -d /etc/unbound ]]; then
        cp -a /etc/unbound "$BACKUP_DIR/etc_unbound" 2>/dev/null || true
        info "已备份 /etc/unbound"
    fi

    if [[ -d /etc/ufw ]]; then
        cp -a /etc/ufw "$BACKUP_DIR/etc_ufw" 2>/dev/null || true
        info "已备份 /etc/ufw"
    fi

    # 备份 sysctl 配置
    if [[ -d /etc/sysctl.d ]]; then
        cp -a /etc/sysctl.d "$BACKUP_DIR/etc_sysctl.d" 2>/dev/null || true
    fi

    # 备份 SSH 配置
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config" 2>/dev/null || true
        info "已备份 /etc/ssh/sshd_config"
    fi
}

###############################################################################
# 系统更新和软件包安装
###############################################################################
install_packages() {
    info "正在更新系统软件包..."
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq
    apt-get upgrade -y -qq

    info "正在安装必需的软件包..."
    local packages=(
        unbound
        unbound-anchor
        unbound-host
        dns-root-data
        dnsutils
        ufw
        openssl
        curl
        wget
        ca-certificates
        gnupg
        lsb-release
        jq
        fail2ban
        logrotate
        rsyslog
        net-tools
        sudo
    )

    apt-get install -y -qq "${packages[@]}"

    # 清理 APT 缓存以释放磁盘空间（对 1 GiB 内存环境尤为重要）
    apt-get clean
    apt-get autoremove -y -qq 2>/dev/null || true

    info "所有软件包安装完成。"
}

###############################################################################
# DNS 服务器性能调优 + CIS 基准内核安全加固
###############################################################################
tune_system_for_dns() {
    info "正在应用 DNS 服务器性能调优和内核安全加固..."

    # --- DNS 性能和 CIS/PCI-DSS 内核安全参数 ---
    cat > /etc/sysctl.d/99-unbound-dns.conf <<'SYSCTL'
# =============================================================================
# 企业级 DNS 服务器内核调优参数
# 包含 DNS 性能优化和 CIS 基准/PCI-DSS 安全加固
# =============================================================================

# === 网络性能优化（DNS 流量） ===
# 增大 socket 缓冲区以支持高吞吐 DNS 流量
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.core.optmem_max = 2097152

# TCP 调优（用于 DNS TCP 连接和未来 NGINX 反向代理流量）
net.ipv4.tcp_rmem = 4096 1048576 8388608
net.ipv4.tcp_wmem = 4096 1048576 8388608
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1

# UDP 调优（用于 DNS 查询流量）
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# === 内存 ===
# 降低交换分区使用倾向以提升 DNS 缓存性能
vm.swappiness = 10

# === 文件描述符（支持高并发连接） ===
fs.file-max = 1048576

# 扩展本地端口范围（支持大量出站 DNS 查询）
net.ipv4.ip_local_port_range = 1024 65535

# === CIS 基准 - 内核安全加固 ===

# 禁用 IP 转发（CIS 3.1.1）- DNS 服务器不需要路由功能
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 禁用 ICMP 重定向发送（CIS 3.1.2）
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 禁止接受源路由包（CIS 3.2.1）
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 禁止接受 ICMP 重定向（CIS 3.2.2）
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 禁止接受安全 ICMP 重定向（CIS 3.2.3）
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 记录可疑的火星包（CIS 3.2.4）
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 忽略 ICMP 广播请求（CIS 3.2.5）- 防止 Smurf 攻击
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 忽略伪造的 ICMP 错误响应（CIS 3.2.6）
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 启用反向路径过滤（CIS 3.2.7）- 防止 IP 欺骗
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 启用 TCP SYN Cookie（CIS 3.2.8）- 防止 SYN 洪泛攻击
net.ipv4.tcp_syncookies = 1

# 禁止接受 IPv6 路由通告（CIS 3.3.1）
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# === CIS 基准 - 进程安全 ===

# 启用 ASLR 地址空间布局随机化（CIS 1.5.3）
kernel.randomize_va_space = 2

# 禁用核心转储的 SUID 程序（CIS 1.5.1）
fs.suid_dumpable = 0

# 限制内核指针泄露
kernel.kptr_restrict = 2

# 限制 dmesg 访问
kernel.dmesg_restrict = 1

# 禁用非特权用户 BPF（CIS 安全加固）
kernel.unprivileged_bpf_disabled = 1

# 加固 BPF JIT 编译器（CIS 安全加固）
net.core.bpf_jit_harden = 2

# 限制 ptrace 范围（CIS 1.5.4）
kernel.yama.ptrace_scope = 2
SYSCTL

    sysctl --system >/dev/null 2>&1 || warn "部分 sysctl 参数可能未成功应用。"
    info "DNS 性能调优和内核安全加固参数已应用。"

    # --- 核心转储限制（CIS 1.5.1）---
    cat > /etc/security/limits.d/99-disable-coredumps.conf <<'EOF'
# 禁用核心转储 - CIS 基准 1.5.1
* hard core 0
EOF
    info "核心转储已禁用。"
}

###############################################################################
# 创建 Unbound 用户和目录
###############################################################################
setup_unbound_dirs() {
    info "正在设置 Unbound 目录和权限..."

    # 确保 unbound 用户存在（通常由软件包自动创建）
    if ! id -u unbound &>/dev/null; then
        useradd -r -s /usr/sbin/nologin -d /etc/unbound unbound
        info "已创建 unbound 系统用户。"
    fi

    # 创建必需的目录
    mkdir -p "$UNBOUND_CONF_DIR"
    mkdir -p "$UNBOUND_LOG_DIR"
    mkdir -p /var/lib/unbound

    # 设置目录所有者和权限
    chown -R unbound:unbound "$UNBOUND_LOG_DIR"
    chmod 750 "$UNBOUND_LOG_DIR"
    chown -R unbound:unbound /var/lib/unbound
    chmod 750 /var/lib/unbound

    # 预先创建日志文件（确保 Fail2Ban 启动时日志文件已存在）
    touch "${UNBOUND_LOG_DIR}/unbound.log"
    chown unbound:unbound "${UNBOUND_LOG_DIR}/unbound.log"
    chmod 640 "${UNBOUND_LOG_DIR}/unbound.log"

    info "目录配置完成。"
}

###############################################################################
# DNSSEC 根信任锚配置
###############################################################################
setup_dnssec() {
    info "正在配置 DNSSEC 信任锚..."

    # 下载最新的根提示文件
    local root_hints="/var/lib/unbound/root.hints"
    local root_hints_tmp=""
    if root_hints_tmp="$(mktemp)"; then
        # 立即设置 RETURN 陷阱，确保临时文件在函数退出时被清理
        trap 'rm -f "$root_hints_tmp"' RETURN
        if curl -sSf -o "$root_hints_tmp" https://www.internic.net/domain/named.root && [[ -s "$root_hints_tmp" ]]; then
            mv "$root_hints_tmp" "$root_hints"
            info "已下载最新的根提示文件。"
        else
            rm -f "$root_hints_tmp"
            warn "无法下载根提示文件或文件为空，使用系统默认值。"
            cp /usr/share/dns/root.hints "$root_hints" 2>/dev/null || true
        fi
    else
        warn "无法创建临时文件，使用系统默认根提示。"
        cp /usr/share/dns/root.hints "$root_hints" 2>/dev/null || true
    fi
    chown unbound:unbound "$root_hints"
    chmod 644 "$root_hints"

    # 初始化/更新根信任锚
    local anchor_file="/var/lib/unbound/root.key"
    unbound-anchor -a "$anchor_file" 2>/dev/null || true
    chown unbound:unbound "$anchor_file"
    chmod 644 "$anchor_file"

    info "DNSSEC 信任锚配置完成。"
}

###############################################################################
# 生成 Unbound 配置文件
###############################################################################
configure_unbound() {
    info "正在生成 Unbound 配置..."

    # --- 主配置文件 ---
    cat > "$UNBOUND_MAIN_CONF" <<'EOF'
# =============================================================================
# Unbound 主配置文件
# 企业级公共 DNS 服务器
# =============================================================================
# 引入模块化配置文件
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
EOF

    # --- 服务器核心配置 ---
    cat > "$UNBOUND_CONF_DIR/01-server.conf" <<EOF
# =============================================================================
# 服务器核心配置
# 针对 Azure Standard_B2ats_v2 (2 vCPU, 1 GiB 内存) 优化
# Unbound 仅提供端口 53 DNS 服务，DOT/DoH 由 NGINX 反向代理处理
# =============================================================================
server:
    # --- 接口绑定（仅 DNS 端口 53）---
    interface: 0.0.0.0@${DNS_PORT}
    interface: ::0@${DNS_PORT}

    # --- 访问控制（公共 DNS）---
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow

    # 拒绝查询私有/伪造地址范围以防止 DNS 重绑定攻击
    private-address: 0.0.0.0/8
    private-address: 10.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: 127.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 192.0.2.0/24
    private-address: 192.168.0.0/16
    private-address: 198.18.0.0/15
    private-address: 198.51.100.0/24
    private-address: 203.0.113.0/24
    private-address: 240.0.0.0/4
    private-address: ::1/128
    private-address: ::ffff:0:0/96
    private-address: 2001:db8::/32
    private-address: fc00::/7
    private-address: fe80::/10

    # --- 协议设置 ---
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    prefer-ip6: no

    # --- TCP 连接设置 ---
    incoming-num-tcp: 1024
    outgoing-num-tcp: 100
    edns-tcp-keepalive: yes

    # --- 性能调优 ---
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

    # 使用连接式 UDP socket 提升速度
    udp-connect: yes

    # 轮询 RRset 中的记录顺序以实现负载均衡
    rrset-roundrobin: yes

    # --- 缓存优化 ---
    # 预取即将过期的条目（降低热门查询的延迟）
    prefetch: yes
    prefetch-key: yes

    # 刷新时提供过期数据（零停机缓存）
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-client-timeout: 1800
    serve-expired-reply-ttl: 30

    # 缓存最小/最大 TTL
    cache-min-ttl: 60
    cache-max-ttl: 86400
    cache-max-negative-ttl: 300

    # 基础设施缓存
    infra-host-ttl: 900
    infra-cache-numhosts: 50000

    # --- DNSSEC ---
    # 显式声明模块链，确保 DNSSEC 验证在迭代解析之前执行
    module-config: "validator iterator"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"

    # 加固 DNSSEC 验证
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1

    # --- 安全加固 ---
    # 隐藏服务器身份（CIS 要求）
    hide-identity: yes
    hide-version: yes
    identity: ""
    version: ""

    # 加固协议防护
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-algo-downgrade: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    harden-unknown-additional: yes

    # 使用 0x20 编码的随机位来防止欺骗
    use-caps-for-id: yes

    # 最小化响应（减少放大攻击面）
    minimal-responses: yes

    # QNAME 最小化（隐私增强，RFC 7816）
    qname-minimisation: yes
    qname-minimisation-strict: no

    # 拒绝 ANY 类型查询（防止放大攻击）
    deny-any: yes

    # EDNS 缓冲区大小（防止基于分片的攻击）
    edns-buffer-size: 1232

    # 最大 UDP 响应大小
    max-udp-size: 1232

    # --- 积极 NSEC (RFC 8198) ---
    aggressive-nsec: yes

    # --- 速率限制 ---
    ratelimit: ${RATELIMIT}
    ratelimit-slabs: ${RATELIMIT_SLABS}
    ratelimit-size: 4m
    ip-ratelimit: ${IP_RATELIMIT}
    ip-ratelimit-slabs: ${IP_RATELIMIT_SLABS}
    ip-ratelimit-size: 4m

    # --- 日志记录（PCI-DSS: 全面审计日志）---
    use-syslog: no
    logfile: "${UNBOUND_LOG_DIR}/unbound.log"
    verbosity: 1
    log-queries: no
    log-replies: no
    log-tag-queryreply: yes
    log-local-actions: yes
    log-servfail: yes
    log-time-ascii: yes

    # --- 进程设置 ---
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""
    pidfile: "/run/unbound/unbound.pid"

    # --- 其他 ---
    unwanted-reply-threshold: 10000000
    do-not-query-localhost: yes
    ede: yes
    ede-serve-expired: yes
EOF

    # --- 远程控制配置 ---
    cat > "$UNBOUND_CONF_DIR/02-remote-control.conf" <<'EOF'
# =============================================================================
# 远程控制配置
# 仅允许本地访问以确保安全
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

    # 生成 unbound-control 密钥
    unbound-control-setup 2>/dev/null || warn "unbound-control-setup 存在警告"
    info "Unbound 配置生成完成。"
}

###############################################################################
# 域名黑名单 / RPZ（响应策略区域，企业标准配置）
###############################################################################
configure_rpz() {
    info "正在设置 DNS 响应策略区域 (RPZ) 用于威胁域名拦截..."

    # 创建本地黑名单文件
    cat > /etc/unbound/blocklist.conf <<'EOF'
# =============================================================================
# 本地 DNS 黑名单
# 在此添加需要拦截的域名，每行一条:
# local-zone: "malware-domain.com." always_refuse
# =============================================================================

# 拦截已知的恶意软件指挥控制域名（示例）
# local-zone: "example-malware.com." always_refuse
# local-zone: "bad-actor.net." always_refuse
EOF

    cat > "$UNBOUND_CONF_DIR/04-blocklist.conf" <<'EOF'
# =============================================================================
# 响应策略 / 黑名单集成
# =============================================================================
server:
    # 引入本地黑名单
    include: "/etc/unbound/blocklist.conf"

    # 拒绝私有地址的反向查询（防止向根服务器泄露内部网络信息）
    local-zone: "0.in-addr.arpa." refuse
    local-zone: "10.in-addr.arpa." refuse
    local-zone: "127.in-addr.arpa." refuse
    local-zone: "16.172.in-addr.arpa." refuse
    local-zone: "17.172.in-addr.arpa." refuse
    local-zone: "18.172.in-addr.arpa." refuse
    local-zone: "19.172.in-addr.arpa." refuse
    local-zone: "20.172.in-addr.arpa." refuse
    local-zone: "21.172.in-addr.arpa." refuse
    local-zone: "22.172.in-addr.arpa." refuse
    local-zone: "23.172.in-addr.arpa." refuse
    local-zone: "24.172.in-addr.arpa." refuse
    local-zone: "25.172.in-addr.arpa." refuse
    local-zone: "26.172.in-addr.arpa." refuse
    local-zone: "27.172.in-addr.arpa." refuse
    local-zone: "28.172.in-addr.arpa." refuse
    local-zone: "29.172.in-addr.arpa." refuse
    local-zone: "30.172.in-addr.arpa." refuse
    local-zone: "31.172.in-addr.arpa." refuse
    local-zone: "168.192.in-addr.arpa." refuse
    local-zone: "254.169.in-addr.arpa." refuse
    local-zone: "8.b.d.0.1.0.0.2.ip6.arpa." refuse
    local-zone: "c.f.ip6.arpa." refuse
    local-zone: "d.f.ip6.arpa." refuse
    local-zone: "8.e.f.ip6.arpa." refuse
    local-zone: "9.e.f.ip6.arpa." refuse
    local-zone: "a.e.f.ip6.arpa." refuse
    local-zone: "b.e.f.ip6.arpa." refuse
EOF

    info "RPZ 黑名单配置完成。"
}

###############################################################################
# UFW 防火墙配置
###############################################################################
configure_firewall() {
    info "正在配置 UFW 防火墙..."

    # 重置 UFW 到干净状态（非交互式）
    ufw --force reset >/dev/null 2>&1

    # 默认策略：拒绝入站，允许出站
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    # SSH 速率限制（每个 IP 每 30 秒限制 6 次连接）
    ufw limit ssh/tcp >/dev/null 2>&1

    # DNS (UDP 和 TCP 端口 53)
    ufw allow 53/tcp >/dev/null 2>&1
    ufw allow 53/udp >/dev/null 2>&1

    # DNS-over-TLS (端口 853) - 由 NGINX 反向代理提供
    ufw allow 853/tcp >/dev/null 2>&1

    # DNS-over-HTTPS (端口 443) - 由 NGINX 反向代理提供
    ufw allow 443/tcp >/dev/null 2>&1

    # 启用日志记录（中等级别用于审计）
    ufw logging medium >/dev/null 2>&1

    # 启用 UFW（非交互式）
    ufw --force enable >/dev/null 2>&1

    info "UFW 防火墙已配置并激活。"
    info "已开放端口: SSH(22/tcp-限速), DNS(53/tcp+udp), DoT(853/tcp-NGINX), DoH(443/tcp-NGINX)"
}

###############################################################################
# Fail2Ban DNS 防护配置
###############################################################################
configure_fail2ban() {
    info "正在配置 Fail2Ban DNS 滥用防护..."

    # 创建 DNS 专用监控规则
    cat > /etc/fail2ban/jail.d/unbound-dns.conf <<'EOF'
# =============================================================================
# Fail2Ban DNS 滥用防护监控规则
# =============================================================================
[unbound-dns-abuse]
enabled  = true
port     = 53
protocol = udp,tcp
filter   = unbound-dns-abuse
logpath  = /var/log/unbound/unbound.log
backend  = auto
maxretry = 50
findtime = 60
bantime  = 3600
banaction = ufw
EOF

    # 创建过滤器以匹配 Unbound 速率限制和错误日志条目
    # Unbound 日志格式 (VERB_OPS, verbosity >= 1):
    #   域名速率限制: [ts] unbound[pid:tid] info: ratelimit exceeded <zone> <limit> query <qname> <class> <type> from <ip>
    #   IP 速率限制:   [ts] unbound[pid:tid] info: ip_ratelimit exceeded <ip> <limit>[cookie] <query>
    cat > /etc/fail2ban/filter.d/unbound-dns-abuse.conf <<'EOF'
# =============================================================================
# Fail2Ban Unbound DNS 滥用过滤器
# 匹配 Unbound 记录的速率限制违规（verbosity >= 1, VERB_OPS）
# 域名速率限制日志: ratelimit exceeded <zone> <limit> query ... from <ip>
# IP 速率限制日志:   ip_ratelimit exceeded <ip> <limit>... <query>
# =============================================================================
[Definition]
failregex = ^.+\bunbound\[\d+:\d+\] info: ratelimit exceeded \S+ \d+ query .+ from <HOST>\s*$
            ^.+\bunbound\[\d+:\d+\] info: ip_ratelimit exceeded <HOST> \d+.*$
ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban 2>/dev/null || warn "Fail2Ban 重启遇到问题（将在重启后启动）"

    info "Fail2Ban 配置完成。"
}

###############################################################################
# 日志轮转配置
###############################################################################
configure_logrotate() {
    info "正在配置日志轮转..."

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

    info "日志轮转已配置（保留 90 天以满足 PCI-DSS 合规要求）。"
}

###############################################################################
# Systemd 服务安全加固
###############################################################################
harden_systemd_service() {
    info "正在加固 Unbound systemd 服务..."

    # 创建 systemd 覆盖配置
    mkdir -p /etc/systemd/system/unbound.service.d

    cat > /etc/systemd/system/unbound.service.d/hardening.conf <<'EOF'
# =============================================================================
# Unbound Systemd 服务安全加固
# CIS / PCI-DSS 合规配置
# =============================================================================
[Service]
# --- 文件系统隔离 ---
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/unbound /var/lib/unbound /run/unbound

# --- 权能限制 ---
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_RESOURCE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# --- 安全策略 ---
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

# --- 系统调用过滤 ---
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @module @obsolete @clock @cpu-emulation @debug @raw-io
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# --- 网络限制 ---
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# --- 其他 ---
UMask=0027

# --- 资源限制 ---
LimitNOFILE=65535
LimitNPROC=512

# --- 重启策略 ---
Restart=always
RestartSec=5
WatchdogSec=60
EOF

    # 确保 PID 目录存在
    mkdir -p /run/unbound
    chown unbound:unbound /run/unbound

    # 创建 tmpfiles.d 条目确保重启后 /run/unbound 自动创建
    cat > /etc/tmpfiles.d/unbound.conf <<'EOF'
d /run/unbound 0755 unbound unbound -
EOF

    systemctl daemon-reload
    info "Systemd 服务安全加固已应用。"
}

###############################################################################
# 监控和健康检查脚本
###############################################################################
create_monitoring_scripts() {
    info "正在创建监控和健康检查脚本..."

    # --- 健康检查脚本 ---
    cat > /usr/local/bin/unbound-health-check <<'HEALTHCHECK'
#!/usr/bin/env bash
###############################################################################
# Unbound 健康检查脚本
# 成功返回 0，失败返回 1
###############################################################################
# 注意: 此处不使用 "set -e"，因为我们故意运行可能失败的命令
# 并捕获它们的退出状态用于报告。
set -uo pipefail

CHECKS_PASSED=0
CHECKS_FAILED=0
VERBOSE="${1:-}"

check() {
    local name="$1"
    local result="$2"
    if [[ "$result" == "0" ]]; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        [[ "$VERBOSE" == "-v" ]] && echo "[通过] $name"
    else
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        echo "[失败] $name"
    fi
}

# 检查 1: 服务是否运行
systemctl is-active --quiet unbound 2>/dev/null
check "Unbound 服务运行状态" "$?"

# 检查 2: 端口 53 是否监听
ss -ulnp | grep -q ':53 ' 2>/dev/null
check "端口 53 (UDP) 监听状态" "$?"

ss -tlnp | grep -q ':53 ' 2>/dev/null
check "端口 53 (TCP) 监听状态" "$?"

# 检查 3: DNS 解析是否正常
dig @127.0.0.1 +short +time=5 +tries=2 example.com A >/dev/null 2>&1
check "DNS 解析 (A 记录)" "$?"

# 检查 4: DNSSEC 验证是否正常
dig @127.0.0.1 +dnssec +short +time=5 +tries=2 example.com A >/dev/null 2>&1
check "DNSSEC 解析" "$?"

# 检查 5: DNSSEC 是否拒绝无效签名
dnssec_fail=$(dig @127.0.0.1 +time=5 +tries=2 dnssec-failed.org A 2>&1 | grep -c "SERVFAIL" || true)
if [[ "$dnssec_fail" -ge 1 ]]; then
    check "DNSSEC 拒绝无效签名" "0"
else
    check "DNSSEC 拒绝无效签名" "1"
fi

# 检查 6: unbound-control 是否正常
unbound-control status >/dev/null 2>&1
check "unbound-control 运行状态" "$?"

# 汇总报告
echo ""
echo "健康检查汇总: ${CHECKS_PASSED} 项通过, ${CHECKS_FAILED} 项失败"

if [[ $CHECKS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
HEALTHCHECK

    chmod 755 /usr/local/bin/unbound-health-check

    # --- 统计信息收集脚本 ---
    cat > /usr/local/bin/unbound-stats <<'STATS'
#!/usr/bin/env bash
###############################################################################
# Unbound 统计信息收集
###############################################################################
set -euo pipefail

echo "=== Unbound 服务器统计信息 ==="
echo "时间戳: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# 获取统计数据
unbound-control stats_noreset 2>/dev/null | grep -E \
    "^(total|time|mem|num)" | while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done

echo ""
echo "=== 缓存统计 ==="
unbound-control stats_noreset 2>/dev/null | grep -E "^(rrset|msg|key|infra)" | \
    while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done

echo ""
echo "=== 速率限制统计 ==="
unbound-control stats_noreset 2>/dev/null | grep -E "ratelimit" | \
    while IFS='=' read -r key value; do
    printf "%-45s %s\n" "$key" "$value"
done
STATS

    chmod 755 /usr/local/bin/unbound-stats

    # --- 根提示更新脚本（每月 systemd 定时器）---
    cat > /usr/local/bin/update-root-hints <<'ROOTHINTS'
#!/usr/bin/env bash
###############################################################################
# 更新 DNS 根提示文件
# 通过 systemd timer 每月执行
###############################################################################
set -euo pipefail

ROOT_HINTS="/var/lib/unbound/root.hints"
TEMP_FILE=$(mktemp) || { logger -t "root-hints-update" "无法创建临时文件"; exit 1; }
trap 'rm -f "$TEMP_FILE"' EXIT

if curl -sSf -o "$TEMP_FILE" https://www.internic.net/domain/named.root; then
    if [[ -s "$TEMP_FILE" ]]; then
        mv "$TEMP_FILE" "$ROOT_HINTS"
        chown unbound:unbound "$ROOT_HINTS"
        chmod 644 "$ROOT_HINTS"
        unbound-control reload 2>/dev/null || systemctl reload unbound
        logger -t "root-hints-update" "根提示文件更新成功"
    else
        logger -t "root-hints-update" "下载的文件为空，跳过更新"
    fi
else
    logger -t "root-hints-update" "下载根提示文件失败"
fi
ROOTHINTS

    chmod 755 /usr/local/bin/update-root-hints

    # --- systemd 定时器：每月更新根提示文件 ---
    cat > /etc/systemd/system/update-root-hints.service <<'EOF'
[Unit]
Description=Update DNS root hints file
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-root-hints
EOF

    cat > /etc/systemd/system/update-root-hints.timer <<'EOF'
[Unit]
Description=Monthly DNS root hints update

[Timer]
OnCalendar=monthly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now update-root-hints.timer 2>/dev/null || true

    # --- DNSSEC 信任锚更新脚本（每周 systemd 定时器）---
    cat > /usr/local/bin/update-trust-anchor <<'TRUSTANCHOR'
#!/usr/bin/env bash
###############################################################################
# 更新 DNSSEC 信任锚
# 通过 systemd timer 每周执行
###############################################################################
set -euo pipefail

anchor_exit=0
/usr/sbin/unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || anchor_exit=$?
if [[ $anchor_exit -eq 0 ]]; then
    logger -t "trust-anchor-update" "DNSSEC 信任锚无需更新"
elif [[ $anchor_exit -eq 1 ]]; then
    logger -t "trust-anchor-update" "DNSSEC 信任锚已更新"
else
    logger -t "trust-anchor-update" "unbound-anchor 执行失败 (退出码: $anchor_exit)"
fi
if ! systemctl reload unbound 2>/dev/null; then
    logger -t "trust-anchor-update" "Unbound 重载失败，服务可能未运行"
fi
logger -t "trust-anchor-update" "DNSSEC 信任锚更新任务完成"
TRUSTANCHOR

    chmod 755 /usr/local/bin/update-trust-anchor

    cat > /etc/systemd/system/update-trust-anchor.service <<'EOF'
[Unit]
Description=Update DNSSEC trust anchor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-trust-anchor
EOF

    cat > /etc/systemd/system/update-trust-anchor.timer <<'EOF'
[Unit]
Description=Weekly DNSSEC trust anchor update

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now update-trust-anchor.timer 2>/dev/null || true

    info "监控和维护脚本创建完成。"
}

###############################################################################
# 验证配置文件
###############################################################################
validate_config() {
    info "正在验证 Unbound 配置..."

    if unbound-checkconf "$UNBOUND_MAIN_CONF"; then
        info "配置文件验证通过。"
    else
        fatal "配置文件验证失败。请检查 $UNBOUND_MAIN_CONF"
    fi
}

###############################################################################
# 启动并启用 Unbound
###############################################################################
start_unbound() {
    info "正在启动 Unbound DNS 服务器..."

    systemctl enable unbound

    # 如果 systemd-resolved 正在运行则停止它（与端口 53 冲突）
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl disable --now systemd-resolved
        info "已禁用 systemd-resolved（端口 53 冲突）"
    fi

    # 检查是否有其他服务占用端口 53（BIND9、dnsmasq 等）
    if ss -tlnp 2>/dev/null | grep -q ':53 ' || ss -ulnp 2>/dev/null | grep -q ':53 '; then
        warn "检测到端口 53 被其他服务占用，正在尝试释放..."
        local dns_services=(named bind9 dnsmasq)
        for svc in "${dns_services[@]}"; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                systemctl disable --now "$svc" 2>/dev/null || true
                info "已停止并禁用冲突服务: $svc"
            fi
        done
        # 等待端口释放
        sleep 2
        if ss -tlnp 2>/dev/null | grep -q ':53 ' || ss -ulnp 2>/dev/null | grep -q ':53 '; then
            fatal "端口 53 仍被占用，无法启动 Unbound。请手动检查: ss -tlnp | grep ':53 '"
        fi
    fi

    # 立即启动 Unbound 以最小化 DNS 不可用窗口
    systemctl restart unbound

    # 等待服务就绪
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if systemctl is-active --quiet unbound; then
            break
        fi
        sleep 1
        retries=$((retries - 1))
    done

    if systemctl is-active --quiet unbound; then
        info "Unbound 正在运行。"
        # Unbound 启动成功后才更新 resolv.conf
        # 先移除不可变属性（如果存在）
        chattr -i /etc/resolv.conf 2>/dev/null || true
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf <<'EOF'
# 由 Unbound DNS 安装脚本管理
nameserver 127.0.0.1
nameserver ::1
options edns0 trust-ad
EOF
        # 设置不可变属性防止 DHCP 或 networkd 覆盖
        chattr +i /etc/resolv.conf 2>/dev/null || true
        info "已更新 resolv.conf 指向本地 DNS（已设置不可变属性）"
    else
        error "Unbound 启动失败。正在检查日志..."
        journalctl -u unbound --no-pager -n 30
        fatal "Unbound 启动失败。请检查上面的日志输出。"
    fi
}

###############################################################################
# 安装后验证
###############################################################################
post_install_validation() {
    info "正在运行安装后验证..."

    echo ""
    echo "============================================================"
    echo "  安装后验证"
    echo "============================================================"
    echo ""

    local pass=0
    local fail=0

    # 测试 1: 服务状态
    if systemctl is-active --quiet unbound; then
        printf '%b[通过]%b Unbound 服务运行中\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b Unbound 服务未运行\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    # 测试 2: DNS 解析
    if dig @127.0.0.1 +short +time=5 +tries=2 example.com A >/dev/null 2>&1; then
        printf '%b[通过]%b DNS 解析正常 (example.com)\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b DNS 解析失败\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    # 测试 3: DNSSEC 验证
    local ad_flag
    ad_flag=$(dig @127.0.0.1 +time=5 +tries=2 example.com A 2>&1 | grep -c "ad;" || true)
    if [[ "$ad_flag" -ge 1 ]]; then
        printf '%b[通过]%b DNSSEC 验证已启用 (AD 标志已设置)\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[警告]%b 未检测到 DNSSEC AD 标志（可能需要时间初始化缓存）\n' "${YELLOW}" "${NC}"
    fi

    # 测试 4: 端口监听状态
    if ss -tlnp | grep -q ":53 "; then
        printf '%b[通过]%b TCP 端口 53 正在监听\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b TCP 端口 53 未监听\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    if ss -ulnp | grep -q ":53 "; then
        printf '%b[通过]%b UDP 端口 53 正在监听\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b UDP 端口 53 未监听\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    # 测试 5: 配置文件验证
    if unbound-checkconf "$UNBOUND_MAIN_CONF" >/dev/null 2>&1; then
        printf '%b[通过]%b 配置文件有效\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b 配置文件存在错误\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    # 测试 6: unbound-control
    if unbound-control status >/dev/null 2>&1; then
        printf '%b[通过]%b unbound-control 运行正常\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[警告]%b unbound-control 无响应（可能需要重启服务）\n' "${YELLOW}" "${NC}"
    fi

    # 测试 7: 防火墙状态
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        printf '%b[通过]%b UFW 防火墙已激活\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[失败]%b UFW 防火墙未激活\n' "${RED}" "${NC}"
        fail=$((fail + 1))
    fi

    # 测试 8: 服务器身份是否隐藏
    local identity
    identity=$(dig @127.0.0.1 +time=5 +tries=2 CH TXT id.server 2>&1 || true)
    if echo "$identity" | grep -q "REFUSED\|connection timed out\|no servers"; then
        printf '%b[通过]%b 服务器身份已隐藏\n' "${GREEN}" "${NC}"
        pass=$((pass + 1))
    else
        printf '%b[警告]%b 服务器身份可能可见\n' "${YELLOW}" "${NC}"
    fi

    echo ""
    echo "============================================================"
    printf '  结果: %b%d 项通过%b, %b%d 项失败%b\n' "${GREEN}" "$pass" "${NC}" "${RED}" "$fail" "${NC}"
    echo "============================================================"
    echo ""

    if [[ $fail -gt 0 ]]; then
        warn "部分验证检查未通过。请查看上面的输出。"
    else
        info "所有验证检查均已通过！"
    fi
}

###############################################################################
# 打印安装摘要
###############################################################################
print_summary() {
    cat <<EOF

╔══════════════════════════════════════════════════════════════════════════════╗
║               企业级 Unbound DNS 服务器 - 安装完成                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  服务状态:                                                                  ║
║    • Unbound DNS:  systemctl status unbound                                ║
║    • 防火墙:       ufw status verbose                                      ║
║    • Fail2Ban:     systemctl status fail2ban                               ║
║                                                                            ║
║  监听端口:                                                                  ║
║    • DNS (UDP/TCP):  ${DNS_PORT}                                                    ║
║    • 远程控制:       8953 (仅限本地)                                         ║
║                                                                            ║
║  注意: DOT (端口 853) 和 DoH (端口 443) 由 NGINX 反向代理提供               ║
║        请单独安装和配置 NGINX 以启用 DOT/DoH 功能                            ║
║                                                                            ║
║  配置文件:                                                                  ║
║    • 主配置:        ${UNBOUND_MAIN_CONF}                           ║
║    • 服务器:        ${UNBOUND_CONF_DIR}/01-server.conf       ║
║    • 远程控制:      ${UNBOUND_CONF_DIR}/02-remote-control.conf║
║    • 黑名单:        ${UNBOUND_CONF_DIR}/04-blocklist.conf    ║
║                                                                            ║
║  常用命令:                                                                  ║
║    • 健康检查:      /usr/local/bin/unbound-health-check -v                 ║
║    • 查看统计:      /usr/local/bin/unbound-stats                           ║
║    • 查看日志:      tail -f ${UNBOUND_LOG_DIR}/unbound.log             ║
║    • 清除缓存:      unbound-control flush_zone .                           ║
║    • 重载配置:      unbound-control reload                                 ║
║    • 检查配置:      unbound-checkconf                                      ║
║                                                                            ║
║  安全特性:                                                                  ║
║    ✓ DNSSEC 验证已启用                                                      ║
║    ✓ 速率限制（每 IP 和全局）                                                ║
║    ✓ UFW 防火墙（基于 nftables 后端）                                       ║
║    ✓ Fail2Ban DNS 滥用防护                                                  ║
║    ✓ Systemd 沙箱隔离（ProtectSystem, NoNewPrivileges 等）                  ║
║    ✓ QNAME 最小化 (RFC 7816)                                               ║
║    ✓ 0x20 查询随机化                                                        ║
║    ✓ 最小化响应（防放大攻击）                                                ║
║    ✓ deny-any 已启用                                                        ║
║    ✓ DNS 性能内核调优                                                        ║
║    ✓ CIS 基准内核安全加固                                                    ║
║    ✓ SSH 安全加固                                                            ║
║    ✓ 登录横幅和核心转储限制                                                  ║
║    ✓ 90 天日志保留                                                           ║
║                                                                            ║
║  备份位置: ${BACKUP_DIR}                         ║
║  安装日志: ${LOG_FILE}                                    ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF
}

###############################################################################
# CIS 基准 - SSH 安全加固
###############################################################################
harden_ssh() {
    info "正在应用 SSH 安全加固（CIS 基准）..."

    local sshd_config_dir="/etc/ssh/sshd_config.d"

    # 使用独立配置文件以避免修改主配置
    mkdir -p "$sshd_config_dir"

    cat > "${sshd_config_dir}/99-cis-hardening.conf" <<'EOF'
# =============================================================================
# SSH 安全加固 - CIS 基准合规配置
# =============================================================================

# 注意: Protocol 2 在现代 OpenSSH (7.6+) 中已移除 SSH v1 支持，
# 该指令已废弃，无需显式声明。

# 禁止 root 使用密码登录（CIS 5.2.10）- 仅允许密钥认证
PermitRootLogin prohibit-password

# 最大认证尝试次数（CIS 5.2.6）
MaxAuthTries 4

# 登录超时时间（CIS 5.2.16）
LoginGraceTime 60

# 空闲超时设置（CIS 5.2.13）
ClientAliveInterval 300
ClientAliveCountMax 3

# 禁用空密码（CIS 5.2.9）
PermitEmptyPasswords no

# 禁用主机认证（CIS 5.2.7）
HostbasedAuthentication no

# 忽略用户已知主机文件中的 rhosts（CIS 5.2.8）
IgnoreRhosts yes

# 日志级别（CIS 5.2.3）
LogLevel VERBOSE

# 最大并发未认证连接数（CIS 5.2.19）
MaxStartups 10:30:60

# 最大会话数
MaxSessions 10

# 禁用 X11 转发（CIS 5.2.5）
X11Forwarding no

# 禁用远程 TCP 转发，允许本地转发用于管理
AllowTcpForwarding local

# 登录前警告横幅（CIS 5.2.18）
Banner /etc/issue.net

# 使用强加密算法
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
EOF

    # 验证 SSH 配置有效性
    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        info "SSH 安全加固已应用。"
    else
        warn "SSH 配置验证失败，已回滚更改。"
        rm -f "${sshd_config_dir}/99-cis-hardening.conf"
    fi
}

###############################################################################
# CIS 基准 - 禁用不必要的服务
###############################################################################
disable_unnecessary_services() {
    info "正在检查并禁用不必要的服务（CIS 基准 2.1 / 2.2）..."

    local services=(
        avahi-daemon        # mDNS/DNS-SD - DNS 服务器不需要
        cups                # 打印服务
        isc-dhcp-server     # DHCP 服务器
        slapd               # LDAP 服务器
        nfs-server          # NFS 文件共享
        rpcbind             # RPC 端口映射
        rsync               # 远程同步服务
        vsftpd              # FTP 服务器
        apache2             # Web 服务器
        nginx               # 仅在此阶段禁用；NGINX 由单独脚本安装
        squid               # 代理服务器
        snmpd               # SNMP 监控
        telnet.socket       # Telnet（不安全协议）
    )

    local disabled_count=0
    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null || \
           systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            systemctl disable --now "$svc" 2>/dev/null || true
            info "  已禁用: $svc"
            disabled_count=$((disabled_count + 1))
        fi
    done

    if [[ $disabled_count -eq 0 ]]; then
        info "未检测到需要禁用的不必要服务。"
    else
        info "已禁用 ${disabled_count} 个不必要的服务。"
    fi
}

###############################################################################
# CIS 基准 - 登录横幅配置
###############################################################################
configure_login_banners() {
    info "正在配置登录横幅（CIS 基准）..."

    # 设置登录前横幅（CIS 1.7.1）
    cat > /etc/issue <<'EOF'
*******************************************************************************
*                           授权访问警告                                       *
*  未经授权的访问是被禁止的。所有活动都将被监控和记录。                            *
*  继续使用即表示您同意接受安全监控和审计。                                       *
*******************************************************************************
EOF

    cat > /etc/issue.net <<'EOF'
*******************************************************************************
*                           授权访问警告                                       *
*  未经授权的访问是被禁止的。所有活动都将被监控和记录。                            *
*  继续使用即表示您同意接受安全监控和审计。                                       *
*******************************************************************************
EOF

    # 设置登录后横幅 (MOTD)
    cat > /etc/motd <<'EOF'
=== 企业级 Unbound DNS 服务器 ===
所有操作均受安全监控。仅限授权管理员使用。
EOF

    # 设置文件权限（CIS 1.7.4 - 1.7.6）
    chown root:root /etc/issue /etc/issue.net /etc/motd
    chmod 644 /etc/issue /etc/issue.net /etc/motd

    info "登录横幅配置完成。"
}

###############################################################################
# 主函数
###############################################################################
main() {
    parse_args "$@"

    # 注册错误处理陷阱（在参数解析之后，确保 BACKUP_DIR 等变量可用）
    trap 'cleanup_on_error $LINENO' ERR

    # 初始化日志文件
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"

    echo ""
    info "╔══════════════════════════════════════════════════════════════╗"
    info "║   企业级 Unbound DNS 服务器安装程序 v${SCRIPT_VERSION}            ║"
    info "║   目标: Debian 13 / Azure Standard_B2ats_v2                 ║"
    info "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    info "Unbound 仅提供 DNS 端口 53 服务"
    info "DOT/DoH 将由单独安装的 NGINX 反向代理提供"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        info "试运行模式 - 不会做任何更改。"
        info "将要执行以下步骤:"
        info "  1.  安装前环境检查（root 权限、系统版本、内存、网络）"
        info "  2.  备份现有配置文件"
        info "  3.  安装必需的软件包（unbound, fail2ban 等）"
        info "  4.  应用 DNS 性能调优和 CIS 内核安全加固"
        info "  5.  创建 Unbound 用户和目录结构"
        info "  6.  配置 DNSSEC 信任锚和根提示文件"
        info "  7.  生成 Unbound 主配置文件（仅 DNS 端口 53）"
        info "  8.  配置域名黑名单/RPZ"
        info "  9.  配置 UFW 防火墙规则"
        info "  10. 配置 Fail2Ban DNS 滥用防护"
        info "  11. 配置日志轮转（90 天保留）"
        info "  12. 应用 Systemd 服务安全加固"
        info "  13. 创建监控和健康检查脚本及 systemd 定时器"
        info "  14. SSH 安全加固（CIS 基准）"
        info "  15. 禁用不必要的服务（CIS 基准）"
        info "  16. 配置登录横幅"
        info "  17. 验证配置文件语法"
        info "  18. 启动 Unbound 服务"
        info "  19. 运行安装后验证测试"
        info ""
        info "注意: DOT/DoH 由单独安装的 NGINX 反向代理提供，不在本脚本范围内。"
        exit 0
    fi

    # 执行安装步骤
    preflight_checks
    backup_existing
    install_packages
    tune_system_for_dns
    setup_unbound_dirs
    setup_dnssec
    configure_unbound
    configure_rpz
    configure_firewall
    configure_fail2ban
    configure_logrotate
    harden_systemd_service
    create_monitoring_scripts
    harden_ssh
    disable_unnecessary_services
    configure_login_banners
    validate_config
    start_unbound
    post_install_validation
    print_summary

    info "安装完成！"
    info "请查看上面的摘要并测试您的 DNS 服务器。"
    info "运行 '/usr/local/bin/unbound-health-check -v' 进行全面健康检查。"
}

# 使用所有参数运行主函数
main "$@"
