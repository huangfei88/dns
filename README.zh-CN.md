[English](README.md) | **中文**

# 企业级 Unbound 公共 DNS 服务器

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

面向 **Debian 13 (Trixie)** 和 **Azure Standard_B2ats_v2** 虚拟机的企业级 Unbound DNS 服务器安装脚本。专为公共 DNS 服务设计，兼顾最高安全性、性能和合规性。

## 功能特性

### 安全性
- **DNSSEC** 验证，支持自动根信任锚管理
- **QNAME 最小化查询**（RFC 7816），保护上游隐私
- **0x20 查询随机化**，防止欺骗攻击
- **速率限制**（按 IP 和全局），自动封禁恶意请求
- **UFW 防火墙**（nftables 后端），默认拒绝策略
- **Fail2Ban** 集成，防御 DNS 滥用
- **Systemd 沙箱**（ProtectSystem、NoNewPrivileges、MemoryDenyWriteExecute 等）
- **deny-any** 防止放大攻击
- **最小化响应**，减少攻击面
- 隐藏服务器标识和版本信息

### 性能
- 针对 **2 vCPU / 1 GiB RAM**（Azure Standard_B2ats_v2）优化
- **2 线程**配合 `SO_REUSEPORT` 实现负载分发
- **激进缓存预取**，加速热门域名解析
- **过期缓存服务**，刷新时零停机响应（serve-expired）
- **激进 NSEC**（RFC 8198），减少上游查询
- 优化 Socket 缓冲区和连接限制
- 适配低内存环境的保守缓存配置

### 合规性
- **PCI-DSS** 合规（通过 NGINX 代理实现 TLS 1.2+、审计日志、365 天日志保留、访问控制）
- 全面的审计日志（Unbound DNS 专用 auditd 规则）
- DNS 配置和 DNSSEC 变更监控

> **注意**：CIS 基准系统级加固（内核参数、登录横幅、核心转储限制、禁用不必要的服务等）假定已由系统管理员统一管理。本脚本仅负责 Unbound DNS 相关组件。

### 监控与维护
- 健康检查脚本（`/usr/local/bin/unbound-health-check`）
- 统计信息收集（`/usr/local/bin/unbound-stats`）
- 自动更新根提示文件（通过 systemd 定时器每月执行）
- 自动更新 DNSSEC 信任锚（通过 systemd 定时器每周执行）
- 日志轮转，保留 365 天

## 系统要求

- **操作系统**：Debian 13 (Trixie)
- **虚拟机**：Azure Standard_B2ats_v2（2 vCPU Arm64，1 GiB RAM）或类似配置
- **网络**：公网 IP 地址，端口 53 开放（如使用 NGINX 代理 DoT/DoH，还需开放 443/853 端口）
- **权限**：Root 访问权限（sudo）

> **注意**：DNS-over-TLS（DoT，端口 853）和 DNS-over-HTTPS（DoH，端口 443）由单独安装的 NGINX 反向代理处理。TLS 证书在 NGINX 安装时配置。本脚本将 Unbound 配置为端口 53 上的递归 DNS 解析器，并自动放通 DoT 防火墙端口（853）。DoH 端口（443）由 NGINX 安装脚本放通。

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/huangfei88/dns.git
cd dns

# 赋予脚本执行权限
chmod +x install_unbound.sh

# 运行安装
sudo ./install_unbound.sh

# 或预览将执行的操作（试运行模式）
sudo ./install_unbound.sh --dry-run
```

## 用法

```
用法: sudo install_unbound.sh [命令] [选项]

命令:
  install               安装并配置 Unbound DNS 服务器（默认）
  uninstall             卸载 Unbound DNS 服务器并清理所有配置
  update                更新 Unbound 软件包、根提示文件和信任锚

选项:
  --dry-run             仅显示将要执行的操作，不做任何更改
  -h, --help            显示帮助信息
  -v, --version         显示脚本版本

注意:
  DoT (DNS-over-TLS, 端口 853) 防火墙端口由本脚本放通。
  DoH (DNS-over-HTTPS, 端口 443) 由单独安装的 NGINX 放通。
  TLS 证书在 NGINX 安装时配置。本脚本配置 Unbound 为端口 53 上的递归 DNS 解析器。

示例:
  sudo ./install_unbound.sh                 # 默认执行安装
  sudo ./install_unbound.sh install         # 安装 Unbound
  sudo ./install_unbound.sh uninstall       # 卸载 Unbound
  sudo ./install_unbound.sh update          # 更新 Unbound
  sudo ./install_unbound.sh install --dry-run
```

## 架构

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

## 配置文件

| 文件 | 说明 |
|------|------|
| `/etc/unbound/unbound.conf` | 主配置文件（包含模块化配置） |
| `/etc/unbound/unbound.conf.d/01-server.conf` | 核心服务器设置、性能、安全 |
| `/etc/unbound/unbound.conf.d/02-remote-control.conf` | 远程控制（仅限本地） |
| `/etc/unbound/unbound.conf.d/03-doh.conf` | DoH 后端（localhost:8443，随 NGINX 添加） |
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | 响应策略 / 域名黑名单 |
| `/etc/unbound/blocklist.conf` | 自定义域名黑名单条目 |
| `/etc/sysctl.d/99-unbound-dns.conf` | DNS 服务器网络性能调优 |

## 管理命令

```bash
# 服务管理
sudo systemctl status unbound
sudo systemctl restart unbound
sudo systemctl reload unbound

# 健康检查
sudo /usr/local/bin/unbound-health-check -v

# 查看统计信息
sudo /usr/local/bin/unbound-stats

# 查看日志
sudo tail -f /var/log/unbound/unbound.log

# 清空 DNS 缓存
sudo unbound-control flush_zone .

# 检查配置
sudo unbound-checkconf

# 查看缓存转储
sudo unbound-control dump_cache

# 查看防火墙规则
sudo ufw status verbose
```

## 测试

```bash
# 测试 DNS 解析
dig @<server-ip> example.com A

# 测试 DNSSEC 验证
dig @<server-ip> +dnssec example.com A

# 测试 DNS-over-TLS（需要 NGINX 代理和 knot-dnsutils 中的 kdig）
kdig @<server-ip> +tls example.com A

# 测试 DNS-over-HTTPS（需要 NGINX 代理，RFC 8484 线格式）
# 注意：Unbound 的 DoH 仅支持 application/dns-message（线格式），
# 不支持 application/dns-json。使用 base64url 编码的 DNS 查询：
curl -sSf 'https://dns.example.com/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# 验证 DNSSEC 拒绝无效签名
dig @<server-ip> dnssec-failed.org A  # 应返回 SERVFAIL
```

## 安全加固概要

### DNS 专用安全（由本脚本管理）
- [x] DNSSEC 验证及自动信任锚管理
- [x] 速率限制（按 IP 和全局）及 Fail2Ban 集成
- [x] UFW 防火墙 DNS 规则（默认拒绝、增量添加、保留已有规则）
- [x] Systemd 沙箱（ProtectSystem、NoNewPrivileges、MemoryDenyWriteExecute 等）
- [x] 隐藏服务器标识和版本信息
- [x] QNAME 最小化查询（RFC 7816）
- [x] 0x20 查询随机化
- [x] deny-any 防止放大攻击
- [x] 最小化响应，减少攻击面
- [x] 文件权限加固（配置文件、密钥、日志）
- [x] Unbound DNS 专用 auditd 审计规则
- [x] 365 天日志保留（PCI-DSS v4.0 要求 10.7.1）

### 系统级加固（由系统管理员另行管理）
- [ ] 内核加固（IP 转发、源路由、ICMP 重定向、SYN cookies、ASLR）
- [ ] 核心转储限制
- [ ] 禁用不必要的服务（avahi、cups、rpcbind 等）
- [ ] 登录横幅（登录前和登录后）
- [ ] BPF 和 ptrace 限制
- [ ] SSH 加固和访问控制

### PCI-DSS 要求
- [x] 通过 NGINX 代理实现加密 DNS 的 TLS 1.2+（要求 4.1）
- [x] 强密码套件（DNS 传输）
- [x] 全面的审计日志（要求 10）
- [x] 365 天日志保留（PCI-DSS v4.0 要求 10.7.1）
- [x] 默认拒绝策略的防火墙（要求 1）
- [x] 系统加固（要求 2）
- [x] 访问控制（要求 7）

## Azure NSG 配置

请记得配置 Azure 网络安全组（NSG）以允许以下流量：

| 优先级 | 端口 | 协议 | 来源 | 说明 |
|--------|------|------|------|------|
| 100 | 53 | UDP | 任意 | DNS 查询 |
| 110 | 53 | TCP | 任意 | DNS 查询（TCP） |
| 120 | 853 | TCP | 任意 | DNS-over-TLS |
| 130 | 443 | TCP | 任意 | DNS-over-HTTPS |
| 140 | 22 | TCP | 仅您的 IP | SSH 管理 |

## 故障排查

```bash
# 检查服务状态和最近日志
sudo systemctl status unbound
sudo journalctl -u unbound -n 50 --no-pager

# 验证配置语法
sudo unbound-checkconf

# 检查监听端口（Unbound 仅监听端口 53；853/443 通过 NGINX 处理）
sudo ss -tlnp | grep ':53\s'
sudo ss -ulnp | grep ':53\s'

# 详细输出测试
dig @127.0.0.1 +trace example.com

# 检查防火墙规则
sudo ufw status verbose

# 检查 Fail2Ban 状态
sudo fail2ban-client status unbound-dns-abuse
```

## 详细部署教程

### 步骤 1：创建 Azure 虚拟机

1. 登录 [Azure 门户](https://portal.azure.com)
2. 使用以下设置创建新虚拟机：
   - **镜像**：Debian 13 (Trixie) ARM64
   - **规格**：Standard_B2ats_v2（2 vCPU Arm64，1 GiB RAM）
   - **认证方式**：SSH 公钥（推荐）或密码
   - **公网 IP**：静态（DNS 服务必需）
   - **系统盘**：30 GB 标准 SSD（P4）

3. 配置**网络安全组（NSG）**：

> ⚠️ **安全警告**：务必将 SSH（端口 22）访问限制为仅您自己的 IP 地址，切勿将 SSH 开放给 `Any`。

| 优先级 | 端口 | 协议 | 来源 | 说明 |
|--------|------|------|------|------|
| 100 | 53 | UDP | 任意 | DNS 查询 |
| 110 | 53 | TCP | 任意 | DNS 查询（TCP） |
| 120 | 853 | TCP | 任意 | DNS-over-TLS（用于 NGINX） |
| 130 | 443 | TCP | 任意 | DNS-over-HTTPS（用于 NGINX） |
| 140 | 22 | TCP | 仅您的 IP | SSH 管理 |

### 步骤 2：初始服务器配置

```bash
# SSH 连接到服务器
ssh <username>@<server-public-ip>

# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# 安装 git（如果未安装）
sudo apt-get install -y git
```

### 步骤 3：克隆并运行

```bash
# 克隆仓库
git clone https://github.com/huangfei88/dns.git
cd dns

# 赋予脚本执行权限
chmod +x install_unbound.sh

# （可选）预览将执行的操作
sudo ./install_unbound.sh --dry-run

# 运行安装
sudo ./install_unbound.sh
```

脚本将自动完成以下操作：
1. 安装所有必需的软件包（Unbound、Fail2Ban、UFW 等）
2. 应用 DNS 服务器网络性能调优（sysctl）
3. 配置 DNSSEC 及自动根信任锚管理
4. 根据虚拟机规格优化 Unbound 配置
5. 配置 UFW 防火墙默认拒绝策略（仅 DNS 规则，保留已有规则）
6. 设置 Fail2Ban 防御 DNS 滥用
7. 应用 systemd 沙箱加固
8. 创建监控脚本和维护定时器
9. 配置 Unbound DNS 专用 auditd 审计规则
10. 验证配置并启动服务
11. 运行安装后健康检查

> **提示**：安装日志保存在 `/var/log/unbound-install.log`。如有问题，请首先检查此文件。

### 步骤 4：验证安装

```bash
# 运行内置健康检查（显示所有检查结果）
sudo /usr/local/bin/unbound-health-check -v

# 从服务器本机测试 DNS 解析
dig @127.0.0.1 example.com A

# 测试 DNSSEC 验证（查看响应中的 "ad" 标志）
dig @127.0.0.1 +dnssec example.com A

# 验证 DNSSEC 拒绝错误签名（应返回 SERVFAIL）
dig @127.0.0.1 dnssec-failed.org A

# 检查服务状态
sudo systemctl status unbound
sudo ufw status verbose
sudo fail2ban-client status unbound-dns-abuse

# 查看统计信息
sudo /usr/local/bin/unbound-stats
```

**预期结果：**
- `dig` 应返回 `example.com` 的 IP 地址
- `+dnssec` 查询应显示 `flags: ... ad;`（已认证数据）
- `dnssec-failed.org` 应返回 `SERVFAIL`（证明 DNSSEC 验证正常工作）
- 所有健康检查应显示 `[通过]`（PASS）

### 步骤 5：从外部客户端测试

```bash
# 将 <server-ip> 替换为您虚拟机的公网 IP 地址

# 基本 DNS 查询
dig @<server-ip> example.com A

# 启用 DNSSEC 的查询
dig @<server-ip> +dnssec google.com A

# TCP 查询
dig @<server-ip> +tcp example.com AAAA

# 反向 DNS 查找
dig @<server-ip> -x 8.8.8.8

# 查询响应时间基准测试
dig @<server-ip> example.com A | grep "Query time"
```

> 如果外部查询失败，请检查：(1) Azure NSG 允许端口 53 入站流量，(2) UFW 未阻止流量（`sudo ufw status verbose`），(3) Unbound 正在所有接口上监听（`ss -ulnp | grep :53`）。

### 步骤 6：配置 DNS-over-TLS 和 DNS-over-HTTPS

DNS-over-TLS（DoT，端口 853）和 DNS-over-HTTPS（DoH，端口 443）由 NGINX 作为 Unbound 前端的反向代理提供。本节提供完整的生产级配置。

> 安装脚本已自动放通端口 853（DoT）的防火墙规则。启动 NGINX 之前，仅需手动放通端口 443（DoH）：
> ```bash
> sudo ufw allow 443/tcp
> ```

#### 6.1 前置条件

1. **Unbound 已运行** — 先完成步骤 1–5 并确认端口 53 的 DNS 正常工作
2. **域名** — 将域名（如 `dns.example.com`）通过 A/AAAA 记录指向服务器公网 IP
3. **DNS 传播** — 等待 DNS 记录传播完成（使用 `dig dns.example.com` 验证）

#### 6.2 安装 NGINX 和 Certbot

```bash
# 安装 NGINX（nginx-full 包含 DoT 所需的 stream 模块）
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx

# 验证 NGINX stream 模块可用
nginx -V 2>&1 | grep -o with-stream
# 应输出：with-stream

# 临时停止 NGINX 以便签发证书
sudo systemctl stop nginx
```

#### 6.3 获取 TLS 证书

```bash
# 使用独立模式获取证书（NGINX 必须已停止）
# 将 dns.example.com 替换为您的实际域名
sudo certbot certonly --standalone \
    -d dns.example.com \
    --agree-tos \
    --email admin@example.com \
    --non-interactive

# 验证证书文件存在
ls -la /etc/letsencrypt/live/dns.example.com/
# 应显示：fullchain.pem、privkey.pem、cert.pem、chain.pem

# 设置自动续期（certbot 通过 systemd 定时器自动续期）
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# 创建续期后钩子，在证书续期后重载 NGINX
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post
cat <<'HOOK' | sudo tee /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
#!/bin/bash
systemctl reload nginx 2>/dev/null || true
HOOK
sudo chmod 755 /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
```

#### 6.4 配置 NGINX 实现 DoT（DNS-over-TLS）

DoT 使用 NGINX 的 `stream` 模块在端口 853 终止 TLS，并将原始 TCP DNS 流量代理到 Unbound 的端口 53。

**第 1 步：在 NGINX 主配置中启用 stream 模块**

```bash
# 检查是否已存在 stream 块加载
grep -q 'stream' /etc/nginx/nginx.conf && echo "stream found" || echo "need to add stream"

# 编辑 nginx.conf 以包含 stream 配置
# stream 块必须在顶层（与 'http' 同级），不能放在 'http {}' 内部
sudo nano /etc/nginx/nginx.conf
```

在 `/etc/nginx/nginx.conf` 的 `http {` 块**之前**添加以下行：

```nginx
# Load stream configuration for DNS-over-TLS (DoT)
include /etc/nginx/stream.conf.d/*.conf;
```

`nginx.conf` 的最终结构应如下所示：

```nginx
# ... (existing worker_processes, events, etc.)

# DoT stream configuration (MUST be outside http block)
include /etc/nginx/stream.conf.d/*.conf;

http {
    # ... (existing http configuration)
}
```

**第 2 步：创建 DoT stream 配置**

```bash
# 创建 stream 配置目录
sudo mkdir -p /etc/nginx/stream.conf.d

# 创建 DoT 配置
# 将 dns.example.com 替换为您的实际域名
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

# 重要：将下方的 YOUR_ACTUAL_DOMAIN 替换为您的实际域名，然后运行：
# 示例：sudo sed -i 's/dns.example.com/dns.myserver.com/g' /etc/nginx/stream.conf.d/dns-over-tls.conf
sudo sed -i 's/dns.example.com/YOUR_ACTUAL_DOMAIN/g' /etc/nginx/stream.conf.d/dns-over-tls.conf
```

#### 6.5 配置 NGINX 实现 DoH（DNS-over-HTTPS）

DoH 使用 NGINX 的 `http` 模块在端口 443 终止 HTTPS，并将请求代理到 Unbound 内置的 HTTP/2 端点。由于 Unbound 的 DoH 模块（基于 libnghttp2）**严格要求 HTTP/2**，会直接拒绝 HTTP/1.1 连接，因此使用 NGINX 的 `grpc_pass` 指令建立 HTTP/2 明文（h2c）连接到后端。

**第 1 步：启用 Unbound 的 DoH 后端**

为本地 DoH 监听器创建附加的 Unbound 配置文件：

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

# 验证配置是否有效
sudo unbound-checkconf

# 重载 Unbound 以应用 DoH 后端
sudo unbound-control reload
# 如果重载失败，可重启：
# sudo systemctl restart unbound

# 验证 Unbound 正在监听端口 8443
ss -tlnp | grep 8443
```

> **注意**：`http-notls-downstream: yes` 选项需要 Unbound 1.17.0+。Debian 13 (Trixie) 附带的 Unbound 1.19+ 支持此功能。如果遇到错误，请使用 `unbound -V` 检查您的 Unbound 版本。

**第 2 步：为 DoH 创建 NGINX HTTP 配置**

```bash
# 创建 DoH 站点配置
# 将 dns.example.com 替换为您的实际域名
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

    # DoH 端点（RFC 8484）
    location /dns-query {
        # 使用 grpc_pass 建立 HTTP/2 明文（h2c）连接到 Unbound DoH 后端。
        # Unbound 的 DoH 模块（libnghttp2）严格要求 HTTP/2，
        # 会直接拒绝 HTTP/1.1 连接。NGINX 的 proxy_pass 仅支持 HTTP/1.x，
        # 因此使用 grpc_pass 建立 h2c 连接到后端。
        grpc_pass grpc://127.0.0.1:8443;

        # 覆盖默认 gRPC Content-Type（application/grpc），
        # 保留客户端原始的 DoH Content-Type（application/dns-message）
        grpc_set_header Content-Type $content_type;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;

        # 超时设置
        grpc_connect_timeout 5s;
        grpc_send_timeout 10s;
        grpc_read_timeout 10s;

        # 限制请求体大小（DNS 消息通常很小，典型值最大 512 字节）
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

# 重要：将下方的 YOUR_ACTUAL_DOMAIN 替换为您的实际域名，然后运行：
# 示例：sudo sed -i 's/dns.example.com/dns.myserver.com/g' /etc/nginx/sites-available/dns-over-https
sudo sed -i 's/dns.example.com/YOUR_ACTUAL_DOMAIN/g' /etc/nginx/sites-available/dns-over-https

# 启用站点
sudo ln -sf /etc/nginx/sites-available/dns-over-https /etc/nginx/sites-enabled/

# 删除默认 NGINX 站点（可选但推荐）
sudo rm -f /etc/nginx/sites-enabled/default
```

#### 6.6 启动 NGINX

```bash
# 测试 NGINX 配置语法
sudo nginx -t

# 如果测试通过，启动 NGINX
sudo systemctl enable nginx
sudo systemctl start nginx

# 验证 NGINX 正在正确端口上监听
sudo ss -tlnp | grep -E ':(443|853)\s'
# 应显示 NGINX 同时监听 443 和 853
```

#### 6.7 测试 DoT 和 DoH

**测试 DNS-over-TLS（DoT）：**

```bash
# 安装 kdig（knot-dnsutils 的一部分）用于 DoT 测试
sudo apt-get install -y knot-dnsutils

# 从服务器本机测试 DoT
kdig @127.0.0.1 +tls -p 853 example.com A

# 从外部机器测试 DoT（替换为您的域名或 IP）
kdig @dns.example.com +tls example.com A

# 使用指定 TLS 主机名验证进行测试
kdig @<server-ip> +tls-host=dns.example.com +tls example.com A

# 验证 TLS 证书
echo | openssl s_client -connect dns.example.com:853 -servername dns.example.com 2>/dev/null | openssl x509 -noout -subject -dates
```

**测试 DNS-over-HTTPS（DoH）：**

```bash
# 使用 curl 测试 DoH（POST 方法，RFC 8484 线格式）
echo -n 'q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=' | base64 -d | \
    curl -sSf -H 'content-type: application/dns-message' \
    --data-binary @- \
    'https://dns.example.com/dns-query' | \
    od -A x -t x1

# 使用 curl 测试 DoH（通过 GET 请求和 base64url dns 参数的线格式）
# 此查询请求 example.com 的 A 记录
curl -sSf 'https://dns.example.com/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# 注意：Unbound 的 DoH 仅支持 RFC 8484 线格式（application/dns-message）。
# Unbound 原生 DoH 端点不支持 JSON 格式（application/dns-json）。

# 测试健康检查端点
curl -sSf https://dns.example.com/health

# 验证端口 443 的 TLS 证书
echo | openssl s_client -connect dns.example.com:443 -servername dns.example.com 2>/dev/null | openssl x509 -noout -subject -dates
```

**预期结果：**
- 通过 `kdig` 的 DoT 查询应返回有效的 DNS 响应
- DoH POST/GET 请求应返回二进制 DNS 响应数据（RFC 8484 线格式）
- TLS 证书应显示您的域名和有效日期

> **注意**：Unbound 的原生 DoH 端点仅支持 RFC 8484 线格式（`application/dns-message`）。**不**支持 JSON 格式（`application/dns-json`）。

#### 6.8 配置客户端私有 DNS

**Android 9+（私有 DNS / DoT）：**
1. 设置 → 网络和互联网 → 私人 DNS
2. 选择"私人 DNS 提供商主机名"
3. 输入：`dns.example.com`

**iOS 14+ / macOS（DoH）：**

创建并安装 DNS 配置描述文件（`.mobileconfig`）：
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

**Windows 11（DoH）：**
1. 设置 → 网络和互联网 → Wi-Fi / 以太网 → DNS
2. 将 DNS 设置为手动
3. 输入服务器 IP 并启用"DNS over HTTPS"
4. 模板：`https://dns.example.com/dns-query`

**Firefox（DoH）：**
1. 设置 → 隐私与安全 → DNS over HTTPS
2. 选择"自定义"并输入：`https://dns.example.com/dns-query`

#### 6.9 DoT/DoH 故障排查

```bash
# 检查 NGINX 错误日志
sudo tail -20 /var/log/nginx/error.log

# 检查 NGINX 是否在 853 和 443 端口监听
sudo ss -tlnp | grep -E ':(443|853)\s'

# 检查 Unbound DoH 后端是否在 8443 端口监听
sudo ss -tlnp | grep ':8443\s'

# 直接测试 Unbound DoH 后端（绕过 NGINX，使用线格式 GET，查询 example.com A 记录）
# 注意：必须使用 --http2-prior-knowledge，因为 Unbound DoH 仅接受 HTTP/2（h2c）
curl --http2-prior-knowledge -sSf 'http://127.0.0.1:8443/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# 检查 TLS 证书有效性
sudo certbot certificates

# 手动续期证书（如需要）
sudo certbot renew --dry-run

# 检查 NGINX 配置是否有错误
sudo nginx -t

# 验证包含 DoH 的 Unbound 配置
sudo unbound-checkconf

# 检查防火墙是否允许流量
sudo ufw status | grep -E '(443|853)'

# 详细输出调试 DoT
kdig @dns.example.com +tls +tls-host=dns.example.com -d example.com A
```

**常见问题：**
- **端口 853 "Connection refused"**：确保 NGINX 正在运行且 stream 配置已加载。检查 `include stream.conf.d/*.conf;` 行是否在 `http {}` 块**外部**。
- **DoH 出现 "502 Bad Gateway"**：确保 Unbound 正在监听端口 8443。运行 `unbound-checkconf` 并检查 `https-port` 错误。如果 `http-notls-downstream` 未被识别，可能是您的 Unbound 版本过旧。
- **DoH 直接测试失败（"curl: (56) Recv failure"）**：Unbound 的 DoH 模块（libnghttp2）严格要求 HTTP/2。直接测试（绕过 NGINX）时，必须使用 `curl --http2-prior-knowledge`。普通 `curl` 默认使用 HTTP/1.1，Unbound 会直接拒绝连接。
- **证书错误**：运行 `sudo certbot certificates` 检查证书状态。确保域名匹配。
- **"SSL handshake failed"**：检查 NGINX 中的 `ssl_protocols` 和 `ssl_ciphers` 是否与客户端支持的协议匹配。

### 步骤 7：配置 DNS 记录

如果您希望客户端通过域名使用您的服务器，请创建以下 DNS 记录：

| 类型 | 名称 | 值 | 用途 |
|------|------|------|------|
| A | dns.example.com | `<server-ip>` | 服务器地址 |
| AAAA | dns.example.com | `<server-ipv6>` | 服务器 IPv6 地址 |

### 步骤 8：管理域名黑名单

将恶意或不需要的域名添加到黑名单：

```bash
# 编辑黑名单文件
sudo nano /etc/unbound/blocklist.conf

# 按以下格式添加条目（每行一个）：
# local-zone: "malware-domain.com." always_refuse
# local-zone: "tracking-site.net." always_refuse

# 编辑完成后，验证配置语法
sudo unbound-checkconf

# 重载 Unbound 以应用更改（无需重启）
sudo unbound-control reload
```

### 步骤 9：客户端配置

配置您的设备使用新的 DNS 服务器：

**Linux/macOS：**
```bash
# 临时测试
dig @<server-ip> example.com

# 永久设置 DNS（因发行版而异）
# 对于使用 systemd-resolved 的系统，编辑 /etc/systemd/resolved.conf：
#   [Resolve]
#   DNS=<server-ip>
```

**Windows：**
1. 打开网络和互联网设置 → 更改适配器选项
2. 右键点击您的连接 → 属性 → IPv4 → 属性
3. 将首选 DNS 服务器设置为 `<server-ip>`

**Android（私有 DNS）：**
1. 设置 → 网络和互联网 → 私人 DNS
2. 选择"私人 DNS 提供商主机名"
3. 输入 `dns.example.com`（需要通过 NGINX 配置 DoT）

**iOS：**
1. 设置 → Wi-Fi → 点击您的网络 → 配置 DNS → 手动
2. 添加 `<server-ip>` 作为 DNS 服务器

### 日常维护

```bash
# 查看实时日志
sudo tail -f /var/log/unbound/unbound.log

# 查看统计信息
sudo /usr/local/bin/unbound-stats

# 运行健康检查
sudo /usr/local/bin/unbound-health-check -v

# 清空整个 DNS 缓存
sudo unbound-control flush_zone .

# 清空特定域名的缓存
sudo unbound-control flush example.com

# 修改配置后重载（无停机时间）
sudo unbound-control reload

# 完全重启（短暂停机）
sudo systemctl restart unbound

# 重载前验证配置语法
sudo unbound-checkconf

# 检查自动更新定时器
systemctl list-timers --all | grep -E 'root-hints|trust-anchor'

# 检查 Fail2Ban 封禁的 IP
sudo fail2ban-client status unbound-dns-abuse

# 解封 Fail2Ban 中的特定 IP
sudo fail2ban-client set unbound-dns-abuse unbanip <ip-address>

# 查看防火墙规则
sudo ufw status numbered
```

根提示文件会自动更新（每月），DNSSEC 信任锚通过 systemd 定时器每周更新。

### 备份与恢复

安装脚本在进行更改前会自动在 `/var/backups/unbound-install-<timestamp>/` 创建备份。手动备份方法：

```bash
# 创建手动备份
sudo cp -a /etc/unbound /var/backups/unbound-manual-$(date +%Y%m%d)
sudo cp -a /etc/fail2ban/jail.d/unbound-dns.conf /var/backups/
sudo cp -a /etc/sysctl.d/99-unbound-dns.conf /var/backups/
```

从备份恢复：
```bash
# 停止 Unbound
sudo systemctl stop unbound

# 恢复配置（将 <timestamp> 替换为您的备份时间戳）
sudo cp -a /var/backups/unbound-install-<timestamp>/etc_unbound/* /etc/unbound/

# 验证并重启
sudo unbound-checkconf
sudo systemctl start unbound
```

### 卸载

**推荐：使用内置卸载命令：**

```bash
# 预览将要移除的内容（试运行）
sudo ./install_unbound.sh uninstall --dry-run

# 执行完整卸载
sudo ./install_unbound.sh uninstall
```

内置卸载命令会自动处理所有清理步骤，包括停止服务、移除配置、清理防火墙规则和恢复 DNS 设置。

<details>
<summary>替代方案：手动卸载步骤</summary>

手动删除 Unbound 及所有配置：

```bash
# 停止并禁用服务
sudo systemctl stop unbound
sudo systemctl disable unbound
sudo systemctl stop fail2ban

# 移除 resolv.conf 的不可变属性
sudo chattr -i /etc/resolv.conf

# 恢复默认 DNS
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# 移除软件包
sudo apt-get purge -y unbound unbound-anchor unbound-host
sudo apt-get autoremove -y

# 删除配置文件
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

# 重载 systemd
sudo systemctl daemon-reload

# 重新应用 sysctl 默认值
sudo sysctl --system
```

</details>

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。
