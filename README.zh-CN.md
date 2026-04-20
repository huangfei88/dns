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
- **UFW 防火墙**（nftables 后端），默认拒绝策略，SSH 速率限制
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
- **CIS 基准**加固（内核、文件系统、服务、登录横幅、核心转储限制）
- **PCI-DSS** 合规（TLS 1.2+、审计日志、365 天日志保留、访问控制）
- 全面的审计日志
- 登录横幅和访问限制
- 禁用不必要的服务

### 监控与维护
- 健康检查脚本（`/usr/local/bin/unbound-health-check`）
- 统计信息收集（`/usr/local/bin/unbound-stats`）
- 自动更新根提示文件（通过 systemd 定时器每月执行）
- 自动更新 DNSSEC 信任锚（通过 systemd 定时器每周执行）
- 日志轮转，保留 365 天

## 系统要求

- **操作系统**：Debian 13 (Trixie)
- **虚拟机**：Azure Standard_B2ats_v2（2 vCPU Arm64，1 GiB RAM）或类似配置
- **网络**：公网 IP 地址，端口 53/443/853 开放
- **权限**：Root 访问权限（sudo）

> **注意**：DNS-over-TLS（DoT，端口 853）和 DNS-over-HTTPS（DoH，端口 443）由 Unbound 原生提供（需要 libnghttp2 编译支持）。安装时自动生成自签名 TLS 证书用于初始使用，生产环境建议替换为 Let's Encrypt 等 CA 签发的正式证书。

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
  DoT (DNS-over-TLS, 端口 853) 和 DoH (DNS-over-HTTPS, 端口 443) 由
  Unbound 原生提供（需要 libnghttp2 编译支持）。安装时自动生成自签名
  TLS 证书，生产环境建议替换为正式 CA 证书。

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

## 配置文件

| 文件 | 说明 |
|------|------|
| `/etc/unbound/unbound.conf` | 主配置文件（包含模块化配置） |
| `/etc/unbound/unbound.conf.d/01-server.conf` | 核心服务器设置、性能、安全、DoT/DoH |
| `/etc/unbound/unbound.conf.d/02-remote-control.conf` | 远程控制（仅限本地） |
| `/etc/unbound/unbound.conf.d/04-blocklist.conf` | 响应策略 / 域名黑名单 |
| `/etc/unbound/tls/server.pem` | DoT/DoH TLS 证书（默认自签名） |
| `/etc/unbound/tls/server.key` | DoT/DoH TLS 私钥 |
| `/etc/unbound/blocklist.conf` | 自定义域名黑名单条目 |
| `/etc/sysctl.d/99-unbound-dns.conf` | DNS 性能 + CIS 内核安全调优 |
| `/etc/security/limits.d/99-disable-coredumps.conf` | 核心转储限制 |

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

# 测试 DNS-over-TLS（需要 knot-dnsutils 中的 kdig）
kdig @<server-ip> +tls example.com A

# 测试 DNS-over-HTTPS（RFC 8484 线格式）
# 注意：Unbound 的 DoH 仅支持 application/dns-message（线格式），
# 不支持 application/dns-json。使用 base64url 编码的 DNS 查询：
# 使用自签名证书时需要 -k 参数跳过证书验证
curl -ksSf 'https://<server-ip>/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# 验证 DNSSEC 拒绝无效签名
dig @<server-ip> dnssec-failed.org A  # 应返回 SERVFAIL
```

## 安全加固概要

### CIS 基准控制
- [x] 内核加固（IP 转发、源路由、ICMP 重定向、SYN cookies）
- [x] 核心转储限制
- [x] 文件权限加固
- [x] 禁用不必要的服务（avahi、cups、rpcbind 等）
- [x] 登录横幅（登录前和登录后）
- [x] 启用 ASLR
- [x] BPF 和 ptrace 限制

### PCI-DSS 要求
- [x] 通过 Unbound 原生 DoT/DoH 实现加密 DNS 的 TLS 1.2+（要求 4.1）
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

# 检查监听端口（Unbound 监听端口 53、853、443）
sudo ss -tlnp | grep -E ':(53|853|443)\s'
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
| 120 | 853 | TCP | 任意 | DNS-over-TLS |
| 130 | 443 | TCP | 任意 | DNS-over-HTTPS |
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
2. 应用内核安全加固（CIS 基准 + DNS 性能调优）
3. 配置 DNSSEC 及自动根信任锚管理
4. 根据虚拟机规格优化 Unbound 配置
5. 配置 UFW 防火墙默认拒绝策略
6. 设置 Fail2Ban 防御 DNS 滥用
7. 应用 systemd 沙箱加固
8. 创建监控脚本和维护定时器
9. 验证配置并启动服务
10. 运行安装后健康检查

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

### 步骤 6：验证 DNS-over-TLS 和 DNS-over-HTTPS

安装脚本已自动配置 Unbound 原生 DoT（端口 853）和 DoH（端口 443）支持，并生成自签名 TLS 证书。

#### 6.1 验证 DoT/DoH 端口监听

```bash
# 验证 Unbound 正在监听 DoT 和 DoH 端口
sudo ss -tlnp | grep -E ':(53|853|443)\s'
# 应显示 Unbound 同时监听 53、853 和 443
```

#### 6.2 测试 DNS-over-TLS（DoT）

```bash
# 安装 kdig（knot-dnsutils 的一部分）用于 DoT 测试
sudo apt-get install -y knot-dnsutils

# 从服务器本机测试 DoT（自签名证书需要 +tls-ca= 跳过验证）
kdig @127.0.0.1 +tls -p 853 example.com A

# 从外部机器测试 DoT（替换为您的域名或 IP）
kdig @dns.example.com +tls -p 853 example.com A
```

#### 6.3 测试 DNS-over-HTTPS（DoH）

```bash
# 使用 curl 测试 DoH（GET 方法，RFC 8484 线格式）
# 自签名证书需要 -k 参数跳过证书验证
curl -ksSf 'https://127.0.0.1/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' | \
    od -A x -t x1

# 使用 curl 测试 DoH（POST 方法，RFC 8484 线格式）
curl -ksSf -X POST https://127.0.0.1/dns-query \
    -H 'Content-Type: application/dns-message' \
    --data-binary @<(printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01') | \
    od -A x -t x1

# 注意：Unbound 的 DoH 仅支持 RFC 8484 线格式（application/dns-message）。
# 不支持 JSON 格式（application/dns-json）。
```

#### 6.4 替换为正式 TLS 证书（生产环境）

安装脚本默认生成自签名证书，生产环境建议使用 Let's Encrypt 等 CA 签发的正式证书：

```bash
# 安装 certbot
sudo apt-get install -y certbot

# 暂停 Unbound 以释放 443 端口（certbot standalone 模式需要）
sudo systemctl stop unbound

# 获取证书（替换域名和邮箱）
sudo certbot certonly --standalone \
    -d dns.example.com \
    --agree-tos \
    --email admin@example.com \
    --non-interactive

# 替换 Unbound 的 TLS 证书
sudo cp /etc/letsencrypt/live/dns.example.com/fullchain.pem /etc/unbound/tls/server.pem
sudo cp /etc/letsencrypt/live/dns.example.com/privkey.pem /etc/unbound/tls/server.key
sudo chown root:unbound /etc/unbound/tls/server.pem /etc/unbound/tls/server.key
sudo chmod 644 /etc/unbound/tls/server.pem
sudo chmod 640 /etc/unbound/tls/server.key

# 重启 Unbound
sudo systemctl start unbound

# 设置自动续期（certbot 通过 systemd 定时器自动续期）
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# 创建续期后钩子，在证书续期后重载 Unbound
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

#### 6.5 客户端加密 DNS 配置

**Android 9+（私有 DNS / DoT）：**
1. 设置 → 网络和互联网 → 私人 DNS
2. 选择"私人 DNS 提供商主机名"
3. 输入 `dns.example.com`

**iOS 14+ / macOS（DoH）：**

创建 `.mobileconfig` 配置文件并安装到设备：

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

**Windows 11（DoH）：**
1. 设置 → 网络和互联网 → 高级网络设置 → 更多网络适配器选项
2. 编辑 DNS 设置，添加 `https://dns.example.com/dns-query`

**Firefox（DoH）：**
1. 设置 → 隐私和安全 → DNS over HTTPS → 最大保护
2. 自定义提供商填写 `https://dns.example.com/dns-query`

#### 6.6 DoT/DoH 故障排查

```bash
# 检查 Unbound 是否在 853 和 443 端口监听
sudo ss -tlnp | grep -E ':(443|853)\s'

# 检查 Unbound 日志
sudo tail -20 /var/log/unbound/unbound.log

# 验证 Unbound 配置
sudo unbound-checkconf

# 检查防火墙是否允许流量
sudo ufw status | grep -E '(443|853)'

# 详细输出调试 DoT
kdig @dns.example.com +tls +tls-host=dns.example.com -d example.com A
```

**常见问题：**
- **端口 853/443 "Connection refused"**：确保 Unbound 正在运行。运行 `systemctl status unbound` 检查服务状态。
- **DoH 返回空响应**：确保 Unbound 编译时包含 `--with-libnghttp2` 支持。运行 `unbound -V` 检查 Linked libs 是否包含 libnghttp2 或运行 `ldd $(which unbound) | grep nghttp2`。
- **TLS 证书错误**：检查证书文件路径和权限。运行 `openssl x509 -in /etc/unbound/tls/server.pem -noout -subject -dates` 验证证书。
- **"SSL handshake failed"**：检查 TLS 证书是否有效以及客户端是否信任该证书（自签名证书需要客户端端跳过验证）。

> **注意**：Unbound 的原生 DoH 端点仅支持 RFC 8484 线格式（`application/dns-message`）。**不**支持 JSON 格式（`application/dns-json`）。

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
3. 输入 `dns.example.com`（需要正式 TLS 证书）

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

# 重载 systemd
sudo systemctl daemon-reload

# 重新应用 sysctl 默认值
sudo sysctl --system
```

</details>

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。
