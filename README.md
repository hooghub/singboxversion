📦 Sing-box 一键部署脚本（IPv6-only / 免 GitHub API / 内核仓库回退）
项目简介

这是一个为 IPv6-only VPS / GitHub 访问受限环境 设计的 sing-box 一键部署脚本，支持主流协议组合，并内置多级下载回退机制，即使 VPS 完全无法访问 github.com，也能正常安装和运行 sing-box。

适合场景：

    双栈vps和只有 IPv6 出口（无 IPv4 NAT）
    
    github.com / api.github.com 无法访问
    
    GitHub Release / 官方安装脚本全部失败
    
    需要稳定、可复现、可维护的一键部署方案

✨ 核心特性

✅ 协议支持

    VLESS-TLS (TCP)
    
    VLESS-REALITY (TCP, xtls-rprx-vision)
    
    Hysteria2 (UDP)
    
    IPv4 + IPv6 双栈监听（自动分配端口）

✅ 两种部署模式
    模式 1：域名 + Let’s Encrypt
    
    使用 acme.sh standalone
    
    自动选择 IPv4 / IPv6 监听
    
    证书自动安装到 sing-box
    
    模式 2：公网 IP + 自签证书
    
    固定域名：www.epple.com
    
    SAN 自动包含可用 IPv4 / IPv6
    
    节点自动使用 [IPv6] 格式
    
    客户端使用 insecure=true

✅ sing-box 内核下载策略（重点）

    脚本 完全不依赖 GitHub API，安装 sing-box 时按以下顺序尝试：
    
    ① 外部源（优先）
    
    v6.gh-proxy.org
    
    mirror.ghproxy.com
    
    github.com 直连
    
    所有下载：
    
    IPv6 优先
    
    IPv6 失败自动回退 IPv4
    
    带超时与重试
    
    ② 外部源全部失败 → 自动回退到你们仓库内核
    https://raw.githubusercontent.com/hooghub/singboxversion/main/bin/
    ├── VERSION
    ├── sing-box-linux-amd64
    └── sing-box-linux-arm64
    
    
    ✔ 只要 raw.githubusercontent.com 可访问
    ✔ 即使 github.com 完全不可达
    ✔ 依然可以安装和更新 sing-box

✅ 内核仓库机制（你们的核心优势）

    sing-box 二进制 直接存放在仓库
    
    GitHub Actions 自动同步最新官方 Release
    
    VPS 只访问 raw.githubusercontent.com
    
    不依赖 GitHub API、不依赖 Release 页面

✅ IPv6-only 友好设计

    IPv4 探测失败 不会中断脚本
    
    所有 curl 操作 -6 优先，失败才 -4
    
    节点 URI 自动处理 [IPv6]
    
    systemd、证书、REALITY 全部支持 IPv6

✅ 其它特性

    自动安装依赖（curl / iproute2 / socat / ufw / cron 等）
    
    自动生成 UUID / 密码 / REALITY keypair
    
    自动生成 sing-box 严格 JSON 配置
    
    自动创建 systemd 服务
    
    自动开放防火墙端口（ufw）
    
    自动输出：
    
    节点链接
    
    二维码（可选）
    
    订阅文件 /root/singbox_nodes.txt

🚀 使用方法
一键脚本
```
    bash <(curl -Ls https://raw.githubusercontent.com/hooghub/singboxversion/main/sbinstall.sh)
```
需要 root 权限
支持 Debian / Ubuntu 系

📁 仓库结构说明
   ```
    .
    ├── sbinstall.sh        # 一键部署脚本
    ├── README.md
    └── bin/
        ├── VERSION         # 当前内核版本号
        ├── sing-box-linux-amd64/x86_64
        └── sing-box-linux-arm64
  ```

🔄 内核如何保持最新？

    你们仓库使用 GitHub Actions 自动完成：
    
    定期检查 sing-box 官方 Release
    
    下载最新 linux-amd64 / arm64
    
    更新 bin/ 目录
    
    更新 bin/VERSION
    
    自动提交到 main 分支
    
    VPS 侧无需任何改动，下次运行脚本自动安装最新版。

❓ 常见问题说明
Q1：为什么能访问 raw.githubusercontent.com，但访问不了 github.com？

这是 网络策略差异 导致的：

    github.com
    
    Web + Release + API
    
    常被封锁 / 阻断 / TCP Reset
    
    raw.githubusercontent.com
    
    纯静态文件 CDN
    
    常被放行
    
    IPv6 覆盖更好

👉 本项目正是利用这一点实现“免 GitHub API 安装”

Q2：为什么不直接用官方 deb-install.sh？

官方脚本依赖：

    github.com
    
    api.github.com
    
    在 IPv6-only / 国外小厂 VPS 上失败率极高
    
    本脚本 完全绕开这些依赖

Q3：模式 2 为什么要 insecure=true？

    因为使用的是 自签证书，不是 CA 签发证书，这是 TLS 规范要求。
    
    ⚠️ 注意事项
    
    请确保 VPS 网络 允许 TCP/UDP 出站
    
    IPv6-only VPS：客户端必须支持 IPv6
    
    请勿在受限制地区或违反服务商 ToS 使用

🧠 总结一句话

这是一个为“GitHub 被墙 + IPv6-only VPS”专门打造的 sing-box 一键部署方案，
外部源能用就用，不能用就直接吃自家仓库内核，稳定、可控、可维护。
⚠️ 免责声明（Disclaimer）

本项目仅用于 学习、研究和技术测试 sing-box 相关功能。

使用本项目所产生的一切后果（包括但不限于服务器封禁、账号封号、
网络异常、安全配置风险或数据丢失等），均由使用者自行承担，
作者不对任何直接或间接损失承担责任。

本脚本会修改系统网络配置、防火墙规则并安装系统服务，
请确保你对目标服务器拥有完全控制权，并在理解脚本内容后再执行。

请确保你的使用行为符合所在国家或地区的法律法规及服务商 ToS。
如不同意上述条款，请勿使用或传播本项目。
本免责声明适合整个hooghub仓库
