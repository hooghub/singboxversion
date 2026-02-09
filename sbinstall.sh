#!/bin/bash
# ⚠️ 免责声明：
# 本脚本仅供学习与技术研究使用。
# 使用本脚本造成的任何后果（包括但不限于法律风险、服务器封禁、网络中断、数据丢失等）均由使用者自行承担。
# 请确保你的使用行为符合当地法律法规。
# Sing-box 一键部署脚本（最终发布版 / V5 稳定整理版 + 安装顺序增强）
# 特性：
# - IPv6-only 友好
# - sing-box 安装：优先官方 deb-install.sh -> 外部3源 -> 回退仓库 raw
# - 外部源失败自动回退到仓库 raw 内核
# - 订阅文件按组写入并带注释分隔（先 IPv4 后 IPv6）
#
# 支持模式：
# 1) 域名 + Let's Encrypt（acme.sh standalone）
# 2) 公网 IP + 自签固定域名 www.epple.com
#
# 协议：
# - VLESS-TLS (TCP)   （模式2 自签默认 allowInsecure=1）
# - VLESS-REALITY (TCP, xtls-rprx-vision)
# - Hysteria2 (UDP)   （模式2 自签默认 insecure=1）
#
# 输出策略：
# - 模式2：服务器有 IPv4 就输出 IPv4 节点；有 IPv6 就输出 IPv6 节点；都有就都输出；都没有则报错
# - 模式1：由于 v4/v6 端口不同，输出两套（同域名不同端口：DOMAIN-V4PORT / DOMAIN-V6PORT）
#
# 注意：
# - 模式2自签：客户端需要允许不校验证书（VLESS-TLS: allowInsecure=1；HY2: insecure=1）
# - IPv6-only：客户端网络必须可访问 IPv6

set -euo pipefail

log() { echo -e "$*"; }

echo "=================== Sing-box 部署前环境检查 ==================="

# --------- 检查 root ---------
if [[ ${EUID:-1} -ne 0 ]]; then
  log "[✖] 请用 root 权限运行"
  exit 1
fi
log "[✔] Root 权限 OK"

# --------- 检测公网 IP（失败不退出） ---------
SERVER_IPV4="$(curl -4 -s --max-time 3 ipv4.icanhazip.com 2>/dev/null || curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || true)"

SERVER_IPV6=""
if curl -6 -s --max-time 3 ipv6.icanhazip.com >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
elif curl -6 -s --max-time 3 ifconfig.me >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
fi
rm -f /tmp/ipv6 2>/dev/null || true

[[ -n "$SERVER_IPV4" ]] && echo "[✔] 检测到公网 IPv4: $SERVER_IPV4" || echo "[✖] 未检测到公网 IPv4"
[[ -n "$SERVER_IPV6" ]] && echo "[✔] 检测到公网 IPv6: $SERVER_IPV6" || echo "[!] 未检测到公网 IPv6（可忽略）"

# --------- 自动安装依赖（apt/yum/dnf + 自动去重） ---------
REQUIRED_CMDS=(curl ss openssl dig systemctl bash socat cron ufw qrencode tar)

# 自动识别包管理器
PKG_MGR=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MGR="yum"
else
  log "[✖] 未找到支持的包管理器（apt/yum/dnf），无法自动安装依赖。"
  exit 1
fi

# 找出缺失命令
MISSING_CMDS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
done

if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then
  log "[!] 检测到缺失命令: ${MISSING_CMDS[*]}"
  log "[!] 使用包管理器: $PKG_MGR"
  log "[!] 自动安装依赖中..."

  # 用关联数组实现“自动去重”
  declare -A PKGS=()

  add_pkg() { PKGS["$1"]=1; }

  for cmd in "${MISSING_CMDS[@]}"; do
    case "$PKG_MGR" in
      apt)
        case "$cmd" in
          dig)  add_pkg "dnsutils" ;;
          ss)   add_pkg "iproute2" ;;
          cron) add_pkg "cron" ;;
          *)    add_pkg "$cmd" ;;
        esac
        ;;
      yum|dnf)
        case "$cmd" in
          dig)  add_pkg "bind-utils" ;;
          ss)   add_pkg "iproute" ;;
          cron) add_pkg "cronie" ;;
          *)    add_pkg "$cmd" ;;
        esac
        ;;
    esac
  done

  # 组装最终安装列表（已去重）
  INSTALL_PACKAGES=()
  for pkg in "${!PKGS[@]}"; do
    INSTALL_PACKAGES+=("$pkg")
  done

  # 执行安装
  case "$PKG_MGR" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${INSTALL_PACKAGES[@]}"
      ;;
    dnf)
      dnf -y makecache
      dnf -y install "${INSTALL_PACKAGES[@]}"
      ;;
    yum)
      yum -y makecache
      yum -y install "${INSTALL_PACKAGES[@]}"
      ;;
  esac

  # 安装后复检（可选但推荐）
  POST_MISSING=()
  for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || POST_MISSING+=("$cmd")
  done
  if [[ ${#POST_MISSING[@]} -gt 0 ]]; then
    log "[✖] 安装后仍缺少命令: ${POST_MISSING[*]}"
    log "[!] 可能原因：系统源里没有对应包（例如部分 RHEL 系没有 ufw），请手动处理或改用 firewalld。"
    exit 1
  fi
else
  log "[✔] 依赖齐全，无需安装。"
fi


# --------- 检查常用端口 ---------
for port in 80 443; do
  if ss -tuln | grep -q ":$port"; then
    log "[✖] 端口 $port 已被占用"
  else
    log "[✔] 端口 $port 空闲"
  fi
done

read -rp "环境检查完成 ✅  确认继续执行部署吗？(y/N): " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || exit 0

# --------- 模式选择 ---------
while true; do
  log "\n请选择部署模式：\n1) 使用域名 + Let's Encrypt 证书\n2) 使用公网 IP + 自签固定域名 www.epple.com"
  read -rp "请输入选项 (1 或 2): " MODE
  [[ "$MODE" =~ ^[12]$ ]] && break
  log "[!] 输入错误，请重新输入 1 或 2"
done

# --------- 下载函数（v6优先，失败再v4；多URL回退；带重试） ---------
download_with_fallback() {
  # 用法：download_with_fallback <output_path> <url1> <url2> ...
  local out="$1"; shift
  local url
  for url in "$@"; do
    log ">>> 尝试下载: $url"
    if curl -6 -fL --retry 2 --retry-delay 1 --connect-timeout 6 --max-time 180 "$url" -o "$out" 2>/dev/null; then
      return 0
    fi
    if curl -4 -fL --retry 2 --retry-delay 1 --connect-timeout 6 --max-time 180 "$url" -o "$out" 2>/dev/null; then
      return 0
    fi
    log "[!] 失败，换下一个源..."
  done
  return 1
}

# --------- 计算架构 ---------
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "" ;;
  esac
}

# --------- 1) 优先尝试官方 deb-install.sh（仅 Debian/Ubuntu；失败不炸） ---------
try_official_deb_install() {
  command -v apt-get >/dev/null 2>&1 || return 1
  command -v curl >/dev/null 2>&1 || return 1
  command -v bash >/dev/null 2>&1 || return 1

  command -v sing-box >/dev/null 2>&1 && return 0

  log ">>> 尝试官方安装脚本：https://sing-box.app/deb-install.sh"
  if bash <(curl -fsSL https://sing-box.app/deb-install.sh); then
    :
  else
    log "[!] 官方 deb-install.sh 执行失败，进入多源下载兜底..."
  fi

  command -v sing-box >/dev/null 2>&1
}

# --------- 2) 外部3源下载官方 release tar.gz（你原逻辑封装） ---------
install_from_official_release_with_proxies() {
  local ARCH="$1"
  local ORI="https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-${ARCH}.tar.gz"
  local SRC1="https://v6.gh-proxy.org/${ORI}"
  local SRC2="https://mirror.ghproxy.com/${ORI}"
  local SRC3="${ORI}"

  local TGZ="/tmp/sing-box.tgz"
  if download_with_fallback "$TGZ" "$SRC1" "$SRC2" "$SRC3"; then
    log "[✔] 外部源下载成功，开始安装..."
    rm -rf /tmp/sing-box-* 2>/dev/null || true
    tar -xzf "$TGZ" -C /tmp

    local BIN_PATH
    BIN_PATH="$(find /tmp -maxdepth 3 -type f -name sing-box -perm -u+x 2>/dev/null | head -n1 || true)"
    [[ -n "$BIN_PATH" ]] || { log "[✖] 解压后未找到 sing-box 二进制"; return 1; }

    install -m 755 "$BIN_PATH" /usr/local/bin/sing-box
    log "[✔] sing-box 安装完成：$(/usr/local/bin/sing-box version | head -n1)"
    return 0
  fi
  return 1
}

# --------- 3) 回退到你们仓库 raw（你原逻辑封装） ---------
install_from_your_raw_repo() {
  local ARCH="$1"
  log "[!] 外部源全部失败，回退从仓库 raw 下载内核..."

  local CORE_BASE="https://raw.githubusercontent.com/hooghub/singboxversion/main/bin"
  local CORE_URL="${CORE_BASE}/sing-box-linux-${ARCH}"

  if download_with_fallback "/usr/local/bin/sing-box" "$CORE_URL"; then
    chmod +x /usr/local/bin/sing-box
    log -n ">>> 仓库内核版本："
    if download_with_fallback /tmp/sbver "${CORE_BASE}/VERSION"; then
      cat /tmp/sbver
    else
      echo "unknown"
    fi
    log "[✔] sing-box 安装完成：$(/usr/local/bin/sing-box version | head -n1)"
    return 0
  fi
  return 1
}

# --------- 安装 sing-box：官方脚本 -> 外部3源 -> 回退raw ---------
install_singbox() {
    if command -v sing-box >/dev/null 2>&1; then
      SB_PATH="$(command -v sing-box)"
      log "[✔] sing-box 已存在：$($SB_PATH version | head -n1)"
      install -m 755 "$SB_PATH" /usr/local/bin/sing-box
      return 0
    fi

  log ">>> 安装 sing-box（官方脚本 -> 外部3源 -> 回退仓库 raw）..."

  local ARCH
  ARCH="$(detect_arch)"
  [[ -n "$ARCH" ]] || { log "[✖] 不支持的架构: $(uname -m)"; exit 1; }

  # 1) 官方 deb-install.sh（最标准的安装路径）
  if try_official_deb_install; then
    log "[✔] 官方脚本安装完成：$(sing-box version | head -n1)"
    return 0
  fi

  # 2) 你原来的外部3源（更抗网络）
  if install_from_official_release_with_proxies "$ARCH"; then
    return 0
  fi

  # 3) 回退 raw（二进制兜底）
  if install_from_your_raw_repo "$ARCH"; then
    return 0
  fi

  log "[✖] 安装失败：官方脚本 + 外部源 + 仓库 raw 都不可用"
  exit 1
}

install_singbox

CERT_DIR="/etc/ssl/sing-box"
mkdir -p "$CERT_DIR"

get_random_port() {
  while :; do
    local PORT=$((RANDOM%50000+10000))
    ss -tuln | grep -q ":$PORT" || { echo "$PORT"; return; }
  done
}

# --------- 证书：域名模式 / 自签模式 ---------
if [[ "$MODE" == "1" ]]; then
  while true; do
    read -rp "请输入你的域名 (例如: example.com): " DOMAIN
    [[ -z "$DOMAIN" ]] && { log "[!] 域名不能为空"; continue; }

    DOMAIN_IPV4="$(dig +short A "$DOMAIN" | tail -n1 || true)"
    DOMAIN_IPV6="$(dig +short AAAA "$DOMAIN" | tail -n1 || true)"
    log "[✔] 域名解析检查完成 (IPv4: ${DOMAIN_IPV4:-无}, IPv6: ${DOMAIN_IPV6:-无})"
    break
  done

  if ! command -v acme.sh >/dev/null 2>&1; then
    log ">>> 安装 acme.sh ..."
    curl -fsSL https://get.acme.sh | sh
    source ~/.bashrc || true
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

  LE_CERT_PATH="$HOME/.acme.sh/${DOMAIN}_ecc/fullchain.cer"
  LE_KEY_PATH="$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key"

  if [[ -f "$LE_CERT_PATH" && -f "$LE_KEY_PATH" ]]; then
    log "[✔] 已检测到现有 Let's Encrypt 证书，直接导入"
    cp "$LE_CERT_PATH" "$CERT_DIR/fullchain.pem"
    cp "$LE_KEY_PATH" "$CERT_DIR/privkey.pem"
    chmod 644 "$CERT_DIR"/*.pem
  else
    log ">>> 申请新的 Let's Encrypt TLS 证书"

    if [[ -n "${SERVER_IPV4:-}" ]]; then
      USE_LISTEN="--listen-v4"
    elif [[ -n "${SERVER_IPV6:-}" ]]; then
      USE_LISTEN="--listen-v6"
    else
      log "[✖] 未检测到可用 IPv4 或 IPv6，无法申请证书"
      exit 1
    fi

    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone $USE_LISTEN --keylength ec-256 --force
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --ecc \
      --key-file "$CERT_DIR/privkey.pem" \
      --fullchain-file "$CERT_DIR/fullchain.pem" \
      --force
    chmod 644 "$CERT_DIR"/*.pem
    log "[✔] TLS 证书申请完成"
  fi
else
  DOMAIN="www.epple.com"
  log "[!] 自签模式，将生成固定域名 $DOMAIN 的自签证书"

  SAN="DNS:$DOMAIN"
  [[ -n "${SERVER_IPV4:-}" ]] && SAN+=",IP:$SERVER_IPV4"
  [[ -n "${SERVER_IPV6:-}" ]] && SAN+=",IP:$SERVER_IPV6"

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName = $SAN"
  chmod 644 "$CERT_DIR"/*.pem
  log "[✔] 自签证书生成完成（SAN: $SAN）"
fi

# --------- 输入端口 ---------
read -rp "请输入 VLESS TCP TLS 端口 (默认 443, 输入0随机): " VLESS_PORT
[[ -z "${VLESS_PORT:-}" || "$VLESS_PORT" == "0" ]] && VLESS_PORT=$(get_random_port)

read -rp "请输入 VLESS REALITY 端口 (默认 0 随机): " VLESS_R_PORT
[[ -z "${VLESS_R_PORT:-}" || "$VLESS_R_PORT" == "0" ]] && VLESS_R_PORT=$(get_random_port)

read -rp "请输入 Hysteria2 UDP 端口 (默认 8443, 输入0随机): " HY2_PORT
[[ -z "${HY2_PORT:-}" || "$HY2_PORT" == "0" ]] && HY2_PORT=$(get_random_port)

# IPv6 端口（独立）
VLESS6_PORT=$(get_random_port)
VLESS_R6_PORT=$(get_random_port)
HY2_6_PORT=$(get_random_port)

UUID="$(cat /proc/sys/kernel/random/uuid)"
HY2_PASS="$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 24)"

# --------- REALITY 参数 ---------
read -rp "REALITY 伪装站点(Handshake server) [默认: www.speedtest.net]: " REALITY_SERVER
REALITY_SERVER=${REALITY_SERVER:-www.speedtest.net}
read -rp "REALITY SNI(server_name) [默认同上]: " REALITY_SNI
REALITY_SNI=${REALITY_SNI:-$REALITY_SERVER}

REALITY_KEYPAIR="$(sing-box generate reality-keypair)"
REALITY_PRIVATE_KEY="$(echo "$REALITY_KEYPAIR" | awk '/PrivateKey/ {print $2}')"
REALITY_PUBLIC_KEY="$(echo "$REALITY_KEYPAIR" | awk '/PublicKey/ {print $2}')"
REALITY_SHORT_ID="$(openssl rand -hex 8)"

# --------- 生成 sing-box 配置（严格 JSON） ---------
mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "listen": "0.0.0.0",
      "listen_port": $VLESS_PORT,
      "users": [{ "uuid": "$UUID" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": $VLESS6_PORT,
      "users": [{ "uuid": "$UUID" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "vless",
      "listen": "0.0.0.0",
      "listen_port": $VLESS_R_PORT,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["$REALITY_SHORT_ID"]
        }
      }
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": $VLESS_R6_PORT,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": ["$REALITY_SHORT_ID"]
        }
      }
    },
    {
      "type": "hysteria2",
      "listen": "0.0.0.0",
      "listen_port": $HY2_PORT,
      "users": [{ "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    },
    {
      "type": "hysteria2",
      "listen": "::",
      "listen_port": $HY2_6_PORT,
      "users": [{ "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF
log "[✔] sing-box 配置生成完成：/etc/sing-box/config.json"

# --------- systemd 服务 ---------
if [[ ! -f /etc/systemd/system/sing-box.service ]]; then
  cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload

# --------- 防火墙端口 ---------
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow "${VLESS_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${VLESS6_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${VLESS_R_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${VLESS_R6_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${HY2_PORT}/udp" >/dev/null 2>&1 || true
  ufw allow "${HY2_6_PORT}/udp" >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
fi

# --------- 启动 ---------
systemctl enable sing-box >/dev/null 2>&1 || true
systemctl restart sing-box
sleep 2

log "=================== 服务状态 ==================="
systemctl --no-pager -l status sing-box || true

log "\n=================== sing-box 监听端口状态 ==================="
check_port() {
  local name="$1"
  local ipver="$2"
  local proto="$3"
  local port="$4"

  [[ -z "${port:-}" ]] && return 0

  if [[ "$proto" == "tcp" ]]; then
    if ss -tlnp 2>/dev/null | grep -qE "LISTEN.*:${port}\b.*sing-box"; then
      echo "[✔️] ${name} ${ipver} (TCP/${port}) 已监听"
    else
      echo "[❌] ${name} ${ipver} (TCP/${port}) 未监听"
    fi
  else
    if ss -ulnp 2>/dev/null | grep -qE ":${port}\b.*sing-box"; then
      echo "[✔️] ${name} ${ipver} (UDP/${port}) 已监听"
    else
      echo "[❌] ${name} ${ipver} (UDP/${port}) 未监听"
    fi
  fi
}

check_port "VLESS-TLS" "IPv4" "tcp" "$VLESS_PORT"
check_port "VLESS-TLS" "IPv6" "tcp" "$VLESS6_PORT"
echo
check_port "VLESS-REALITY" "IPv4" "tcp" "$VLESS_R_PORT"
check_port "VLESS-REALITY" "IPv6" "tcp" "$VLESS_R6_PORT"
echo
check_port "Hysteria2" "IPv4" "udp" "$HY2_PORT"
check_port "Hysteria2" "IPv6" "udp" "$HY2_6_PORT"

# --------- 生成节点 URI（按实际拥有的 IP 输出：有啥输出啥） ---------
SUB_FILE="/root/singbox_nodes.txt"
: > "$SUB_FILE"

print_nodes() {
  local TAG="$1"
  local HOST_RAW="$2"
  local HOST_BR="$3"
  local VP="$4"
  local RP="$5"
  local HP="$6"
  local INS="$7"

  local VLESS_URI_LOCAL="vless://$UUID@$HOST_BR:$VP?encryption=none&security=tls&sni=$DOMAIN&allowInsecure=$INS&type=tcp#VLESS-TLS-${TAG}-${HOST_RAW}"
  local VLESS_REALITY_URI_LOCAL="vless://$UUID@$HOST_BR:$RP?encryption=none&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SHORT_ID&type=tcp&flow=xtls-rprx-vision#VLESS-REALITY-${TAG}-${HOST_RAW}"
  local HY2_URI_LOCAL="hysteria2://$HY2_PASS@$HOST_BR:$HP?insecure=$INS&sni=$DOMAIN#HY2-${TAG}-${HOST_RAW}"

  log "\n=================== [$TAG] VLESS-TLS ==================="
  echo "$VLESS_URI_LOCAL"
  command -v qrencode >/dev/null 2>&1 && echo "$VLESS_URI_LOCAL" | qrencode -t ansiutf8 || true

  log "\n=================== [$TAG] VLESS-REALITY ==================="
  echo "$VLESS_REALITY_URI_LOCAL"
  command -v qrencode >/dev/null 2>&1 && echo "$VLESS_REALITY_URI_LOCAL" | qrencode -t ansiutf8 || true

  log "\n=================== [$TAG] Hysteria2 ==================="
  echo "$HY2_URI_LOCAL"
  command -v qrencode >/dev/null 2>&1 && echo "$HY2_URI_LOCAL" | qrencode -t ansiutf8 || true

  {
    echo ""
    echo "# ===== ${TAG} ====="
    echo "$VLESS_URI_LOCAL"
    echo "$VLESS_REALITY_URI_LOCAL"
    echo "$HY2_URI_LOCAL"
  } >> "$SUB_FILE"
}

if [[ "$MODE" == "1" ]]; then
  print_nodes "DOMAIN-V4PORT" "$DOMAIN" "$DOMAIN" "$VLESS_PORT" "$VLESS_R_PORT" "$HY2_PORT" "0"
  print_nodes "DOMAIN-V6PORT" "$DOMAIN" "$DOMAIN" "$VLESS6_PORT" "$VLESS_R6_PORT" "$HY2_6_PORT" "0"
else
  any=0
  if [[ -n "${SERVER_IPV4:-}" ]]; then
    print_nodes "V4" "$SERVER_IPV4" "$SERVER_IPV4" "$VLESS_PORT" "$VLESS_R_PORT" "$HY2_PORT" "1"
    any=1
  fi
  if [[ -n "${SERVER_IPV6:-}" ]]; then
    print_nodes "V6" "$SERVER_IPV6" "[$SERVER_IPV6]" "$VLESS6_PORT" "$VLESS_R6_PORT" "$HY2_6_PORT" "1"
    any=1
  fi
  if [[ "$any" -eq 0 ]]; then
    log "[✖] 未检测到可用公网 IP，无法生成节点链接"
    exit 1
  fi
fi

log "\n=================== 订阅文件内容 ==================="
cat "$SUB_FILE"
log "\n订阅文件已保存到：$SUB_FILE"
log "\n=================== 部署完成 ==================="
