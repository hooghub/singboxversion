#!/bin/bash

# ⚠️ 免责声明：
# 本脚本仅供学习与技术研究使用。
# 使用本脚本造成的任何后果（包括但不限于法律风险、服务器封禁、
# 网络中断、数据丢失等）均由使用者自行承担。
# 请确保你的使用行为符合当地法律法规。

# Sing-box 一键部署脚本
# 完整修正版
#
# 特性：
# - IPv4 / IPv6 双栈
# - IPv6-only 友好
# - sing-box 安装：官方 deb-install.sh -> 官方 release 多源 -> raw 备用
# - acme.sh：自有镜像优先 -> 官方 archive
# - Let's Encrypt / 自签证书
# - VLESS-TLS
# - VLESS-REALITY
# - Hysteria2
# - 自动生成节点 URI
# - 自动生成二维码
# - 自动生成订阅文件
#
# 支持模式：
# 1) 域名 + Let's Encrypt
# 2) 公网 IP + 自签固定域名 kyn.com
#
# 注意：
# - 模式2自签：
#   VLESS-TLS 使用 allowInsecure=1
#   Hysteria2 使用 insecure=1
# - IPv6-only 客户端必须具备 IPv6 网络

set -euo pipefail

log() {
  echo -e "$*"
}

echo "=================== Sing-box 部署前环境检查 ==================="

# ============================================================
# 检查 root
# ============================================================

if [[ ${EUID:-1} -ne 0 ]]; then
  log "[✖] 请用 root 权限运行"
  exit 1
fi

log "[✔] Root 权限 OK"

# ============================================================
# 检测公网 IPv4
# ============================================================

SERVER_IPV4="$(
  curl -4 -s --max-time 3 ipv4.icanhazip.com 2>/dev/null ||
  curl -4 -s --max-time 3 ifconfig.me 2>/dev/null ||
  true
)"

# ============================================================
# 检测公网 IPv6
# ============================================================

SERVER_IPV6=""

if curl -6 -s --max-time 3 ipv6.icanhazip.com >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
elif curl -6 -s --max-time 3 ifconfig.me >/tmp/ipv6 2>/dev/null; then
  SERVER_IPV6="$(cat /tmp/ipv6)"
fi

rm -f /tmp/ipv6 2>/dev/null || true

if [[ -n "$SERVER_IPV4" ]]; then
  echo "[✔] 检测到公网 IPv4: $SERVER_IPV4"
else
  echo "[✖] 未检测到公网 IPv4"
fi

if [[ -n "$SERVER_IPV6" ]]; then
  echo "[✔] 检测到公网 IPv6: $SERVER_IPV6"
else
  echo "[!] 未检测到公网 IPv6（可忽略）"
fi

# ============================================================
# 自动安装依赖
# ============================================================

REQUIRED_CMDS=(
  curl
  ss
  openssl
  dig
  systemctl
  bash
  socat
  cron
  ufw
  qrencode
  tar
)

PKG_MGR=""

if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MGR="yum"
else
  log "[✖] 未找到支持的包管理器（apt/yum/dnf）"
  exit 1
fi

MISSING_CMDS=()

for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
done

if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then

  log "[!] 检测到缺失命令: ${MISSING_CMDS[*]}"
  log "[!] 使用包管理器: $PKG_MGR"
  log "[!] 自动安装依赖中..."

  declare -A PKGS=()

  add_pkg() {
    PKGS["$1"]=1
  }

  for cmd in "${MISSING_CMDS[@]}"; do

    case "$PKG_MGR" in

      apt)
        case "$cmd" in
          dig)
            add_pkg "dnsutils"
            ;;
          ss)
            add_pkg "iproute2"
            ;;
          cron)
            add_pkg "cron"
            ;;
          qrencode)
            add_pkg "qrencode"
            ;;
          *)
            add_pkg "$cmd"
            ;;
        esac
        ;;

      yum|dnf)
        case "$cmd" in
          dig)
            add_pkg "bind-utils"
            ;;
          ss)
            add_pkg "iproute"
            ;;
          cron)
            add_pkg "cronie"
            ;;
          *)
            add_pkg "$cmd"
            ;;
        esac
        ;;

    esac

  done

  INSTALL_PACKAGES=()

  for pkg in "${!PKGS[@]}"; do
    INSTALL_PACKAGES+=("$pkg")
  done

  case "$PKG_MGR" in

    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive \
        apt-get install -y "${INSTALL_PACKAGES[@]}"
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

  POST_MISSING=()

  for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 ||
      POST_MISSING+=("$cmd")
  done

  if [[ ${#POST_MISSING[@]} -gt 0 ]]; then

    log "[✖] 安装后仍缺少命令: ${POST_MISSING[*]}"

    log "[!] 某些系统仓库可能没有对应软件包。"
    log "[!] 例如部分 RHEL 系统没有 ufw。"
    log "[!] 请手动安装缺失组件，或者改用 firewalld。"

    exit 1
  fi

else

  log "[✔] 依赖齐全，无需安装。"

fi

# ============================================================
# 检查常用端口
# ============================================================

for port in 80 443; do

  if ss -tuln | grep -q ":$port"; then
    log "[!] 端口 $port 当前已被占用"
  else
    log "[✔] 端口 $port 空闲"
  fi

done

# ============================================================
# 用户确认
# ============================================================

read -rp \
  "环境检查完成 ✅  确认继续执行部署吗？(y/N): " \
  CONFIRM

[[ "$CONFIRM" =~ ^[Yy]$ ]] || exit 0

# ============================================================
# 模式选择
# ============================================================

while true; do

  log ""
  log "请选择部署模式："
  log "1) 使用域名 + Let's Encrypt 证书"
  log "2) 使用公网 IP + 自签固定域名 kyn.com"

  read -rp "请输入选项 (1 或 2): " MODE

  if [[ "$MODE" =~ ^[12]$ ]]; then
    break
  fi

  log "[!] 输入错误，请重新输入 1 或 2"

done

# ============================================================
# 下载函数
# IPv6 优先 -> IPv4
# 多 URL 回退
# ============================================================

download_with_fallback() {

  local out="$1"
  shift

  local url

  for url in "$@"; do

    log ">>> 尝试下载: $url"

    if curl -6 -fL \
      --retry 2 \
      --retry-delay 1 \
      --connect-timeout 6 \
      --max-time 180 \
      "$url" \
      -o "$out" 2>/dev/null; then

      return 0

    fi

    if curl -4 -fL \
      --retry 2 \
      --retry-delay 1 \
      --connect-timeout 6 \
      --max-time 180 \
      "$url" \
      -o "$out" 2>/dev/null; then

      return 0

    fi

    log "[!] 下载失败，换下一个源..."

  done

  return 1
}

# ============================================================
# 检测 CPU 架构
# ============================================================

detect_arch() {

  case "$(uname -m)" in

    x86_64|amd64)
      echo "amd64"
      ;;

    aarch64|arm64)
      echo "arm64"
      ;;

    *)
      echo ""
      ;;

  esac

}

# ============================================================
# 官方 deb-install.sh
# ============================================================

try_official_deb_install() {

  command -v apt-get >/dev/null 2>&1 || return 1
  command -v curl >/dev/null 2>&1 || return 1
  command -v bash >/dev/null 2>&1 || return 1

  command -v sing-box >/dev/null 2>&1 && return 0

  log ">>> 尝试官方安装脚本："
  log "https://sing-box.app/deb-install.sh"

  if bash <(
    curl -fsSL https://sing-box.app/deb-install.sh
  ); then
    :
  else
    log "[!] 官方 deb-install.sh 执行失败"
    log "[!] 进入多源下载兜底..."
  fi

  command -v sing-box >/dev/null 2>&1
}

# ============================================================
# 官方 release 多源安装
# ============================================================

install_from_official_release_with_proxies() {

  local ARCH="$1"

  local ORI
  ORI="https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-${ARCH}.tar.gz"

  local SRC1
  SRC1="https://v6.gh-proxy.org/${ORI}"

  local SRC2
  SRC2="https://mirror.ghproxy.com/${ORI}"

  local SRC3
  SRC3="${ORI}"

  local TGZ="/tmp/sing-box.tgz"

  if download_with_fallback \
    "$TGZ" \
    "$SRC1" \
    "$SRC2" \
    "$SRC3"; then

    log "[✔] 官方 release 下载成功"
    log "[>] 开始安装..."

    rm -rf /tmp/sing-box-* 2>/dev/null || true

    tar -xzf "$TGZ" -C /tmp

    local BIN_PATH

    BIN_PATH="$(
      find /tmp \
        -maxdepth 3 \
        -type f \
        -name sing-box \
        -perm -u+x \
        2>/dev/null |
      head -n1 ||
      true
    )"

    if [[ -z "$BIN_PATH" ]]; then
      log "[✖] 解压后未找到 sing-box 二进制"
      return 1
    fi

    install -m 755 \
      "$BIN_PATH" \
      /usr/local/bin/sing-box

    log "[✔] sing-box 安装完成："
    /usr/local/bin/sing-box version | head -n1

    return 0

  fi

  return 1
}

# ============================================================
# raw 仓库备用安装
# ============================================================

install_from_your_raw_repo() {

  local ARCH="$1"

  log "[!] 外部源全部失败"
  log "[!] 回退从仓库 raw 下载 sing-box..."

  local CORE_BASE
  CORE_BASE="https://raw.githubusercontent.com/hooghub/singboxversion/main/bin"

  local CORE_URL
  CORE_URL="${CORE_BASE}/sing-box-linux-${ARCH}"

  if download_with_fallback \
    "/usr/local/bin/sing-box" \
    "$CORE_URL"; then

    chmod +x /usr/local/bin/sing-box

    log -n ">>> 仓库内核版本："

    if download_with_fallback \
      /tmp/sbver \
      "${CORE_BASE}/VERSION"; then

      cat /tmp/sbver

    else

      echo "unknown"

    fi

    log "[✔] sing-box 安装完成："
    /usr/local/bin/sing-box version | head -n1

    return 0
  fi

  return 1
}

# ============================================================
# 安装 sing-box
# ============================================================

install_singbox() {

  if command -v sing-box >/dev/null 2>&1; then

    local SB_PATH
    SB_PATH="$(command -v sing-box)"

    log "[✔] sing-box 已存在："
    "$SB_PATH" version | head -n1

    return 0
  fi

  log ">>> 安装 sing-box..."
  log ">>> 官方脚本 -> 官方 release 多源 -> raw 备用"

  local ARCH
  ARCH="$(detect_arch)"

  if [[ -z "$ARCH" ]]; then
    log "[✖] 不支持的架构: $(uname -m)"
    exit 1
  fi

  # 1. 官方 deb-install.sh

  if try_official_deb_install; then

    log "[✔] 官方脚本安装完成："
    sing-box version | head -n1

    return 0
  fi

  # 2. 官方 release 多源

  if install_from_official_release_with_proxies "$ARCH"; then
    return 0
  fi

  # 3. raw 备用

  if install_from_your_raw_repo "$ARCH"; then
    return 0
  fi

  log "[✖] sing-box 安装失败"
  log "[✖] 官方脚本 + release 多源 + raw 均不可用"

  exit 1
}

install_singbox

# ============================================================
# 证书目录
# ============================================================

CERT_DIR="/etc/ssl/sing-box"

mkdir -p "$CERT_DIR"

# ============================================================
# 随机端口
# ============================================================

get_random_port() {

  while :; do

    local PORT
    PORT=$((RANDOM % 50000 + 10000))

    if ! ss -tuln | grep -q ":$PORT"; then
      echo "$PORT"
      return
    fi

  done
}

# ============================================================
# 证书处理
#
# 这里是本次修正版最重要的地方：
#
# MODE=1
#   域名 + Let's Encrypt
#
# MODE=2
#   kyn.com + 自签证书
#
# acme.sh 只在 MODE=1 中执行
# ============================================================

if [[ "$MODE" == "1" ]]; then

  # ----------------------------------------------------------
  # 模式1：域名 + Let's Encrypt
  # ----------------------------------------------------------

  while true; do

    read -rp \
      "请输入你的域名 (例如: example.com): " \
      DOMAIN

    if [[ -z "$DOMAIN" ]]; then
      log "[!] 域名不能为空"
      continue
    fi

    DOMAIN_IPV4="$(
      dig +short A "$DOMAIN" |
      tail -n1 ||
      true
    )"

    DOMAIN_IPV6="$(
      dig +short AAAA "$DOMAIN" |
      tail -n1 ||
      true
    )"

    log "[✔] 域名解析检查完成"
    log "    IPv4: ${DOMAIN_IPV4:-无}"
    log "    IPv6: ${DOMAIN_IPV6:-无}"

    break

  done

     # ----------------------------------------------------------
  # 安装 acme.sh
  # ----------------------------------------------------------

  if ! command -v acme.sh >/dev/null 2>&1 &&
     [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then

    log ">>> 安装 acme.sh ..."

    ACME_TGZ="/tmp/acme.sh.tar.gz"
    ACME_SRC="/tmp/acme.sh-src"

    rm -f "$ACME_TGZ"
    rm -rf "$ACME_SRC"

    ACME_OFFICIAL_URL="https://github.com/acmesh-official/acme.sh/archive/master.tar.gz"

    ACME_MIRROR_URL="https://raw.githubusercontent.com/hooghub/singboxversion/main/acme.sh/master.tar.gz"

    log ">>> 下载 acme.sh archive..."

    # --------------------------------------------------------
    # 官方 GitHub
    # --------------------------------------------------------

    if download_with_fallback \
      "$ACME_TGZ" \
      "$ACME_OFFICIAL_URL"; then

      log "[✔] acme.sh 官方 archive 下载成功"

    # --------------------------------------------------------
    # 自有镜像
    # --------------------------------------------------------

    elif download_with_fallback \
      "$ACME_TGZ" \
      "$ACME_MIRROR_URL"; then

      log "[✔] acme.sh 仓库镜像下载成功"

    else

      log "[✖] acme.sh 下载失败"
      log "[✖] 官方源和仓库镜像均不可用"

      exit 1

    fi

    # --------------------------------------------------------
    # 解压
    # --------------------------------------------------------

    mkdir -p "$ACME_SRC"

    if ! tar -xzf "$ACME_TGZ" \
      -C "$ACME_SRC" \
      --strip-components=1; then

      log "[✖] acme.sh archive 解压失败"
      exit 1

    fi

    # --------------------------------------------------------
    # 检查 acme.sh
    # --------------------------------------------------------

    if [[ ! -f "$ACME_SRC/acme.sh" ]]; then

      log "[✖] acme.sh archive 中未找到 acme.sh"
      exit 1

    fi

    chmod +x "$ACME_SRC/acme.sh"

    log ">>> 检测 acme.sh 版本..."

    ACME_VERSION="$(
      bash "$ACME_SRC/acme.sh" --version 2>/dev/null |
      tail -n1
    )"

    if [[ -z "$ACME_VERSION" ]]; then

      log "[✖] 无法读取 acme.sh 版本"
      exit 1

    fi

    log "[✔] 下载的 acme.sh：$ACME_VERSION"

    # --------------------------------------------------------
    # 直接安装 acme.sh
    #
    # 不使用 acme.sh --install。
    #
    # 原因：
    # 当前 archive 版 installer 内部使用：
    #
    #   cp acme.sh ...
    #
    # 它会依赖当前工作目录中的 acme.sh。
    #
    # 因此这里直接复制已经验证正常的
    # acme.sh 主程序，避免 installer 的路径问题。
    # --------------------------------------------------------

    log ">>> 使用本地 acme.sh 源码安装..."

    ACME_HOME="$HOME/.acme.sh"

    mkdir -p "$ACME_HOME"

    cp \
      "$ACME_SRC/acme.sh" \
      "$ACME_HOME/acme.sh"

    chmod 700 \
      "$ACME_HOME/acme.sh"

    # --------------------------------------------------------
    # 初始化 acme.sh home
    # --------------------------------------------------------

    export LE_WORKING_DIR="$ACME_HOME"

    # --------------------------------------------------------
    # 建立全局命令
    # --------------------------------------------------------

    ln -sf \
      "$ACME_HOME/acme.sh" \
      /usr/local/bin/acme.sh

    # --------------------------------------------------------
    # 检查安装结果
    # --------------------------------------------------------

    if [[ ! -x "$ACME_HOME/acme.sh" ]]; then

      log "[✖] acme.sh 安装后未找到："
      log "$ACME_HOME/acme.sh"

      exit 1

    fi

    if ! "$ACME_HOME/acme.sh" --version >/dev/null 2>&1; then

      log "[✖] 安装后的 acme.sh 无法执行"
      exit 1

    fi

    log "[✔] acme.sh 安装完成："
    "$ACME_HOME/acme.sh" --version

    # --------------------------------------------------------
    # 清理临时文件
    # --------------------------------------------------------

    rm -rf "$ACME_SRC"
    rm -f "$ACME_TGZ"

    source "$HOME/.bashrc" 2>/dev/null || true

  fi



    # --------------------------------------------------------
    # 检查 archive
    # --------------------------------------------------------

    if [[ ! -s "$ACME_TGZ" ]]; then

      log "[✖] acme.sh archive 文件为空"

      exit 1

    fi

    log "[✔] archive 下载完成："
    ls -lh "$ACME_TGZ"

    # --------------------------------------------------------
    # 解压
    # --------------------------------------------------------

    mkdir -p "$ACME_SRC"

    if ! tar -xzf "$ACME_TGZ" \
      -C "$ACME_SRC" \
      --strip-components=1; then

      log "[✖] acme.sh archive 解压失败"

      rm -rf "$ACME_SRC"
      rm -f "$ACME_TGZ"

      exit 1

    fi

    # --------------------------------------------------------
    # 检查 acme.sh
    # --------------------------------------------------------

    if [[ ! -f "$ACME_SRC/acme.sh" ]]; then

      log "[✖] archive 中未找到 acme.sh"

      rm -rf "$ACME_SRC"
      rm -f "$ACME_TGZ"

      exit 1

    fi

    chmod +x "$ACME_SRC/acme.sh"

    # --------------------------------------------------------
    # 显示版本
    # --------------------------------------------------------

    log ">>> 检测 acme.sh 版本..."

    ACME_VERSION="$(
      bash "$ACME_SRC/acme.sh" --version |
      tail -n1 ||
      true
    )"

    log "[✔] 下载的 acme.sh：$ACME_VERSION"

    # --------------------------------------------------------
    # 安装
    # --------------------------------------------------------

    log ">>> 使用本地 acme.sh 源码安装..."

    if ! bash "$ACME_SRC/acme.sh" \
      --install \
      --home "$ACME_HOME"; then

      log "[✖] acme.sh 安装失败"

      rm -rf "$ACME_SRC"
      rm -f "$ACME_TGZ"

      exit 1

    fi

    # --------------------------------------------------------
    # 清理临时文件
    # --------------------------------------------------------

    rm -rf "$ACME_SRC"
    rm -f "$ACME_TGZ"

    # --------------------------------------------------------
    # 检查安装结果
    # --------------------------------------------------------

    if [[ ! -x "$ACME_HOME/acme.sh" ]]; then

      log "[✖] acme.sh 安装后未找到："
      log "$ACME_HOME/acme.sh"

      exit 1

    fi

    log "[✔] acme.sh 安装成功"

  else

    log "[✔] 已存在 acme.sh："
    log "$ACME_HOME/acme.sh"

  fi

  # ----------------------------------------------------------
  # 确认 acme.sh
  # ----------------------------------------------------------

  if [[ ! -x "$ACME_HOME/acme.sh" ]]; then

    log "[✖] acme.sh 不可执行："
    log "$ACME_HOME/acme.sh"

    exit 1

  fi

  "$ACME_HOME/acme.sh" --version || {
    log "[✖] acme.sh 无法运行"
    exit 1
  }

  # ----------------------------------------------------------
  # 设置 Let's Encrypt
  # ----------------------------------------------------------

  "$ACME_HOME/acme.sh" \
    --set-default-ca \
    --server letsencrypt

  LE_CERT_PATH="$ACME_HOME/${DOMAIN}_ecc/fullchain.cer"
  LE_KEY_PATH="$ACME_HOME/${DOMAIN}_ecc/${DOMAIN}.key"

  # ----------------------------------------------------------
  # 已存在证书
  # ----------------------------------------------------------

  if [[ -f "$LE_CERT_PATH" && -f "$LE_KEY_PATH" ]]; then

    log "[✔] 已检测到现有 Let's Encrypt 证书"
    log "[>] 直接导入"

    cp \
      "$LE_CERT_PATH" \
      "$CERT_DIR/fullchain.pem"

    cp \
      "$LE_KEY_PATH" \
      "$CERT_DIR/privkey.pem"

    chmod 644 \
      "$CERT_DIR/fullchain.pem"

    chmod 600 \
      "$CERT_DIR/privkey.pem"

  else

    # --------------------------------------------------------
    # 申请新证书
    # --------------------------------------------------------

    log ">>> 申请新的 Let's Encrypt TLS 证书"

    USE_LISTEN=""

    if [[ -n "${SERVER_IPV4:-}" ]]; then

      USE_LISTEN="--listen-v4"

    elif [[ -n "${SERVER_IPV6:-}" ]]; then

      USE_LISTEN="--listen-v6"

    else

      log "[✖] 未检测到可用 IPv4 或 IPv6"
      log "[✖] 无法申请证书"

      exit 1

    fi

    "$ACME_HOME/acme.sh" \
      --issue \
      -d "$DOMAIN" \
      --standalone \
      $USE_LISTEN \
      --keylength ec-256 \
      --force

    "$ACME_HOME/acme.sh" \
      --install-cert \
      -d "$DOMAIN" \
      --ecc \
      --key-file "$CERT_DIR/privkey.pem" \
      --fullchain-file "$CERT_DIR/fullchain.pem" \
      --force

    chmod 644 \
      "$CERT_DIR/fullchain.pem"

    chmod 600 \
      "$CERT_DIR/privkey.pem"

    log "[✔] TLS 证书申请完成"

  fi

else

  # ----------------------------------------------------------
  # 模式2：公网 IP + 自签证书
  # ----------------------------------------------------------

  DOMAIN="kyn.com"

  log "[!] 自签模式"
  log "[!] 固定域名：$DOMAIN"

  SAN="DNS:$DOMAIN"

  if [[ -n "${SERVER_IPV4:-}" ]]; then
    SAN+=",IP:$SERVER_IPV4"
  fi

  if [[ -n "${SERVER_IPV6:-}" ]]; then
    SAN+=",IP:$SERVER_IPV6"
  fi

  openssl req \
    -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=$DOMAIN" \
    -addext "subjectAltName = $SAN"

  chmod 644 \
    "$CERT_DIR/fullchain.pem"

  chmod 600 \
    "$CERT_DIR/privkey.pem"

  log "[✔] 自签证书生成完成"
  log "[✔] SAN: $SAN"

fi

# ============================================================
# 输入端口
# ============================================================

read -rp \
  "请输入 VLESS TCP TLS 端口 (默认 443, 输入0随机): " \
  VLESS_PORT

if [[ -z "${VLESS_PORT:-}" || "$VLESS_PORT" == "0" ]]; then
  VLESS_PORT="$(get_random_port)"
fi

read -rp \
  "请输入 VLESS REALITY 端口 (默认 0 随机): " \
  VLESS_R_PORT

if [[ -z "${VLESS_R_PORT:-}" || "$VLESS_R_PORT" == "0" ]]; then
  VLESS_R_PORT="$(get_random_port)"
fi

read -rp \
  "请输入 Hysteria2 UDP 端口 (默认 8443, 输入0随机): " \
  HY2_PORT

if [[ -z "${HY2_PORT:-}" || "$HY2_PORT" == "0" ]]; then
  HY2_PORT="$(get_random_port)"
fi

# ============================================================
# IPv6 独立端口
# ============================================================

VLESS6_PORT="$(get_random_port)"
VLESS_R6_PORT="$(get_random_port)"
HY2_6_PORT="$(get_random_port)"

# ============================================================
# UUID / Hysteria2 密码
# ============================================================

UUID="$(cat /proc/sys/kernel/random/uuid)"

HY2_PASS="$(
  openssl rand -base64 16 |
  tr -dc 'a-zA-Z0-9' |
  head -c 24
)"

# ============================================================
# REALITY 参数
# ============================================================

read -rp \
  "REALITY 伪装站点(Handshake server) [默认: www.speedtest.net]: " \
  REALITY_SERVER

REALITY_SERVER="${REALITY_SERVER:-www.speedtest.net}"

read -rp \
  "REALITY SNI(server_name) [默认同上]: " \
  REALITY_SNI

REALITY_SNI="${REALITY_SNI:-$REALITY_SERVER}"

REALITY_KEYPAIR="$(
  sing-box generate reality-keypair
)"

REALITY_PRIVATE_KEY="$(
  echo "$REALITY_KEYPAIR" |
  awk '/PrivateKey/ {print $2}'
)"

REALITY_PUBLIC_KEY="$(
  echo "$REALITY_KEYPAIR" |
  awk '/PublicKey/ {print $2}'
)"

REALITY_SHORT_ID="$(
  openssl rand -hex 8
)"

# ============================================================
# 生成 sing-box 配置
# ============================================================

mkdir -p /etc/sing-box

cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "vless",
      "listen": "0.0.0.0",
      "listen_port": $VLESS_PORT,
      "users": [
        {
          "uuid": "$UUID"
        }
      ],
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
      "users": [
        {
          "uuid": "$UUID"
        }
      ],
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
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": [
            "$REALITY_SHORT_ID"
          ]
        }
      }
    },
    {
      "type": "vless",
      "listen": "::",
      "listen_port": $VLESS_R6_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_SERVER",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": [
            "$REALITY_SHORT_ID"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "listen": "0.0.0.0",
      "listen_port": $HY2_PORT,
      "users": [
        {
          "password": "$HY2_PASS"
        }
      ],
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
      "users": [
        {
          "password": "$HY2_PASS"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_DIR/fullchain.pem",
        "key_path": "$CERT_DIR/privkey.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
EOF

log "[✔] sing-box 配置生成完成：/etc/sing-box/config.json"

# ============================================================
# 检查 sing-box 配置
# ============================================================

if ! sing-box check -c /etc/sing-box/config.json; then
  log "[✖] sing-box 配置检查失败"
  exit 1
fi

log "[✔] sing-box 配置检查通过"

# ============================================================
# systemd 服务
# ============================================================

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

# ============================================================
# 防火墙
# ============================================================

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

# ============================================================
# 启动 sing-box
# ============================================================

systemctl enable sing-box >/dev/null 2>&1 || true

systemctl restart sing-box

sleep 8

# ============================================================
# 服务状态
# ============================================================

log ""
log "=================== 服务状态 ==================="

systemctl --no-pager -l status sing-box || true

# ============================================================
# 监听端口检查
# ============================================================

log ""
log "=================== sing-box 监听端口状态 ==================="

check_port() {

  local name="$1"
  local ipver="$2"
  local proto="$3"
  local port="$4"

  [[ -z "${port:-}" ]] && return 0

  if [[ "$proto" == "tcp" ]]; then

    if ss -tlnp 2>/dev/null |
      grep -qE "LISTEN.*:${port}\b.*sing-box"; then

      echo "[✔️] ${name} ${ipver} (TCP/${port}) 已监听"

    else

      echo "[❌] ${name} ${ipver} (TCP/${port}) 未监听"

    fi

  else

    if ss -ulnp 2>/dev/null |
      grep -qE ":${port}\b.*sing-box"; then

      echo "[✔️] ${name} ${ipver} (UDP/${port}) 已监听"

    else

      echo "[❌] ${name} ${ipver} (UDP/${port}) 未监听"

    fi

  fi
}

check_port \
  "VLESS-TLS" \
  "IPv4" \
  "tcp" \
  "$VLESS_PORT"

check_port \
  "VLESS-TLS" \
  "IPv6" \
  "tcp" \
  "$VLESS6_PORT"

echo

check_port \
  "VLESS-REALITY" \
  "IPv4" \
  "tcp" \
  "$VLESS_R_PORT"

check_port \
  "VLESS-REALITY" \
  "IPv6" \
  "tcp" \
  "$VLESS_R6_PORT"

echo

check_port \
  "Hysteria2" \
  "IPv4" \
  "udp" \
  "$HY2_PORT"

check_port \
  "Hysteria2" \
  "IPv6" \
  "udp" \
  "$HY2_6_PORT"

# ============================================================
# 生成节点 URI
# ============================================================

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

  local VLESS_URI_LOCAL

  VLESS_URI_LOCAL="vless://${UUID}@${HOST_BR}:${VP}?encryption=none&security=tls&sni=${DOMAIN}&allowInsecure=${INS}&type=tcp#VLESS-TLS-${TAG}-${HOST_RAW}"

  local VLESS_REALITY_URI_LOCAL

  VLESS_REALITY_URI_LOCAL="vless://${UUID}@${HOST_BR}:${RP}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&flow=xtls-rprx-vision#VLESS-REALITY-${TAG}-${HOST_RAW}"

  local HY2_URI_LOCAL

  HY2_URI_LOCAL="hysteria2://${HY2_PASS}@${HOST_BR}:${HP}?insecure=${INS}&sni=${DOMAIN}#HY2-${TAG}-${HOST_RAW}"

  # ----------------------------------------------------------
  # VLESS-TLS
  # ----------------------------------------------------------

  log ""
  log "=================== [$TAG] VLESS-TLS ==================="

  echo "$VLESS_URI_LOCAL"

  if command -v qrencode >/dev/null 2>&1; then
    echo "$VLESS_URI_LOCAL" |
      qrencode -t ansiutf8 ||
      true
  fi

  # ----------------------------------------------------------
  # VLESS-REALITY
  # ----------------------------------------------------------

  log ""
  log "=================== [$TAG] VLESS-REALITY ==================="

  echo "$VLESS_REALITY_URI_LOCAL"

  if command -v qrencode >/dev/null 2>&1; then
    echo "$VLESS_REALITY_URI_LOCAL" |
      qrencode -t ansiutf8 ||
      true
  fi

  # ----------------------------------------------------------
  # Hysteria2
  # ----------------------------------------------------------

  log ""
  log "=================== [$TAG] Hysteria2 ==================="

  echo "$HY2_URI_LOCAL"

  if command -v qrencode >/dev/null 2>&1; then
    echo "$HY2_URI_LOCAL" |
      qrencode -t ansiutf8 ||
      true
  fi

  # ----------------------------------------------------------
  # 写入订阅文件
  # ----------------------------------------------------------

  {
    echo ""
    echo "# ===== ${TAG} ====="
    echo "$VLESS_URI_LOCAL"
    echo "$VLESS_REALITY_URI_LOCAL"
    echo "$HY2_URI_LOCAL"
  } >> "$SUB_FILE"
}

# ============================================================
# 模式1：域名
# ============================================================

if [[ "$MODE" == "1" ]]; then

  print_nodes \
    "DOMAIN-V4PORT" \
    "$DOMAIN" \
    "$DOMAIN" \
    "$VLESS_PORT" \
    "$VLESS_R_PORT" \
    "$HY2_PORT" \
    "0"

  print_nodes \
    "DOMAIN-V6PORT" \
    "$DOMAIN" \
    "$DOMAIN" \
    "$VLESS6_PORT" \
    "$VLESS_R6_PORT" \
    "$HY2_6_PORT" \
    "0"

# ============================================================
# 模式2：公网 IP
# ============================================================

else

  any=0

  if [[ -n "${SERVER_IPV4:-}" ]]; then

    print_nodes \
      "V4" \
      "$SERVER_IPV4" \
      "$SERVER_IPV4" \
      "$VLESS_PORT" \
      "$VLESS_R_PORT" \
      "$HY2_PORT" \
      "1"

    any=1

  fi

  if [[ -n "${SERVER_IPV6:-}" ]]; then

    print_nodes \
      "V6" \
      "$SERVER_IPV6" \
      "[$SERVER_IPV6]" \
      "$VLESS6_PORT" \
      "$VLESS_R6_PORT" \
      "$HY2_6_PORT" \
      "1"

    any=1

  fi

  if [[ "$any" -eq 0 ]]; then

    log "[✖] 未检测到可用公网 IP"
    log "[✖] 无法生成节点链接"

    exit 1

  fi

fi

# ============================================================
# 输出订阅文件
# ============================================================

log ""
log "=================== 订阅文件内容 ==================="

cat "$SUB_FILE"

log ""
log "订阅文件已保存到：$SUB_FILE"

log ""
log "=================== 部署完成 ==================="

log ""
log "VLESS-TLS IPv4 端口：$VLESS_PORT"
log "VLESS-TLS IPv6 端口：$VLESS6_PORT"

log ""
log "VLESS-REALITY IPv4 端口：$VLESS_R_PORT"
log "VLESS-REALITY IPv6 端口：$VLESS_R6_PORT"

log ""
log "Hysteria2 IPv4 端口：$HY2_PORT"
log "Hysteria2 IPv6 端口：$HY2_6_PORT"

log ""
log "UUID：$UUID"

log ""
log "REALITY SNI：$REALITY_SNI"
log "REALITY Server：$REALITY_SERVER"
log "REALITY PublicKey：$REALITY_PUBLIC_KEY"
log "REALITY ShortID：$REALITY_SHORT_ID"

log ""
log "订阅文件：$SUB_FILE"
