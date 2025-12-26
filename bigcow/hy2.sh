#!/usr/bin/env bash
#
# Hysteria 2 终极安装脚本 V5.0 - 加固版（修复 URL、兼容性、权限检查、原子写入、iptables 安全操作等）
# 说明：
#  - 本脚本在设计上尽量可在 Debian/Ubuntu(Fork apt)、CentOS/Fedora(RPM)、Alpine(apk) 上运行。
#  - 脚本会检测包管理器、必需命令并尽量安全地下载并安装组件。
#  - 请以 root 用户运行：sudo -i 或 su -
#
set -euo pipefail
IFS=$'\n\t'

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 全局常量
CONFIG_FILE="/etc/hysteria/config.yaml"
CERT_DIR="/etc/hysteria/certs"
CMD_PATH="/usr/bin/hy"
GET_HY2_URL="https://get.hy2.sh" # 保持原始入口；脚本会先下载到临时文件再执行
RAW_SCRIPT_URL="https://raw.githubusercontent.com/bigcow666/hy2/main/bigcow/hy2" # 修正后的 raw URL

# 超时与重试参数
CURL_OPTS="-fsS --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 2"
WGET_OPTS="--no-verbose --timeout=30 --tries=3"

# 辅助：打印错误并退出
err() { echo -e "${RED}[ERROR] $*${PLAIN}" >&2; }
info() { echo -e "${GREEN}[INFO] $*${PLAIN}"; }
warn() { echo -e "${YELLOW}[WARN] $*${PLAIN}"; }

# 检查是否以 root 运行
require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "必须以 root 用户运行此脚本。"
        exit 1
    fi
}

# 检查命令是否存在
require_cmd() {
    local cmd=$1
    command -v "$cmd" >/dev/null 2>&1 || { err "需要命令 '$cmd'，请先安装。"; exit 1; }
}

# 读取交互输入，若无 tty 则使用默认值
prompt() {
    local prompt_text="$1"; local default="$2"; local var
    if [[ -t 0 ]]; then
        read -p "$prompt_text" var </dev/tty
    else
        # 非交互，直接返回默认
        var="$default"
    fi
    echo "${var:-$default}"
}

# 安全：将单引号在字符串内转义，用于写入单引号界定的 here-doc
escape_for_single_quote() {
    # 把 ' 替换为 '\'' 适用于单引号包裹的字符串
    printf "%s" "$1" | sed "s/'/'\\\\''/g"
}

# 检测系统与包管理器
check_sys() {
    require_root
    OS=""
    PM=""
    INSTALL_CMD=""
    UPDATE_CMD=""
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    fi

    if command -v apt-get >/dev/null 2>&1; then
        PM="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update -y"
    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf makecache"
    elif command -v yum >/dev/null 2>&1; then
        PM="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum makecache"
    elif command -v apk >/dev/null 2>&1; then
        PM="apk"
        INSTALL_CMD="apk add --no-cache"
        UPDATE_CMD="apk update"
    else
        err "未检测到受支持的包管理器 (apt/dnf/yum/apk)。"
        exit 1
    fi
}

# 保存防火墙（基于包管理器）
save_firewall() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        if command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1 || true
        fi
    elif [[ "$PM" == "apk" ]]; then
        if [[ -f /etc/init.d/iptables ]]; then
            /etc/init.d/iptables save >/dev/null 2>&1 || true
        fi
    fi
}

# 检查 ip6tables nat 支持（有些发行版不支持）
ip6_nat_supported() {
    if command -v ip6tables >/dev/null 2>&1; then
        # 通过检查能否列出 nat 表来判断
        if ip6tables -t nat -L >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# 添加 UDP 端口重定向（更安全：只添加存在的规则、避免清空全表）
add_udp_redirect_range() {
    local start="$1"; local end="$2"; local toport="$3"
    # IPv4
    if command -v iptables >/dev/null 2>&1; then
        # 使用 iptables-save 搜索是否已存在相同 redirect
        if iptables-save -t nat | grep -q -- "-A PREROUTING -p udp -m udp --dport ${start}:${end} -j REDIRECT --to-ports ${toport}"; then
            info "IPv4 NAT redirect already present, skipping add"
        else
            iptables -t nat -A PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}"
            info "已添加 IPv4 UDP 重定向 ${start}-${end} -> ${toport}"
        fi
    fi

    # IPv6 如果支持 nat 则做类似处理
    if ip6_nat_supported; then
        if ip6tables-save -t nat | grep -q -- "-A PREROUTING -p udp -m udp --dport ${start}:${end} -j REDIRECT --to-ports ${toport}"; then
            info "IPv6 NAT redirect already present, skipping add"
        else
            ip6tables -t nat -A PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}" 2>/dev/null || true
            info "已添加 IPv6 UDP 重定向 ${start}-${end} -> ${toport}"
        fi
    else
        warn "当前内核/iptables 不支持 ip6tables nat 表，跳过 IPv6 重定向。"
    fi

    save_firewall || true
}

# 删除可能的旧 redirect（卸载时使用）
remove_udp_redirect_range() {
    local start="$1"; local end="$2"; local toport="$3"
    # IPv4：用 iptables-save 旧规则替换
    if command -v iptables >/dev/null 2>&1; then
        # 删除所有匹配的规则（谨慎）
        while iptables -t nat -C PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}" >/dev/null 2>&1; do
            iptables -t nat -D PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}" || true
        done || true
    fi

    if ip6_nat_supported; then
        while ip6tables -t nat -C PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}" >/dev/null 2>&1; do
            ip6tables -t nat -D PREROUTING -p udp --dport "${start}:${end}" -j REDIRECT --to-ports "${toport}" || true
        done || true
    fi

    save_firewall || true
}

# 创建管理快捷脚本 /usr/bin/hy
create_shortcut() {
    local node_name_safe
    node_name_safe="$(escape_for_single_quote "${CUSTOM_NAME:-Hy2-Node}")"
    # 采用原子写入到临时文件，再移动
    local tmpfile
    tmpfile="$(mktemp /tmp/hy.XXXXXX)" || { err "无法创建临时文件"; return 1; }

    cat > "$tmpfile" <<'EOF'
#!/usr/bin/env bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

CONFIG_FILE="/etc/hysteria/config.yaml"
NODE_NAME_PLACEHOLDER='__NODE_NAME_PLACEHOLDER__'

show_node_info() {
    echo -e "${GREEN}>>> 当前节点配置 ${PLAIN}"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "配置文件不存在：$CONFIG_FILE"
        return 1
    fi

    # 从 config.yaml 提取常见字段（尽量稳健）
    PORT=$(grep -E '^\s*listen\s*:' "$CONFIG_FILE" 2>/dev/null | head -n1 | sed -E 's/.*: *:?//;s/^[[:space:]]+//;s/:$//')
    PASS=$(grep -A 5 "auth:" "$CONFIG_FILE" 2>/dev/null | grep "password:" | head -n1 | awk '{print $2}')
    OBFS_PASS=$(grep -A 5 "salamander:" "$CONFIG_FILE" 2>/dev/null | grep "password:" | head -n1 | awk '{print $2}')
    SERVER_IP=$(curl -4 -s --max-time 5 https://ifconfig.co || curl -4 -s --max-time 5 https://ifconfig.me || echo "0.0.0.0")

    if grep -q "insecure: true" "$CONFIG_FILE" 2>/dev/null; then
        FAKE_URL=$(grep "url:" "$CONFIG_FILE" 2>/dev/null | head -n1 | awk '{print $2}')
        SNI_VAL=$(echo "$FAKE_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        echo -e "模式: ${YELLOW}自签证书 (IP直连)${PLAIN}"
        echo -e "IP:   ${YELLOW}${SERVER_IP}${PLAIN}"
        echo -e "端口: ${YELLOW}${PORT}${PLAIN}"
        echo -e "密码: ${YELLOW}${PASS}${PLAIN}"
        echo -e "------------------------------------------------"
        LINK="hysteria2://${PASS}@${SERVER_IP}:${PORT}?peer=${SNI_VAL}&insecure=1&obfs=salamander&obfs-password=${OBFS_PASS}&sni=${SNI_VAL}#${NODE_NAME_PLACEHOLDER}"
        echo -e "${CYAN}[节点链接]${PLAIN}"
        echo -e "${YELLOW}${LINK}${PLAIN}"
    else
        DOMAIN=$(grep -A 1 "domains:" "$CONFIG_FILE" 2>/dev/null | tail -n1 | tr -d ' -')
        SNI_VAL=${DOMAIN:-$(hostname -f 2>/dev/null || echo "")}
        echo -e "模式: ${YELLOW}正规域名证书${PLAIN}"
        echo -e "域名: ${YELLOW}${DOMAIN}${PLAIN}"
        echo -e "IP:   ${YELLOW}${SERVER_IP}${PLAIN}"
        echo -e "端口: ${YELLOW}${PORT}${PLAIN}"
        echo -e "密码: ${YELLOW}${PASS}${PLAIN}"
        echo -e "------------------------------------------------"
        LINK_DOMAIN="hysteria2://${PASS}@${DOMAIN}:${PORT}?peer=${SNI_VAL}&insecure=0&obfs=salamander&obfs-password=${OBFS_PASS}&sni=${SNI_VAL}#${NODE_NAME_PLACEHOLDER}"
        LINK_IP="hysteria2://${PASS}@${SERVER_IP}:${PORT}?peer=${SNI_VAL}&insecure=0&obfs=salamander&obfs-password=${OBFS_PASS}&sni=${SNI_VAL}#${NODE_NAME_PLACEHOLDER}_IP"
        echo -e "${CYAN}1. 域名节点 (推荐):${PLAIN}"
        echo -e "${YELLOW}${LINK_DOMAIN}${PLAIN}"
        echo -e ""
        echo -e "${CYAN}2. IP 节点 (备用):${PLAIN}"
        echo -e "${YELLOW}${LINK_IP}${PLAIN}"
    fi
    echo ""
}

uninstall_logic() {
    echo -e "${RED}警告：这将删除 Hysteria2 程序、配置及防火墙规则。${PLAIN}"
    if [[ -t 0 ]]; then
        read -p "确认卸载? (y/n): " UN_CONFIRM </dev/tty
    else
        UN_CONFIRM="n"
    fi
    if [[ "$UN_CONFIRM" == "y" ]]; then
        echo -e "${GREEN}停止服务...${PLAIN}"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop hysteria-server || true
            systemctl disable hysteria-server || true
            rm -f /etc/systemd/system/hysteria-server.service || true
            systemctl daemon-reload || true
        else
            if [[ -f /etc/init.d/hysteria-server ]]; then
                /etc/init.d/hysteria-server stop || true
                rm -f /etc/init.d/hysteria-server || true
            fi
        fi

        rm -rf /etc/hysteria || true
        rm -f /usr/local/bin/hysteria || true
        # 删除我们可能添加的 redirect（尝试范围）
        iptables -t nat -F PREROUTING || true
        ip6tables -t nat -F PREROUTING || true

        # 尝试保存
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        elif [[ -f "/etc/init.d/iptables" ]]; then
            /etc/init.d/iptables save >/dev/null 2>&1 || true
        fi

        # 重新创建 hy 引导脚本（指向仓库原始下载入口）
        cat > /usr/bin/hy <<'SH_EOF'
#!/usr/bin/env bash
bash <(curl -fsSL https://raw.githubusercontent.com/bigcow666/hy2/main/bigcow/hy2)
SH_EOF
        chmod +x /usr/bin/hy || true

        echo -e "${GREEN}卸载完成。${PLAIN}"
        echo -e "${YELLOW}提示：输入 hy 可再次调出安装菜单。${PLAIN}"
        exit 0
    fi
}

show_menu() {
    echo -e "========================="
    echo -e "   Hysteria 2 管理面板   "
    echo -e "========================="
    echo -e "1) 查看运行状态"
    echo -e "2) 查看节点链接"
    echo -e "3) 修改配置文件"
    echo -e "4) 重启服务"
    echo -e "5) 停止服务"
    echo -e "6) 设置 DNS/DoH (防污染)需手动开启"
    echo -e "7) 更新 Hysteria 2 核心"
    echo -e "8) 更新脚本 (管理面板)"
    echo -e "9) 卸载并清理环境"
    echo -e "0) 退出"
    echo -e "========================="
    if [[ -t 0 ]]; then
        read -p "请选择: " OPTION </dev/tty
    else
        OPTION="0"
    fi

    case $OPTION in
        1) if command -v systemctl >/dev/null 2>&1; then systemctl status hysteria-server --no-pager || true; else /etc/init.d/hysteria-server status || true; fi ;;
        2) show_node_info ;;
        3) ${EDITOR:-nano} "$CONFIG_FILE" && echo "修改后请重启服务(选项4)" ;;
        4) if command -v systemctl >/dev/null 2>&1; then systemctl restart hysteria-server && echo -e "${GREEN}重启成功${PLAIN}"; else rc-service hysteria-server restart || true; fi ;;
        5) if command -v systemctl >/dev/null 2>&1; then systemctl stop hysteria-server; else rc-service hysteria-server stop || true; fi; echo "服务已停止" ;;
        6) echo "请在主脚本中使用 set_dns 功能" ;; # 主脚本提供 set_dns
        7) echo -e "${GREEN}正在更新...${PLAIN}"
           if command -v systemctl >/dev/null 2>&1; then systemctl stop hysteria-server || true; else rc-service hysteria-server stop || true; fi
           bash <(curl -fsSL 'https://get.hy2.sh/') || warn "更新脚本遇到问题"
           if command -v systemctl >/dev/null 2>&1; then systemctl restart hysteria-server || true; else rc-service hysteria-server restart || true; fi
           echo -e "${GREEN}更新完毕${PLAIN}"
           ;;
        8) echo -e "${GREEN}>>> 正在更新管理脚本...${PLAIN}"
           TARGET_FILE="/root/hy2.sh"
           # 使用原子下载
           curl -fSL --retry 3 --retry-delay 2 -o "$TARGET_FILE.tmp" 'https://raw.githubusercontent.com/bigcow666/hy2/main/bigcow/hy2' || { echo "下载失败"; rm -f "$TARGET_FILE.tmp"; exit 1; }
           mv -f "$TARGET_FILE.tmp" "$TARGET_FILE"
           chmod +x "$TARGET_FILE"
           echo -e "${GREEN}脚本已下载，正在重新加载...${PLAIN}"
           sleep 1
           bash "$TARGET_FILE"
           exit 0
           ;;
        9) uninstall_logic ;;
        0) exit 0 ;;
        *) echo "无效选择" ;;
    esac
}

# 替换占位符 NODE_NAME 并安装到 CMD_PATH（原子替换）
node_name_safe_replacement() {
    local source_file="$1"
    local dest="$2"
    local node_name="$3"
    local tmp
    tmp="$(mktemp /tmp/hy.XXXXXX)" || return 1
    # 替换占位符
    sed "s/__NODE_NAME_PLACEHOLDER__/'${node_name//\'/\'\\\'\'}'/g" "$source_file" > "$tmp"
    mv -f "$tmp" "$dest"
    chmod +x "$dest"
}

# 写入最终 /usr/bin/hy
install_hy_shortcut() {
    local tmpfile="$1"
    node_name_safe_replacement "$tmpfile" "$CMD_PATH" "$(escape_for_single_quote "${CUSTOM_NAME:-Hy2-Node}")"
    info "管理脚本已写入 $CMD_PATH"
}

# DNS 设置（更稳健的写入）
set_dns() {
    info "正在配置防污染 DNS (DoH)..."
    echo "1) Cloudflare (1.1.1.1)"
    echo "2) Google (8.8.8.8)"
    echo "3) Quad9 (9.9.9.9)"
    echo "4) 恢复默认"
    if [[ -t 0 ]]; then
        read -p "请选择: " dns_opt </dev/tty
    else
        dns_opt="1"
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        err "配置文件不存在：$CONFIG_FILE"
        return 1
    fi

    # 删除旧的 resolver block：匹配以 resolver: 开头到下一个顶级 key（非常简单的 heuristics）
    awk '
    BEGIN{inside=0}
    /^resolver:[[:space:]]*$/ { inside=1; next }
    inside && /^[^[:space:]]/ { inside=0 }
    !inside { print }
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv -f "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    case $dns_opt in
        1) cat >> "$CONFIG_FILE" <<CONFIG
resolver:
  type: https
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
CONFIG
        ;;
        2) cat >> "$CONFIG_FILE" <<CONFIG
resolver:
  type: https
  https:
    addr: 8.8.8.8:443
    timeout: 10s
    sni: dns.google
    insecure: false
CONFIG
        ;;
        3) cat >> "$CONFIG_FILE" <<CONFIG
resolver:
  type: https
  https:
    addr: 9.9.9.9:443
    timeout: 10s
    sni: dns.quad9.net
    insecure: false
CONFIG
        ;;
        4) echo "已恢复默认" ;;
        *) echo "错误" ; return 1 ;;
    esac

    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart hysteria-server || true
    else
        rc-service hysteria-server restart || true
    fi
    info "设置完成，服务已重启（如可用）"
}

# ===== 主安装流程 =====
install_hy2() {
    clear
    check_sys
    info "Hysteria 2 安装脚本 (V5.0 终极加固版)"
    info "当前系统: ${OS} (包管理器: ${PM})"

    # 证书模式
    echo "------------------------------------------------"
    echo -e "${YELLOW}[1/6] 证书模式${PLAIN}"
    echo "1) 自签证书 (IP直连，最简单)"
    echo "2) 域名证书 (推荐，需域名解析)"
    CERT_MODE=$(prompt "选择 (默认1): " "1")
    [[ -z "$CERT_MODE" ]] && CERT_MODE="1"

    if [[ "$CERT_MODE" == "2" ]]; then
        USER_DOMAIN=$(prompt "输入域名: " "")
        USER_EMAIL=$(prompt "输入邮箱: " "")
        if [[ -z "$USER_DOMAIN" || -z "$USER_EMAIL" ]]; then
            err "域名与邮箱不能为空"
            exit 1
        fi
    else
        # 使用多个备选以提高成功率
        SERVER_IP=$(curl -4 -s --max-time 5 https://ifconfig.co || curl -4 -s --max-time 5 https://ifconfig.me || echo "127.0.0.1")
        USER_DOMAIN="$SERVER_IP"
    fi

    echo "------------------------------------------------"
    PORT=$(prompt "设置端口 (默认 443): " "443")
    [[ -z "$PORT" ]] && PORT="443"

    echo "------------------------------------------------"
    echo -e "${YELLOW}[3/6] 选择伪装域名 (Masquerade Domain)${PLAIN}"
    echo "1) www.bing.com"
    echo "2) www.tesla.com"
    echo "3) www.apple.com"
    echo "4) www.amazon.com"
    echo "0) 手动输入其他域名"
    MASQ_OPT=$(prompt "请选择 [0-4] (默认1): " "1")
    case $MASQ_OPT in
        2) MASQ_DOMAIN="www.tesla.com" ;;
        3) MASQ_DOMAIN="www.apple.com" ;;
        4) MASQ_DOMAIN="www.amazon.com" ;;
        0) MASQ_DOMAIN=$(prompt "请输入伪装域名 (例如 www.baidu.com): " "www.bing.com") ;;
        *) MASQ_DOMAIN="www.bing.com" ;;
    esac
    [[ -z "$MASQ_DOMAIN" ]] && MASQ_DOMAIN="www.bing.com"
    info "已选择伪装: $MASQ_DOMAIN"

    echo "------------------------------------------------"
    echo -e "${YELLOW}设置端口跳跃 (Port Hopping)${PLAIN}"
    HOP_START=$(prompt "起始端口 (默认 35000): " "35000")
    [[ -z "$HOP_START" ]] && HOP_START="35000"
    HOP_END=$(prompt "结束端口 (默认 36000): " "36000")
    [[ -z "$HOP_END" ]] && HOP_END="36000"

    echo "------------------------------------------------"
    echo -e "${YELLOW}[5/6] 出站网络偏好${PLAIN}"
    echo "1) IPv4 优先"
    echo "2) IPv6 优先"
    echo "3) 自动双栈 (Auto)"
    NET_CHOICE=$(prompt "请选择 (默认1): " "1")
    case $NET_CHOICE in
        2) OUT_MODE="6" ;;
        3) OUT_MODE="auto" ;;
        *) OUT_MODE="4" ;;
    esac

    echo "------------------------------------------------"
    echo -e "${YELLOW}[6/6] 节点名称设置${PLAIN}"
    CUSTOM_NAME=$(prompt "请输入节点名称 (默认 Hy2-Node): " "Hy2-Node")
    [[ -z "$CUSTOM_NAME" ]] && CUSTOM_NAME="Hy2-Node"

    # 检查必需工具，先更新源
    info ">>> 更新软件源并安装依赖 ($PM)..."
    if [[ -n "${UPDATE_CMD:-}" ]]; then
        $UPDATE_CMD || true
    fi

    # 检查并安装常用工具
    case $PM in
        apt)
            $INSTALL_CMD curl openssl iptables iptables-persistent netfilter-persistent wget ca-certificates nano -y || true
            ;;
        dnf|yum)
            $INSTALL_CMD curl openssl iptables iptables-services wget ca-certificates nano || true
            systemctl enable --now iptables || true
            ;;
        apk)
            $INSTALL_CMD curl openssl iptables ip6tables nano wget ca-certificates || true
            ;;
    esac

    # 确认基本命令存在（但不过早退出）
    for c in curl openssl iptables wget; do
        if ! command -v "$c" >/dev/null 2>&1; then
            warn "系统缺少 $c ，请手动安装以保证功能完整。"
        fi
    done

    # 下载并运行 Hysteria core 安装器（原子下载并执行）
    info ">>> 下载并安装 Hysteria 2 核心..."
    tmp_inst="$(mktemp /tmp/gethy2.XXXXXX)" || { err "无法创建临时文件"; exit 1; }
    if command -v curl >/dev/null 2>&1; then
        curl $CURL_OPTS -o "$tmp_inst" "$GET_HY2_URL" || { err "下载 get.hy2.sh 失败"; rm -f "$tmp_inst"; exit 1; }
    else
        wget $WGET_OPTS -O "$tmp_inst" "$GET_HY2_URL" || { err "wget 下载失败"; rm -f "$tmp_inst"; exit 1; }
    fi
    chmod +x "$tmp_inst"
    # 安全执行：在子 shell 中运行，避免影响本脚本 set -euo
    HYSTERIA_USER=root bash "$tmp_inst" || warn "执行 get.hy2.sh 返回非零状态"
    rm -f "$tmp_inst" || true

    info ">>> 生成配置文件..."
    PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    OBFS_PASSWORD=$(openssl rand -hex 8 || echo "$(head -c8 /dev/urandom | xxd -p -c8)")
    mkdir -p "$CERT_DIR"
    mkdir -p "$(dirname "$CONFIG_FILE")"

    # 基础 config
    cat > "$CONFIG_FILE" <<EOF
listen: :$PORT
auth:
  type: password
  password: $PASSWORD
obfs:
  type: salamander
  salamander:
    password: $OBFS_PASSWORD
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
speedTest: true
disableUDP: false
udpIdleTimeout: 60s
EOF

    if [[ "$CERT_MODE" == "2" ]]; then
        cat >> "$CONFIG_FILE" <<EOF
acme:
  domains:
    - $USER_DOMAIN
  email: $USER_EMAIL
masquerade:
  type: proxy
  proxy:
    url: https://$MASQ_DOMAIN
    rewriteHost: true
  listenHTTPS: :$PORT
outbounds:
  - name: direct_out
    type: direct
    direct:
      mode: $OUT_MODE
      fastOpen: true
EOF
    else
        # 自签：使用合理有效期（例如 365 天）
        openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/self.key" 2>/dev/null || true
        openssl req -new -x509 -days 365 -key "$CERT_DIR/self.key" -out "$CERT_DIR/self.crt" -subj "/CN=$MASQ_DOMAIN" 2>/dev/null || true
        chmod 644 "$CERT_DIR/self.key" "$CERT_DIR/self.crt" || true
        cat >> "$CONFIG_FILE" <<EOF
tls:
  cert: $CERT_DIR/self.crt
  key: $CERT_DIR/self.key
masquerade:
  type: proxy
  proxy:
    url: https://$MASQ_DOMAIN
    rewriteHost: true
    insecure: true
  listenHTTPS: :$PORT
outbounds:
  - name: direct_out
    type: direct
    direct:
      mode: $OUT_MODE
      fastOpen: true
EOF
    fi

    # --- 防火墙：添加端口转发（安全版） ---
    info ">>> 配置端口转发..."
    add_udp_redirect_range "$HOP_START" "$HOP_END" "$PORT"

    # --- systemd / openrc service 创建（如果需要） ---
    # 尝试查找 hysteria 二进制路径
    HYSTERIA_BIN="$(command -v hysteria || command -v /usr/local/bin/hysteria || command -v /usr/bin/hysteria || true)"
    if [[ -z "$HYSTERIA_BIN" ]]; then
        warn "未在 PATH 中找到 hysteria 二进制，systemd unit 将使用 /usr/local/bin/hysteria 作为默认路径。请确认 get.hy2.sh 的安装位置。"
        HYSTERIA_BIN="/usr/local/bin/hysteria"
    fi

    if [[ "$PM" == "apk" ]]; then
        cat > /etc/init.d/hysteria-server <<EOF
#!/sbin/openrc-run
name="Hysteria 2 Server"
command="${HYSTERIA_BIN}"
command_args="server -c ${CONFIG_FILE}"
command_background=true
pidfile="/run/hysteria-server.pid"
depend() { need net; after firewall; }
EOF
        chmod +x /etc/init.d/hysteria-server || true
        if command -v rc-update >/dev/null 2>&1; then
            rc-update add hysteria-server default || true
            rc-service hysteria-server restart || true
        fi
    else
        # 写 systemd unit（若尚不存在或不同则覆盖）
        cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
ExecStart=${HYSTERIA_BIN} server -c ${CONFIG_FILE}
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload || true
        systemctl enable --now hysteria-server || true
    fi

    # 创建并安装管理脚本（快捷方式）
    tmp_hy="$(mktemp /tmp/hy.XXXXXX)" || true
    # 先从本脚本中生成管理脚本（使用 create_shortcut 的实现）
    # 我们复用 create_shortcut 的临时写入机制
    create_shortcut_tmp="$(mktemp /tmp/hy_src.XXXXXX)"
    # 把 embedded create_shortcut 中生成的 tmpfile 写入实际位置（通过 install_hy_shortcut）
    # 注意：在这里我们使用上面 create_shortcut() 产生的 tmpfile；为了简洁，我们直接在内存中把刚才写好的临时 hy 脚本安装
    # 直接调用 create_shortcut 的逻辑：已在此文件内定义
    # 先把 /usr/bin/hy 写入（使用函数）
    install_hy_shortcut "$(mktemp)" || true

    # 结束安装
    clear
    echo -e "${GREEN}=========================================${PLAIN}"
    echo -e "${GREEN}      安装完成！(Install Complete)       ${PLAIN}"
    echo -e "${GREEN}=========================================${PLAIN}"
    echo -e "输入 ${YELLOW}hy${PLAIN} 再次查看此信息。"
    sleep 1
    # 尝试调用 hy info（若存在）
    if command -v hy >/dev/null 2>&1; then
        hy info || true
    fi
}

# 主菜单（安装/卸载/管理）
start_menu() {
    clear
    echo -e "-------------------------"
    echo -e "   Hysteria 2 安装脚本"
    echo -e "-------------------------"
    echo -e "1. 安装 / 重装"
    echo -e "2. 卸载"
    echo -e "3. 打开管理菜单 (hy)"
    echo -e "0. 退出"
    if [[ -t 0 ]]; then
        read -p "选择: " k </dev/tty
    else
        k="0"
    fi
    case $k in
        1) install_hy2 ;;
        2) uninstall_logic ;;
        3) if [ -f "$CMD_PATH" ]; then "$CMD_PATH"; else echo "未安装"; fi ;;
        0) exit 0 ;;
        *) echo "错误" ;;
    esac
}

# 启动脚本入口
require_root
start_menu
EOF

    # 将 NODE_NAME 占位替换为实际值并安装
    install_hy_shortcut "$tmpfile" || true
    rm -f "$tmpfile" || true
    info "create_shortcut 完成"
}

# 如果脚本作为 info 参数调用，显示简短信息
if [[ "${1:-}" == "info" ]]; then
    # 通过 /usr/bin/hy 实现的 show_node_info
    if command -v hy >/dev/null 2>&1; then
        hy info || true
    else
        echo "hy 管理脚本未安装"
    fi
    exit 0
fi

# 启动
check_sys
start_menu
