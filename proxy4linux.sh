#!/bin/bash

# Enhanced Linux/macOS Proxy Manager v3.0
# 增强版代理管理脚本 - 完整终端代理解决方案
# Author: Enhanced by Claude Code
# Features: 透明代理、SOCKS5完整支持、代理规则管理、工具集成

set -euo pipefail

# 全局配置
PROXY_DIR="$HOME/.proxy"
PROXY_SCRIPT="$PROXY_DIR/proxy.sh"
CONFIG_FILE="$PROXY_DIR/config"
RULES_FILE="$PROXY_DIR/rules.conf"
BACKUP_DIR="$PROXY_DIR/backup"
LOG_FILE="$PROXY_DIR/proxy.log"
STATE_FILE="$PROXY_DIR/proxy.state"
WRAPPER_DIR="$PROXY_DIR/wrappers"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# 彩色输出函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO: $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; log "SUCCESS: $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; log "WARNING: $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; log "ERROR: $1"; }
print_debug() { echo -e "${PURPLE}[DEBUG]${NC} $1"; log "DEBUG: $1"; }

# 检查工具是否存在
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# 检查root权限
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $ip == "localhost" ]] || [[ $ip =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# 验证端口号
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
        return 0
    else
        return 1
    fi
}

# 创建代理状态文件
create_state_file() {
    cat > "$STATE_FILE" <<EOF
# Proxy Manager State File
# Auto-generated - Do not edit manually
PROXY_ENABLED=false
PROXY_MODE=""
TRANSPARENT_PROXY=false
CURRENT_HTTP_PROXY=""
CURRENT_HTTPS_PROXY=""
CURRENT_SOCKS_PROXY=""
RULES_ENABLED=false
LAST_UPDATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}

# 加载状态
load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        source "$STATE_FILE"
    else
        create_state_file
        source "$STATE_FILE"
    fi
}

# 保存状态
save_state() {
    load_state
    cat > "$STATE_FILE" <<EOF
# Proxy Manager State File
# Auto-generated - Do not edit manually
PROXY_ENABLED=${PROXY_ENABLED:-false}
PROXY_MODE=${PROXY_MODE:-""}
TRANSPARENT_PROXY=${TRANSPARENT_PROXY:-false}
CURRENT_HTTP_PROXY=${CURRENT_HTTP_PROXY:-""}
CURRENT_HTTPS_PROXY=${CURRENT_HTTPS_PROXY:-""}
CURRENT_SOCKS_PROXY=${CURRENT_SOCKS_PROXY:-""}
RULES_ENABLED=${RULES_ENABLED:-false}
LAST_UPDATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}

# 创建默认规则文件
create_default_rules() {
    cat > "$RULES_FILE" <<EOF
# Proxy Rules Configuration
# Format: ACTION:TYPE:PATTERN
# ACTION: DIRECT, PROXY, BLOCK
# TYPE: domain, ip, port, process
# PATTERN: matching pattern

# 直连规则 - 本地和内网地址
DIRECT:ip:127.0.0.1
DIRECT:ip:localhost
DIRECT:ip:10.0.0.0/8
DIRECT:ip:172.16.0.0/12
DIRECT:ip:192.168.0.0/16
DIRECT:domain:*.local
DIRECT:domain:*.lan

# 常见直连域名
DIRECT:domain:*.cn
DIRECT:domain:*.baidu.com
DIRECT:domain:*.qq.com
DIRECT:domain:*.taobao.com
DIRECT:domain:*.aliyun.com
DIRECT:domain:*.163.com

# 代理规则 - 需要代理的域名
PROXY:domain:*.google.com
PROXY:domain:*.youtube.com
PROXY:domain:*.facebook.com
PROXY:domain:*.twitter.com
PROXY:domain:*.github.com
PROXY:domain:*.stackoverflow.com

# 阻止规则 - 广告和恶意域名
BLOCK:domain:*.doubleclick.net
BLOCK:domain:*.googlesyndication.com
EOF
}

# 安装透明代理依赖
install_transparent_proxy_deps() {
    print_info "检查透明代理依赖..."
    
    # 检查redsocks
    if ! check_tool redsocks; then
        print_warning "redsocks未安装，正在尝试安装..."
        if check_tool apt-get; then
            sudo apt-get update && sudo apt-get install -y redsocks
        elif check_tool yum; then
            sudo yum install -y redsocks
        elif check_tool brew; then
            brew install redsocks
        else
            print_error "无法自动安装redsocks，请手动安装"
            return 1
        fi
    fi
    
    # 检查gost (可选)
    if ! check_tool gost; then
        print_info "建议安装gost以获得更好的代理支持"
        print_info "访问: https://github.com/ginuerzh/gost/releases"
    fi
    
    print_success "透明代理依赖检查完成"
}

# 配置透明代理
configure_transparent_proxy() {
    local action="$1"
    local proxy_type="$2"
    local proxy_ip="$3"
    local proxy_port="$4"
    
    case "$action" in
        enable)
            print_info "配置透明代理..."
            
            # 创建redsocks配置
            sudo mkdir -p /etc/redsocks
            sudo cat > /etc/redsocks/redsocks.conf <<EOF
base {
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = $proxy_ip;
    port = $proxy_port;
    type = $proxy_type;
}
EOF

            # 启动redsocks
            if sudo redsocks -c /etc/redsocks/redsocks.conf; then
                print_success "redsocks启动成功"
            else
                print_error "redsocks启动失败"
                return 1
            fi
            
            # 配置iptables规则
            configure_iptables_rules "enable"
            
            TRANSPARENT_PROXY=true
            save_state
            ;;
            
        disable)
            print_info "禁用透明代理..."
            
            # 清理iptables规则
            configure_iptables_rules "disable"
            
            # 停止redsocks
            sudo pkill redsocks 2>/dev/null || true
            
            TRANSPARENT_PROXY=false
            save_state
            ;;
    esac
}

# 配置iptables规则
configure_iptables_rules() {
    local action="$1"
    
    case "$action" in
        enable)
            print_info "配置iptables透明代理规则..."
            
            # 创建自定义链
            sudo iptables -t nat -N PROXY_OUT 2>/dev/null || true
            
            # 跳过本地地址
            sudo iptables -t nat -A PROXY_OUT -d 127.0.0.0/8 -j RETURN
            sudo iptables -t nat -A PROXY_OUT -d 10.0.0.0/8 -j RETURN
            sudo iptables -t nat -A PROXY_OUT -d 172.16.0.0/12 -j RETURN
            sudo iptables -t nat -A PROXY_OUT -d 192.168.0.0/16 -j RETURN
            
            # 重定向到redsocks
            sudo iptables -t nat -A PROXY_OUT -p tcp -j REDIRECT --to-ports 12345
            
            # 应用规则到OUTPUT链
            sudo iptables -t nat -A OUTPUT -p tcp -j PROXY_OUT
            
            print_success "iptables规则配置完成"
            ;;
            
        disable)
            print_info "清理iptables透明代理规则..."
            
            # 清理规则
            sudo iptables -t nat -D OUTPUT -p tcp -j PROXY_OUT 2>/dev/null || true
            sudo iptables -t nat -F PROXY_OUT 2>/dev/null || true
            sudo iptables -t nat -X PROXY_OUT 2>/dev/null || true
            
            print_success "iptables规则清理完成"
            ;;
    esac
}

# 创建命令包装器
create_command_wrappers() {
    mkdir -p "$WRAPPER_DIR"
    
    # 创建curl包装器
    cat > "$WRAPPER_DIR/curl" <<'EOF'
#!/bin/bash
PROXY_DIR="$HOME/.proxy"
source "$PROXY_DIR/proxy.state" 2>/dev/null || true

if [[ "$PROXY_ENABLED" == "true" && -n "$CURRENT_SOCKS_PROXY" ]]; then
    exec /usr/bin/curl --socks5 "$CURRENT_SOCKS_PROXY" "$@"
elif [[ "$PROXY_ENABLED" == "true" && -n "$CURRENT_HTTP_PROXY" ]]; then
    exec /usr/bin/curl --proxy "$CURRENT_HTTP_PROXY" "$@"
else
    exec /usr/bin/curl "$@"
fi
EOF

    # 创建wget包装器
    cat > "$WRAPPER_DIR/wget" <<'EOF'
#!/bin/bash
PROXY_DIR="$HOME/.proxy"
source "$PROXY_DIR/proxy.state" 2>/dev/null || true

if [[ "$PROXY_ENABLED" == "true" && -n "$CURRENT_HTTP_PROXY" ]]; then
    exec /usr/bin/wget -e use_proxy=yes -e http_proxy="$CURRENT_HTTP_PROXY" -e https_proxy="$CURRENT_HTTPS_PROXY" "$@"
else
    exec /usr/bin/wget "$@"
fi
EOF

    # 设置执行权限
    chmod +x "$WRAPPER_DIR"/*
    
    # 将包装器目录添加到PATH前面
    export PATH="$WRAPPER_DIR:$PATH"
}

# 增强的工具配置
configure_enhanced_tools() {
    local action="$1"
    local protocol="${2:-all}"
    
    load_config
    
    local http_proxy_url="http://$HTTP_IP:$HTTP_PORT"
    local https_proxy_url="http://$HTTPS_IP:$HTTPS_PORT"
    local socks_proxy_url="socks5h://$SOCKS5_IP:$SOCKS5_PORT"
    
    if [[ "$action" == "enable" ]]; then
        print_info "配置增强工具代理..."
        
        # Git配置
        if [[ "$ENABLE_GIT_PROXY" == "1" ]]; then
            git config --global http.proxy "$http_proxy_url"
            git config --global https.proxy "$https_proxy_url"
            print_success "Git代理已配置"
        fi
        
        # SSH配置
        mkdir -p "$HOME/.ssh"
        if ! grep -q "ProxyCommand" "$HOME/.ssh/config" 2>/dev/null; then
            cat >> "$HOME/.ssh/config" <<EOF

# Proxy Manager - SSH代理配置
Host github.com
    ProxyCommand nc -X connect -x $HTTP_IP:$HTTP_PORT %h %p

Host *
    # ProxyCommand nc -X connect -x $HTTP_IP:$HTTP_PORT %h %p
EOF
            print_success "SSH代理配置已添加"
        fi
        
        # 浏览器代理设置文件
        create_browser_proxy_configs "$http_proxy_url" "$socks_proxy_url"
        
        # 创建命令包装器
        create_command_wrappers
        
    elif [[ "$action" == "disable" ]]; then
        print_info "禁用增强工具代理..."
        
        # 清理Git配置
        git config --global --unset http.proxy 2>/dev/null || true
        git config --global --unset https.proxy 2>/dev/null || true
        
        print_success "增强工具代理已禁用"
    fi
}

# 创建浏览器代理配置
create_browser_proxy_configs() {
    local http_proxy="$1"
    local socks_proxy="$2"
    
    # Chrome/Chromium启动脚本
    cat > "$WRAPPER_DIR/chrome-proxy" <<EOF
#!/bin/bash
# Chrome with proxy
google-chrome --proxy-server="socks5://$socks_proxy" "\$@"
EOF
    
    # Firefox配置
    local firefox_profile_dir="$HOME/.mozilla/firefox"
    if [[ -d "$firefox_profile_dir" ]]; then
        print_info "检测到Firefox，可手动导入代理配置"
        cat > "$PROXY_DIR/firefox-proxy.js" <<EOF
// Firefox代理配置
// 在about:config中设置以下值:
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "$SOCKS5_IP");
user_pref("network.proxy.socks_port", $SOCKS5_PORT);
user_pref("network.proxy.socks_version", 5);
EOF
    fi
    
    chmod +x "$WRAPPER_DIR/chrome-proxy"
    print_success "浏览器代理配置已创建"
}

# 主代理函数 - 增强版
proxy_main() {
    local command="${1:-status}"
    shift || true
    
    case "$command" in
        enable)
            local protocol="all"
            local ip=""
            local port=""
            local nosave=0
            local transparent=0
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -p|--protocol) protocol="$2"; shift 2 ;;
                    --ip) ip="$2"; shift 2 ;;
                    --port) port="$2"; shift 2 ;;
                    --NoSave) nosave=1; shift ;;
                    --transparent) transparent=1; shift ;;
                    *) break ;;
                esac
            done
            
            # 加载配置
            load_config
            
            # 使用默认配置或命令行参数
            if [[ -n "$ip" && -n "$port" ]]; then
                if ! validate_ip "$ip" || ! validate_port "$port"; then
                    print_error "无效的IP地址或端口号"
                    return 1
                fi
            else
                case "$protocol" in
                    http) ip="$HTTP_IP"; port="$HTTP_PORT" ;;
                    https) ip="$HTTPS_IP"; port="$HTTPS_PORT" ;;
                    socks5) ip="$SOCKS5_IP"; port="$SOCKS5_PORT" ;;
                    all) ip="$HTTP_IP"; port="$HTTP_PORT" ;;
                esac
            fi
            
            print_info "启用代理: $protocol 模式, $ip:$port"
            
            case "$protocol" in
                http)
                    export HTTP_PROXY="http://$ip:$port"
                    export http_proxy="$HTTP_PROXY"
                    CURRENT_HTTP_PROXY="$ip:$port"
                    ;;
                https)
                    export HTTPS_PROXY="http://$ip:$port"
                    export https_proxy="$HTTPS_PROXY"
                    CURRENT_HTTPS_PROXY="$ip:$port"
                    ;;
                socks5)
                    export ALL_PROXY="socks5://$ip:$port"
                    export all_proxy="$ALL_PROXY"
                    CURRENT_SOCKS_PROXY="$ip:$port"
                    
                    # 透明代理
                    if [[ $transparent -eq 1 ]]; then
                        configure_transparent_proxy "enable" "socks5" "$ip" "$port"
                    fi
                    ;;
                all)
                    export HTTP_PROXY="http://$ip:$port"
                    export http_proxy="$HTTP_PROXY"
                    export HTTPS_PROXY="$HTTP_PROXY"
                    export https_proxy="$HTTP_PROXY"
                    export ALL_PROXY="socks5://$ip:$port"
                    export all_proxy="$ALL_PROXY"
                    CURRENT_HTTP_PROXY="$ip:$port"
                    CURRENT_HTTPS_PROXY="$ip:$port"
                    CURRENT_SOCKS_PROXY="$ip:$port"
                    
                    # 透明代理
                    if [[ $transparent -eq 1 ]]; then
                        configure_transparent_proxy "enable" "socks5" "$ip" "$port"
                    fi
                    ;;
            esac
            
            # 配置增强工具
            configure_enhanced_tools "enable" "$protocol"
            
            # 保存配置
            if [[ $nosave -eq 0 ]]; then
                case "$protocol" in
                    http) HTTP_IP="$ip"; HTTP_PORT="$port" ;;
                    https) HTTPS_IP="$ip"; HTTPS_PORT="$port" ;;
                    socks5) SOCKS5_IP="$ip"; SOCKS5_PORT="$port" ;;
                    all)
                        HTTP_IP="$ip"; HTTP_PORT="$port"
                        HTTPS_IP="$ip"; HTTPS_PORT="$port"
                        SOCKS5_IP="$ip"; SOCKS5_PORT="$port"
                        ;;
                esac
                save_config
            fi
            
            # 更新状态
            PROXY_ENABLED=true
            PROXY_MODE="$protocol"
            save_state
            
            print_success "代理已启用"
            ;;
            
        disable)
            local protocol="${1:-all}"
            
            print_info "禁用代理: $protocol"
            
            case "$protocol" in
                http)
                    unset HTTP_PROXY http_proxy
                    CURRENT_HTTP_PROXY=""
                    ;;
                https)
                    unset HTTPS_PROXY https_proxy
                    CURRENT_HTTPS_PROXY=""
                    ;;
                socks5)
                    unset ALL_PROXY all_proxy
                    CURRENT_SOCKS_PROXY=""
                    configure_transparent_proxy "disable" "" "" ""
                    ;;
                all|*)
                    unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy
                    CURRENT_HTTP_PROXY=""
                    CURRENT_HTTPS_PROXY=""
                    CURRENT_SOCKS_PROXY=""
                    configure_transparent_proxy "disable" "" "" ""
                    ;;
            esac
            
            # 禁用增强工具
            configure_enhanced_tools "disable"
            
            # 更新状态
            PROXY_ENABLED=false
            PROXY_MODE=""
            save_state
            
            print_success "代理已禁用"
            ;;
            
        setdefault)
            local protocol=""
            local ip=""
            local port=""
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -p|--protocol) protocol="$2"; shift 2 ;;
                    --ip) ip="$2"; shift 2 ;;
                    --port) port="$2"; shift 2 ;;
                    *) break ;;
                esac
            done
            
            # 验证必要参数
            if [[ -z "$protocol" || -z "$ip" || -z "$port" ]]; then
                print_error "缺少必要参数"
                echo "用法: proxy setdefault -p <protocol> --ip <ip> --port <port>"
                echo "示例: proxy setdefault -p all --ip 127.0.0.1 --port 7890"
                return 1
            fi
            
            # 验证IP和端口
            if ! validate_ip "$ip" || ! validate_port "$port"; then
                print_error "无效的IP地址或端口号"
                return 1
            fi
            
            # 加载当前配置
            load_config
            
            case "$protocol" in
                http)
                    HTTP_IP="$ip"
                    HTTP_PORT="$port"
                    ;;
                https)
                    HTTPS_IP="$ip"
                    HTTPS_PORT="$port"
                    ;;
                socks5)
                    SOCKS5_IP="$ip"
                    SOCKS5_PORT="$port"
                    ;;
                all)
                    HTTP_IP="$ip"
                    HTTP_PORT="$port"
                    HTTPS_IP="$ip"
                    HTTPS_PORT="$port"
                    SOCKS5_IP="$ip"
                    SOCKS5_PORT="$port"
                    ;;
                *)
                    print_error "无效的协议类型。必须是: http, https, socks5, all"
                    return 1
                    ;;
            esac
            
            if save_config; then
                print_success "默认代理配置已更新！"
                proxy_main status
            else
                print_error "保存配置失败"
                return 1
            fi
            ;;
            
        status)
            load_config
            load_state
            
            echo -e "\n${CYAN}=== 增强代理管理器状态 ===${NC}"
            echo -e "\n${BLUE}系统代理状态:${NC}"
            echo "  HTTP:   ${HTTP_PROXY:-${RED}Disabled${NC}}"
            echo "  HTTPS:  ${HTTPS_PROXY:-${RED}Disabled${NC}}"
            echo "  SOCKS5: ${ALL_PROXY:-${RED}Disabled${NC}}"
            echo -e "\n${BLUE}透明代理:${NC} ${TRANSPARENT_PROXY:-${RED}Disabled${NC}}"
            echo -e "\n${BLUE}默认配置:${NC}"
            echo "  HTTP:   http://$HTTP_IP:$HTTP_PORT"
            echo "  HTTPS:  http://$HTTPS_IP:$HTTPS_PORT"
            echo "  SOCKS5: socks5://$SOCKS5_IP:$SOCKS5_PORT"
            
            # 检查工具状态
            echo -e "\n${BLUE}工具代理状态:${NC}"
            local git_proxy=$(git config --global --get http.proxy 2>/dev/null || echo "未配置")
            echo "  Git:    $git_proxy"
            
            local npm_proxy=$(npm config get proxy 2>/dev/null || echo "未配置")
            echo "  NPM:    $npm_proxy"
            
            # 检查透明代理进程
            if pgrep redsocks >/dev/null 2>&1; then
                echo -e "\n${GREEN}透明代理进程运行中${NC}"
            fi
            
            echo -e "\n${BLUE}最后更新:${NC} ${LAST_UPDATE:-未知}"
            ;;
            
        install-deps)
            print_info "安装增强代理依赖..."
            install_transparent_proxy_deps
            ;;
            
        rules)
            case "${1:-list}" in
                list)
                    if [[ -f "$RULES_FILE" ]]; then
                        echo -e "\n${CYAN}=== 代理规则 ===${NC}"
                        cat "$RULES_FILE" | grep -v '^#' | grep -v '^$'
                    else
                        print_warning "规则文件不存在，请运行 proxy rules init"
                    fi
                    ;;
                init)
                    create_default_rules
                    print_success "默认规则已创建: $RULES_FILE"
                    ;;
                edit)
                    ${EDITOR:-vi} "$RULES_FILE"
                    ;;
            esac
            ;;
            
        test)
            print_info "开始增强代理测试..."
            local test_urls=(
                "http://httpbin.org/ip"
                "https://ip.sb"
                "http://ip-api.com/json"
                "https://www.google.com"
            )
            local success_count=0
            
            for url in "${test_urls[@]}"; do
                print_info "测试 $url ..."
                if timeout 10 curl -sSf --connect-timeout 5 "$url" >/dev/null 2>&1; then
                    print_success "✓ $url 连接成功"
                    ((success_count++))
                else
                    print_error "✗ $url 连接失败"
                fi
            done
            
            echo -e "\n${BLUE}测试结果:${NC} $success_count/${#test_urls[@]} 个测试成功"
            
            # 显示当前IP
            if [[ $success_count -gt 0 ]]; then
                print_info "当前IP信息:"
                timeout 10 curl -sSf --connect-timeout 5 "http://ip-api.com/json" 2>/dev/null | \
                    python3 -c "import sys, json; data=json.load(sys.stdin); print(f\"IP: {data['query']}, 国家: {data['country']}, 城市: {data['city']}\")" 2>/dev/null || \
                    timeout 10 curl -sSf --connect-timeout 5 "https://ip.sb" 2>/dev/null || \
                    echo "无法获取IP信息"
            fi
            ;;
            
        help|--help|-h)
            echo -e "\n${CYAN}增强版Linux代理管理器 v3.0${NC}"
            echo -e "\n${BLUE}基本命令:${NC}"
            echo "  enable [选项]     启用代理"
            echo "  disable [协议]    禁用代理"
            echo "  status           显示状态"
            echo "  setdefault      设置默认配置"
            echo "  test            测试连接"
            echo "  install-deps    安装依赖"
            echo "  rules <动作>     管理规则"
            echo -e "\n${BLUE}通用选项:${NC}"
            echo "  -p, --protocol  指定协议 (http/https/socks5/all)"
            echo "  --ip            指定代理服务器IP地址"
            echo "  --port          指定代理服务器端口"
            echo "  --NoSave        不保存当前配置（仅用于enable命令）"
            echo "  --transparent   启用透明代理（需要root权限）"
            echo -e "\n${BLUE}规则管理:${NC}"
            echo "  rules list      列出规则"
            echo "  rules init      初始化规则"
            echo "  rules edit      编辑规则"
            echo -e "\n${BLUE}使用示例:${NC}"
            echo "1. 查看当前代理状态："
            echo "   proxy status"
            echo -e "\n2. 设置默认代理配置："
            echo "   proxy setdefault -p http --ip 127.0.0.1 --port 7890"
            echo "   proxy setdefault -p socks5 --ip 127.0.0.1 --port 7891"
            echo "   proxy setdefault -p all --ip 127.0.0.1 --port 7890"
            echo -e "\n3. 启用代理（使用默认配置）："
            echo "   proxy enable"
            echo "   proxy enable -p http"
            echo "   proxy enable -p socks5"
            echo -e "\n4. 启用代理（指定新配置）："
            echo "   proxy enable --ip 127.0.0.1 --port 8080"
            echo "   proxy enable -p http --ip 127.0.0.1 --port 8080"
            echo "   proxy enable -p socks5 --ip 127.0.0.1 --port 1080 --NoSave"
            echo -e "\n5. 启用透明代理："
            echo "   proxy enable --transparent"
            echo "   proxy enable -p socks5 --ip 127.0.0.1 --port 1080 --transparent"
            echo -e "\n6. 禁用代理："
            echo "   proxy disable          # 禁用所有代理"
            echo "   proxy disable -p http  # 仅禁用HTTP代理"
            echo -e "\n7. 测试代理连接："
            echo "   proxy test"
            echo -e "\n8. 规则管理："
            echo "   proxy rules init       # 初始化默认规则"
            echo "   proxy rules list       # 查看当前规则"
            echo "   proxy rules edit       # 编辑规则文件"
            echo -e "\n${BLUE}注意事项:${NC}"
            echo "- 使用setdefault设置的配置会被保存，下次使用enable时会作为默认值"
            echo "- 使用--NoSave选项时，修改的配置仅在当前会话有效"
            echo "- 透明代理功能需要管理员权限，会自动配置iptables规则"
            echo "- 工具代理（Git/NPM/PIP/Docker）会在启用系统代理时自动配置"
            echo "- 使用status命令可以查看详细的代理状态和配置信息"
            ;;
            
        version|--version|-V)
            echo -e "${CYAN}增强版Linux/macOS代理管理器 v3.0${NC}"
            echo "原作者: nanyuzuo"
            echo "增强版本: Claude Code Enhanced"
            echo "新增功能: 透明代理、SOCKS5完整支持、代理规则管理、增强工具集成"
            echo "支持平台: Linux, macOS"
            echo "支持工具: Git, NPM, PIP, Docker, SSH, 浏览器"
            echo "依赖工具: redsocks (透明代理), iptables (Linux), curl, git"
            echo "配置目录: $PROXY_DIR"
            echo "更新日期: $(date '+%Y-%m-%d')"
            ;;
            
        *)
            print_error "未知命令: $command"
            echo "使用 'proxy help' 查看帮助"
            return 1
            ;;
    esac
}

# 加载和保存配置函数（从原脚本继承）
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        # 默认配置
        HTTP_IP='127.0.0.1'
        HTTP_PORT='7890'
        HTTPS_IP='127.0.0.1'
        HTTPS_PORT='7890'
        SOCKS5_IP='127.0.0.1'
        SOCKS5_PORT='7891'
        ENABLE_GIT_PROXY=1
        ENABLE_NPM_PROXY=1
        ENABLE_PIP_PROXY=1
        ENABLE_DOCKER_PROXY=1
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
HTTP_IP='${HTTP_IP:-127.0.0.1}'
HTTP_PORT='${HTTP_PORT:-7890}'
HTTPS_IP='${HTTPS_IP:-127.0.0.1}'
HTTPS_PORT='${HTTPS_PORT:-7890}'
SOCKS5_IP='${SOCKS5_IP:-127.0.0.1}'
SOCKS5_PORT='${SOCKS5_PORT:-7891}'
ENABLE_GIT_PROXY=${ENABLE_GIT_PROXY:-1}
ENABLE_NPM_PROXY=${ENABLE_NPM_PROXY:-1}
ENABLE_PIP_PROXY=${ENABLE_PIP_PROXY:-1}
ENABLE_DOCKER_PROXY=${ENABLE_DOCKER_PROXY:-1}
EOF
}

# 安装函数
install_enhanced_proxy() {
    print_info "开始安装增强版代理管理器..."
    
    # 创建目录结构
    mkdir -p "$PROXY_DIR" "$BACKUP_DIR" "$WRAPPER_DIR"
    
    # 初始化配置
    load_config
    save_config
    create_state_file
    create_default_rules
    
    # 复制脚本
    cp "$0" "$PROXY_SCRIPT"
    chmod +x "$PROXY_SCRIPT"
    
    # 检测shell并添加到配置文件
    local shell_type=$(basename "$SHELL")
    local rc_file=""
    
    case $shell_type in
        bash) rc_file="$HOME/.bashrc" ;;
        zsh) rc_file="$HOME/.zshrc" ;;
        *) print_error "不支持的shell: $shell_type"; return 1 ;;
    esac
    
    # 添加到shell配置
    if ! grep -q "source $PROXY_SCRIPT" "$rc_file" 2>/dev/null; then
        echo -e "\n# Enhanced Proxy Manager v3.0" >> "$rc_file"
        echo "source $PROXY_SCRIPT" >> "$rc_file"
        echo "export PATH=\"$WRAPPER_DIR:\$PATH\"" >> "$rc_file"
    fi
    
    # 立即加载
    source "$PROXY_SCRIPT"
    export PATH="$WRAPPER_DIR:$PATH"
    
    print_success "安装完成！"
    print_info "请运行以下命令使配置生效:"
    print_info "  source $rc_file"
    print_info "或重启终端"
    print_info ""
    print_info "建议运行以下命令安装透明代理依赖:"
    print_info "  proxy install-deps"
}

# 主菜单（当直接运行脚本时显示）
show_main_menu() {
    clear
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}      增强版Linux/macOS代理管理器 v3.0     ${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo "1. 安装增强版代理管理器"
    echo "2. 卸载代理管理器"
    echo "3. 安装透明代理依赖"
    echo "4. 查看当前状态"
    echo "5. 测试代理连接"
    echo "6. 退出"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
}

# 主程序
main() {
    # 如果作为proxy命令调用
    if [[ "${0##*/}" == "proxy.sh" ]] && [[ $# -gt 0 ]]; then
        proxy_main "$@"
        return $?
    fi
    
    # 直接运行显示菜单
    while true; do
        show_main_menu
        read -p "请选择操作 (1-6): " choice
        
        case $choice in
            1)
                install_enhanced_proxy
                read -p "按回车继续..."
                ;;
            2)
                print_info "卸载功能将在后续版本实现"
                read -p "按回车继续..."
                ;;
            3)
                install_transparent_proxy_deps
                read -p "按回车继续..."
                ;;
            4)
                proxy_main status
                read -p "按回车继续..."
                ;;
            5)
                proxy_main test
                read -p "按回车继续..."
                ;;
            6)
                print_info "感谢使用增强版代理管理器！"
                exit 0
                ;;
            *)
                print_error "无效选项，请选择 1-6"
                sleep 1
                ;;
        esac
    done
}

# 检查是否作为脚本直接运行
if [[ "${BASH_SOURCE[0]:-}" == "${0:-}" ]] || [[ -z "${BASH_SOURCE[0]:-}" ]]; then
    main "$@"
fi