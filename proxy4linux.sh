#!/bin/bash

# Linux/macOS Proxy Manager - Enhanced Version
# 增强版代理管理脚本，支持安全配置、备份恢复、错误处理等功能

# 设置基本的错误处理，但不使用严格模式避免交互问题

# 全局配置
PROXY_DIR="$HOME/.proxy"
PROXY_SCRIPT="$PROXY_DIR/proxy.sh"
CONFIG_FILE="$PROXY_DIR/config"
BACKUP_DIR="$PROXY_DIR/backup"
LOG_FILE="$PROXY_DIR/proxy.log"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# 彩色输出函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO: $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; log "SUCCESS: $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; log "WARNING: $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; log "ERROR: $1"; }

# 检查工具是否存在
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# 创建备份
create_backup() {
    local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_path"
    
    # 备份shell配置文件
    for shell_rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$shell_rc" ]]; then
            cp "$shell_rc" "$backup_path/" 2>/dev/null || true
        fi
    done
    
    # 备份现有代理配置
    if [[ -d "$PROXY_DIR" ]]; then
        cp -r "$PROXY_DIR" "$backup_path/proxy_config" 2>/dev/null || true
    fi
    
    print_success "备份已创建: $backup_path"
    echo "$backup_path" > "$PROXY_DIR/.last_backup"
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

show_menu() {
    clear
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}       Linux/macOS Proxy Manager        ${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo "1. Install proxy function"
    echo "2. Uninstall proxy function"
    echo "3. Create configuration backup"
    echo "4. Restore from backup"
    echo "5. View logs"
    echo "6. Exit"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
}

detect_shell() {
    case $(basename "$SHELL") in
        zsh)  echo "zsh"  ;;
        bash) echo "bash" ;;
        *)    echo ""     ;;
    esac
}

install_proxy() {
    print_info "开始安装代理管理器..."
    
    # 创建必要目录
    if ! mkdir -p "$PROXY_DIR" "$BACKUP_DIR"; then
        print_error "无法创建配置目录 $PROXY_DIR"
        return 1
    fi
    
    # 创建备份
    print_info "创建安装前备份..."
    create_backup

    # 初始化默认配置文件
    cat > "$CONFIG_FILE" <<EOL
HTTP_IP='127.0.0.1'
HTTP_PORT='7890'
HTTPS_IP='127.0.0.1'
HTTPS_PORT='7890'
SOCKS5_IP='127.0.0.1'
SOCKS5_PORT='7891'
# 工具代理配置开关
ENABLE_GIT_PROXY=1
ENABLE_NPM_PROXY=1
ENABLE_PIP_PROXY=1
ENABLE_DOCKER_PROXY=1
EOL

    # 生成代理函数脚本
    cat > "$PROXY_SCRIPT" <<'EOL'
#!/bin/bash

# Linux/macOS Proxy Manager - Enhanced Runtime Version
# 运行时代理管理脚本

# 配置管理
CONFIG_FILE="$HOME/.proxy/config"
LOG_FILE="$HOME/.proxy/proxy.log"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# 彩色输出函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO: $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; log "SUCCESS: $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; log "WARNING: $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; log "ERROR: $1"; }

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

# 安全的配置加载函数
load_config() {
    # 初始化默认配置
    HTTP_IP="127.0.0.1"
    HTTP_PORT="7890"
    HTTPS_IP="127.0.0.1"
    HTTPS_PORT="7890"
    SOCKS5_IP="127.0.0.1"
    SOCKS5_PORT="7891"
    ENABLE_GIT_PROXY=1
    ENABLE_NPM_PROXY=1
    ENABLE_PIP_PROXY=1
    ENABLE_DOCKER_PROXY=1
    
    if [[ -f "$CONFIG_FILE" ]]; then
        # 安全地读取配置文件，避免代码注入
        while IFS='=' read -r key value; do
            # 跳过空行和注释
            [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
            
            # 验证键名是否合法
            if [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
                # 移除值的引号
                value="${value#\'}"
                value="${value%\'}"
                value="${value#\"}"
                value="${value%\"}"
                
                # 根据键名安全地设置变量
                case "$key" in
                    HTTP_IP|HTTPS_IP|SOCKS5_IP)
                        if validate_ip "$value"; then
                            declare -g "$key=$value"
                        else
                            print_warning "无效的IP地址: $key=$value，使用默认值"
                        fi
                        ;;
                    HTTP_PORT|HTTPS_PORT|SOCKS5_PORT)
                        if validate_port "$value"; then
                            declare -g "$key=$value"
                        else
                            print_warning "无效的端口号: $key=$value，使用默认值"
                        fi
                        ;;
                    ENABLE_GIT_PROXY|ENABLE_NPM_PROXY|ENABLE_PIP_PROXY|ENABLE_DOCKER_PROXY)
                        if [[ "$value" == "0" || "$value" == "1" ]]; then
                            declare -g "$key=$value"
                        else
                            print_warning "无效的开关值: $key=$value，使用默认值"
                        fi
                        ;;
                esac
            fi
        done < "$CONFIG_FILE"
    else
        print_info "配置文件不存在，使用默认配置"
        save_config
    fi
}

# Git代理配置函数
configure_git_proxy() {
    local action=$1
    local protocol=${2:-"all"}  # 新增参数，用于指定当前启用的代理协议
    local http_proxy_url="http://$HTTP_IP:$HTTP_PORT"
    local https_proxy_url="http://$HTTPS_IP:$HTTPS_PORT"
    local socks_proxy_url="socks5h://$SOCKS5_IP:$SOCKS5_PORT"  # 修改为 socks5h
    
    if [ "$action" = "enable" ] && [ "$ENABLE_GIT_PROXY" = "1" ]; then
        # 根据协议类型设置不同的代理
        case $protocol in
            http)
                git config --global http.proxy "$http_proxy_url"
                git config --global https.proxy "$http_proxy_url"
                echo "已配置Git HTTP代理:"
                echo "  http.proxy  -> $http_proxy_url"
                echo "  https.proxy -> $http_proxy_url"
                ;;
            https)
                git config --global http.proxy "$https_proxy_url"
                git config --global https.proxy "$https_proxy_url"
                echo "已配置Git HTTPS代理:"
                echo "  http.proxy  -> $https_proxy_url"
                echo "  https.proxy -> $https_proxy_url"
                ;;
            socks5)
                git config --global http.proxy "$socks_proxy_url"
                git config --global https.proxy "$socks_proxy_url"
                echo "已配置Git SOCKS5代理:"
                echo "  http.proxy  -> $socks_proxy_url"
                echo "  https.proxy -> $socks_proxy_url"
                ;;
            all)
                git config --global http.proxy "$http_proxy_url"
                git config --global https.proxy "$http_proxy_url"
                echo "已配置Git代理:"
                echo "  http.proxy  -> $http_proxy_url"
                echo "  https.proxy -> $http_proxy_url"
                ;;
        esac
        
        # 根据操作系统设置SSL后端
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS 通常使用 OpenSSL
            git config --global http.sslBackend "openssl"
        elif [[ "$(uname)" == "Linux" ]]; then
            # 检查系统支持的 SSL 后端
            if git config --global http.sslBackend "gnutls" 2>/dev/null; then
                echo "已配置 Git SSL 后端: GnuTLS"
            elif git config --global http.sslBackend "openssl" 2>/dev/null; then
                echo "已配置 Git SSL 后端: OpenSSL"
            else
                # 如果都不支持，则不设置 SSL 后端
                git config --global --unset http.sslBackend
                echo "未配置 Git SSL 后端（使用系统默认值）"
            fi
        fi
    elif [ "$action" = "disable" ]; then
        git config --global --unset http.proxy
        git config --global --unset https.proxy
        git config --global --unset http.sslBackend
        echo "已清除Git代理配置"
    fi
}

# NPM代理配置函数
configure_npm_proxy() {
    local action=$1
    local protocol=${2:-"all"}
    local http_proxy_url="http://$HTTP_IP:$HTTP_PORT"
    local https_proxy_url="http://$HTTPS_IP:$HTTPS_PORT"
    local socks_proxy_url="socks5://$SOCKS5_IP:$SOCKS5_PORT"
    
    if [ "$action" = "enable" ] && [ "$ENABLE_NPM_PROXY" = "1" ]; then
        case $protocol in
            http)
                npm config set proxy "$http_proxy_url"
                npm config set https-proxy "$http_proxy_url"
                echo "已配置NPM HTTP代理:"
                echo "  proxy       -> $http_proxy_url"
                echo "  https-proxy -> $http_proxy_url"
                ;;
            https)
                npm config set proxy "$https_proxy_url"
                npm config set https-proxy "$https_proxy_url"
                echo "已配置NPM HTTPS代理:"
                echo "  proxy       -> $https_proxy_url"
                echo "  https-proxy -> $https_proxy_url"
                ;;
            socks5)
                npm config set proxy "$socks_proxy_url"
                npm config set https-proxy "$socks_proxy_url"
                echo "已配置NPM SOCKS5代理:"
                echo "  proxy       -> $socks_proxy_url"
                echo "  https-proxy -> $socks_proxy_url"
                ;;
            all)
                npm config set proxy "$http_proxy_url"
                npm config set https-proxy "$http_proxy_url"
                echo "已配置NPM代理:"
                echo "  proxy       -> $http_proxy_url"
                echo "  https-proxy -> $http_proxy_url"
                ;;
        esac
    elif [ "$action" = "disable" ]; then
        npm config delete proxy
        npm config delete https-proxy
        echo "已清除NPM代理配置"
    fi
}

# PIP代理配置函数
configure_pip_proxy() {
    local action=$1
    local protocol=${2:-"all"}
    local http_proxy_url="http://$HTTP_IP:$HTTP_PORT"
    local https_proxy_url="http://$HTTPS_IP:$HTTPS_PORT"
    local socks_proxy_url="socks5h://$SOCKS5_IP:$SOCKS5_PORT"  # 修改为 socks5h
    local pip_config_dir="$HOME/.config/pip"
    local pip_config_file="$pip_config_dir/pip.conf"
    
    if [ "$action" = "enable" ] && [ "$ENABLE_PIP_PROXY" = "1" ]; then
        mkdir -p "$pip_config_dir"
        
        case $protocol in
            http)
                cat > "$pip_config_file" <<EOF
[global]
proxy = $http_proxy_url
https_proxy = $http_proxy_url
EOF
                echo "已配置PIP HTTP代理:"
                echo "  proxy       -> $http_proxy_url"
                echo "  https_proxy -> $http_proxy_url"
                ;;
            https)
                cat > "$pip_config_file" <<EOF
[global]
proxy = $https_proxy_url
https_proxy = $https_proxy_url
EOF
                echo "已配置PIP HTTPS代理:"
                echo "  proxy       -> $https_proxy_url"
                echo "  https_proxy -> $https_proxy_url"
                ;;
            socks5)
                cat > "$pip_config_file" <<EOF
[global]
proxy = $socks_proxy_url
https_proxy = $socks_proxy_url
EOF
                echo "已配置PIP SOCKS5代理:"
                echo "  proxy       -> $socks_proxy_url"
                echo "  https_proxy -> $socks_proxy_url"
                ;;
            all)
                cat > "$pip_config_file" <<EOF
[global]
proxy = $http_proxy_url
https_proxy = $http_proxy_url
EOF
                echo "已配置PIP代理:"
                echo "  proxy       -> $http_proxy_url"
                echo "  https_proxy -> $http_proxy_url"
                ;;
        esac
    elif [ "$action" = "disable" ]; then
        rm -f "$pip_config_file"
        echo "已清除PIP代理配置"
    fi
}

# Docker代理配置函数
configure_docker_proxy() {
    local action=$1
    local protocol=${2:-"all"}
    local http_proxy_url="http://$HTTP_IP:$HTTP_PORT"
    local https_proxy_url="http://$HTTPS_IP:$HTTPS_PORT"
    local socks_proxy_url="socks5://$SOCKS5_IP:$SOCKS5_PORT"
    local docker_config_dir="$HOME/.docker"
    local docker_config_file="$docker_config_dir/config.json"
    local docker_daemon_dir="/etc/docker"
    local docker_daemon_file="$docker_daemon_dir/daemon.json"
    local docker_service_dir="/etc/systemd/system/docker.service.d"
    local docker_service_file="$docker_service_dir/http-proxy.conf"
    
    if [ "$action" = "enable" ] && [ "$ENABLE_DOCKER_PROXY" = "1" ]; then
        # 确保目录存在
        mkdir -p "$docker_config_dir"
        
        # 如果配置文件不存在，创建一个新的
        if [ ! -f "$docker_config_file" ]; then
            echo '{}' > "$docker_config_file"
        fi
        
        # 尝试配置 Docker 守护进程
        if [ -w "$docker_daemon_dir" ]; then
            sudo mkdir -p "$docker_daemon_dir"
            
            case $protocol in
                http)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$http_proxy_url"'",
      "httpsProxy": "'"$http_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}' | sudo tee "$docker_daemon_file" > /dev/null
                    echo "已配置Docker HTTP代理:"
                    echo "  HTTP_PROXY  -> $http_proxy_url"
                    echo "  HTTPS_PROXY -> $http_proxy_url"
                    ;;
                https)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$https_proxy_url"'",
      "httpsProxy": "'"$https_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}' | sudo tee "$docker_daemon_file" > /dev/null
                    echo "已配置Docker HTTPS代理:"
                    echo "  HTTP_PROXY  -> $https_proxy_url"
                    echo "  HTTPS_PROXY -> $https_proxy_url"
                    ;;
                socks5)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$socks_proxy_url"'",
      "httpsProxy": "'"$socks_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}' | sudo tee "$docker_daemon_file" > /dev/null
                    echo "已配置Docker SOCKS5代理:"
                    echo "  HTTP_PROXY  -> $socks_proxy_url"
                    echo "  HTTPS_PROXY -> $socks_proxy_url"
                    ;;
                all)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$http_proxy_url"'",
      "httpsProxy": "'"$http_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}' | sudo tee "$docker_daemon_file" > /dev/null
                    echo "已配置Docker代理:"
                    echo "  HTTP_PROXY  -> $http_proxy_url"
                    echo "  HTTPS_PROXY -> $http_proxy_url"
                    ;;
            esac
            
            # 重启 Docker 服务（如果有权限）
            if command -v systemctl >/dev/null 2>&1; then
                sudo systemctl daemon-reload
                sudo systemctl restart docker || true
            fi
        else
            # 提供手动配置指南
            echo "警告: 无法自动配置Docker代理（需要root权限）"
            echo "请按照以下步骤手动配置Docker代理："
            echo -e "\n1. 创建或编辑 Docker 守护进程配置文件："
            echo "   sudo mkdir -p $docker_daemon_dir"
            echo "   sudo nano $docker_daemon_file"
            echo -e "\n2. 在编辑器中添加以下内容："
            case $protocol in
                http)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$http_proxy_url"'",
      "httpsProxy": "'"$http_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}'
                    ;;
                https)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$https_proxy_url"'",
      "httpsProxy": "'"$https_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}'
                    ;;
                socks5)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$socks_proxy_url"'",
      "httpsProxy": "'"$socks_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}'
                    ;;
                all)
                    echo '{
  "proxies": {
    "default": {
      "httpProxy": "'"$http_proxy_url"'",
      "httpsProxy": "'"$http_proxy_url"'",
      "noProxy": "localhost,127.0.0.1"
    }
  }
}'
                    ;;
            esac
            
            echo -e "\n3. 创建 systemd 配置目录："
            echo "   sudo mkdir -p $docker_service_dir"
            
            echo -e "\n4. 创建代理配置文件："
            echo "   sudo nano $docker_service_file"
            
            echo -e "\n5. 在编辑器中添加以下内容："
            case $protocol in
                http)
                    echo "[Service]
Environment=\"HTTP_PROXY=$http_proxy_url\"
Environment=\"HTTPS_PROXY=$http_proxy_url\"
Environment=\"NO_PROXY=localhost,127.0.0.1\""
                    ;;
                https)
                    echo "[Service]
Environment=\"HTTP_PROXY=$https_proxy_url\"
Environment=\"HTTPS_PROXY=$https_proxy_url\"
Environment=\"NO_PROXY=localhost,127.0.0.1\""
                    ;;
                socks5)
                    echo "[Service]
Environment=\"HTTP_PROXY=$socks_proxy_url\"
Environment=\"HTTPS_PROXY=$socks_proxy_url\"
Environment=\"NO_PROXY=localhost,127.0.0.1\""
                    ;;
                all)
                    echo "[Service]
Environment=\"HTTP_PROXY=$http_proxy_url\"
Environment=\"HTTPS_PROXY=$http_proxy_url\"
Environment=\"NO_PROXY=localhost,127.0.0.1\""
                    ;;
            esac
            
            echo -e "\n6. 重新加载配置并重启 Docker 服务："
            echo "   sudo systemctl daemon-reload"
            echo "   sudo systemctl restart docker"
            
            echo -e "\n7. 验证配置是否生效："
            echo "   docker info | grep -i proxy"
            
            echo -e "\n注意："
            echo "- 如果使用的是其他编辑器，可以将 nano 替换为 vim 或其他编辑器"
            echo "- 确保 JSON 格式正确，不要有多余的逗号"
            echo "- 如果配置不生效，请检查 Docker 服务状态："
            echo "  sudo systemctl status docker"
        fi
    elif [ "$action" = "disable" ]; then
        if [ -w "$docker_daemon_dir" ]; then
            sudo rm -f "$docker_daemon_file"
            sudo rm -f "$docker_service_file"
            if command -v systemctl >/dev/null 2>&1; then
                sudo systemctl daemon-reload
                sudo systemctl restart docker || true
            fi
            echo "已清除Docker代理配置"
        else
            echo "警告: 无法自动清除Docker代理配置（需要root权限）"
            echo "请手动执行以下命令清除Docker代理配置："
            echo "1. 删除代理配置文件："
            echo "   sudo rm -f $docker_daemon_file"
            echo "   sudo rm -f $docker_service_file"
            echo "2. 重新加载配置并重启 Docker 服务："
            echo "   sudo systemctl daemon-reload"
            echo "   sudo systemctl restart docker"
        fi
    fi
}

# 工具代理状态检查函数
check_tool_proxy_status() {
    echo -e "\n工具代理状态:"
    
    # Git代理状态
    echo "Git:"
    if [ "$ENABLE_GIT_PROXY" = "1" ]; then
        echo "  http.proxy  -> $(git config --global http.proxy || echo '未设置')"
        echo "  https.proxy -> $(git config --global https.proxy || echo '未设置')"
    else
        echo "  已禁用"
    fi
    
    # NPM代理状态
    echo -e "\nNPM:"
    if [ "$ENABLE_NPM_PROXY" = "1" ]; then
        echo "  proxy       -> $(npm config get proxy || echo '未设置')"
        echo "  https-proxy -> $(npm config get https-proxy || echo '未设置')"
    else
        echo "  已禁用"
    fi
    
    # PIP代理状态
    echo -e "\nPIP:"
    if [ "$ENABLE_PIP_PROXY" = "1" ]; then
        if [ -f "$HOME/.config/pip/pip.conf" ]; then
            echo "  已配置 ($HOME/.config/pip/pip.conf)"
        else
            echo "  未配置"
        fi
    else
        echo "  已禁用"
    fi
    
    # Docker代理状态
    echo -e "\nDocker:"
    if [ "$ENABLE_DOCKER_PROXY" = "1" ]; then
        if [ -f "/etc/docker/daemon.json" ]; then
            echo "  已配置 (/etc/docker/daemon.json)"
        else
            echo "  未配置"
        fi
    else
        echo "  已禁用"
    fi
}

save_config() {
    # 确保配置目录存在
    mkdir -p "$(dirname "$CONFIG_FILE")"
    
    # 保存配置并确保写入成功
    cat > "$CONFIG_FILE" <<EOF || return 1
HTTP_IP='$HTTP_IP'
HTTP_PORT='$HTTP_PORT'
HTTPS_IP='$HTTPS_IP'
HTTPS_PORT='$HTTPS_PORT'
SOCKS5_IP='$SOCKS5_IP'
SOCKS5_PORT='$SOCKS5_PORT'
ENABLE_GIT_PROXY=$ENABLE_GIT_PROXY
ENABLE_NPM_PROXY=$ENABLE_NPM_PROXY
ENABLE_PIP_PROXY=$ENABLE_PIP_PROXY
ENABLE_DOCKER_PROXY=$ENABLE_DOCKER_PROXY
EOF
    
    # 验证配置文件是否成功创建
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Error: Failed to save configuration"
        return 1
    fi
}

# 核心功能
proxy() {
    case $1 in
        enable|disable|status|setdefault|test|--help|--version)
            cmd=$1
            shift
            ;;
        *)
            echo "Invalid command: $1"
            return 1
            ;;
    esac

    case $cmd in
        enable)
            local protocol="all" ip="" port="" nosave=0
            while [ $# -gt 0 ]; do
                case $1 in
                    -p|--protocol) protocol=$2; shift 2 ;;
                    --ip)          ip=$2;        shift 2 ;;
                    --port)        port=$2;      shift 2 ;;
                    --NoSave)      nosave=1;     shift ;;
                    *)             break ;;
                esac
            done
            
            load_config
            if [[ -z "$ip" || -z "$port" ]]; then
                case $protocol in
                    http)   ip=$HTTP_IP;   port=$HTTP_PORT ;;
                    https)  ip=$HTTPS_IP;  port=$HTTPS_PORT ;;
                    socks5) ip=$SOCKS5_IP; port=$SOCKS5_PORT ;;
                esac
            fi

            case $protocol in
                http)
                    export HTTP_PROXY="http://$ip:$port"
                    export http_proxy="$HTTP_PROXY"
                    [ $nosave -eq 0 ] && { HTTP_IP=$ip; HTTP_PORT=$port; save_config; }
                    # 配置工具代理
                    configure_git_proxy "enable" "http"
                    configure_npm_proxy "enable" "http"
                    configure_pip_proxy "enable" "http"
                    configure_docker_proxy "enable" "http"
                    ;;
                https)
                    export HTTPS_PROXY="http://$ip:$port"
                    export https_proxy="$HTTPS_PROXY"
                    [ $nosave -eq 0 ] && { HTTPS_IP=$ip; HTTPS_PORT=$port; save_config; }
                    # 配置工具代理
                    configure_git_proxy "enable" "https"
                    configure_npm_proxy "enable" "https"
                    configure_pip_proxy "enable" "https"
                    configure_docker_proxy "enable" "https"
                    ;;
                socks5)
                    export ALL_PROXY="socks5://$ip:$port"
                    export all_proxy="$ALL_PROXY"
                    [ $nosave -eq 0 ] && { SOCKS5_IP=$ip; SOCKS5_PORT=$port; save_config; }
                    # 配置工具代理
                    configure_git_proxy "enable" "socks5"
                    configure_npm_proxy "enable" "socks5"
                    configure_pip_proxy "enable" "socks5"
                    configure_docker_proxy "enable" "socks5"
                    ;;
                all)
                    export HTTP_PROXY="http://$ip:$port"
                    export http_proxy="$HTTP_PROXY"
                    export HTTPS_PROXY="$HTTP_PROXY"
                    export https_proxy="$HTTP_PROXY"
                    export ALL_PROXY="socks5://$ip:$port"
                    export all_proxy="$ALL_PROXY"
                    [ $nosave -eq 0 ] && {
                        HTTP_IP=$ip; HTTP_PORT=$port
                        HTTPS_IP=$ip; HTTPS_PORT=$port
                        SOCKS5_IP=$ip; SOCKS5_PORT=$port
                        save_config
                    }
                    # 配置工具代理
                    configure_git_proxy "enable" "all"
                    configure_npm_proxy "enable" "all"
                    configure_pip_proxy "enable" "all"
                    configure_docker_proxy "enable" "all"
                    ;;
            esac
            ;;

        disable)
            case $2 in
                -p|--protocol)
                    case $3 in
                        http)   unset HTTP_PROXY http_proxy ;;
                        https)  unset HTTPS_PROXY https_proxy ;;
                        socks5) unset ALL_PROXY all_proxy ;;
                        all)    
                            unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy
                            configure_git_proxy "disable"
                            configure_npm_proxy "disable"
                            configure_pip_proxy "disable"
                            configure_docker_proxy "disable"
                            ;;
                    esac
                    ;;
                *) 
                    unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy
                    configure_git_proxy "disable"
                    configure_npm_proxy "disable"
                    configure_pip_proxy "disable"
                    configure_docker_proxy "disable"
                    ;;
            esac
            ;;

        status)
            load_config
            echo -e "\n系统代理状态:"
            echo "HTTP:   ${HTTP_PROXY:-Disabled}"
            echo "HTTPS:  ${HTTPS_PROXY:-Disabled}"
            echo "SOCKS5: ${ALL_PROXY:-Disabled}"
            echo -e "\n默认配置:"
            echo "HTTP:   http://$HTTP_IP:$HTTP_PORT"
            echo "HTTPS:  http://$HTTPS_IP:$HTTPS_PORT"
            echo "SOCKS5: socks5://$SOCKS5_IP:$SOCKS5_PORT"
            
            # 显示工具代理状态
            check_tool_proxy_status
            ;;

        setdefault)
            load_config || { echo "Error: Failed to load configuration"; return 1; }
            local protocol="" ip="" port=""
            while [ $# -gt 0 ]; do
                case $1 in
                    -p|--protocol) protocol=$2; shift 2 ;;
                    --ip)          ip=$2;      shift 2 ;;
                    --port)        port=$2;    shift 2 ;;
                    *)             break ;;
                esac
            done

            # 验证必要参数
            if [[ -z "$protocol" || -z "$ip" || -z "$port" ]]; then
                echo "Error: Missing required parameters"
                echo "Usage: proxy setdefault -p <protocol> --ip <ip> --port <port>"
                echo "Example: proxy setdefault -p all --ip 127.0.0.1 --port 7890"
                return 1
            fi

            # 验证端口号
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                echo "Error: Invalid port number (must be between 1-65535)"
                return 1
            fi

            case $protocol in
                http)   
                    HTTP_IP=$ip
                    HTTP_PORT=$port
                    ;;
                https)  
                    HTTPS_IP=$ip
                    HTTPS_PORT=$port
                    ;;
                socks5) 
                    SOCKS5_IP=$ip
                    SOCKS5_PORT=$port
                    ;;
                all)    
                    HTTP_IP=$ip
                    HTTP_PORT=$port
                    HTTPS_IP=$ip
                    HTTPS_PORT=$port
                    SOCKS5_IP=$ip
                    SOCKS5_PORT=$port
                    ;;
                *)
                    echo "Error: Invalid protocol. Must be one of: http, https, socks5, all"
                    return 1
                    ;;
            esac
            
            if save_config; then
                echo "Default proxy settings updated successfully!"
                proxy status
            else
                echo "Error: Failed to save configuration"
                return 1
            fi
            ;;

        test)
            print_info "开始测试代理连接..."
            local test_urls=("http://httpbin.org/ip" "https://ip.sb" "http://ip-api.com/json")
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
            
            if [[ $success_count -gt 0 ]]; then
                print_success "代理测试完成: $success_count/${#test_urls[@]} 个测试成功"
                
                # 显示当前IP
                print_info "当前IP信息:"
                timeout 10 curl -sSf --connect-timeout 5 "http://ip-api.com/json" 2>/dev/null | \
                    python3 -m json.tool 2>/dev/null || \
                    timeout 10 curl -sSf --connect-timeout 5 "https://ip.sb" 2>/dev/null || \
                    echo "无法获取IP信息"
            else
                print_error "代理测试失败: 所有测试都未通过"
                return 1
            fi
            ;;

        --help)
            echo -e "\nLinux Proxy Manager 使用指南\n"
            echo "基本语法: proxy <命令> [选项]"
            echo -e "\n可用命令:"
            echo "  enable      启用代理"
            echo "  disable     禁用代理"
            echo "  status      显示当前代理状态"
            echo "  setdefault  设置默认代理配置"
            echo "  test        测试代理连接"
            echo -e "\n通用选项:"
            echo "  -p, --protocol  指定协议 (http/https/socks5/all)"
            echo "  --ip            指定代理服务器IP地址"
            echo "  --port          指定代理服务器端口"
            echo "  --NoSave        不保存当前配置（仅用于 enable 命令）"
            echo -e "\n支持的开发工具代理:"
            echo "  - Git"
            echo "  - NPM"
            echo "  - PIP"
            echo "  - Docker"
            echo -e "\n使用示例:"
            echo "1. 查看当前代理状态："
            echo "   proxy status"
            echo -e "\n2. 设置默认代理配置："
            echo "   proxy setdefault -p http --ip 127.0.0.1 --port 7890"
            echo "   proxy setdefault -p socks5 --ip 10.0.0.1 --port 7891"
            echo "   proxy setdefault -p all --ip 127.0.0.1 --port 7890"
            echo -e "\n3. 启用代理（使用默认配置）："
            echo "   proxy enable"
            echo "   proxy enable -p http"
            echo "   proxy enable -p socks5"
            echo -e "\n4. 启用代理（指定新配置）："
            echo "   proxy enable --ip 10.0.0.1 --port 8080"
            echo "   proxy enable -p http --ip 10.0.0.1 --port 8080"
            echo "   proxy enable -p socks5 --ip 10.0.0.1 --port 1080 --NoSave"
            echo -e "\n5. 禁用代理："
            echo "   proxy disable          # 禁用所有代理"
            echo "   proxy disable -p http  # 仅禁用 HTTP 代理"
            echo -e "\n6. 测试代理连接："
            echo "   proxy test"
            echo -e "\n注意事项:"
            echo "- 使用 setdefault 设置的配置会被保存，下次使用 enable 时会作为默认值"
            echo "- 使用 --NoSave 选项时，修改的配置仅在当前会话有效"
            echo "- 建议先使用 setdefault 设置好常用的代理配置"
            echo "- 使用 status 命令可以同时查看当前代理状态和默认配置"
            echo "- 如果不指定协议，默认会设置所有协议的代理"
            echo "- 工具代理（Git/NPM/PIP/Docker）会在启用系统代理时自动配置"
            ;;

        --version)
            echo -e "${BLUE}Linux/macOS Proxy Manager v2.0 Enhanced${NC}"
            echo "原作者: nanyuzuo"
            echo "增强版本: 添加了安全性、备份恢复、错误处理等功能"
            echo "支持平台: Linux, macOS"
            echo "支持工具: Git, NPM, PIP, Docker"
            ;;
    esac
}

EOL

    # 设置权限
    chmod +x "$PROXY_SCRIPT"
    chmod 600 "$CONFIG_FILE"  # 设置配置文件权限

    # 检测shell类型
    shell_type=$(detect_shell)
    case $shell_type in
        bash) rc_file="$HOME/.bashrc" ;;
        zsh)  rc_file="$HOME/.zshrc"  ;;
        *)    echo "Unsupported shell"; return 1 ;;
    esac

    # 添加自动加载
    if ! grep -q "source $PROXY_SCRIPT" "$rc_file"; then
        echo -e "\n# Proxy Manager\nsource $PROXY_SCRIPT" >> "$rc_file"
    fi

    # 立即加载脚本
    source "$PROXY_SCRIPT"
    
    echo -e "\n安装完成！"
    echo "请运行以下命令使配置生效："
    echo "source $rc_file"
    echo -e "\n以下是代理管理器的使用说明：\n"
    proxy --help
}

uninstall_proxy() {
    echo "开始卸载代理管理器..."
    
    # 1. 首先禁用所有代理
    if [ -f "$PROXY_DIR/proxy.sh" ]; then
        source "$PROXY_DIR/proxy.sh"
        proxy disable
    fi

    # 2. 清理环境变量
    unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy

    # 3. 清理 Git 配置
    echo "清理 Git 代理配置..."
    git config --global --unset http.proxy
    git config --global --unset https.proxy
    git config --global --unset http.sslBackend
    git config --global --unset https.sslBackend

    # 4. 清理 NPM 配置
    echo "清理 NPM 代理配置..."
    npm config delete proxy
    npm config delete https-proxy
    npm config delete registry

    # 5. 清理 PIP 配置
    echo "清理 PIP 代理配置..."
    local pip_config_dir="$HOME/.config/pip"
    local pip_config_file="$pip_config_dir/pip.conf"
    if [ -f "$pip_config_file" ]; then
        rm -f "$pip_config_file"
    fi

    # 6. 清理 Docker 配置
    echo "清理 Docker 代理配置..."
    local docker_daemon_dir="/etc/docker"
    local docker_daemon_file="$docker_daemon_dir/daemon.json"
    local docker_service_dir="/etc/systemd/system/docker.service.d"
    local docker_service_file="$docker_service_dir/http-proxy.conf"
    
    if [ -w "$docker_daemon_dir" ]; then
        sudo rm -f "$docker_daemon_file"
        sudo rm -f "$docker_service_file"
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl daemon-reload
            sudo systemctl restart docker || true
        fi
    else
        echo "注意: Docker 代理配置需要手动清理，请执行以下命令："
        echo "sudo rm -f $docker_daemon_file"
        echo "sudo rm -f $docker_service_file"
        echo "sudo systemctl daemon-reload"
        echo "sudo systemctl restart docker"
    fi

    # 7. 删除配置目录
    echo "删除代理管理器配置目录..."
    rm -rf "$PROXY_DIR"

    # 8. 清理 shell 配置文件
    echo "清理 shell 配置文件..."
    shell_type=$(detect_shell)
    case $shell_type in
        bash) rc_file="$HOME/.bashrc" ;;
        zsh)  rc_file="$HOME/.zshrc"  ;;
        *)    echo "警告: 未知的 shell 类型，请手动检查配置文件"; return 1 ;;
    esac

    # 使用临时文件来保存清理后的内容
    temp_file=$(mktemp)
    grep -v "# Proxy Manager" "$rc_file" | grep -v "source $PROXY_SCRIPT" > "$temp_file"
    mv "$temp_file" "$rc_file"

    echo -e "\n代理管理器卸载完成！"
    echo "请执行以下命令使更改生效："
    echo "source $rc_file"
    
    # 9. 显示验证步骤
    echo -e "\n请验证以下配置是否已清理："
    echo "1. 环境变量："
    echo "   echo \$HTTP_PROXY \$HTTPS_PROXY \$ALL_PROXY"
    echo "2. Git 配置："
    echo "   git config --global --get http.proxy"
    echo "   git config --global --get https.proxy"
    echo "3. NPM 配置："
    echo "   npm config get proxy"
    echo "   npm config get https-proxy"
    echo "4. PIP 配置："
    echo "   ls $pip_config_file"
    echo "5. Docker 配置："
    echo "   ls $docker_daemon_file"
    echo "   ls $docker_service_file"
    echo "6. 代理管理器文件："
    echo "   ls $PROXY_DIR"
}

# 恢复备份功能
restore_backup() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        print_error "没有找到备份目录"
        return 1
    fi
    
    local backups=($(ls -1t "$BACKUP_DIR" 2>/dev/null))
    if [[ ${#backups[@]} -eq 0 ]]; then
        print_error "没有可用的备份"
        return 1
    fi
    
    print_info "可用的备份:"
    for i in "${!backups[@]}"; do
        echo "  $((i+1)). ${backups[$i]}"
    done
    
    read -p "请选择要恢复的备份编号 (1-${#backups[@]}): " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#backups[@]} ]]; then
        local backup_path="$BACKUP_DIR/${backups[$((choice-1))]}"
        print_info "正在恢复备份: $backup_path"
        
        # 恢复shell配置文件
        for shell_rc in ".bashrc" ".zshrc" ".profile"; do
            if [[ -f "$backup_path/$shell_rc" ]]; then
                cp "$backup_path/$shell_rc" "$HOME/" 2>/dev/null || true
                print_success "已恢复: $HOME/$shell_rc"
            fi
        done
        
        # 恢复代理配置
        if [[ -d "$backup_path/proxy_config" ]]; then
            rm -rf "$PROXY_DIR"
            cp -r "$backup_path/proxy_config" "$PROXY_DIR" 2>/dev/null || true
            print_success "已恢复代理配置"
        fi
        
        print_success "备份恢复完成，请重新启动终端或运行 source ~/.bashrc 使配置生效"
    else
        print_error "无效的选择"
        return 1
    fi
}

# 查看日志功能
view_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        print_info "最近的日志记录:"
        tail -20 "$LOG_FILE"
    else
        print_info "没有日志文件"
    fi
}

# 错误处理函数（保留用于手动调用）
handle_error() {
    local error_code=$?
    local line_number=${1:-"unknown"}
    print_error "发生错误 (退出码: $error_code)"
    print_info "请检查日志文件: $LOG_FILE"
    return $error_code
}

# 主菜单
main() {
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
    while true; do
        show_menu
        read -p "请选择操作 (1-6): " choice
        case $choice in
            1) 
                if install_proxy; then
                    print_success "安装完成！"
                else
                    print_error "安装失败"
                fi
                echo -e "\n按回车键返回主菜单..."
                read
                ;;
            2) 
                if uninstall_proxy; then
                    print_success "卸载完成！"
                else
                    print_error "卸载失败"
                fi
                echo -e "\n按回车键返回主菜单..."
                read
                ;;
            3)
                create_backup
                echo -e "\n按回车键返回主菜单..."
                read
                ;;
            4)
                restore_backup
                echo -e "\n按回车键返回主菜单..."
                read
                ;;
            5)
                view_logs
                echo -e "\n按回车键返回主菜单..."
                read
                ;;
            6) 
                print_info "感谢使用代理管理器！"
                exit 0
                ;;
            *) 
                print_error "无效选项，请选择 1-6"
                ;;
        esac
    done
}

# 启动主程序
main "$@"

