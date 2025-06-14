#!/bin/bash

# 安装管理脚本
PROXY_DIR="$HOME/.proxy"
PROXY_SCRIPT="$PROXY_DIR/proxy.sh"
CONFIG_FILE="$PROXY_DIR/config"

show_menu() {
    clear
    echo "Linux Proxy Manager"
    echo "----------------------------------"
    echo "1. Install proxy function"
    echo "2. Uninstall proxy function"
    echo "3. Exit"
    echo "----------------------------------"
}

detect_shell() {
    case $(basename "$SHELL") in
        zsh)  echo "zsh"  ;;
        bash) echo "bash" ;;
        *)    echo ""     ;;
    esac
}

install_proxy() {
    # 创建配置目录
    mkdir -p "$PROXY_DIR" || { echo "Failed to create $PROXY_DIR"; exit 1; }

    # 初始化默认配置文件
    cat > "$CONFIG_FILE" <<EOL
HTTP_IP='127.0.0.1'
HTTP_PORT='7890'
HTTPS_IP='127.0.0.1'
HTTPS_PORT='7890'
SOCKS5_IP='127.0.0.1'
SOCKS5_PORT='7891'
EOL

    # 生成代理函数脚本
    cat > "$PROXY_SCRIPT" <<'EOL'
#!/bin/bash

# 配置管理
CONFIG_FILE="$HOME/.proxy/config"

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # 使用eval来安全地加载配置
        while IFS='=' read -r key value; do
            if [[ $key && $value ]]; then
                eval "$key=$value"
            fi
        done < "$CONFIG_FILE"
    else
        # 初始化默认配置
        HTTP_IP="127.0.0.1"
        HTTP_PORT="7890"
        HTTPS_IP="127.0.0.1"
        HTTPS_PORT="7890"
        SOCKS5_IP="127.0.0.1"
        SOCKS5_PORT="7891"
        save_config
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
EOF
    
    # 验证配置文件是否成功创建
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Error: Failed to save configuration file"
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
                    ;;
                https)
                    export HTTPS_PROXY="http://$ip:$port"
                    export https_proxy="$HTTPS_PROXY"
                    [ $nosave -eq 0 ] && { HTTPS_IP=$ip; HTTPS_PORT=$port; save_config; }
                    ;;
                socks5)
                    export ALL_PROXY="socks5://$ip:$port"
                    export all_proxy="$ALL_PROXY"
                    [ $nosave -eq 0 ] && { SOCKS5_IP=$ip; SOCKS5_PORT=$port; save_config; }
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
                        all)    unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy ;;
                    esac
                    ;;
                *) unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy ;;
            esac
            ;;

        status)
            load_config
            echo -e "\nCurrent Proxy Status:"
            echo "HTTP:   ${HTTP_PROXY:-Disabled}"
            echo "HTTPS:  ${HTTPS_PROXY:-Disabled}"
            echo "SOCKS5: ${ALL_PROXY:-Disabled}"
            echo -e "\nDefault Configuration:"
            echo "HTTP:   http://$HTTP_IP:$HTTP_PORT"
            echo "HTTPS:  http://$HTTPS_IP:$HTTPS_PORT"
            echo "SOCKS5: socks5://$SOCKS5_IP:$SOCKS5_PORT"
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
            curl -sSf --connect-timeout 5 http://ip-api.com/json && echo "Proxy test success" || echo "Proxy test failed"
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
            ;;

        --version)
            echo "Linux Proxy Manager v1.0"
            echo "Created By nanyuzuo"
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
    # 删除配置目录
    rm -rf "$PROXY_DIR"

    # 清理shell配置
    shell_type=$(detect_shell)
    case $shell_type in
        bash) rc_file="$HOME/.bashrc" ;;
        zsh)  rc_file="$HOME/.zshrc"  ;;
        *)    return 1 ;;
    esac

    sed -i '/# Proxy Manager/d' "$rc_file"
    sed -i "\|source $PROXY_SCRIPT|d" "$rc_file"

    echo "Proxy manager uninstalled. Please restart your shell."
}

# 主菜单
while true; do
    show_menu
    read -p "请选择操作 (1/2/3): " choice
    case $choice in
        1) 
            install_proxy
            echo -e "\n按回车键返回主菜单..."
            read
            ;;
        2) 
            uninstall_proxy
            echo -e "\n按回车键返回主菜单..."
            read
            ;;
        3) exit ;;
        *) echo "无效选项" ;;
    esac
done

