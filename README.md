# 增强版代理管理器 v3.0

**完整终端代理解决方案 - 无需proxychains4！**

## 新功能亮点

### 🚀 核心改进
- **透明代理支持** - 真正的系统级代理，支持所有应用程序
- **SOCKS5完整支持** - 包装器和透明代理双重保障
- **智能命令包装** - 自动为curl、wget等工具添加代理支持
- **代理规则管理** - 精确控制哪些流量走代理
- **状态持久化** - 跨终端会话保持代理状态

### 💻 平台支持
- **Linux/macOS**: 基于redsocks + iptables的透明代理
- **Windows**: 系统代理集成 + 第三方工具支持

## 安装使用

### Linux/macOS 版本

```bash
# 1. 运行增强版安装脚本
bash proxy4linux_enhanced.sh

# 2. 选择菜单选项1进行安装

# 3. 安装透明代理依赖
proxy install-deps

# 4. 基本使用
proxy enable --transparent          # 启用透明代理
proxy enable -p socks5 --ip 127.0.0.1 --port 1080
proxy status                       # 查看详细状态
proxy test                        # 测试代理连接
proxy rules init                  # 初始化代理规则
```

### Windows PowerShell 版本

```powershell
# 1. 运行增强版安装脚本
.\proxy4powershell_enhanced.ps1

# 2. 选择菜单选项1进行安装

# 3. 基本使用
proxy enable -SystemProxy         # 启用系统代理
proxy enable -Protocol socks5 -IP 127.0.0.1 -Port 1080
proxy status                     # 查看详细状态
proxy test                      # 测试代理连接
proxy rules init               # 初始化代理规则
```

## 主要特性

### 1. 透明代理 (Linux/macOS)
- 使用 `redsocks` 实现真正的透明代理
- 自动配置 iptables 规则
- 支持所有TCP流量代理
- 无需修改应用程序配置

```bash
# 启用透明代理
proxy enable --transparent -p socks5 --ip 127.0.0.1 --port 1080

# 所有程序自动通过代理，包括：
curl https://google.com      # 无需手动配置
wget https://github.com      # 自动使用代理
ssh user@server             # SSH连接也走代理
```

### 2. 智能命令包装器
- 自动为常用命令添加代理支持
- 包装器位置：`~/.proxy/wrappers/`
- 支持 curl、wget 等命令

```bash
# 包装器会自动检测代理状态
curl https://httpbin.org/ip  # 自动使用SOCKS5或HTTP代理
wget https://example.com     # 自动配置代理参数
```

### 3. 代理规则管理
- 支持域名、IP、端口规则
- 直连、代理、阻止三种动作
- 配置文件：`~/.proxy/rules.conf`

```bash
# 规则管理
proxy rules init    # 创建默认规则
proxy rules list    # 查看当前规则
proxy rules edit    # 编辑规则文件

# 规则格式示例
DIRECT:domain:*.cn           # 中国域名直连
PROXY:domain:*.google.com    # Google域名走代理
BLOCK:domain:*.ads.com       # 阻止广告域名
```

### 4. 增强工具集成
- **Git**: 自动配置 http.proxy 和 https.proxy
- **NPM**: 自动设置 proxy 和 https-proxy
- **Docker**: 自动配置 daemon 代理
- **SSH**: 生成 ProxyCommand 配置
- **浏览器**: 生成启动脚本和配置文件

### 5. 状态管理
- 持久化状态文件
- 跨终端会话保持设置
- 详细的状态显示

```bash
# 查看完整状态
proxy status

# 输出示例:
=== 增强代理管理器状态 ===

系统代理状态:
  HTTP:   http://127.0.0.1:7890
  HTTPS:  http://127.0.0.1:7890
  SOCKS5: socks5://127.0.0.1:1080

透明代理: 已启用

工具代理状态:
  Git:    http://127.0.0.1:7890
  NPM:    http://127.0.0.1:7890

最后更新: 2025-01-15 14:30:25
```

## 与 proxychains4 的对比

| 功能 | proxychains4 | 增强版代理管理器 |
|------|-------------|-----------------|
| 透明代理 | ❌ 需要前缀命令 | ✅ 真正透明代理 |
| 系统集成 | ❌ 应用程序单独配置 | ✅ 自动配置常用工具 |
| 规则管理 | ❌ 基本配置 | ✅ 完整规则系统 |
| 状态管理 | ❌ 无状态 | ✅ 持久化状态 |
| Windows支持 | ❌ Linux/macOS only | ✅ 跨平台支持 |
| 易用性 | ❌ 需要学习配置 | ✅ 开箱即用 |

## 使用场景

### 1. 开发环境
```bash
# 一键启用开发代理
proxy enable --transparent
# Git、NPM、Docker等工具自动配置完成
git clone https://github.com/user/repo  # 自动走代理
npm install                             # 自动走代理
```

### 2. 服务器管理
```bash
# 临时代理访问
proxy enable --NoSave -p socks5 --ip proxy-server --port 1080
ssh user@target-server  # SSH连接走代理
```

### 3. 网络测试
```bash
# 测试代理连通性
proxy test
# 查看代理后的IP
curl https://ip.sb
```

## 依赖要求

### Linux/macOS
- bash 4.0+
- curl
- redsocks (透明代理)
- iptables (透明代理)
- git, npm, docker (可选)

### Windows
- PowerShell 5.0+
- curl (Windows 10+自带)
- git, npm, docker (可选)

## 故障排除

### 透明代理无法启动
```bash
# 检查redsocks安装
which redsocks

# 手动安装redsocks
# Ubuntu/Debian
sudo apt-get install redsocks

# CentOS/RHEL
sudo yum install redsocks

# macOS
brew install redsocks
```

### 权限问题
```bash
# Linux需要sudo权限配置iptables
sudo ./proxy4linux_enhanced.sh
```

### 代理不生效
```bash
# 检查环境变量
env | grep -i proxy

# 检查状态
proxy status

# 重新加载shell配置
source ~/.bashrc  # 或 source ~/.zshrc
```

## 高级配置

### 自定义规则文件
编辑 `~/.proxy/rules.conf`:
```
# 企业内网直连
DIRECT:ip:10.0.0.0/8
DIRECT:domain:*.company.com

# 开发工具走代理
PROXY:domain:*.github.com
PROXY:domain:*.npmjs.org
PROXY:domain:*.docker.io

# 阻止恶意域名
BLOCK:domain:*.malware.com
```

### 多代理配置
```bash
# 设置不同协议的代理
proxy setdefault -p http --ip proxy1.com --port 8080
proxy setdefault -p socks5 --ip proxy2.com --port 1080

# 启用特定协议
proxy enable -p socks5
```

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

## 许可证

本项目基于原版代理管理器进行增强，保持开源精神。