# 透明代理安装和使用指南

## 🛠️ 修复的权限问题

原来的透明代理配置存在权限问题，现在已修复：

### ✅ 修复内容
1. **权限预检查** - 在配置前检查sudo权限
2. **友好的权限提示** - 明确告知需要管理员权限的原因
3. **错误处理** - 详细的错误信息和故障排除提示
4. **依赖检查** - 自动检查redsocks和iptables是否可用

## 📋 透明代理要求

### 系统要求
- **Linux系统** (Ubuntu/Debian/CentOS/RHEL等)
- **管理员权限** (sudo)
- **redsocks包** (自动安装检查)
- **iptables** (通常系统自带)

### macOS限制
- macOS不支持完整的透明代理功能
- 建议macOS用户使用常规代理模式

## 🚀 使用步骤

### 1. 安装依赖
```bash
# 首次使用需要安装依赖
proxy install-deps

# 这将检查并安装:
# - redsocks (透明代理核心组件)
# - iptables (流量重定向)
```

### 2. 启用透明代理
```bash
# 使用默认配置启用透明代理
proxy enable --transparent

# 或指定具体的代理配置
proxy enable -p socks5 --ip 127.0.0.1 --port 1080 --transparent
```

### 3. 验证透明代理状态
```bash
# 查看代理状态
proxy status

# 应该显示:
# 透明代理: 已启用
# 系统代理状态: [各种协议状态]
```

### 4. 测试透明代理
```bash
# 测试代理连接
proxy test

# 验证IP变化
curl https://ip.sb
# 应该显示代理服务器的IP地址
```

## 🔧 故障排除

### 权限问题
```bash
# 错误: Permission denied
# 解决: 确保有sudo权限
sudo -v  # 验证sudo权限

# 如果没有sudo权限，联系系统管理员
```

### redsocks未安装
```bash
# 错误: redsocks未安装
# 解决: 运行依赖安装
proxy install-deps

# 手动安装 (Ubuntu/Debian)
sudo apt-get install redsocks

# 手动安装 (CentOS/RHEL)
sudo yum install redsocks
# 或
sudo dnf install redsocks
```

### 端口冲突
```bash
# 错误: redsocks启动失败
# 原因: 端口12345被占用

# 检查端口占用
sudo netstat -tlnp | grep 12345
# 或
sudo ss -tlnp | grep 12345

# 停止占用端口的进程或修改配置
```

### iptables规则问题
```bash
# 错误: 无法添加iptables规则
# 检查iptables状态
sudo iptables -t nat -L

# 清理现有规则 (谨慎操作)
proxy disable  # 这会清理代理相关的iptables规则
```

## ⚠️ 重要注意事项

### 1. 管理员权限
- 透明代理需要修改系统网络配置
- 需要root权限创建redsocks配置和iptables规则
- 首次运行会提示输入密码

### 2. 网络影响
- 透明代理会影响所有TCP连接
- 本地和内网连接会被排除(127.0.0.1, 10.x.x.x, 192.168.x.x)
- 停用代理会恢复正常网络配置

### 3. 安全考虑
- 只在可信任的网络环境中使用
- 代理服务器应该是可信任的
- 定期检查透明代理状态

### 4. 性能影响
- 透明代理会有轻微的性能开销
- 不影响本地和内网连接的性能
- 可以随时禁用恢复正常模式

## 📱 使用示例

### 完整工作流程
```bash
# 1. 安装脚本
bash proxy4linux.sh
# 选择 1 安装

# 2. 激活配置
source ~/.zshrc  # 或 source ~/.bashrc

# 3. 安装依赖
proxy install-deps

# 4. 配置代理服务器信息
proxy setdefault -p socks5 --ip 127.0.0.1 --port 1080

# 5. 启用透明代理
proxy enable --transparent

# 6. 验证工作状态
proxy status
proxy test

# 7. 正常使用 - 所有程序自动走代理
curl https://google.com     # 自动通过代理
wget https://github.com     # 自动通过代理
git clone https://...       # 自动通过代理

# 8. 禁用透明代理
proxy disable
```

## 🎯 优势对比

### vs proxychains4
| 功能 | proxychains4 | 透明代理 |
|------|-------------|----------|
| 使用方式 | `proxychains4 command` | 直接运行 `command` |
| 覆盖范围 | 单个命令 | 全系统TCP流量 |
| 配置复杂度 | 需要修改配置文件 | 一键启用 |
| 性能影响 | 每个命令启动开销 | 系统级透明处理 |

**结论**: 透明代理提供了更好的用户体验，真正实现了"设置一次，到处使用"的目标。