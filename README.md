# Proxy Manager

一个用于在命令行界面下灵活便捷设置和切换代理的工具集。支持 Windows PowerShell、Linux 和 macOS 环境。

## 功能特点

- 支持 HTTP、HTTPS 和 SOCKS5 代理协议
- 支持单独设置或同时设置多种代理
- 支持保存默认配置，方便快速切换
- 支持查看当前代理状态
- 支持代理连接测试
- 支持临时代理设置（不保存配置）

## 安装说明

### Windows PowerShell

1. 下载 `proxy4powershell.ps1` 到本地
2. 运行脚本进行安装：
```powershell
.\proxy4powershell.ps1
```
3. 在弹出的菜单中选择 `1` 进行安装
4. 根据提示重启 PowerShell 或执行 `. $PROFILE` 使配置生效

### Linux/macOS

1. 下载 `proxy4linux.sh` 到本地
2. 运行脚本进行安装：
```bash
bash proxy4linux.sh
```
3. 在弹出的菜单中选择 `1` 进行安装
4. 根据提示执行 `source ~/.bashrc` 或 `source ~/.zshrc` 使配置生效

## 基本用法

### Linux/macOS 版本

#### 命令格式
```bash
proxy <命令> [选项]
```

#### 可用命令
- `enable`: 启用代理
- `disable`: 禁用代理
- `status`: 显示当前代理状态
- `setdefault`: 设置默认代理配置
- `test`: 测试代理连接
- `--help`: 显示帮助信息
- `--version`: 显示版本信息

#### 通用选项
- `-p, --protocol`: 指定协议 (http/https/socks5/all)
- `--ip`: 指定代理服务器IP地址
- `--port`: 指定代理服务器端口
- `--NoSave`: 不保存当前配置（仅用于 enable 命令）

### Windows PowerShell 版本

#### 命令格式
```powershell
proxy <命令> [-protocol <协议>] [-ip <IP地址>] [-port <端口>] [-NoSave]
```

#### 可用命令
- `enable`: 启用代理
- `disable`: 禁用代理
- `status`: 显示当前代理状态
- `setdefault`: 设置默认代理配置
- `test`: 测试代理连接
- `curltest`: 生成 curl 测试命令
- `-V` 或 `-version`: 显示版本信息
- `-h` 或 `-help`: 显示帮助信息

#### 通用选项
- `-protocol`: 指定协议 (http/https/socks5/all)
- `-ip`: 指定代理服务器IP地址
- `-port`: 指定代理服务器端口
- `-NoSave`: 不保存当前配置（仅用于 enable 命令）

#### PowerShell 特有功能
- Windows 系统代理自动配置（SOCKS5）
- 内置 curl 命令测试工具
- 更详细的代理连接测试信息
- Windows 防火墙相关提示

## 使用示例（以 Clash 为例）

假设 Clash 的默认配置为：
- HTTP/HTTPS 代理：127.0.0.1:7890
- SOCKS5 代理：127.0.0.1:7891

### Linux/macOS 环境

```bash
# 设置所有协议的默认代理
proxy setdefault -p all --ip 127.0.0.1 --port 7890

# 单独设置 SOCKS5 代理
proxy setdefault -p socks5 --ip 127.0.0.1 --port 7891

# 启用所有代理
proxy enable

# 临时启用 HTTP 代理（不保存配置）
proxy enable -p http --ip 127.0.0.1 --port 7890 --NoSave

# 查看代理设置情况
proxy status

# 禁用特定协议代理
proxy disable -p http
# 禁用所有协议代理
proxy disable 
# 测试代理连接（包含详细信息，返回当前ip以验证是否以实现代理）
proxy test
```

### Windows PowerShell 环境

```powershell
# 设置所有协议的默认代理
proxy setdefault -protocol all -ip 127.0.0.1 -port 7890

# 单独设置 SOCKS5 代理
proxy setdefault -protocol socks5 -ip 127.0.0.1 -port 7891

# 启用所有代理
proxy enable

# 启用socks5代理
proxy enable -protocol socks5 

# 临时启用 HTTP 代理（不保存配置）
proxy enable -protocol http -ip 127.0.0.1 -port 7890 -NoSave

# 查看代理设置情况
proxy status

# 测试代理连接（包含详细信息，返回当前ip以验证是否以实现代理）
proxy test

# 生成 curl 测试命令
proxy curltest
```

## 配置文件位置

- Windows PowerShell: `$HOME\proxyconfig.xml`
- Linux/macOS: `$HOME/.proxy/config`

## 注意事项

1. PowerShell 环境下的 SOCKS5 代理会同时设置环境变量和 Windows 系统代理
2. PowerShell 版本提供更详细的代理测试功能和 curl 命令生成工具
3. Linux/macOS 版本使用双横线参数（如 `--protocol`），而 PowerShell 版本使用单横线参数（如 `-protocol`）
4. 某些应用可能需要重启才能识别代理更改
5. 使用 `--NoSave` 或 `-NoSave` 选项时，修改的配置仅在当前会话有效
6. 建议先使用 `setdefault` 设置好常用的代理配置
7. 使用 `status` 命令可以同时查看当前代理状态和默认配置

## 卸载说明

### Windows PowerShell

1. 运行脚本：`.\proxy4powershell.ps1`
2. 在菜单中选择 `2` 进行卸载
3. 重启 PowerShell 或执行 `. $PROFILE` 使更改生效

### Linux/macOS

1. 运行脚本：`./proxy4linux.sh`
2. 在菜单中选择 `2` 进行卸载
3. 重启终端或重新加载配置文件使更改生效
