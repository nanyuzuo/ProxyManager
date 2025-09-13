# Enhanced PowerShell Proxy Manager v3.0
# 增强版Windows代理管理脚本 - 完整终端代理解决方案
# Author: Enhanced by Claude Code
# Features: 系统代理集成、透明代理、增强工具支持、代理规则管理

param(
    [Parameter(Position=0)]
    [ValidateSet("enable", "disable", "status", "setdefault", "test", "rules", "install-deps", "help", "curltest", IgnoreCase=$true)]
    [string]$Action = "status",
    
    [Parameter()]
    [ValidateSet("http", "https", "socks5", "all", IgnoreCase=$true)]
    [string]$Protocol = "all",
    
    [Parameter()]
    [string]$IP,
    
    [Parameter()]
    [int]$Port,
    
    [Parameter()]
    [switch]$NoSave,
    
    [Parameter()]
    [switch]$Transparent,
    
    [Parameter()]
    [switch]$SystemProxy,
    
    [Parameter()]
    [Alias("V", "version")]
    [switch]$Version,
    
    [Parameter()]
    [Alias("h", "help")]
    [switch]$Help
)

# 全局配置
$script:ProxyDir = "$env:USERPROFILE\.proxy"
$script:ConfigFile = "$script:ProxyDir\config.xml"
$script:RulesFile = "$script:ProxyDir\rules.conf"
$script:StateFile = "$script:ProxyDir\proxy.state.xml"
$script:WrapperDir = "$script:ProxyDir\wrappers"
$script:LogFile = "$script:ProxyDir\proxy.log"

# 颜色配置
$script:Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Debug = "Magenta"
}

# 日志函数
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # 忽略日志写入错误
    }
}

# 彩色输出函数
function Write-ColorOutput {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$Type = "Info"
    )
    
    $color = $script:Colors[$Type]
    Write-Host "[$Type] $Message" -ForegroundColor $color
    Write-Log -Message $Message -Level $Type.ToUpper()
}

# 检查管理员权限
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 验证IP地址
function Test-IPAddress {
    param([string]$IP)
    
    if ([string]::IsNullOrEmpty($IP)) { return $false }
    
    # 检查IP格式
    if ($IP -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
        return $true
    }
    
    # 检查域名格式
    if ($IP -match '^[a-zA-Z0-9.-]+$' -or $IP -eq "localhost") {
        return $true
    }
    
    return $false
}

# 验证端口号
function Test-Port {
    param([int]$Port)
    return ($Port -ge 1 -and $Port -le 65535)
}

# 创建目录结构
function Initialize-ProxyDirectories {
    $dirs = @($script:ProxyDir, "$script:ProxyDir\backup", $script:WrapperDir)
    
    foreach ($dir in $dirs) {
        if (!(Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

# 创建默认配置
function Initialize-DefaultConfig {
    $config = @{
        HTTP_IP = "127.0.0.1"
        HTTP_PORT = 7890
        HTTPS_IP = "127.0.0.1"
        HTTPS_PORT = 7890
        SOCKS5_IP = "127.0.0.1"
        SOCKS5_PORT = 7891
        ENABLE_SYSTEM_PROXY = $true
        ENABLE_GIT_PROXY = $true
        ENABLE_NPM_PROXY = $true
        ENABLE_DOCKER_PROXY = $true
        LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $config | Export-Clixml -Path $script:ConfigFile -Force
    Write-ColorOutput "默认配置已创建: $script:ConfigFile" "Success"
}

# 加载配置
function Get-ProxyConfig {
    if (Test-Path $script:ConfigFile) {
        try {
            return Import-Clixml -Path $script:ConfigFile
        } catch {
            Write-ColorOutput "配置文件损坏，重新创建默认配置" "Warning"
            Initialize-DefaultConfig
            return Import-Clixml -Path $script:ConfigFile
        }
    } else {
        Initialize-DefaultConfig
        return Import-Clixml -Path $script:ConfigFile
    }
}

# 保存配置
function Save-ProxyConfig {
    param($Config)
    
    $Config.LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Config | Export-Clixml -Path $script:ConfigFile -Force
}

# 创建状态文件
function Initialize-StateFile {
    $state = @{
        PROXY_ENABLED = $false
        PROXY_MODE = ""
        SYSTEM_PROXY_ENABLED = $false
        TRANSPARENT_PROXY = $false
        CURRENT_HTTP_PROXY = ""
        CURRENT_HTTPS_PROXY = ""
        CURRENT_SOCKS_PROXY = ""
        RULES_ENABLED = $false
        LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $state | Export-Clixml -Path $script:StateFile -Force
}

# 加载状态
function Get-ProxyState {
    if (Test-Path $script:StateFile) {
        try {
            return Import-Clixml -Path $script:StateFile
        } catch {
            Initialize-StateFile
            return Import-Clixml -Path $script:StateFile
        }
    } else {
        Initialize-StateFile
        return Import-Clixml -Path $script:StateFile
    }
}

# 保存状态
function Save-ProxyState {
    param($State)
    
    $State.LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $State | Export-Clixml -Path $script:StateFile -Force
}

# 创建默认代理规则
function Initialize-ProxyRules {
    $rules = @"
# Enhanced Proxy Rules Configuration
# Format: ACTION:TYPE:PATTERN
# ACTION: DIRECT, PROXY, BLOCK
# TYPE: domain, ip, port, process

# 直连规则 - 本地和内网地址
DIRECT:ip:127.0.0.1
DIRECT:ip:localhost
DIRECT:ip:10.0.0.0/8
DIRECT:ip:172.16.0.0/12
DIRECT:ip:192.168.0.0/16
DIRECT:domain:*.local
DIRECT:domain:*.lan

# 中国大陆直连域名
DIRECT:domain:*.cn
DIRECT:domain:*.baidu.com
DIRECT:domain:*.qq.com
DIRECT:domain:*.taobao.com
DIRECT:domain:*.aliyun.com
DIRECT:domain:*.163.com
DIRECT:domain:*.sina.com.cn
DIRECT:domain:*.weibo.com
DIRECT:domain:*.zhihu.com

# 需要代理的域名
PROXY:domain:*.google.com
PROXY:domain:*.youtube.com
PROXY:domain:*.facebook.com
PROXY:domain:*.twitter.com
PROXY:domain:*.github.com
PROXY:domain:*.stackoverflow.com
PROXY:domain:*.reddit.com
PROXY:domain:*.wikipedia.org

# 阻止的域名 - 广告和恶意网站
BLOCK:domain:*.doubleclick.net
BLOCK:domain:*.googlesyndication.com
BLOCK:domain:*.googleadservices.com
BLOCK:domain:ad.*.com
"@
    
    Set-Content -Path $script:RulesFile -Value $rules -Encoding UTF8
    Write-ColorOutput "默认代理规则已创建: $script:RulesFile" "Success"
}

# Windows系统代理配置
function Set-WindowsSystemProxy {
    param(
        [string]$Action,
        [string]$HttpProxy = "",
        [string]$SocksProxy = ""
    )
    
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    try {
        switch ($Action.ToLower()) {
            "enable" {
                if (![string]::IsNullOrEmpty($HttpProxy)) {
                    Set-ItemProperty -Path $registryPath -Name "ProxyServer" -Value $HttpProxy
                    Set-ItemProperty -Path $registryPath -Name "ProxyEnable" -Value 1
                    Write-ColorOutput "Windows系统HTTP代理已启用: $HttpProxy" "Success"
                }
                
                if (![string]::IsNullOrEmpty($SocksProxy)) {
                    # SOCKS代理设置较复杂，需要通过ProxyServer字符串格式
                    $proxyString = "socks=$SocksProxy"
                    if (![string]::IsNullOrEmpty($HttpProxy)) {
                        $proxyString = "http=$HttpProxy;https=$HttpProxy;socks=$SocksProxy"
                    }
                    Set-ItemProperty -Path $registryPath -Name "ProxyServer" -Value $proxyString
                    Set-ItemProperty -Path $registryPath -Name "ProxyEnable" -Value 1
                    Write-ColorOutput "Windows系统SOCKS代理已启用: $SocksProxy" "Success"
                }
                
                # 设置代理覆盖列表
                $bypassList = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"
                Set-ItemProperty -Path $registryPath -Name "ProxyOverride" -Value $bypassList
            }
            
            "disable" {
                Set-ItemProperty -Path $registryPath -Name "ProxyEnable" -Value 0
                Write-ColorOutput "Windows系统代理已禁用" "Success"
            }
        }
        
        # 通知系统代理设置已更改
        $signature = @'
[DllImport("wininet.dll")]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
        
        $wininet = Add-Type -MemberDefinition $signature -Name WinINet -Namespace InternetSettings -PassThru
        $wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
        $wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
        
    } catch {
        Write-ColorOutput "配置Windows系统代理失败: $($_.Exception.Message)" "Error"
    }
}

# 配置增强工具代理
function Set-EnhancedToolsProxy {
    param(
        [string]$Action,
        [string]$HttpProxy = "",
        [string]$SocksProxy = ""
    )
    
    switch ($Action.ToLower()) {
        "enable" {
            Write-ColorOutput "配置增强工具代理..." "Info"
            
            # Git配置
            if (Get-Command git -ErrorAction SilentlyContinue) {
                if (![string]::IsNullOrEmpty($HttpProxy)) {
                    git config --global http.proxy $HttpProxy
                    git config --global https.proxy $HttpProxy
                    Write-ColorOutput "Git代理已配置: $HttpProxy" "Success"
                }
            }
            
            # NPM配置
            if (Get-Command npm -ErrorAction SilentlyContinue) {
                if (![string]::IsNullOrEmpty($HttpProxy)) {
                    npm config set proxy $HttpProxy
                    npm config set https-proxy $HttpProxy
                    Write-ColorOutput "NPM代理已配置: $HttpProxy" "Success"
                }
            }
            
            # Docker配置
            if (Get-Command docker -ErrorAction SilentlyContinue) {
                $dockerConfigDir = "$env:USERPROFILE\.docker"
                if (!(Test-Path $dockerConfigDir)) {
                    New-Item -Path $dockerConfigDir -ItemType Directory -Force | Out-Null
                }
                
                $dockerConfig = @{
                    proxies = @{
                        default = @{
                            httpProxy = $HttpProxy
                            httpsProxy = $HttpProxy
                            noProxy = "localhost,127.0.0.1"
                        }
                    }
                }
                
                $dockerConfig | ConvertTo-Json -Depth 3 | Set-Content -Path "$dockerConfigDir\config.json" -Encoding UTF8
                Write-ColorOutput "Docker代理已配置" "Success"
            }
            
            # 创建命令包装器
            Create-CommandWrappers $HttpProxy $SocksProxy
        }
        
        "disable" {
            Write-ColorOutput "禁用增强工具代理..." "Info"
            
            # 清理Git配置
            if (Get-Command git -ErrorAction SilentlyContinue) {
                git config --global --unset http.proxy 2>$null
                git config --global --unset https.proxy 2>$null
            }
            
            # 清理NPM配置
            if (Get-Command npm -ErrorAction SilentlyContinue) {
                npm config delete proxy 2>$null
                npm config delete https-proxy 2>$null
            }
            
            Write-ColorOutput "增强工具代理已禁用" "Success"
        }
    }
}

# 创建命令包装器
function Create-CommandWrappers {
    param(
        [string]$HttpProxy,
        [string]$SocksProxy
    )
    
    # PowerShell curl包装器函数
    $curlWrapper = @"
function Invoke-ProxyCurl {
    param([Parameter(ValueFromRemainingArguments=`$true)]`$Arguments)
    
    `$proxyArgs = @()
    if ("`$env:CURRENT_SOCKS_PROXY") {
        `$proxyArgs += "--socks5", "`$env:CURRENT_SOCKS_PROXY"
    } elseif ("`$env:CURRENT_HTTP_PROXY") {
        `$proxyArgs += "--proxy", "`$env:CURRENT_HTTP_PROXY"
    }
    
    if (`$proxyArgs.Count -gt 0) {
        & curl @proxyArgs @Arguments
    } else {
        & curl @Arguments
    }
}

Set-Alias -Name curl -Value Invoke-ProxyCurl -Force -Scope Global
"@
    
    $wrapperFile = "$script:WrapperDir\ProxyWrappers.ps1"
    Set-Content -Path $wrapperFile -Value $curlWrapper -Encoding UTF8
    
    Write-ColorOutput "命令包装器已创建: $wrapperFile" "Success"
}

# 透明代理支持（Windows）
function Set-TransparentProxy {
    param(
        [string]$Action,
        [string]$ProxyIP,
        [int]$ProxyPort
    )
    
    switch ($Action.ToLower()) {
        "enable" {
            if (!(Test-Administrator)) {
                Write-ColorOutput "透明代理需要管理员权限，请以管理员身份运行" "Warning"
                return
            }
            
            Write-ColorOutput "Windows透明代理功能需要第三方工具支持" "Info"
            Write-ColorOutput "建议安装: Proxifier, SocksCap64, 或 v2rayN" "Info"
            
            # 这里可以添加与第三方工具的集成
        }
        
        "disable" {
            Write-ColorOutput "透明代理已禁用" "Success"
        }
    }
}

# 主代理控制函数
function Invoke-ProxyControl {
    param(
        [string]$Action,
        [string]$Protocol = "all",
        [string]$IP = "",
        [int]$Port = 0,
        [switch]$NoSave,
        [switch]$Transparent,
        [switch]$SystemProxy
    )
    
    $config = Get-ProxyConfig
    $state = Get-ProxyState
    
    switch ($Action.ToLower()) {
        "enable" {
            # 使用默认配置或命令行参数
            if ([string]::IsNullOrEmpty($IP) -or $Port -eq 0) {
                switch ($Protocol.ToLower()) {
                    "http" { $IP = $config.HTTP_IP; $Port = $config.HTTP_PORT }
                    "https" { $IP = $config.HTTPS_IP; $Port = $config.HTTPS_PORT }
                    "socks5" { $IP = $config.SOCKS5_IP; $Port = $config.SOCKS5_PORT }
                    "all" { $IP = $config.HTTP_IP; $Port = $config.HTTP_PORT }
                }
            }
            
            # 验证参数
            if (!(Test-IPAddress $IP) -or !(Test-Port $Port)) {
                Write-ColorOutput "无效的IP地址或端口号: $IP:$Port" "Error"
                return
            }
            
            Write-ColorOutput "启用代理: $Protocol 模式, $IP:$Port" "Info"
            
            # 设置环境变量
            switch ($Protocol.ToLower()) {
                "http" {
                    $env:HTTP_PROXY = "http://$IP`:$Port"
                    $env:http_proxy = $env:HTTP_PROXY
                    $state.CURRENT_HTTP_PROXY = "$IP`:$Port"
                }
                "https" {
                    $env:HTTPS_PROXY = "http://$IP`:$Port"
                    $env:https_proxy = $env:HTTPS_PROXY
                    $state.CURRENT_HTTPS_PROXY = "$IP`:$Port"
                }
                "socks5" {
                    $env:ALL_PROXY = "socks5://$IP`:$Port"
                    $env:all_proxy = $env:ALL_PROXY
                    $env:CURRENT_SOCKS_PROXY = "$IP`:$Port"
                    $state.CURRENT_SOCKS_PROXY = "$IP`:$Port"
                    
                    if ($Transparent) {
                        Set-TransparentProxy "enable" $IP $Port
                        $state.TRANSPARENT_PROXY = $true
                    }
                }
                "all" {
                    $env:HTTP_PROXY = "http://$IP`:$Port"
                    $env:http_proxy = $env:HTTP_PROXY
                    $env:HTTPS_PROXY = $env:HTTP_PROXY
                    $env:https_proxy = $env:HTTP_PROXY
                    $env:ALL_PROXY = "socks5://$IP`:$Port"
                    $env:all_proxy = $env:ALL_PROXY
                    $env:CURRENT_HTTP_PROXY = "$IP`:$Port"
                    $env:CURRENT_HTTPS_PROXY = "$IP`:$Port"
                    $env:CURRENT_SOCKS_PROXY = "$IP`:$Port"
                    
                    $state.CURRENT_HTTP_PROXY = "$IP`:$Port"
                    $state.CURRENT_HTTPS_PROXY = "$IP`:$Port"
                    $state.CURRENT_SOCKS_PROXY = "$IP`:$Port"
                    
                    if ($Transparent) {
                        Set-TransparentProxy "enable" $IP $Port
                        $state.TRANSPARENT_PROXY = $true
                    }
                }
            }
            
            # Windows系统代理
            if ($SystemProxy -or $config.ENABLE_SYSTEM_PROXY) {
                $httpProxyString = "http://$IP`:$Port"
                $socksProxyString = "$IP`:$Port"
                Set-WindowsSystemProxy "enable" $httpProxyString $socksProxyString
                $state.SYSTEM_PROXY_ENABLED = $true
            }
            
            # 配置工具代理
            Set-EnhancedToolsProxy "enable" "http://$IP`:$Port" "$IP`:$Port"
            
            # 保存配置
            if (!$NoSave) {
                switch ($Protocol.ToLower()) {
                    "http" { $config.HTTP_IP = $IP; $config.HTTP_PORT = $Port }
                    "https" { $config.HTTPS_IP = $IP; $config.HTTPS_PORT = $Port }
                    "socks5" { $config.SOCKS5_IP = $IP; $config.SOCKS5_PORT = $Port }
                    "all" {
                        $config.HTTP_IP = $IP; $config.HTTP_PORT = $Port
                        $config.HTTPS_IP = $IP; $config.HTTPS_PORT = $Port
                        $config.SOCKS5_IP = $IP; $config.SOCKS5_PORT = $Port
                    }
                }
                Save-ProxyConfig $config
            }
            
            $state.PROXY_ENABLED = $true
            $state.PROXY_MODE = $Protocol
            Save-ProxyState $state
            
            Write-ColorOutput "代理已启用" "Success"
        }
        
        "disable" {
            Write-ColorOutput "禁用代理: $Protocol" "Info"
            
            switch ($Protocol.ToLower()) {
                "http" {
                    Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:http_proxy -ErrorAction SilentlyContinue
                    $state.CURRENT_HTTP_PROXY = ""
                }
                "https" {
                    Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:https_proxy -ErrorAction SilentlyContinue
                    $state.CURRENT_HTTPS_PROXY = ""
                }
                "socks5" {
                    Remove-Item Env:ALL_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:all_proxy -ErrorAction SilentlyContinue
                    Remove-Item Env:CURRENT_SOCKS_PROXY -ErrorAction SilentlyContinue
                    $state.CURRENT_SOCKS_PROXY = ""
                    Set-TransparentProxy "disable" "" 0
                    $state.TRANSPARENT_PROXY = $false
                }
                default {
                    Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:http_proxy -ErrorAction SilentlyContinue
                    Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:https_proxy -ErrorAction SilentlyContinue
                    Remove-Item Env:ALL_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:all_proxy -ErrorAction SilentlyContinue
                    Remove-Item Env:CURRENT_HTTP_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:CURRENT_HTTPS_PROXY -ErrorAction SilentlyContinue
                    Remove-Item Env:CURRENT_SOCKS_PROXY -ErrorAction SilentlyContinue
                    
                    $state.CURRENT_HTTP_PROXY = ""
                    $state.CURRENT_HTTPS_PROXY = ""
                    $state.CURRENT_SOCKS_PROXY = ""
                    Set-TransparentProxy "disable" "" 0
                    $state.TRANSPARENT_PROXY = $false
                }
            }
            
            # 禁用系统代理
            Set-WindowsSystemProxy "disable"
            $state.SYSTEM_PROXY_ENABLED = $false
            
            # 禁用工具代理
            Set-EnhancedToolsProxy "disable"
            
            $state.PROXY_ENABLED = $false
            $state.PROXY_MODE = ""
            Save-ProxyState $state
            
            Write-ColorOutput "代理已禁用" "Success"
        }
    }
}

# 显示代理状态
function Show-ProxyStatus {
    $config = Get-ProxyConfig
    $state = Get-ProxyState
    
    Write-Host "`n" -NoNewline
    Write-Host "=== 增强PowerShell代理管理器状态 ===" -ForegroundColor Cyan
    
    Write-Host "`n环境变量代理状态:" -ForegroundColor Blue
    Write-Host "  HTTP:   $($env:HTTP_PROXY ?? 'Disabled')" -ForegroundColor $(if ($env:HTTP_PROXY) { "Green" } else { "Red" })
    Write-Host "  HTTPS:  $($env:HTTPS_PROXY ?? 'Disabled')" -ForegroundColor $(if ($env:HTTPS_PROXY) { "Green" } else { "Red" })
    Write-Host "  SOCKS5: $($env:ALL_PROXY ?? 'Disabled')" -ForegroundColor $(if ($env:ALL_PROXY) { "Green" } else { "Red" })
    
    Write-Host "`nWindows系统代理:" -ForegroundColor Blue
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $proxyEnabled = Get-ItemProperty -Path $regPath -Name "ProxyEnable" -ErrorAction SilentlyContinue
        $proxyServer = Get-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue
        
        if ($proxyEnabled.ProxyEnable -eq 1) {
            Write-Host "  状态: 已启用" -ForegroundColor Green
            Write-Host "  服务器: $($proxyServer.ProxyServer)" -ForegroundColor Green
        } else {
            Write-Host "  状态: 已禁用" -ForegroundColor Red
        }
    } catch {
        Write-Host "  状态: 无法获取" -ForegroundColor Yellow
    }
    
    Write-Host "`n透明代理:" -ForegroundColor Blue
    Write-Host "  状态: $(if ($state.TRANSPARENT_PROXY) { '已启用' } else { '已禁用' })" -ForegroundColor $(if ($state.TRANSPARENT_PROXY) { "Green" } else { "Red" })
    
    Write-Host "`n默认配置:" -ForegroundColor Blue
    Write-Host "  HTTP:   http://$($config.HTTP_IP):$($config.HTTP_PORT)"
    Write-Host "  HTTPS:  http://$($config.HTTPS_IP):$($config.HTTPS_PORT)"
    Write-Host "  SOCKS5: socks5://$($config.SOCKS5_IP):$($config.SOCKS5_PORT)"
    
    Write-Host "`n工具代理状态:" -ForegroundColor Blue
    
    # Git状态
    try {
        $gitProxy = git config --global --get http.proxy 2>$null
        Write-Host "  Git:    $($gitProxy ?? '未配置')"
    } catch {
        Write-Host "  Git:    未安装"
    }
    
    # NPM状态
    try {
        $npmProxy = npm config get proxy 2>$null
        if ($npmProxy -eq "null") { $npmProxy = "未配置" }
        Write-Host "  NPM:    $npmProxy"
    } catch {
        Write-Host "  NPM:    未安装"
    }
    
    Write-Host "`n最后更新: $($state.LAST_UPDATE)" -ForegroundColor Blue
}

# 代理连接测试
function Test-ProxyConnection {
    Write-ColorOutput "开始增强代理测试..." "Info"
    
    $testUrls = @(
        "http://httpbin.org/ip",
        "https://ip.sb",
        "http://ip-api.com/json",
        "https://www.google.com"
    )
    
    $successCount = 0
    
    foreach ($url in $testUrls) {
        Write-ColorOutput "测试 $url ..." "Info"
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-ColorOutput "✓ $url 连接成功" "Success"
                $successCount++
            } else {
                Write-ColorOutput "✗ $url 连接失败 (状态码: $($response.StatusCode))" "Error"
            }
        } catch {
            Write-ColorOutput "✗ $url 连接失败: $($_.Exception.Message)" "Error"
        }
    }
    
    Write-Host "`n测试结果: " -NoNewline
    Write-Host "$successCount/$($testUrls.Count) " -ForegroundColor $(if ($successCount -gt 0) { "Green" } else { "Red" }) -NoNewline
    Write-Host "个测试成功"
    
    # 显示当前IP信息
    if ($successCount -gt 0) {
        Write-ColorOutput "当前IP信息:" "Info"
        try {
            $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json" -TimeoutSec 10 -ErrorAction Stop
            Write-Host "IP: $($ipInfo.query), 国家: $($ipInfo.country), 城市: $($ipInfo.city)" -ForegroundColor Green
        } catch {
            try {
                $ip = Invoke-RestMethod -Uri "https://ip.sb" -TimeoutSec 10 -ErrorAction Stop
                Write-Host "IP: $ip" -ForegroundColor Green
            } catch {
                Write-ColorOutput "无法获取IP信息" "Warning"
            }
        }
    }
}

# 规则管理
function Manage-ProxyRules {
    param([string]$RuleAction = "list")
    
    switch ($RuleAction.ToLower()) {
        "list" {
            if (Test-Path $script:RulesFile) {
                Write-Host "`n=== 代理规则 ===" -ForegroundColor Cyan
                Get-Content $script:RulesFile | Where-Object { $_ -notmatch '^#' -and $_ -ne '' } | ForEach-Object {
                    Write-Host $_ -ForegroundColor White
                }
            } else {
                Write-ColorOutput "规则文件不存在，请运行 proxy rules init" "Warning"
            }
        }
        
        "init" {
            Initialize-ProxyRules
        }
        
        "edit" {
            if (Test-Path $script:RulesFile) {
                if (Get-Command notepad -ErrorAction SilentlyContinue) {
                    Start-Process notepad $script:RulesFile
                } else {
                    Write-ColorOutput "请手动编辑文件: $script:RulesFile" "Info"
                }
            } else {
                Write-ColorOutput "规则文件不存在，请先运行 proxy rules init" "Warning"
            }
        }
    }
}

# 安装依赖
function Install-ProxyDependencies {
    Write-ColorOutput "检查PowerShell代理依赖..." "Info"
    
    # 检查PowerShell版本
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-ColorOutput "建议升级到PowerShell 5.0或更高版本" "Warning"
    } else {
        Write-ColorOutput "PowerShell版本检查通过: $($PSVersionTable.PSVersion)" "Success"
    }
    
    # 检查curl
    if (Get-Command curl -ErrorAction SilentlyContinue) {
        Write-ColorOutput "curl 已安装" "Success"
    } else {
        Write-ColorOutput "curl 未找到，某些功能可能受限" "Warning"
    }
    
    # 检查git
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-ColorOutput "Git 已安装" "Success"
    } else {
        Write-ColorOutput "Git 未找到，Git代理功能将不可用" "Warning"
    }
    
    Write-ColorOutput "依赖检查完成" "Success"
    Write-ColorOutput "建议安装: Proxifier 或 SocksCap64 以获得更好的透明代理支持" "Info"
}

# 生成curl测试命令
function Generate-CurlTestCommands {
    $config = Get-ProxyConfig
    $state = Get-ProxyState
    
    Write-Host "`n=== CURL测试命令生成器 ===" -ForegroundColor Cyan
    
    if (!$state.PROXY_ENABLED) {
        Write-ColorOutput "代理未启用，显示基本测试命令" "Warning"
        Write-Host "`n基本HTTP测试:" -ForegroundColor Green
        Write-Host "curl http://httpbin.org/ip" -ForegroundColor White
        Write-Host "curl https://ip.sb" -ForegroundColor White
        return
    }
    
    Write-Host "`n当前代理配置:" -ForegroundColor Blue
    if ($state.CURRENT_HTTP_PROXY) {
        Write-Host "  HTTP: http://$($state.CURRENT_HTTP_PROXY)" -ForegroundColor Green
    }
    if ($state.CURRENT_SOCKS_PROXY) {
        Write-Host "  SOCKS5: socks5://$($state.CURRENT_SOCKS_PROXY)" -ForegroundColor Green
    }
    
    Write-Host "`n=== HTTP代理测试命令 ===" -ForegroundColor Yellow
    if ($state.CURRENT_HTTP_PROXY) {
        $httpProxy = $state.CURRENT_HTTP_PROXY
        Write-Host "# 基本IP检查" -ForegroundColor Green
        Write-Host "curl --proxy http://$httpProxy http://httpbin.org/ip" -ForegroundColor White
        Write-Host "curl --proxy http://$httpProxy https://ip.sb" -ForegroundColor White
        
        Write-Host "`n# 详细信息检查" -ForegroundColor Green
        Write-Host "curl --proxy http://$httpProxy http://ip-api.com/json" -ForegroundColor White
        Write-Host "curl --proxy http://$httpProxy https://httpbin.org/headers" -ForegroundColor White
        
        Write-Host "`n# 连接测试" -ForegroundColor Green
        Write-Host "curl --proxy http://$httpProxy -v https://www.google.com" -ForegroundColor White
        Write-Host "curl --proxy http://$httpProxy --max-time 10 https://github.com" -ForegroundColor White
    }
    
    Write-Host "`n=== SOCKS5代理测试命令 ===" -ForegroundColor Yellow
    if ($state.CURRENT_SOCKS_PROXY) {
        $socksProxy = $state.CURRENT_SOCKS_PROXY
        Write-Host "# 基本IP检查" -ForegroundColor Green
        Write-Host "curl --socks5-hostname $socksProxy http://httpbin.org/ip" -ForegroundColor White
        Write-Host "curl --socks5-hostname $socksProxy https://ip.sb" -ForegroundColor White
        
        Write-Host "`n# 详细信息检查" -ForegroundColor Green
        Write-Host "curl --socks5-hostname $socksProxy http://ip-api.com/json" -ForegroundColor White
        Write-Host "curl --socks5-hostname $socksProxy https://httpbin.org/headers" -ForegroundColor White
        
        Write-Host "`n# 连接测试" -ForegroundColor Green
        Write-Host "curl --socks5-hostname $socksProxy -v https://www.google.com" -ForegroundColor White
        Write-Host "curl --socks5-hostname $socksProxy --max-time 10 https://github.com" -ForegroundColor White
        
        Write-Host "`n# DNS测试（SOCKS5特有）" -ForegroundColor Green
        Write-Host "curl --socks5-hostname $socksProxy https://dns.google/resolve?name=google.com&type=A" -ForegroundColor White
    }
    
    Write-Host "`n=== 自动测试执行 ===" -ForegroundColor Yellow
    Write-Host "是否要执行自动测试？[Y/N]: " -NoNewline -ForegroundColor Cyan
    $response = Read-Host
    
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "`n执行自动测试..." -ForegroundColor Cyan
        
        if ($state.CURRENT_SOCKS_PROXY) {
            Write-Host "`n测试SOCKS5代理:" -ForegroundColor Green
            try {
                $result = curl --socks5-hostname $state.CURRENT_SOCKS_PROXY --max-time 10 -s http://httpbin.org/ip 2>$null
                if ($result) {
                    $ipInfo = $result | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($ipInfo.origin) {
                        Write-Host "✓ SOCKS5代理工作正常，当前IP: $($ipInfo.origin)" -ForegroundColor Green
                    } else {
                        Write-Host "✓ SOCKS5代理连接成功，响应: $result" -ForegroundColor Green
                    }
                } else {
                    Write-Host "✗ SOCKS5代理测试失败" -ForegroundColor Red
                }
            } catch {
                Write-Host "✗ SOCKS5代理测试出错: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        if ($state.CURRENT_HTTP_PROXY) {
            Write-Host "`n测试HTTP代理:" -ForegroundColor Green
            try {
                $result = curl --proxy http://$($state.CURRENT_HTTP_PROXY) --max-time 10 -s http://httpbin.org/ip 2>$null
                if ($result) {
                    $ipInfo = $result | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($ipInfo.origin) {
                        Write-Host "✓ HTTP代理工作正常，当前IP: $($ipInfo.origin)" -ForegroundColor Green
                    } else {
                        Write-Host "✓ HTTP代理连接成功，响应: $result" -ForegroundColor Green
                    }
                } else {
                    Write-Host "✗ HTTP代理测试失败" -ForegroundColor Red
                }
            } catch {
                Write-Host "✗ HTTP代理测试出错: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "`n提示:" -ForegroundColor Yellow
    Write-Host "- 使用 --max-time 10 来设置超时时间" -ForegroundColor Gray
    Write-Host "- 使用 -v 参数可以查看详细连接信息" -ForegroundColor Gray
    Write-Host "- 使用 -s 参数可以静默执行（不显示进度）" -ForegroundColor Gray
}

# 显示帮助信息
function Show-Help {
    Write-Host "`n增强PowerShell代理管理器 v3.0" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "`n基本命令:" -ForegroundColor Blue
    Write-Host "  enable [选项]     启用代理"
    Write-Host "  disable [协议]    禁用代理"
    Write-Host "  status           显示状态"
    Write-Host "  setdefault      设置默认配置"
    Write-Host "  test            测试连接"
    Write-Host "  curltest        生成curl测试命令"
    Write-Host "  install-deps    检查依赖"
    Write-Host "  rules <动作>     管理规则"
    Write-Host "  help            显示帮助"
    Write-Host "  version         显示版本"
    
    Write-Host "`n通用选项:" -ForegroundColor Blue
    Write-Host "  -Protocol <协议>  指定协议 (http/https/socks5/all)"
    Write-Host "  -IP <地址>       指定代理服务器IP地址"
    Write-Host "  -Port <端口>     指定代理服务器端口"
    Write-Host "  -NoSave         不保存当前配置（仅用于enable命令）"
    
    Write-Host "`n高级选项:" -ForegroundColor Blue
    Write-Host "  -SystemProxy    启用Windows系统代理"
    Write-Host "  -Transparent    启用透明代理支持"
    Write-Host "  -V, -Version    显示版本信息"
    Write-Host "  -h, -Help       显示帮助信息"
    
    Write-Host "`n规则管理:" -ForegroundColor Blue
    Write-Host "  rules list      列出规则"
    Write-Host "  rules init      初始化规则"
    Write-Host "  rules edit      编辑规则"
    
    Write-Host "`n使用示例:" -ForegroundColor Blue
    Write-Host "1. 查看当前代理状态："
    Write-Host "   proxy status" -ForegroundColor Gray
    
    Write-Host "`n2. 设置默认代理配置："
    Write-Host "   proxy setdefault -Protocol http -IP 127.0.0.1 -Port 7890" -ForegroundColor Gray
    Write-Host "   proxy setdefault -Protocol socks5 -IP 127.0.0.1 -Port 1080" -ForegroundColor Gray
    Write-Host "   proxy setdefault -Protocol all -IP 127.0.0.1 -Port 7890" -ForegroundColor Gray
    
    Write-Host "`n3. 启用代理（使用默认配置）："
    Write-Host "   proxy enable" -ForegroundColor Gray
    Write-Host "   proxy enable -Protocol socks5" -ForegroundColor Gray
    Write-Host "   proxy enable -SystemProxy" -ForegroundColor Gray
    
    Write-Host "`n4. 启用代理（指定新配置）："
    Write-Host "   proxy enable -IP 127.0.0.1 -Port 8080" -ForegroundColor Gray
    Write-Host "   proxy enable -Protocol socks5 -IP 127.0.0.1 -Port 1080 -NoSave" -ForegroundColor Gray
    Write-Host "   proxy enable -Protocol all -IP 127.0.0.1 -Port 7890 -SystemProxy" -ForegroundColor Gray
    
    Write-Host "`n5. 禁用代理："
    Write-Host "   proxy disable          # 禁用所有代理" -ForegroundColor Gray
    Write-Host "   proxy disable http     # 仅禁用HTTP代理" -ForegroundColor Gray
    
    Write-Host "`n6. 测试和故障排除："
    Write-Host "   proxy test            # 测试代理连接" -ForegroundColor Gray
    Write-Host "   proxy curltest        # 生成curl测试命令" -ForegroundColor Gray
    
    Write-Host "`n7. 规则管理："
    Write-Host "   proxy rules init      # 初始化默认规则" -ForegroundColor Gray
    Write-Host "   proxy rules list      # 查看当前规则" -ForegroundColor Gray
    Write-Host "   proxy rules edit      # 编辑规则文件" -ForegroundColor Gray
    
    Write-Host "`n注意事项:" -ForegroundColor Yellow
    Write-Host "• 使用 setdefault 设置的配置会被保存，下次使用 enable 时会作为默认值" -ForegroundColor Gray
    Write-Host "• 使用 -NoSave 选项时，修改的配置仅在当前会话有效" -ForegroundColor Gray
    Write-Host "• -SystemProxy 选项会同时配置Windows系统代理，影响所有应用程序" -ForegroundColor Gray
    Write-Host "• SOCKS5代理会同时设置环境变量和Windows系统代理（如果启用）" -ForegroundColor Gray
    Write-Host "• 某些应用可能需要重启才能识别代理更改" -ForegroundColor Gray
    Write-Host "• 使用 curltest 可以生成详细的curl测试命令，方便故障排除" -ForegroundColor Gray
    
    Write-Host "`n配置文件位置:" -ForegroundColor Blue
    Write-Host "  配置: $script:ConfigFile" -ForegroundColor Gray
    Write-Host "  规则: $script:RulesFile" -ForegroundColor Gray
    Write-Host "  状态: $script:StateFile" -ForegroundColor Gray
}

# 主函数
function Main {
    # 检查直接运行还是作为函数调用
    if ($MyInvocation.InvocationName -eq ".\proxy4powershell.ps1") {
        # 直接运行脚本 - 显示安装菜单
        Show-InstallationMenu
        return
    }
    
    # 初始化目录
    Initialize-ProxyDirectories
    
    # 处理版本和帮助参数
    if ($Version) {
        Write-Host "`n增强PowerShell代理管理器 v3.0" -ForegroundColor Cyan
        Write-Host "原作者: nanyuzuo" -ForegroundColor Green
        Write-Host "增强版本: Claude Code Enhanced" -ForegroundColor Green
        Write-Host "新增功能: 系统代理集成、透明代理支持、增强工具集成、代理规则管理" -ForegroundColor Blue
        Write-Host "支持平台: Windows (PowerShell 5.0+)" -ForegroundColor Blue
        Write-Host "支持工具: Git, NPM, Docker, curl, 浏览器" -ForegroundColor Blue
        Write-Host "依赖工具: curl (Windows 10+自带), git, npm" -ForegroundColor Blue
        Write-Host "配置目录: $script:ProxyDir" -ForegroundColor Blue
        Write-Host "更新日期: $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor Blue
        Write-Host "`n特色功能:" -ForegroundColor Yellow
        Write-Host "• Windows系统代理自动配置" -ForegroundColor Gray
        Write-Host "• curl测试命令生成器 (curltest)" -ForegroundColor Gray
        Write-Host "• 智能命令包装器" -ForegroundColor Gray
        Write-Host "• 代理规则管理系统" -ForegroundColor Gray
        Write-Host "• 状态持久化" -ForegroundColor Gray
        return
    }
    
    if ($Help) {
        Show-Help
        return
    }
    
    # 执行主要功能
    switch ($Action.ToLower()) {
        "enable" {
            Invoke-ProxyControl "enable" $Protocol $IP $Port -NoSave:$NoSave -Transparent:$Transparent -SystemProxy:$SystemProxy
        }
        "disable" {
            Invoke-ProxyControl "disable" $Protocol
        }
        "status" {
            Show-ProxyStatus
        }
        "test" {
            Test-ProxyConnection
        }
        "setdefault" {
            $config = Get-ProxyConfig
            
            if ($IP -and $Port -and (Test-IPAddress $IP) -and (Test-Port $Port)) {
                switch ($Protocol.ToLower()) {
                    "http" { $config.HTTP_IP = $IP; $config.HTTP_PORT = $Port }
                    "https" { $config.HTTPS_IP = $IP; $config.HTTPS_PORT = $Port }
                    "socks5" { $config.SOCKS5_IP = $IP; $config.SOCKS5_PORT = $Port }
                    "all" {
                        $config.HTTP_IP = $IP; $config.HTTP_PORT = $Port
                        $config.HTTPS_IP = $IP; $config.HTTPS_PORT = $Port
                        $config.SOCKS5_IP = $IP; $config.SOCKS5_PORT = $Port
                    }
                }
                
                Save-ProxyConfig $config
                Write-ColorOutput "默认代理配置已更新" "Success"
                Show-ProxyStatus
            } else {
                Write-ColorOutput "请提供有效的IP地址和端口号" "Error"
                Write-ColorOutput "示例: proxy setdefault -Protocol all -IP 127.0.0.1 -Port 7890" "Info"
            }
        }
        "rules" {
            $ruleAction = if ($IP) { $IP } else { "list" }  # 重用IP参数传递规则动作
            Manage-ProxyRules $ruleAction
        }
        "curltest" {
            Generate-CurlTestCommands
        }
        "install-deps" {
            Install-ProxyDependencies
        }
        default {
            Write-ColorOutput "未知命令: $Action" "Error"
            Write-ColorOutput "使用 'proxy help' 查看帮助" "Info"
        }
    }
}

# 安装菜单（直接运行脚本时显示）
function Show-InstallationMenu {
    Clear-Host
    Write-Host "`n增强PowerShell代理管理器安装" -ForegroundColor Cyan
    Write-Host "----------------------------------" -ForegroundColor Cyan
    Write-Host "1. 安装增强代理管理器"
    Write-Host "2. 卸载代理管理器"
    Write-Host "3. 检查依赖环境"
    Write-Host "Q. 退出"
    Write-Host "----------------------------------" -ForegroundColor Cyan
    
    do {
        $choice = Read-Host "`n请选择操作 (1/2/3/Q)"
        $choice = $choice.ToUpper()
    } while ($choice -notin @("1", "2", "3", "Q"))
    
    switch ($choice) {
        "1" {
            Install-EnhancedProxyManager
        }
        "2" {
            Uninstall-ProxyManager
        }
        "3" {
            Install-ProxyDependencies
            Read-Host "`n按回车键继续..."
        }
        "Q" {
            Write-ColorOutput "感谢使用增强代理管理器！" "Info"
            exit 0
        }
    }
}

# 安装增强代理管理器
function Install-EnhancedProxyManager {
    Write-ColorOutput "开始安装增强PowerShell代理管理器..." "Info"
    
    try {
        # 创建模块目录
        $modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\EnhancedProxyManager"
        New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
        
        # 复制脚本到模块目录
        Copy-Item -Path $PSCommandPath -Destination "$modulePath\proxy4powershell.ps1" -Force
        
        # 确保Profile目录存在
        $profileDir = Split-Path $PROFILE -Parent
        if (!(Test-Path $profileDir)) {
            New-Item -Path $profileDir -ItemType Directory -Force | Out-Null
        }
        
        # 备份现有Profile
        if (Test-Path $PROFILE) {
            Copy-Item -Path $PROFILE -Destination "$PROFILE.backup" -Force
            Write-ColorOutput "Profile备份已创建: $PROFILE.backup" "Success"
        }
        
        # 创建proxy函数
        $proxyFunction = @'

# Enhanced Proxy Manager v3.0
function proxy {
    param(
        [Parameter(Position=0)]
        [string]$action = "status",
        [Parameter()]
        [string]$protocol = "all",
        [Parameter()]
        [string]$ip,
        [Parameter()]
        [int]$port,
        [Parameter()]
        [switch]$NoSave,
        [Parameter()]
        [switch]$Transparent,
        [Parameter()]
        [switch]$SystemProxy,
        [Parameter()]
        [switch]$Version,
        [Parameter()]
        [switch]$Help
    )
    
    & "$env:USERPROFILE\Documents\PowerShell\Modules\EnhancedProxyManager\proxy4powershell.ps1" -Action $action -Protocol $protocol -IP $ip -Port $port -NoSave:$NoSave -Transparent:$Transparent -SystemProxy:$SystemProxy -Version:$Version -Help:$Help
}

# 加载代理包装器
$wrapperFile = "$env:USERPROFILE\.proxy\wrappers\ProxyWrappers.ps1"
if (Test-Path $wrapperFile) {
    . $wrapperFile
}
'@
        
        # 检查proxy函数是否已存在
        $existingContent = ""
        if (Test-Path $PROFILE) {
            $existingContent = Get-Content $PROFILE -Raw
        }
        
        if ($existingContent -notlike "*function proxy*") {
            Add-Content -Path $PROFILE -Value $proxyFunction
        }
        
        # 初始化配置
        Initialize-ProxyDirectories
        $null = Get-ProxyConfig  # 自动创建默认配置
        Initialize-ProxyRules
        
        Write-ColorOutput "安装完成！" "Success"
        Write-ColorOutput "请重启PowerShell或运行以下命令使配置生效:" "Info"
        Write-ColorOutput ". `$PROFILE" "Info"
        Write-ColorOutput "" "Info"
        Write-ColorOutput "开始使用:" "Info"
        Write-ColorOutput "  proxy status     # 查看状态" "Info"
        Write-ColorOutput "  proxy help       # 查看帮助" "Info"
        Write-ColorOutput "  proxy install-deps  # 检查依赖" "Info"
        
    } catch {
        Write-ColorOutput "安装失败: $($_.Exception.Message)" "Error"
    }
    
    Read-Host "`n按回车键继续..."
}

# 卸载代理管理器
function Uninstall-ProxyManager {
    Write-ColorOutput "卸载功能将在后续版本中实现" "Info"
    Read-Host "`n按回车键继续..."
}

# 执行主函数
Main