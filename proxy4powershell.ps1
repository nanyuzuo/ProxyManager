# PowerShell Proxy Manager
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("enable", "disable", "status", "setdefault", "test", "curltest", IgnoreCase=$true)]
    [string]$action = "status",

    [Parameter(Mandatory=$false)]
    [ValidateSet("http", "https", "socks5", "all", IgnoreCase=$true)]
    [string]$protocol = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$ip,
    
    [Parameter(Mandatory=$false)]
    [int]$port,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoSave,
    
    [Parameter(Mandatory=$false)]
    [Alias("--version")]
    [switch]$Version,
    
    [Parameter(Mandatory=$false)]
    [Alias("--help")]
    [switch]$Help
)

# 检查是否直接运行脚本
if ($MyInvocation.InvocationName -eq ".\proxy4powershell.ps1") {
    Clear-Host
    Write-Host "`nPowerShell Proxy Manager Installation" -ForegroundColor Cyan
    Write-Host "----------------------------------" -ForegroundColor Cyan
    Write-Host "1. Install proxy function"
    Write-Host "2. Uninstall proxy function"
    Write-Host "Q. Exit"
    Write-Host "----------------------------------" -ForegroundColor Cyan
    
    do {
        $choice = Read-Host "`nPlease select an option (1/2/Q)"
        $choice = $choice.ToUpper()
    } while ($choice -notin @("1", "2", "Q"))
    
    switch ($choice) {
        "1" {
            try {
                # Create module directory
                $modulePath = "$HOME\Documents\PowerShell\Modules\ProxyManager"
                New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
                
                # Copy script to module directory
                Copy-Item -Path $PSCommandPath -Destination "$modulePath\proxy4powershell.ps1" -Force
                
                # Ensure profile directory exists
                $profileDir = Split-Path $PROFILE -Parent
                if (-not (Test-Path $profileDir)) {
                    New-Item -Path $profileDir -ItemType Directory -Force | Out-Null
                }
                
                # Backup existing profile
                if (Test-Path $PROFILE) {
                    Copy-Item -Path $PROFILE -Destination "$PROFILE.backup" -Force
                    Write-Host "`nProfile backup created: $PROFILE.backup" -ForegroundColor Green
                }
                
                # Add proxy function
                $proxyFunction = @'

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
        [switch]$Version,
        [Parameter()]
        [switch]$Help
    )
    & "$HOME\Documents\PowerShell\Modules\ProxyManager\proxy4powershell.ps1" @PSBoundParameters
}
'@
                # Check if proxy function already exists
                $existingContent = ""
                if (Test-Path $PROFILE) {
                    $existingContent = Get-Content $PROFILE -Raw
                }
                
                if ($existingContent -notlike "*function proxy*") {
                    Add-Content -Path $PROFILE -Value $proxyFunction
                    Write-Host "`nProxy function installed successfully!" -ForegroundColor Green
                    Write-Host "You can now use the 'proxy' command in PowerShell" -ForegroundColor Cyan
                    Write-Host "`nTo activate, either:" -ForegroundColor Yellow
                    Write-Host "1. Restart PowerShell, or" -ForegroundColor Yellow
                    Write-Host "2. Run: . `$PROFILE" -ForegroundColor Yellow
                    
                    Write-Host "`nShowing help information..." -ForegroundColor Cyan
                    Start-Sleep -Seconds 1
                    & $PSCommandPath -Help
                } else {
                    Write-Host "`nProxy function already exists!" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "`nError during installation: $_" -ForegroundColor Red
            }
        }
        "2" {
            try {
                $backupFile = "$PROFILE.backup"
                
                # Restore from backup if exists
                if (Test-Path $backupFile) {
                    Copy-Item -Path $backupFile -Destination $PROFILE -Force
                    Write-Host "`nOriginal profile restored" -ForegroundColor Green
                } else {
                    # Remove proxy function if no backup
                    if (Test-Path $PROFILE) {
                        $content = Get-Content $PROFILE -Raw
                        $newContent = $content -replace "(?ms)# Proxy Management Function\r?\nfunction proxy.*?}\r?\n", ""
                        Set-Content -Path $PROFILE -Value $newContent
                    }
                }
                
                # Remove module files
                $modulePath = "$HOME\Documents\PowerShell\Modules\ProxyManager"
                if (Test-Path $modulePath) {
                    Remove-Item -Path $modulePath -Recurse -Force
                }
                
                Write-Host "`nProxy function uninstalled successfully!" -ForegroundColor Green
                Write-Host "Please restart PowerShell or run: . `$PROFILE" -ForegroundColor Yellow
            }
            catch {
                Write-Host "`nError during uninstallation: $_" -ForegroundColor Red
            }
        }
        "Q" {
            Write-Host "`nExiting installation" -ForegroundColor Yellow
            exit
        }
    }
    exit
}

# 显示版本信息
if ($Version) {
    Write-Host "PowerShell Proxy Manager v1.0.0" -ForegroundColor Cyan
    Write-Host "Author: nanyuzuo"
    Write-Host "Created: 2025-6-11"
    exit
}

# 显示帮助信息
if ($Help) {
    Write-Host "`nPowerShell Proxy Manager - Help" -ForegroundColor Yellow
    Write-Host "Basic Commands:"
    Write-Host "  proxy [action] [-protocol <protocol>] [-ip <IP>] [-port <port>]"
    Write-Host "  proxy -h｜help     Show this help"
    Write-Host "  proxy -V｜version  Show version info"    
    Write-Host "  enable     Enable proxy"
    Write-Host "  disable    Disable proxy"
    Write-Host "  status     Show current status"
    Write-Host "  setdefault Set default proxy config"
    Write-Host "  test       Test proxy connection"
    Write-Host "  curltest   Generate curl commands for manual testing`n"
    
    Write-Host "Protocol Options:" -ForegroundColor Cyan
    Write-Host "  http       HTTP proxy"
    Write-Host "  https      HTTPS proxy"
    Write-Host "  socks5     SOCKS5 proxy"
    Write-Host "  all        All protocols`n"
    
    Write-Host "Examples:" -ForegroundColor Green
    Write-Host "1. Enable all proxies (using default config)"
    Write-Host "   proxy enable -protocol all`n"
    
    Write-Host "2. Enable specific proxy with address"
    Write-Host "   proxy enable -protocol https -ip 192.168.1.100 -port 8888`n"
    
    Write-Host "3. Disable SOCKS5 proxy"
    Write-Host "   proxy disable -protocol socks5`n"
    
    Write-Host "4. Set default proxy config"
    Write-Host "   proxy setdefault -protocol all -ip 127.0.0.1 -port 7890`n"
    
    Write-Host "5. Show current proxy status"
    Write-Host "   proxy status`n"
    
    Write-Host "6. Disable all proxies"
    Write-Host "   proxy disable -protocol all`n"
    
    Write-Host "7. Test proxy connection"
    Write-Host "   proxy test`n"
    
    
    Write-Host "Advanced Options:" -ForegroundColor Magenta
    Write-Host "  -NoSave    Execute without saving to config"
    Write-Host "             Example: proxy enable -protocol http -NoSave`n"
    
    Write-Host "SOCKS5 Proxy Special Notes:" -ForegroundColor Red
    Write-Host "• SOCKS5 proxy sets both environment variables and Windows system proxy"
    Write-Host "• For curl, use explicit proxy parameter:"
    Write-Host "  curl --socks5-hostname IP:PORT http://example.com"
    Write-Host "  Some applications may require restart to recognize proxy changes"
    Write-Host "  Windows system proxy (netsh) is also configured for better compatibility`n"
    
    Write-Host "Config file: $HOME\proxyconfig.xml`n"
    exit
}

# 配置文件路径
$configPath = Join-Path $HOME "proxyconfig.xml"

# 加载或初始化配置
if (Test-Path $configPath) {
    $config = Import-Clixml -Path $configPath
} else {
    $config = @{
        Proxies = @{
            HTTP = @{
                IP = "127.0.0.1"
                Port = 7890
                Enabled = $false
            }
            HTTPS = @{
                IP = "127.0.0.1"
                Port = 7890
                Enabled = $false
            }
            SOCKS5 = @{
                IP = "127.0.0.1"
                Port = 7891
                Enabled = $false
            }
        }
    }
}

# 添加特殊工具代理配置函数
function Set-ToolProxy {
    param(
        [string]$Type,
        [string]$IP,
        [int]$Port,
        [bool]$Enable
    )
    
    $proxyUrl = if ($Enable) { "${IP}:${Port}" } else { "" }
    $proxyUrlWithProtocol = if ($Enable) { "${Type}://${IP}:${Port}" } else { "" }
    
    # Git配置
    try {
        if ($Enable) {
            # 统一使用 http 协议处理代理
            $proxyUrl = "http://${IP}:${Port}"
            
            if ($Type -eq "socks5") {
                $proxyUrl = "socks5h://${IP}:${Port}"
            }
            
            # 使用相同的 http proxy 配置处理所有请求
            git config --global http.proxy $proxyUrl
            git config --global https.proxy $proxyUrl
            
            # 使用系统证书存储，这样可以利用 Windows 的证书信任机制
            git config --global http.sslBackend schannel
            
            # 增加超时时间以提高稳定性
            git config --global http.lowSpeedLimit 1000
            git config --global http.lowSpeedTime 300
            
            # 设置环境变量以确保 Git 使用正确的代理
            if ($Type -eq "socks5") {
                $env:ALL_PROXY = $proxyUrl
            } else {
                $env:HTTP_PROXY = $proxyUrl
                $env:HTTPS_PROXY = $proxyUrl
            }
            
            Write-Host "Git proxy configured successfully" -ForegroundColor Green
            Write-Host "Current Git proxy settings:" -ForegroundColor Cyan
            git config --global --get http.proxy
            git config --global --get https.proxy
            
        } else {
            # 清除所有Git代理和相关设置
            git config --global --unset http.proxy
            git config --global --unset https.proxy
            git config --global --unset http.sslBackend
            git config --global --unset http.lowSpeedLimit
            git config --global --unset http.lowSpeedTime
            
            # 清除环境变量
            $env:ALL_PROXY = $null
            $env:HTTP_PROXY = $null
            $env:HTTPS_PROXY = $null
            
            Write-Host "Git proxy settings removed" -ForegroundColor Yellow
        }
        
        # 显示当前 Git 配置状态
        Write-Host "`nCurrent Git Configuration:" -ForegroundColor Cyan
        git config --global --list | Select-String -Pattern "http|https|ssl|proxy"
        
    }
    catch {
        Write-Host "Warning: Could not configure Git proxy: $_" -ForegroundColor Yellow
    }
    
    # npm配置
    try {
        if ($Enable) {
            npm config set proxy $proxyUrlWithProtocol
            npm config set https-proxy $proxyUrlWithProtocol
            Write-Host "npm proxy configured successfully" -ForegroundColor Green
        } else {
            npm config delete proxy
            npm config delete https-proxy
            Write-Host "npm proxy removed" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Warning: Could not configure npm proxy: $_" -ForegroundColor Yellow
    }
    
    # Docker配置
    try {
        $dockerConfigPath = "$HOME/.docker/config.json"
        $dockerConfigDir = Split-Path $dockerConfigPath -Parent
        
        if (-not (Test-Path $dockerConfigDir)) {
            New-Item -ItemType Directory -Path $dockerConfigDir -Force | Out-Null
        }
        
        if (Test-Path $dockerConfigPath) {
            $dockerConfig = Get-Content $dockerConfigPath | ConvertFrom-Json
        } else {
            $dockerConfig = @{}
        }
        
        if ($Enable) {
            $dockerConfig.proxies = @{
                default = @{
                    httpProxy = "http://${IP}:${Port}"
                    httpsProxy = "https://${IP}:${Port}"
                    noProxy = "localhost,127.0.0.1"
                }
            }
            $dockerConfig | ConvertTo-Json -Depth 10 | Set-Content $dockerConfigPath
            Write-Host "Docker proxy configured successfully" -ForegroundColor Green
        } else {
            if ($dockerConfig.proxies) {
                $dockerConfig.PSObject.Properties.Remove('proxies')
                $dockerConfig | ConvertTo-Json -Depth 10 | Set-Content $dockerConfigPath
            }
            Write-Host "Docker proxy removed" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Warning: Could not configure Docker proxy: $_" -ForegroundColor Yellow
    }
}

# 核心功能函数
function Enable-Proxy {
    param(
        [string]$Type,
        [string]$IP,
        [int]$Port
    )
    
    $proxyString = "${Type}://${IP}:${Port}"
    
    # 设置 .NET 默认代理配置
    if ($Type.ToLower() -in @("http", "https")) {
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://${IP}:${Port}", $true)
    }
    
    switch ($Type.ToLower()) {
        "http" {
            $env:HTTP_PROXY = $proxyString
            $env:http_proxy = $proxyString
            $config.Proxies.HTTP.IP = $IP
            $config.Proxies.HTTP.Port = $Port
            $config.Proxies.HTTP.Enabled = $true
            Write-Host "HTTP proxy enabled: $proxyString" -ForegroundColor Green
            # 设置工具代理
            Set-ToolProxy -Type "http" -IP $IP -Port $Port -Enable $true
        }
        "https" {
            $env:HTTPS_PROXY = $proxyString
            $env:https_proxy = $proxyString
            $config.Proxies.HTTPS.IP = $IP
            $config.Proxies.HTTPS.Port = $Port
            $config.Proxies.HTTPS.Enabled = $true
            Write-Host "HTTPS proxy enabled: $proxyString" -ForegroundColor Green
            # 设置工具代理
            Set-ToolProxy -Type "https" -IP $IP -Port $Port -Enable $true
        }
        "socks5" {
            $env:ALL_PROXY = $proxyString
            $env:all_proxy = $proxyString
            $env:SOCKS_PROXY = $proxyString
            $env:socks_proxy = $proxyString
            $env:SOCKS5_PROXY = $proxyString
            $env:socks5_proxy = $proxyString
            
            try {
                Set-WindowsProxy -ProxyType "SOCKS5" -IP $IP -Port $Port
                Write-Host "Windows system SOCKS5 proxy configured" -ForegroundColor Cyan
            }
            catch {
                Write-Host "Warning: Could not set Windows system proxy: $_" -ForegroundColor Yellow
            }
            
            $config.Proxies.SOCKS5.IP = $IP
            $config.Proxies.SOCKS5.Port = $Port
            $config.Proxies.SOCKS5.Enabled = $true
            Write-Host "SOCKS5 proxy enabled: $proxyString" -ForegroundColor Green
            Write-Host "Note: For curl, use: curl --socks5-hostname ${IP}:${Port} <url>" -ForegroundColor Yellow
            # 设置工具代理
            Set-ToolProxy -Type "socks5" -IP $IP -Port $Port -Enable $true
        }
    }
}

function Disable-Proxy {
    param(
        [string]$Type
    )
    
    # 禁用 .NET 默认代理配置
    if ($Type.ToLower() -in @("http", "https", "all")) {
        [System.Net.WebRequest]::DefaultWebProxy = $null
    }
    
    switch ($Type.ToLower()) {
        "http" {
            $env:HTTP_PROXY = $null
            $env:http_proxy = $null
            $config.Proxies.HTTP.Enabled = $false
            Write-Host "HTTP proxy disabled" -ForegroundColor Red
            # 禁用工具代理
            Set-ToolProxy -Type "http" -IP "" -Port 0 -Enable $false
        }
        "https" {
            $env:HTTPS_PROXY = $null
            $env:https_proxy = $null
            $config.Proxies.HTTPS.Enabled = $false
            Write-Host "HTTPS proxy disabled" -ForegroundColor Red
            # 禁用工具代理
            Set-ToolProxy -Type "https" -IP "" -Port 0 -Enable $false
        }
        "socks5" {
            $env:ALL_PROXY = $null
            $env:all_proxy = $null
            $env:SOCKS_PROXY = $null
            $env:socks_proxy = $null
            $env:SOCKS5_PROXY = $null
            $env:socks5_proxy = $null
            
            try {
                Disable-WindowsProxy
                Write-Host "Windows system proxy disabled" -ForegroundColor Cyan
            }
            catch {
                Write-Host "Warning: Could not disable Windows system proxy: $_" -ForegroundColor Yellow
            }
            
            $config.Proxies.SOCKS5.Enabled = $false
            Write-Host "SOCKS5 proxy disabled" -ForegroundColor Red
            # 禁用工具代理
            Set-ToolProxy -Type "socks5" -IP "" -Port 0 -Enable $false
        }
        "all" {
            $env:HTTP_PROXY = $null
            $env:http_proxy = $null
            $env:HTTPS_PROXY = $null
            $env:https_proxy = $null
            $env:ALL_PROXY = $null
            $env:all_proxy = $null
            $env:SOCKS_PROXY = $null
            $env:socks_proxy = $null
            $env:SOCKS5_PROXY = $null
            $env:socks5_proxy = $null
            
            try {
                Disable-WindowsProxy
                Write-Host "Windows system proxy disabled" -ForegroundColor Cyan
            }
            catch {
                Write-Host "Warning: Could not disable Windows system proxy: $_" -ForegroundColor Yellow
            }
            
            $config.Proxies.HTTP.Enabled = $false
            $config.Proxies.HTTPS.Enabled = $false
            $config.Proxies.SOCKS5.Enabled = $false
            Write-Host "All proxies disabled" -ForegroundColor Red
            # 禁用所有工具代理
            Set-ToolProxy -Type "all" -IP "" -Port 0 -Enable $false
        }
    }
}

# Windows系统代理设置函数
function Set-WindowsProxy {
    param(
        [string]$ProxyType,
        [string]$IP,
        [int]$Port
    )
    
    if ($ProxyType -eq "SOCKS5") {
        # 使用netsh设置SOCKS5代理
        $netshResult = netsh winhttp set proxy proxy-server="socks=${IP}:${Port}"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Windows SOCKS5 proxy set successfully" -ForegroundColor Green
        }
    }
}

function Disable-WindowsProxy {
    $netshResult = netsh winhttp reset proxy
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Windows proxy reset successfully" -ForegroundColor Green
    }
}

function Show-Status {
    Write-Host "`n--- Current Proxy Status ---" -ForegroundColor Cyan
    
    if ($env:HTTP_PROXY) { 
        Write-Host "HTTP: $env:HTTP_PROXY [Enabled]" -ForegroundColor Green
    } else { 
        Write-Host "HTTP: Disabled" -ForegroundColor Gray
    }
    
    if ($env:HTTPS_PROXY) { 
        Write-Host "HTTPS: $env:HTTPS_PROXY [Enabled]" -ForegroundColor Green
    } else { 
        Write-Host "HTTPS: Disabled" -ForegroundColor Gray
    }
    
    if ($env:ALL_PROXY) { 
        Write-Host "SOCKS5: $env:ALL_PROXY [Enabled]" -ForegroundColor Green
    } else { 
        Write-Host "SOCKS5: Disabled" -ForegroundColor Gray
    }
    
    # 显示Windows系统代理状态
    Write-Host "`n--- Windows System Proxy ---" -ForegroundColor Cyan
    try {
        # 保存原始编码
        $originalEncoding = [Console]::OutputEncoding
        
        # 设置输出编码为UTF8
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        
        # 获取并显示代理设置
        $systemProxy = netsh winhttp show proxy
        $systemProxy -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                Write-Host $line -ForegroundColor White
            }
        }
        
        # 恢复原始编码
        [Console]::OutputEncoding = $originalEncoding
    }
    catch {
        Write-Host "Unable to retrieve Windows system proxy settings" -ForegroundColor Yellow
    }
    
    Write-Host "------------------------`n" -ForegroundColor Cyan
    
    Write-Host "--- Default Config ---" -ForegroundColor Cyan
    Write-Host "HTTP: http://$($config.Proxies.HTTP.IP):$($config.Proxies.HTTP.Port)"
    Write-Host "HTTPS: https://$($config.Proxies.HTTPS.IP):$($config.Proxies.HTTPS.Port)"
    Write-Host "SOCKS5: socks5://$($config.Proxies.SOCKS5.IP):$($config.Proxies.SOCKS5.Port)"
    Write-Host "-------------------`n" -ForegroundColor Cyan
}

# 参数处理逻辑
switch ($action.ToLower()) {
    "enable" {
        if ($protocol -eq "all") {
            # 处理所有协议
            $protocols = @("http", "https", "socks5")
            foreach ($p in $protocols) {
                $currentIP = $ip
                $currentPort = $port
                
                # 如果未提供IP/端口，使用该协议的默认配置
                if (-not ($currentIP -and $currentPort)) {
                    $currentIP = $config.Proxies.$p.IP
                    $currentPort = $config.Proxies.$p.Port
                }
                
                Enable-Proxy -Type $p -IP $currentIP -Port $currentPort
            }
        } else {
            # 处理单个协议
            if (-not ($ip -and $port)) {
                $ip = $config.Proxies.$protocol.IP
                $port = $config.Proxies.$protocol.Port
            }
            
            Enable-Proxy -Type $protocol -IP $ip -Port $port
        }
    }
    
    "disable" {
        if ($protocol -eq "all") {
            Disable-Proxy -Type "all"
        } else {
            Disable-Proxy -Type $protocol
        }
    }
    
    "status" {
        Show-Status
    }
    
    "setdefault" {
        if ($ip -and $port) {
            switch ($protocol) {
                "http" {
                    $config.Proxies.HTTP.IP = $ip
                    $config.Proxies.HTTP.Port = $port
                }
                "https" {
                    $config.Proxies.HTTPS.IP = $ip
                    $config.Proxies.HTTPS.Port = $port
                }
                "socks5" {
                    $config.Proxies.SOCKS5.IP = $ip
                    $config.Proxies.SOCKS5.Port = $port
                }
                "all" {
                    $config.Proxies.HTTP.IP = $ip
                    $config.Proxies.HTTP.Port = $port
                    $config.Proxies.HTTPS.IP = $ip
                    $config.Proxies.HTTPS.Port = $port
                    $config.Proxies.SOCKS5.IP = $ip
                    $config.Proxies.SOCKS5.Port = $port
                }
            }
            
            if ($protocol -eq "all") {
                Write-Host "Default proxies updated: HTTP=${ip}:${port}, HTTPS=${ip}:${port}, SOCKS5=${ip}:${port}" -ForegroundColor Cyan
            } else {
                Write-Host "Default ${protocol} proxy updated: ${protocol}://${ip}:${port}" -ForegroundColor Cyan
            }
        } else {
            Write-Host "Usage example: proxy setdefault -protocol http -ip 127.0.0.1 -port 7890" -ForegroundColor Magenta
        }
    }

    "test" {
        Write-Host "`n--- Testing Proxy Connection ---" -ForegroundColor Cyan
        
        # 检测当前启用的代理类型
        $activeProxy = $null
        $proxyInfo = $null
        
        if ($env:ALL_PROXY -or $env:SOCKS5_PROXY) {
            $activeProxy = "SOCKS5"
            $proxyInfo = if ($env:ALL_PROXY) { $env:ALL_PROXY } else { $env:SOCKS5_PROXY }
        }
        elseif ($env:HTTPS_PROXY) {
            $activeProxy = "HTTPS"
            $proxyInfo = $env:HTTPS_PROXY
        }
        elseif ($env:HTTP_PROXY) {
            $activeProxy = "HTTP"
            $proxyInfo = $env:HTTP_PROXY
        }
        
        if ($activeProxy) {
            Write-Host "Detected active proxy: $activeProxy ($proxyInfo)" -ForegroundColor Cyan
        } else {
            Write-Host "No proxy detected, testing direct connection" -ForegroundColor Yellow
        }
        
        # 测试方法1：使用PowerShell的Invoke-WebRequest（适用于HTTP/HTTPS代理）
        if ($activeProxy -in @("HTTP", "HTTPS", $null)) {
            Write-Host "`nTesting with PowerShell Invoke-WebRequest..." -ForegroundColor Cyan
            try {
                $result = Invoke-WebRequest -Uri "http://ip-api.com/json" -UseBasicParsing -TimeoutSec 10 | ConvertFrom-Json
                Write-Host "PowerShell Test Successful!" -ForegroundColor Green
                Write-Host "Current IP: $($result.query)" -ForegroundColor Yellow
                Write-Host "Location: $($result.country), $($result.regionName), $($result.city)" -ForegroundColor Yellow
                Write-Host "ISP: $($result.isp)" -ForegroundColor Yellow
            }
            catch {
                Write-Host "PowerShell Test Failed: $_" -ForegroundColor Red
            }
        }
        
        # 测试方法2：使用curl（更好地支持SOCKS5）
        Write-Host "`nTesting with curl..." -ForegroundColor Cyan
        try {
            $curlAvailable = Get-Command curl.exe -ErrorAction SilentlyContinue
            if ($curlAvailable) {
                # 根据代理类型构建curl命令
                $curlArgs = @('--connect-timeout', '10', '--max-time', '30', '-s', 'http://ip-api.com/json')
                
                if ($activeProxy -eq "SOCKS5" -and $proxyInfo -match "socks5h?://([^:]+):(\d+)") {
                    $socksIP = $Matches[1]
                    $socksPort = $Matches[2]
                    $curlArgs = @('--socks5-hostname', "${socksIP}:${socksPort}") + $curlArgs
                    Write-Host "Using SOCKS5 proxy: ${socksIP}:${socksPort}" -ForegroundColor Cyan
                }
                
                Write-Host "Executing: curl $($curlArgs -join ' ')" -ForegroundColor Gray
                $curlResult = & curl.exe @curlArgs
                
                if ($LASTEXITCODE -eq 0 -and $curlResult) {
                    try {
                        $result = $curlResult | ConvertFrom-Json
                        Write-Host "Curl Test Successful!" -ForegroundColor Green
                        Write-Host "Current IP: $($result.query)" -ForegroundColor Yellow
                        Write-Host "Location: $($result.country), $($result.regionName), $($result.city)" -ForegroundColor Yellow
                        Write-Host "ISP: $($result.isp)" -ForegroundColor Yellow
                    }
                    catch {
                        Write-Host "Curl response parsing failed: $_" -ForegroundColor Red
                        Write-Host "Raw response: $curlResult" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "Curl Test Failed (Exit code: $LASTEXITCODE)" -ForegroundColor Red
                    Write-Host "Raw response: $curlResult" -ForegroundColor Gray
                    
                    # 尝试直接测试连接性
                    if ($activeProxy -eq "SOCKS5" -and $socksIP -and $socksPort) {
                        Write-Host "`nTrying direct connection test to proxy server..." -ForegroundColor Cyan
                        $testResult = Test-NetConnection -ComputerName $socksIP -Port $socksPort -WarningAction SilentlyContinue
                        if ($testResult.TcpTestSucceeded) {
                            Write-Host "SOCKS5 proxy server is reachable" -ForegroundColor Green
                        } else {
                            Write-Host "Cannot connect to SOCKS5 proxy server" -ForegroundColor Red
                        }
                    }
                }
            } else {
                Write-Host "Curl not available on this system" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Curl Test Error: $_" -ForegroundColor Red
        }
        
        # 如果是SOCKS5代理，提供额外的使用建议
        if ($activeProxy -eq "SOCKS5") {
            Write-Host "`n--- SOCKS5 Proxy Usage Tips ---" -ForegroundColor Magenta
            Write-Host "For curl usage:" -ForegroundColor Yellow
            if ($proxyInfo -match "socks5h?://([^:]+):(\d+)") {
                $socksIP = $Matches[1]
                $socksPort = $Matches[2]
                Write-Host "  curl --socks5-hostname ${socksIP}:${socksPort} http://example.com" -ForegroundColor White
            }
            Write-Host "`nFor other applications:" -ForegroundColor Yellow
            Write-Host "  Current proxy settings:" -ForegroundColor White
            Write-Host "  ALL_PROXY=$env:ALL_PROXY" -ForegroundColor White
            Write-Host "  SOCKS_PROXY=$env:SOCKS_PROXY" -ForegroundColor White
            Write-Host "  SOCKS5_PROXY=$env:SOCKS5_PROXY" -ForegroundColor White
        }
        
        Write-Host "`n-----------------------------`n" -ForegroundColor Cyan
    }
    
    "curltest" {
        Write-Host "`n--- Curl Command Test ---" -ForegroundColor Cyan
        
        # 获取SOCKS5代理配置
        $socksIP = $config.Proxies.SOCKS5.IP
        $socksPort = $config.Proxies.SOCKS5.Port
        
        if (-not $socksIP -or -not $socksPort) {
            Write-Host "No SOCKS5 proxy configured. Use 'proxy setdefault -protocol socks5 -ip <IP> -port <PORT>' first." -ForegroundColor Red
            return
        }
        
        Write-Host "SOCKS5 proxy: ${socksIP}:${socksPort}" -ForegroundColor Cyan
        Write-Host "`nGenerated curl commands you can run manually:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Basic IP check:" -ForegroundColor Green
        Write-Host "curl --socks5-hostname ${socksIP}:${socksPort} http://ipinfo.io" -ForegroundColor White
        Write-Host ""
        Write-Host "Detailed IP info:" -ForegroundColor Green  
        Write-Host "curl --socks5-hostname ${socksIP}:${socksPort} http://ip-api.com/json" -ForegroundColor White
        Write-Host ""
        Write-Host "HTTPS test:" -ForegroundColor Green
        Write-Host "curl --socks5-hostname ${socksIP}:${socksPort} https://httpbin.org/ip" -ForegroundColor White
        Write-Host ""
        Write-Host "Test with verbose output:" -ForegroundColor Green
        Write-Host "curl --socks5-hostname ${socksIP}:${socksPort} -v http://httpbin.org/ip" -ForegroundColor White
        Write-Host ""
        
        # 尝试执行一个简单的测试
        Write-Host "Attempting automatic test..." -ForegroundColor Cyan
        try {
            # 使用最简单的方法
            $testCmd = "curl.exe"
            $testArgs = @("--socks5-hostname", "${socksIP}:${socksPort}", "-s", "--max-time", "10", "http://httpbin.org/ip")
            
            Write-Host "Command: $testCmd $($testArgs -join ' ')" -ForegroundColor Gray
            
            $result = & $testCmd @testArgs
            
            if ($LASTEXITCODE -eq 0 -and $result) {
                Write-Host "Automatic test successful!" -ForegroundColor Green
                try {
                    $jsonResult = $result | ConvertFrom-Json
                    Write-Host "Your IP through proxy: $($jsonResult.origin)" -ForegroundColor White  
                }
                catch {
                    Write-Host "Response: $result" -ForegroundColor White
                }
            } else {
                Write-Host "Automatic test failed (Exit code: $LASTEXITCODE)" -ForegroundColor Red
                Write-Host "Please try running the manual commands above" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Test error: $_" -ForegroundColor Red
            Write-Host "Please try running the manual commands above" -ForegroundColor Yellow
        }
        
        Write-Host "`n--- End ---" -ForegroundColor Cyan
    }
}

# 保存配置
if (-not $NoSave -and $action -ne "status") {
    $config | Export-Clixml -Path $configPath -Force
}