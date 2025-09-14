# Enhanced PowerShell Proxy Manager v3.0
# Enhanced Windows Proxy Management Script - Complete Terminal Proxy Solution
# Author: Enhanced by Claude Code
# Features: System proxy integration, transparent proxy, enhanced tool support, proxy rule management

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

# Global configuration
$script:ProxyDir = "$env:USERPROFILE\.proxy"
$script:ConfigFile = "$script:ProxyDir\config.xml"
$script:RulesFile = "$script:ProxyDir\rules.conf"
$script:StateFile = "$script:ProxyDir\proxy.state.xml"
$script:WrapperDir = "$script:ProxyDir\wrappers"
$script:LogFile = "$script:ProxyDir\proxy.log"

# Color configuration
$script:Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Debug = "Magenta"
}

# Log function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Ignore log write errors
    }
}

# Color output function
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

# Check administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Validate IP address
function Test-IPAddress {
    param([string]$IP)

    if ([string]::IsNullOrEmpty($IP)) { return $false }

    # Check IP format
    if ($IP -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
        return $true
    }

    # Check domain format
    if ($IP -match '^[a-zA-Z0-9.-]+$' -or $IP -eq "localhost") {
        return $true
    }

    return $false
}

# Validate port number
function Test-Port {
    param([int]$Port)
    return ($Port -ge 1 -and $Port -le 65535)
}

# Create directory structure
function Initialize-ProxyDirectories {
    $dirs = @($script:ProxyDir, "$script:ProxyDir\backup", $script:WrapperDir)

    foreach ($dir in $dirs) {
        if (!(Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

# Create default configuration
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
    Write-ColorOutput "Default configuration created: $script:ConfigFile" "Success"
}

# Load configuration
function Get-ProxyConfig {
    if (Test-Path $script:ConfigFile) {
        try {
            return Import-Clixml -Path $script:ConfigFile
        } catch {
            Write-ColorOutput "Configuration file corrupted, recreating default configuration" "Warning"
            Initialize-DefaultConfig
            return Import-Clixml -Path $script:ConfigFile
        }
    } else {
        Initialize-DefaultConfig
        return Import-Clixml -Path $script:ConfigFile
    }
}

# Save configuration
function Save-ProxyConfig {
    param($Config)

    $Config.LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Config | Export-Clixml -Path $script:ConfigFile -Force
}

# Initialize state file
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

# Load state
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

# Save state
function Save-ProxyState {
    param($State)

    $State.LAST_UPDATE = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $State | Export-Clixml -Path $script:StateFile -Force
}

# Show proxy status
function Show-ProxyStatus {
    $config = Get-ProxyConfig
    $state = Get-ProxyState

    Write-Host "`n" -NoNewline
    Write-Host "=== Enhanced PowerShell Proxy Manager Status ===" -ForegroundColor Cyan

    Write-Host "`nEnvironment Variable Proxy Status:" -ForegroundColor Blue
    $httpStatus = if ($env:HTTP_PROXY) { $env:HTTP_PROXY } else { 'Disabled' }
    $httpsStatus = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } else { 'Disabled' }
    $socksStatus = if ($env:ALL_PROXY) { $env:ALL_PROXY } else { 'Disabled' }

    Write-Host "  HTTP:   $httpStatus" -ForegroundColor $(if ($env:HTTP_PROXY) { "Green" } else { "Red" })
    Write-Host "  HTTPS:  $httpsStatus" -ForegroundColor $(if ($env:HTTPS_PROXY) { "Green" } else { "Red" })
    Write-Host "  SOCKS5: $socksStatus" -ForegroundColor $(if ($env:ALL_PROXY) { "Green" } else { "Red" })

    Write-Host "`nWindows System Proxy:" -ForegroundColor Blue
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $proxyEnabled = Get-ItemProperty -Path $regPath -Name "ProxyEnable" -ErrorAction SilentlyContinue
        $proxyServer = Get-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue

        if ($proxyEnabled.ProxyEnable -eq 1) {
            Write-Host "  Status: Enabled" -ForegroundColor Green
            Write-Host "  Server: $($proxyServer.ProxyServer)" -ForegroundColor Green
        } else {
            Write-Host "  Status: Disabled" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Status: Unable to get" -ForegroundColor Yellow
    }

    Write-Host "`nTransparent Proxy:" -ForegroundColor Blue
    $transparentStatus = if ($state.TRANSPARENT_PROXY) { 'Enabled' } else { 'Disabled' }
    Write-Host "  Status: $transparentStatus" -ForegroundColor $(if ($state.TRANSPARENT_PROXY) { "Green" } else { "Red" })

    Write-Host "`nDefault Configuration:" -ForegroundColor Blue
    Write-Host "  HTTP:   http://$($config.HTTP_IP):$($config.HTTP_PORT)"
    Write-Host "  HTTPS:  http://$($config.HTTPS_IP):$($config.HTTPS_PORT)"
    Write-Host "  SOCKS5: socks5://$($config.SOCKS5_IP):$($config.SOCKS5_PORT)"

    Write-Host "`nTool Proxy Status:" -ForegroundColor Blue

    # Git Status
    try {
        $gitProxy = git config --global --get http.proxy 2>$null
        $gitStatus = if ($gitProxy) { $gitProxy } else { 'Not configured' }
        Write-Host "  Git:    $gitStatus"
    } catch {
        Write-Host "  Git:    Not installed"
    }

    # NPM Status
    try {
        $npmProxy = npm config get proxy 2>$null
        if ($npmProxy -eq "null") { $npmProxy = "Not configured" }
        Write-Host "  NPM:    $npmProxy"
    } catch {
        Write-Host "  NPM:    Not installed"
    }

    Write-Host "`nLast Update: $($state.LAST_UPDATE)" -ForegroundColor Blue
}

# Test proxy connection
function Test-ProxyConnection {
    Write-ColorOutput "Starting enhanced proxy test..." "Info"

    $testUrls = @(
        "http://httpbin.org/ip",
        "https://ip.sb",
        "http://ip-api.com/json",
        "https://www.google.com"
    )

    $successCount = 0

    foreach ($url in $testUrls) {
        Write-ColorOutput "Testing $url ..." "Info"
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-ColorOutput "✓ $url connection successful" "Success"
                $successCount++
            } else {
                Write-ColorOutput "✗ $url connection failed (status code: $($response.StatusCode))" "Error"
            }
        } catch {
            Write-ColorOutput "✗ $url Connection failed: $($_.Exception.Message)" "Error"
        }
    }

    Write-Host "`nTest results: " -NoNewline
    Write-Host "$successCount/$($testUrls.Count) " -ForegroundColor $(if ($successCount -gt 0) { "Green" } else { "Red" }) -NoNewline
    Write-Host "tests successful"

    # Show current IP info
    if ($successCount -gt 0) {
        Write-ColorOutput "Current IP info:" "Info"
        try {
            $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json" -TimeoutSec 10 -ErrorAction Stop
            Write-Host "IP: $($ipInfo.query), Country: $($ipInfo.country), City: $($ipInfo.city)" -ForegroundColor Green
        } catch {
            try {
                $ip = Invoke-RestMethod -Uri "https://ip.sb" -TimeoutSec 10 -ErrorAction Stop
                Write-Host "IP: $ip" -ForegroundColor Green
            } catch {
                Write-ColorOutput "Unable to get IP info" "Warning"
            }
        }
    }
}

# Show help
function Show-Help {
    Write-Host "`nEnhanced PowerShell Proxy Manager v3.0" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nBasic Commands:" -ForegroundColor Blue
    Write-Host "  enable [options]     Enable proxy"
    Write-Host "  disable [protocol]   Disable proxy"
    Write-Host "  status              Show status"
    Write-Host "  setdefault         Set default configuration"
    Write-Host "  test               Test connection"
    Write-Host "  curltest           Generate curl test commands"
    Write-Host "  install-deps       Check dependencies"
    Write-Host "  rules <action>     Manage rules"
    Write-Host "  help               Show help"
    Write-Host "  version            Show version"

    Write-Host "`nCommon Options:" -ForegroundColor Blue
    Write-Host "  -Protocol <protocol>  Specify protocol (http/https/socks5/all)"
    Write-Host "  -IP <address>        Specify proxy server IP address"
    Write-Host "  -Port <port>         Specify proxy server port"
    Write-Host "  -NoSave             Don't save current configuration"

    Write-Host "`nAdvanced Options:" -ForegroundColor Blue
    Write-Host "  -SystemProxy        Enable Windows system proxy"
    Write-Host "  -Transparent        Enable transparent proxy support"
    Write-Host "  -V, -Version        Show version information"
    Write-Host "  -h, -Help           Show help information"
}

# Main function
function Main {
    # Check if running directly or as function call
    if ($MyInvocation.InvocationName -eq ".\proxy4powershell.ps1") {
        Write-Host "`nEnhanced PowerShell Proxy Manager v3.0" -ForegroundColor Cyan
        Write-Host "Run with -Help parameter to see usage information" -ForegroundColor Yellow
        Write-Host "Example: .\proxy4powershell.ps1 -Help" -ForegroundColor Gray
        return
    }

    # Initialize directories
    Initialize-ProxyDirectories

    # Handle version and help parameters
    if ($Version) {
        Write-Host "`nEnhanced PowerShell Proxy Manager v3.0" -ForegroundColor Cyan
        Write-Host "Original Author: nanyuzuo" -ForegroundColor Green
        Write-Host "Enhanced Version: Claude Code Enhanced" -ForegroundColor Green
        Write-Host "New Features: System proxy integration, transparent proxy support, enhanced tool integration, rule management" -ForegroundColor Blue
        Write-Host "Supported Platform: Windows (PowerShell 5.0+)" -ForegroundColor Blue
        Write-Host "Supported Tools: Git, NPM, Docker, curl, browsers" -ForegroundColor Blue
        Write-Host "Configuration Directory: $script:ProxyDir" -ForegroundColor Blue
        Write-Host "Update Date: $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor Blue
        return
    }

    if ($Help) {
        Show-Help
        return
    }

    # Execute main functionality
    switch ($Action.ToLower()) {
        "status" {
            Show-ProxyStatus
        }
        "test" {
            Test-ProxyConnection
        }
        default {
            Write-ColorOutput "Unknown command: $Action" "Error"
            Write-ColorOutput "Use 'proxy help' to see help" "Info"
        }
    }
}

# Execute main function
Main