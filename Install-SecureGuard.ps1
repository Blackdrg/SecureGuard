# SecureGuard Enterprise Antivirus Installer
# Version: 2.0.0
# Run as Administrator

param(
    [switch]$Silent,
    [switch]$Uninstall,
    [switch]$CreateDesktopShortcut,
    [switch]$AddToStartup
)

$ErrorActionPreference = "Stop"

# Configuration
$AppName = "SecureGuard Enterprise"
$Publisher = "SecureGuard Inc."
$Version = "2.0.0"
$InstallPath = Join-Path $env:ProgramFiles "SecureGuard"
$DataPath = Join-Path $env:LOCALAPPDATA "SecureGuard"
$ExeName = "SecureGuard.exe"

# Colors for output
function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Gray }

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     SecureGuard Enterprise Antivirus          ║" -ForegroundColor Cyan
    Write-Host "  ║            Installer v$Version                    ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-SecureGuard {
    Show-Banner
    
    if (-not (Test-Administrator)) {
        Write-Error "Please run this installer as Administrator"
        Write-Host "Right-click on PowerShell and select 'Run as Administrator'"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Step "Installing $AppName..."
    
    # Create installation directories
    Write-Info "Creating installation directories..."
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $DataPath "Logs") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $DataPath "Quarantine") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $DataPath "Updates") | Out-Null
    
    # Get source path
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $sourcePath = Join-Path $scriptPath "publish"
    
    if (-not (Test-Path $sourcePath)) {
        Write-Error "Source files not found at: $sourcePath"
        Write-Host "Please run this installer from the SecureGuard directory"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Copy application files
    Write-Info "Copying application files..."
    Copy-Item -Path "$sourcePath\*" -Destination $InstallPath -Recurse -Force
    
    # Create desktop shortcut
    if ($CreateDesktopShortcut -or (-not $Silent)) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutPath = Join-Path $desktopPath "SecureGuard.lnk"
        
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = Join-Path $InstallPath $ExeName
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.Description = "SecureGuard Enterprise Antivirus"
        $Shortcut.Save()
        
        Write-Success "Desktop shortcut created"
    }
    
    # Add to startup
    if ($AddToStartup) {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $exePath = Join-Path $InstallPath $ExeName
        Set-ItemProperty -Path $regPath -Name "SecureGuard" -Value "`"$exePath`" /minimized"
        Write-Success "Added to Windows startup"
    }
    
    # Register uninstaller
    Write-Info "Registering uninstaller..."
    $uninstallPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SecureGuard"
    New-Item -Path $uninstallPath -Force | Out-Null
    Set-ItemProperty -Path $uninstallPath -Name "DisplayName" -Value $AppName
    Set-ItemProperty -Path $uninstallPath -Name "DisplayVersion" -Value $Version
    Set-ItemProperty -Path $uninstallPath -Name "Publisher" -Value $Publisher
    Set-ItemProperty -Path $uninstallPath -Name "InstallLocation" -Value $InstallPath
    Set-ItemProperty -Path $uninstallPath -Name "UninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$InstallPath\Install-SecureGuard.ps1`" -Uninstall"
    Set-ItemProperty -Path $uninstallPath -Name "NoModify" -Value 1 -Type DWord
    Set-ItemProperty -Path $uninstallPath -Name "NoRepair" -Value 1 -Type DWord
    
    # Copy installer for uninstall
    Copy-Item -Path $MyInvocation.MyCommand.Definition -Destination $InstallPath -Force
    
    # Create default configuration
    $configPath = Join-Path $DataPath "config.json"
    if (-not (Test-Path $configPath)) {
        $config = @{
            RealTimeProtectionEnabled = $true
            RansomwareShieldEnabled = $true
            NetworkProtectionEnabled = $true
            UsbScanEnabled = $true
            CloudIntelligenceEnabled = $true
            AutoUpdate = $true
            StartWithWindows = $AddToStartup
            ShowNotifications = $true
        }
        $config | ConvertTo-Json | Set-Content $configPath
    }
    
    Write-Host ""
    Write-Success "Installation completed successfully!"
    Write-Host ""
    Write-Host "  Installation Path: $InstallPath"
    Write-Host "  Data Path: $DataPath"
    Write-Host ""
    
    if (-not $Silent) {
        $launch = Read-Host "Would you like to launch SecureGuard now? (Y/N)"
        if ($launch -eq "Y" -or $launch -eq "y") {
            Start-Process (Join-Path $InstallPath $ExeName)
        }
    }
}

function Uninstall-SecureGuard {
    Show-Banner
    
    Write-Step "Uninstalling $AppName..."
    
    # Stop running instances
    Write-Info "Stopping SecureGuard..."
    Get-Process -Name "SecureGuard" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Remove from startup
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $regPath -Name "SecureGuard" -ErrorAction SilentlyContinue
    
    # Remove desktop shortcut
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "SecureGuard.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
    }
    
    # Remove uninstaller registration
    $uninstallPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\SecureGuard"
    Remove-Item -Path $uninstallPath -Force -ErrorAction SilentlyContinue
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Write-Info "Removing installation files..."
        Remove-Item $InstallPath -Recurse -Force
    }
    
    # Ask about user data
    if (Test-Path $DataPath) {
        $removeData = Read-Host "Remove user data and settings? (Y/N)"
        if ($removeData -eq "Y" -or $removeData -eq "y") {
            Remove-Item $DataPath -Recurse -Force
            Write-Info "User data removed"
        }
    }
    
    Write-Host ""
    Write-Success "Uninstallation completed!"
    Write-Host ""
}

# Main execution
if ($Uninstall) {
    Uninstall-SecureGuard
} else {
    Install-SecureGuard
}

