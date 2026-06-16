#Requires -RunAsAdministrator
# TPT-AV Windows installer (PowerShell)
# Usage:  irm https://raw.githubusercontent.com/tpt-av/tpt-av/main/install.ps1 | iex
# Or:     .\install.ps1
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\TPT-AV",
    [string]$ConfigDir  = "$env:ProgramData\TPT",
    [string]$DataDir    = "$env:ProgramData\TPT\data",
    [string]$LogDir     = "$env:ProgramData\TPT\logs"
)

$Repo = "tpt-av/tpt-av"

Write-Host "TPT-AV Windows Installer" -ForegroundColor Cyan
Write-Host ""

# Fetch latest release
$api = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $release = Invoke-RestMethod -Uri $api -UseBasicParsing
    $tag = $release.tag_name
} catch {
    Write-Error "Could not fetch release info: $_"
    exit 1
}

Write-Host "Latest release: $tag"

$zipName = "tpt-av_${tag}_windows_amd64.zip"
$url = "https://github.com/$Repo/releases/download/$tag/$zipName"

$tmp = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path "$_.dir" }
$zipPath = Join-Path $tmp.FullName $zipName

Write-Host "Downloading $url…"
try {
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}

Write-Host "Extracting…"
Expand-Archive -Path $zipPath -DestinationPath $tmp.FullName -Force

# Create directories
foreach ($dir in @($InstallDir, $ConfigDir, $DataDir, $LogDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Copy binaries
$binaries = @("tpt-guard.exe", "tpt-patrol.exe", "tpt-backup.exe", "tptctl.exe")
foreach ($bin in $binaries) {
    $src = Join-Path $tmp.FullName $bin
    if (Test-Path $src) {
        Copy-Item $src -Destination $InstallDir -Force
        Write-Host "  Installed $bin"
    }
}

# Copy default configs (don't overwrite existing)
foreach ($cfg in @("guard", "patrol", "backup")) {
    $dest = Join-Path $ConfigDir "$cfg.toml"
    $src  = Join-Path $tmp.FullName "$cfg.toml.example"
    if (!(Test-Path $dest) -and (Test-Path $src)) {
        Copy-Item $src -Destination $dest
        Write-Host "  Created $dest — edit before starting the services."
    }
}

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallDir", "Machine")
    Write-Host "  Added $InstallDir to system PATH"
}

# Register Windows services
$guard  = Join-Path $InstallDir "tpt-guard.exe"
$patrol = Join-Path $InstallDir "tpt-patrol.exe"
$backup = Join-Path $InstallDir "tpt-backup.exe"

foreach ($svc in @(
    @{ Name="tpt-guard";  Exe=$guard;  Desc="TPT Guard (firewall + DNS)"; Display="TPT Guard" },
    @{ Name="tpt-patrol"; Exe=$patrol; Desc="TPT Patrol (file scanner)";  Display="TPT Patrol" },
    @{ Name="tpt-backup"; Exe=$backup; Desc="TPT Backup daemon";           Display="TPT Backup" }
)) {
    $existing = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Service $($svc.Name) already exists — skipping"
    } else {
        New-Service -Name $svc.Name -BinaryPathName $svc.Exe `
            -DisplayName $svc.Display -Description $svc.Desc `
            -StartupType Automatic | Out-Null
        Write-Host "  Registered service: $($svc.Name)"
    }
}

# Start core services
Write-Host ""
Write-Host "Starting tpt-guard and tpt-patrol…"
try {
    Start-Service -Name "tpt-guard"
    Start-Service -Name "tpt-patrol"
    Write-Host "  Services started." -ForegroundColor Green
} catch {
    Write-Warning "Could not start services: $_"
    Write-Host "Start manually with: Start-Service tpt-guard, tpt-patrol"
}

# Create Start Menu shortcut for the dashboard
$shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\TPT-AV.url"
$shortcutContent = "[InternetShortcut]`r`nURL=http://127.0.0.1:7731`r`n"
Set-Content -Path $shortcutPath -Value $shortcutContent
Write-Host "  Created Start Menu shortcut → TPT-AV Dashboard"

# Cleanup
Remove-Item -Recurse -Force $tmp.FullName

Write-Host ""
Write-Host "TPT-AV $tag installed successfully." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:7731  (open in browser once services start)"
Write-Host ""
Write-Host "To enable TPT Backup: edit $ConfigDir\backup.toml then: Start-Service tpt-backup"
