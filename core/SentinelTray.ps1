# =====================================================================
# Security Sentinel Ultra v8.0 - System Tray Companion (NotifyIcon)
# Provides instant access from Windows Taskbar System Tray (^ menu)
# =====================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$StateDir      = "$env:LOCALAPPDATA\SecuritySentinel"
$PidFile       = Join-Path $StateDir "sentinel.pid"
$CoreDir       = $PSScriptRoot
$RootDir       = Split-Path -Parent $PSScriptRoot
$DashboardScript = Join-Path $CoreDir "SentinelDashboard.ps1"
$StartScript     = Join-Path $CoreDir "Start-Shield.ps1"
$StopScript      = Join-Path $CoreDir "Stop-Shield.ps1"
$QuarDir         = Join-Path $StateDir "quarantine"

# 1. Initialize Application Context & NotifyIcon
$appContext = New-Object System.Windows.Forms.ApplicationContext
$notify = New-Object System.Windows.Forms.NotifyIcon

$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = "Security Sentinel Ultra v8.0"
$notify.Visible = $true

function Test-IsShieldActive {
    if (Test-Path $PidFile) {
        $rPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($rPid -match '^\d+$') {
            $p = Get-Process -Id [int]$rPid -ErrorAction SilentlyContinue
            if ($p) { return $true }
        }
    }
    return $false
}

function Open-Dashboard {
    try {
        $existingDash = Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match "Security Sentinel" }
        if ($existingDash) {
            # Bring existing window to front
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinUtil {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@ -ErrorAction SilentlyContinue
            [WinUtil]::SetForegroundWindow($existingDash.MainWindowHandle) | Out-Null
            return
        }
    } catch {}

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$DashboardScript`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
    [System.Diagnostics.Process]::Start($psi) | Out-Null
}

function Start-ShieldAction {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$StartScript`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    [System.Diagnostics.Process]::Start($psi) | Out-Null

    $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Shield protection starting...", [System.Windows.Forms.ToolTipIcon]::Info)
}

function Stop-ShieldAction {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$StopScript`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    [System.Diagnostics.Process]::Start($psi) | Out-Null

    $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Shield protection paused/stopped.", [System.Windows.Forms.ToolTipIcon]::Warning)
}

# 2. Build Context Menu (Right-Click)
$menu = New-Object System.Windows.Forms.ContextMenu

$headerItem = New-Object System.Windows.Forms.MenuItem("🛡️ Security Sentinel Ultra v8.0")
$headerItem.Enabled = $false
[void]$menu.MenuItems.Add($headerItem)

[void]$menu.MenuItems.Add("-")

$openDashItem = New-Object System.Windows.Forms.MenuItem("🖥️ Open Dashboard", { Open-Dashboard })
$openDashItem.DefaultItem = $true
[void]$menu.MenuItems.Add($openDashItem)

[void]$menu.MenuItems.Add("-")

$startItem = New-Object System.Windows.Forms.MenuItem("🟢 Start Shield", { Start-ShieldAction })
[void]$menu.MenuItems.Add($startItem)

$stopItem = New-Object System.Windows.Forms.MenuItem("🔴 Stop Shield (Pause)", { Stop-ShieldAction })
[void]$menu.MenuItems.Add($stopItem)

[void]$menu.MenuItems.Add("-")

$quarItem = New-Object System.Windows.Forms.MenuItem("📁 Open Quarantine", {
    if (-not (Test-Path $QuarDir)) { New-Item -ItemType Directory -Path $QuarDir -Force | Out-Null }
    Start-Process "explorer.exe" $QuarDir
})
[void]$menu.MenuItems.Add($quarItem)

[void]$menu.MenuItems.Add("-")

$exitItem = New-Object System.Windows.Forms.MenuItem("❌ Exit System Tray", {
    $notify.Visible = $false
    $notify.Dispose()
    [System.Windows.Forms.Application]::Exit()
})
[void]$menu.MenuItems.Add($exitItem)

$notify.ContextMenu = $menu

# 3. Double-Click or Click to Open Dashboard
$notify.Add_DoubleClick({ Open-Dashboard })
$notify.Add_Click({
    # If left clicked, open Dashboard
    if ([System.Windows.Forms.Control]::MouseButtons -eq [System.Windows.Forms.MouseButtons]::Left) {
        Open-Dashboard
    }
})

# 4. Background Timer to keep Tooltip and Menu Status updated
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000 # Check every 3 seconds
$timer.Add_Tick({
    $isActive = Test-IsShieldActive
    if ($isActive) {
        $notify.Text = "Security Sentinel Ultra v8.0`nStatus: SECURED & ACTIVE"
        $headerItem.Text = "🛡️ Status: Active (Protected)"
        $startItem.Enabled = $false
        $stopItem.Enabled = $true
    } else {
        $notify.Text = "Security Sentinel Ultra v8.0`nStatus: SHIELD OFFLINE"
        $headerItem.Text = "⚠️ Status: Shield Offline"
        $startItem.Enabled = $true
        $stopItem.Enabled = $false
    }
})
$timer.Start()

# Initial balloon tip informing user
$notify.ShowBalloonTip(3000, "Security Sentinel Ultra v8.0", "Active in System Tray. Click here anytime to open the Dashboard.", [System.Windows.Forms.ToolTipIcon]::Info)

# Run message loop
[System.Windows.Forms.Application]::Run($appContext)
