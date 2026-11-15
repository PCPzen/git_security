# =====================================================================
# Security Sentinel Ultra v8.0 - System Tray Companion (NotifyIcon)
# Instant Taskbar access, PID-verified Dashboard focus, UAC-verified Stop,
# Trust-Anchor script verification & 15-minute Auto-Resume monitor
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, System.Security

$RegInstallDir = $null
foreach ($rp in @("HKLM:\SOFTWARE\SecuritySentinel\PublicHashes", "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor")) {
    if (Test-Path $rp) {
        $d = (Get-ItemProperty -Path $rp -Name "InstallDir" -ErrorAction SilentlyContinue).InstallDir
        if ($d -and (Test-Path (Join-Path $d "SentinelWatchdog.ps1"))) { $RegInstallDir = $d; break }
    }
}

$ProgDir       = "$env:ProgramFiles\SecuritySentinel"
$StateDir      = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
$SentinelDir   = if ($RegInstallDir) {
    $RegInstallDir
} elseif (Test-Path (Join-Path $ProgDir "SentinelWatchdog.ps1")) {
    $ProgDir
} elseif ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "SentinelWatchdog.ps1"))) {
    $PSScriptRoot
} else {
    $StateDir
}

$PidFile         = Join-Path $StateDir "sentinel.pid"
$DashPidFile     = Join-Path $StateDir "dashboard.pid"
$PauseFile       = Join-Path $StateDir "paused_until.txt"
$ManifestFile    = Join-Path $StateDir "manifest.json"
$DashboardScript = Join-Path $SentinelDir "SentinelDashboard.ps1"
$StartScript     = Join-Path $SentinelDir "Start-Shield.ps1"
$StopScript      = Join-Path $SentinelDir "Stop-Shield.ps1"
$QuarDir         = Join-Path $StateDir "quarantine"

if (-not ("SentinelTrayNative.WinUtil" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace SentinelTrayNative {
    public static class WinUtil {
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    }
}
"@ -ErrorAction SilentlyContinue
}

function Get-SentinelSecret {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        try {
            $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction Stop).InstallSecret
            if ($b64) {
                $bytes = [Convert]::FromBase64String($b64)
                if ($bytes -and $bytes.Length -ge 16) { return $bytes }
            }
        } catch {}
        return $null
    }
    $vaultFile = Join-Path $StateDir "vault.sec"
    if (Test-Path $vaultFile) {
        try {
            $encB64 = (Get-Content $vaultFile -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
            $encBytes = [Convert]::FromBase64String($encB64)
            $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            if ($decBytes -and $decBytes.Length -ge 16) { return $decBytes }
        } catch {}
    }
    return $null
}

function Test-TrustedScriptIntegrity([string]$FilePath) {
    if (-not (Test-Path $FilePath -PathType Leaf)) { return $false }
    $leaf = Split-Path $FilePath -Leaf
    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if (-not $actual) { return $false }

    foreach ($regPath in @("HKLM:\SOFTWARE\SecuritySentinel\PublicHashes", "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor")) {
        if (Test-Path $regPath) {
            try {
                $expected = (Get-ItemProperty -Path $regPath -Name $leaf -ErrorAction SilentlyContinue).$leaf
                if ($expected) { return ($actual.ToUpper() -eq "$expected".Trim().ToUpper()) }
            } catch {}
        }
    }
    if (Test-Path $ManifestFile) {
        try {
            $sec = Get-SentinelSecret
            if ($sec) {
                $mObj = Get-Content $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($mObj -and $mObj.SealedHashes) {
                    $enc = [Convert]::FromBase64String($mObj.SealedHashes)
                    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $sec, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                    $parsed = ([System.Text.Encoding]::UTF8.GetString($dec)) | ConvertFrom-Json
                    if ($parsed.$leaf) {
                        return ($actual.ToUpper() -eq "$($parsed.$leaf)".Trim().ToUpper())
                    }
                }
            }
        } catch {}
    }
    return $false
}

# 1. Initialize Application Context & NotifyIcon
$appContext = New-Object System.Windows.Forms.ApplicationContext
$notify = New-Object System.Windows.Forms.NotifyIcon

$customIcon = $null
if ($SentinelDir) {
    $icoPath = Join-Path $SentinelDir "sentinel.ico"
    if (Test-Path $icoPath -PathType Leaf) {
        try { $customIcon = New-Object System.Drawing.Icon($icoPath) } catch {}
    }
    if (-not $customIcon) {
        foreach ($ext in @("sentinel.png", "sentinel.jpg")) {
            $imgPath = Join-Path $SentinelDir $ext
            if (Test-Path $imgPath -PathType Leaf) {
                $bmp = $null
                $scaled = $null
                try {
                    $bmp = New-Object System.Drawing.Bitmap($imgPath)
                    $scaled = New-Object System.Drawing.Bitmap($bmp, (New-Object System.Drawing.Size(64, 64)))
                    $hIcon = $scaled.GetHicon()
                    $tmpIcon = [System.Drawing.Icon]::FromHandle($hIcon)
                    $customIcon = $tmpIcon.Clone()
                    $tmpIcon.Dispose()
                    break
                } catch {} finally {
                    if ($scaled) { $scaled.Dispose() }
                    if ($bmp) { $bmp.Dispose() }
                }
            }
        }
    }
}
$notify.Icon = if ($customIcon) { $customIcon } else { [System.Drawing.SystemIcons]::Shield }
$notify.Text = "Security Sentinel Ultra v8.0"
$notify.Visible = $true

function Test-IsShieldActive {
    if (Test-Path $PidFile) {
        $rPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($rPid -and ($rPid.Trim() -match '^\d+$')) {
            $p = Get-Process -Id ([int]$rPid.Trim()) -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -match '^(powershell|pwsh)$') { return $true }
        }
    }
    return $false
}

function Open-Dashboard {
    # C4: Use recorded dashboard.pid + command-line verification instead of spoofable window title
    if (Test-Path $DashPidFile) {
        try {
            $dRaw = (Get-Content $DashPidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($dRaw -and ($dRaw.Trim() -match '^\d+$')) {
                $dPidInt = [int]$dRaw.Trim()
                $dProc = Get-Process -Id $dPidInt -ErrorAction SilentlyContinue
                if ($dProc -and $dProc.MainWindowHandle -ne [IntPtr]::Zero) {
                    $cimD = Get-CimInstance Win32_Process -Filter "ProcessId = $dPidInt" -ErrorAction SilentlyContinue
                    if ($cimD -and $cimD.CommandLine -match "SentinelDashboard\.ps1") {
                        [void][SentinelTrayNative.WinUtil]::ShowWindowAsync($dProc.MainWindowHandle, 9)
                        [void][SentinelTrayNative.WinUtil]::SetForegroundWindow($dProc.MainWindowHandle)
                        return
                    }
                }
            }
        } catch {}
    }

    if (-not (Test-TrustedScriptIntegrity -FilePath $DashboardScript)) {
        [System.Windows.Forms.MessageBox]::Show("SentinelDashboard.ps1 failed Trust Anchor integrity verification! Refusing to launch.", "Security Sentinel Tamper Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -WindowStyle Hidden -File `"$DashboardScript`""
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    [System.Diagnostics.Process]::Start($psi) | Out-Null
}

function Start-ShieldAction {
    if (-not (Test-TrustedScriptIntegrity -FilePath $StartScript)) {
        $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Start-Shield.ps1 failed integrity check!", [System.Windows.Forms.ToolTipIcon]::Error)
        return
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -WindowStyle Hidden -File `"$StartScript`" -Quiet"
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    [System.Diagnostics.Process]::Start($psi) | Out-Null

    $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Verifying Trust Anchor and starting shield...", [System.Windows.Forms.ToolTipIcon]::Info)
}

function Stop-ShieldAction {
    if (-not (Test-TrustedScriptIntegrity -FilePath $StopScript)) {
        $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Stop-Shield.ps1 failed integrity check!", [System.Windows.Forms.ToolTipIcon]::Error)
        return
    }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Are you sure you want to pause Security Sentinel Shield for 15 minutes?`n`nAdministrator privileges (UAC) are required and this action will be recorded in the Windows Event Log.",
        "Confirm Pause Security Sentinel",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -File `"$StopScript`" -PauseMinutes 15 -Confirmed" -Verb RunAs -WindowStyle Hidden -ErrorAction Stop | Out-Null
        $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Shield paused for 15 minutes (Auto-resume armed).", [System.Windows.Forms.ToolTipIcon]::Warning)
    } catch {
        $notify.ShowBalloonTip(3000, "Security Sentinel Ultra", "Pause cancelled (Administrator elevation required).", [System.Windows.Forms.ToolTipIcon]::Info)
    }
}

# 2. Build Context Menu (Right-Click)
$menu = New-Object System.Windows.Forms.ContextMenu

$headerItem = New-Object System.Windows.Forms.MenuItem("Security Sentinel Ultra v8.0")
$headerItem.Enabled = $false
[void]$menu.MenuItems.Add($headerItem)

[void]$menu.MenuItems.Add("-")

$openDashItem = New-Object System.Windows.Forms.MenuItem("Open Dashboard", { Open-Dashboard })
$openDashItem.DefaultItem = $true
[void]$menu.MenuItems.Add($openDashItem)

[void]$menu.MenuItems.Add("-")

$startItem = New-Object System.Windows.Forms.MenuItem("Start Shield", { Start-ShieldAction })
[void]$menu.MenuItems.Add($startItem)

$stopItem = New-Object System.Windows.Forms.MenuItem("Pause Shield (15m / Admin)", { Stop-ShieldAction })
[void]$menu.MenuItems.Add($stopItem)

[void]$menu.MenuItems.Add("-")

$quarItem = New-Object System.Windows.Forms.MenuItem("Open Quarantine", {
    if (-not (Test-Path $QuarDir)) { New-Item -ItemType Directory -Path $QuarDir -Force | Out-Null }
    Start-Process "explorer.exe" $QuarDir
})
[void]$menu.MenuItems.Add($quarItem)

[void]$menu.MenuItems.Add("-")

$exitItem = New-Object System.Windows.Forms.MenuItem("Exit System Tray", {
    $notify.Visible = $false
    $notify.Dispose()
    [System.Windows.Forms.Application]::Exit()
})
[void]$menu.MenuItems.Add($exitItem)

$notify.ContextMenu = $menu

# 3. Double-Click or Left-Click to Open Dashboard
$notify.Add_DoubleClick({ Open-Dashboard })
$notify.Add_Click({
    if ([System.Windows.Forms.Control]::MouseButtons -eq [System.Windows.Forms.MouseButtons]::Left) {
        Open-Dashboard
    }
})

# 4. Background Timer to keep Tooltip, Menu Status & 15-Minute Auto-Resume updated
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({
    $isActive = Test-IsShieldActive
    if ($isActive) {
        $notify.Text = "Security Sentinel Ultra v8.0`nStatus: SECURED & ACTIVE"
        $headerItem.Text = "Status: Active (Protected)"
        $startItem.Enabled = $false
        $stopItem.Enabled = $true
    } else {
        $notify.Text = "Security Sentinel Ultra v8.0`nStatus: SHIELD OFFLINE"
        $headerItem.Text = "Status: Shield Offline"
        $startItem.Enabled = $true
        $stopItem.Enabled = $false

        # Check if 15-minute pause timer has expired -> Auto-Resume!
        if (Test-Path $PauseFile) {
            try {
                $rawTs = (Get-Content $PauseFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
                if ($rawTs -match '^\d+$') {
                    $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    if ($nowUnix -ge ([long]$rawTs)) {
                        Remove-Item $PauseFile -Force -ErrorAction SilentlyContinue
                        Start-ShieldAction
                    }
                }
            } catch {}
        }
    }
})
$timer.Start()

$notify.ShowBalloonTip(3000, "Security Sentinel Ultra v8.0", "Active in System Tray. Click here anytime to open the Dashboard.", [System.Windows.Forms.ToolTipIcon]::Info)
[System.Windows.Forms.Application]::Run($appContext)
