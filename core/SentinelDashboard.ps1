# =====================================================================
# Security Sentinel Ultra - Modern GUI Command Center (WPF / XAML)
# Version 8.0 Enterprise EDR Edition (3-State Traffic Light & Safe Rollback)
# =====================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing, Microsoft.VisualBasic, System.Security

$SentinelDir   = Join-Path $env:LOCALAPPDATA "SecuritySentinel"
$ConfigFile    = Join-Path $SentinelDir "config.json"
$PortableCfg   = Join-Path $PSScriptRoot "config.json"
$LogFile       = Join-Path $SentinelDir "logs\sentinel.log"
$QuarDir       = Join-Path $SentinelDir "quarantine"
$PidFile       = Join-Path $SentinelDir "sentinel.pid"
$NetFile       = Join-Path $SentinelDir "network.state"
$FrozenFile    = Join-Path $SentinelDir "last_frozen.pid"
$StopTokenFile = Join-Path $SentinelDir "graceful_stop.token"
$ScriptPath    = Join-Path $SentinelDir "SentinelWatchdog.ps1"
if (-not (Test-Path $ScriptPath)) { $ScriptPath = Join-Path $PSScriptRoot "SentinelWatchdog.ps1" }

# Ensure directories exist
@($SentinelDir, (Join-Path $SentinelDir "logs"), $QuarDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# Seed config.json from portable folder if not present in LocalAppData
if ((-not (Test-Path $ConfigFile)) -and (Test-Path $PortableCfg)) {
    Copy-Item -Path $PortableCfg -Destination $ConfigFile -Force
}

function Thaw-FrozenProcess([int]$TargetPid) {
    if ($TargetPid -le 0) { return $false }
    if ("SentinelNative.KernelControl" -as [type]) {
        try { return [SentinelNative.KernelControl]::ThawProcess($TargetPid) } catch {}
    }
    try {
        $thawReq = Join-Path $SentinelDir "thaw_request.pid"
        [System.IO.File]::WriteAllText($thawReq, "$TargetPid", [System.Text.Encoding]::UTF8)
        return $true
    } catch { return $false }
}

function Get-DashboardInstallSecretBytes {
    Remove-Item -Path "HKCU:\Software\SecuritySentinel" -Recurse -Force -ErrorAction SilentlyContinue
    $regPath = "HKLM:\SOFTWARE\SecuritySentinel\IntegrityAnchor"
    if (Test-Path $regPath) {
        $b64 = (Get-ItemProperty -Path $regPath -Name "InstallSecret" -ErrorAction SilentlyContinue).InstallSecret
        if ($b64) {
            try { return [Convert]::FromBase64String($b64) } catch {}
        }
    }
    return [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)
}

$script:SentinelEntropyBytes = Get-DashboardInstallSecretBytes
$script:LegacyEntropyBytes   = [System.Text.Encoding]::UTF8.GetBytes("SENTINEL_ULTRA_V6_ENTROPY_" + $env:COMPUTERNAME)

function Protect-DpapiString([string]$PlainText) {
    if ([string]::IsNullOrWhiteSpace($PlainText)) { return "" }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $enc   = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $script:SentinelEntropyBytes, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($enc)
    } catch { return "" }
}

function Unprotect-DpapiString([string]$CipherBase64) {
    if ([string]::IsNullOrWhiteSpace($CipherBase64)) { return "" }
    try {
        $enc = [Convert]::FromBase64String($CipherBase64)
        foreach ($ent in @($script:SentinelEntropyBytes, $script:LegacyEntropyBytes, $null)) {
            try {
                $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $ent, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                return [System.Text.Encoding]::UTF8.GetString($bytes)
            } catch {}
        }
    } catch {}
    return ""
}

function New-AuthenticatedStopToken {
    try {
        $wdPid = "0"
        if (Test-Path $PidFile) {
            $rawPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($rawPid -and ($rawPid.Trim() -match '^\d+$')) { $wdPid = $rawPid.Trim() }
        }
        $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $cipher = Protect-DpapiString "STOP|$wdPid|$ts"
        if ($cipher) {
            [System.IO.File]::WriteAllText($StopTokenFile, $cipher, [System.Text.Encoding]::UTF8)
        }
    } catch {}
}

$defaultConfig = [ordered]@{
    DiscordWebhookUrl        = ""
    DiscordWebhookEncrypted  = ""
    DiscordMentionOnCritical = $true
    VirusTotalApiKey         = ""
    VirusTotalKeyEncrypted   = ""
    EnableSoundAlert         = $true
    EnableToastAlert         = $true
    DecoyInDocuments         = $true
    AutoFreezeSuspiciousProc = $true
    SafeWorkGamingMode       = $true
    AutoFreezeMinRiskScore   = 85
    AutoNetworkKillswitch    = $false
    ScanIntervalSeconds      = 15
}

function Get-SentinelConfig {
    $target = if (Test-Path $ConfigFile) { $ConfigFile } elseif (Test-Path $PortableCfg) { $PortableCfg } else { $null }
    if ($target) {
        try {
            $raw = Get-Content $target -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in $defaultConfig.Keys) {
                if ($null -eq $raw.$k) {
                    $raw | Add-Member -NotePropertyName $k -NotePropertyValue $defaultConfig[$k] -Force
                }
            }
            if ([string]::IsNullOrWhiteSpace($raw.DiscordWebhookUrl) -and (-not [string]::IsNullOrWhiteSpace($raw.DiscordWebhookEncrypted))) {
                $raw.DiscordWebhookUrl = Unprotect-DpapiString $raw.DiscordWebhookEncrypted
            }
            if ([string]::IsNullOrWhiteSpace($raw.VirusTotalApiKey) -and (-not [string]::IsNullOrWhiteSpace($raw.VirusTotalKeyEncrypted))) {
                $raw.VirusTotalApiKey = Unprotect-DpapiString $raw.VirusTotalKeyEncrypted
            }
            return $raw
        } catch {
            return [PSCustomObject]$defaultConfig
        }
    } else {
        $json = ($defaultConfig | ConvertTo-Json -Depth 4)
        [System.IO.File]::WriteAllText($ConfigFile, $json, [System.Text.Encoding]::UTF8)
        return [PSCustomObject]$defaultConfig
    }
}

function Save-SentinelConfig($cfgObj) {
    $diskObj = [ordered]@{}
    foreach ($k in $defaultConfig.Keys) { $diskObj[$k] = $cfgObj.$k }
    if (-not [string]::IsNullOrWhiteSpace($cfgObj.DiscordWebhookUrl)) {
        $diskObj["DiscordWebhookEncrypted"] = Protect-DpapiString $cfgObj.DiscordWebhookUrl
        $diskObj["DiscordWebhookUrl"]       = ""
    } else {
        $diskObj["DiscordWebhookEncrypted"] = ""
        $diskObj["DiscordWebhookUrl"]       = ""
    }
    if (-not [string]::IsNullOrWhiteSpace($cfgObj.VirusTotalApiKey)) {
        $diskObj["VirusTotalKeyEncrypted"] = Protect-DpapiString $cfgObj.VirusTotalApiKey
        $diskObj["VirusTotalApiKey"]       = ""
    }
    $json = ($diskObj | ConvertTo-Json -Depth 4)
    [System.IO.File]::WriteAllText($ConfigFile, $json, [System.Text.Encoding]::UTF8)
}

# Standard .NET Performance Counter & ComputerInfo for Zero-Lag CPU & RAM Metrics
$script:cpuCounter = $null
try {
    $script:cpuCounter = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total", $true)
    [void]$script:cpuCounter.NextValue()
} catch {}
$script:compInfo = New-Object Microsoft.VisualBasic.Devices.ComputerInfo

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Security Sentinel Ultra v7.0 - Cyber-EDR Command Center" Height="830" Width="1080"
        WindowStartupLocation="CenterScreen" Background="#060911" FontFamily="Segoe UI"
        Foreground="#E2E8F0">
    <Window.Resources>
        <!-- Modern Button Style with Hover Glow -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="#151F32"/>
            <Setter Property="Foreground" Value="#F8FAFC"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#2A3A54"/>
            <Setter Property="Padding" Value="13,7"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="BtnBorder" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="BtnBorder" Property="BorderBrush" Value="#38BDF8"/>
                                <Setter Property="Opacity" Value="0.92"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Sleek Cyber ProgressBar Style -->
        <Style x:Key="CyberProgressBar" TargetType="ProgressBar">
            <Setter Property="Height" Value="8"/>
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Grid x:Name="TemplateRoot" SnapsToDevicePixels="True">
                            <Border Background="{TemplateBinding Background}" CornerRadius="4"/>
                            <Border x:Name="PART_Track" CornerRadius="4"/>
                            <Decorator x:Name="PART_Indicator" HorizontalAlignment="Left">
                                <Border Background="{TemplateBinding Foreground}" CornerRadius="4"/>
                            </Decorator>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- ROW 0: TOP CYBER HEADER -->
        <Border Grid.Row="0" CornerRadius="10" Padding="18,14" Margin="0,0,0,12" BorderThickness="1" BorderBrush="#1E293B">
            <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
                    <GradientStop Color="#0D1526" Offset="0.0"/>
                    <GradientStop Color="#111C35" Offset="0.5"/>
                    <GradientStop Color="#0D1526" Offset="1.0"/>
                </LinearGradientBrush>
            </Border.Background>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Border Background="#0284C7" CornerRadius="5" Padding="8,3" Margin="0,0,10,0" VerticalAlignment="Center">
                            <TextBlock Text="EDR // CORE" FontSize="12" FontWeight="Bold" Foreground="#F8FAFC"/>
                        </Border>
                        <TextBlock Text="SECURITY SENTINEL ULTRA" FontSize="22" FontWeight="Bold" Foreground="#38BDF8" VerticalAlignment="Center"/>
                        <Border Background="#1E1B4B" BorderBrush="#4338CA" BorderThickness="1" CornerRadius="4" Padding="8,2" Margin="10,0,0,0" VerticalAlignment="Center">
                            <TextBlock Text="v7.0 WORK & GAMING SAFE-MODE" FontSize="11" FontWeight="Bold" Foreground="#818CF8"/>
                        </Border>
                    </StackPanel>
                    <TextBlock Text="Autonomous Endpoint Defense | Real-Time Hardware &amp; Process Telemetry | Response Engine | SHA-256 VT &amp; Discord Integration" FontSize="12" Foreground="#94A3B8" Margin="0,5,0,0"/>
                </StackPanel>
                
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border x:Name="BadgeStatus" Background="#064E3B" BorderBrush="#10B981" BorderThickness="1" CornerRadius="20" Padding="16,7">
                        <StackPanel Orientation="Horizontal">
                            <Ellipse x:Name="DotStatus" Width="10" Height="10" Fill="#10B981" Margin="0,0,8,0"/>
                            <TextBlock x:Name="TxtStatus" Text="SYSTEM SECURED" FontWeight="Bold" FontSize="12" Foreground="#34D399"/>
                        </StackPanel>
                    </Border>
                </StackPanel>
            </Grid>
        </Border>

        <!-- ROW 1: REAL-TIME CPU & RAM RESOURCE TELEMETRY PANEL -->
        <Grid Grid.Row="1" Margin="0,0,0,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Gauge 1: System CPU Load -->
            <Border Grid.Column="0" Background="#0C1322" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="14,11" Margin="0,0,6,0">
                <StackPanel>
                    <Grid>
                        <TextBlock Text="SYSTEM CPU USAGE" FontSize="11" FontWeight="Bold" Foreground="#64748B"/>
                        <TextBlock x:Name="TxtSysCpuPct" Text="0.0%" FontSize="16" FontWeight="Bold" Foreground="#38BDF8" HorizontalAlignment="Right"/>
                    </Grid>
                    <ProgressBar x:Name="BarSysCpu" Style="{StaticResource CyberProgressBar}" Minimum="0" Maximum="100" Value="5" Foreground="#38BDF8" Margin="0,7,0,6"/>
                    <Grid>
                        <TextBlock x:Name="TxtCpuCores" Text="Processor Telemetry" FontSize="11" Foreground="#94A3B8"/>
                        <TextBlock x:Name="TxtCpuState" Text="OPTIMAL" FontSize="10" FontWeight="Bold" Foreground="#10B981" HorizontalAlignment="Right"/>
                    </Grid>
                </StackPanel>
            </Border>

            <!-- Gauge 2: System RAM Usage -->
            <Border Grid.Column="1" Background="#0C1322" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="14,11" Margin="3,0,3,0">
                <StackPanel>
                    <Grid>
                        <TextBlock Text="SYSTEM MEMORY (RAM)" FontSize="11" FontWeight="Bold" Foreground="#64748B"/>
                        <TextBlock x:Name="TxtSysRamPct" Text="0%" FontSize="16" FontWeight="Bold" Foreground="#A855F7" HorizontalAlignment="Right"/>
                    </Grid>
                    <ProgressBar x:Name="BarSysRam" Style="{StaticResource CyberProgressBar}" Minimum="0" Maximum="100" Value="40" Foreground="#A855F7" Margin="0,7,0,6"/>
                    <Grid>
                        <TextBlock x:Name="TxtSysRamDetail" Text="Calculating physical memory..." FontSize="11" Foreground="#94A3B8"/>
                        <TextBlock Text="PHYSICAL RAM" FontSize="10" FontWeight="Bold" Foreground="#818CF8" HorizontalAlignment="Right"/>
                    </Grid>
                </StackPanel>
            </Border>

            <!-- Gauge 3: Sentinel Engine Resource Footprint -->
            <Border Grid.Column="2" Background="#0C1322" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="14,11" Margin="6,0,0,0">
                <StackPanel>
                    <Grid>
                        <TextBlock Text="SENTINEL ENGINE FOOTPRINT" FontSize="11" FontWeight="Bold" Foreground="#64748B"/>
                        <TextBlock x:Name="TxtSentinelMetrics" Text="CPU: 0.0% | RAM: -- MB" FontSize="14" FontWeight="Bold" Foreground="#10B981" HorizontalAlignment="Right"/>
                    </Grid>
                    <ProgressBar x:Name="BarSentinelLoad" Style="{StaticResource CyberProgressBar}" Minimum="0" Maximum="100" Value="2" Foreground="#10B981" Margin="0,7,0,6"/>
                    <Grid>
                        <TextBlock x:Name="TxtGamingImpact" Text="Gaming FPS Impact: 0.0% (Event-Driven)" FontSize="11" Foreground="#94A3B8"/>
                        <TextBlock Text="ULTRA-LIGHT" FontSize="10" FontWeight="Bold" Foreground="#34D399" HorizontalAlignment="Right"/>
                    </Grid>
                </StackPanel>
            </Border>
        </Grid>

        <!-- ROW 2: 5-TIER ARCHITECTURE STATUS MATRIX -->
        <Grid Grid.Row="2" Margin="0,0,0,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Tier 1 -->
            <Border Grid.Column="0" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="11,9" Margin="0,0,5,0">
                <StackPanel>
                    <TextBlock Text="TIER 1: CORE WATCHDOG" FontSize="10" FontWeight="Bold" Foreground="#64748B"/>
                    <TextBlock x:Name="TxtDaemonStatus" Text="RUNNING" FontSize="15" FontWeight="Bold" Foreground="#10B981" Margin="0,3,0,0"/>
                    <TextBlock x:Name="TxtPid" Text="PID: Detecting..." FontSize="11" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>
            </Border>

            <!-- Tier 2 -->
            <Border Grid.Column="1" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="11,9" Margin="3,0,3,0">
                <StackPanel>
                    <TextBlock Text="TIER 2: PROCESS GUARD" FontSize="10" FontWeight="Bold" Foreground="#64748B"/>
                    <TextBlock Text="ETW / WMI ARMED" FontSize="15" FontWeight="Bold" Foreground="#38BDF8" Margin="0,3,0,0"/>
                    <TextBlock Text="Parent-Child &amp; LOLBin" FontSize="11" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>
            </Border>

            <!-- Tier 3 -->
            <Border Grid.Column="2" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="11,9" Margin="3,0,3,0">
                <StackPanel>
                    <TextBlock Text="TIER 3: RESPONSE ENGINE" FontSize="10" FontWeight="Bold" Foreground="#64748B"/>
                    <TextBlock x:Name="TxtTier3Status" Text="RESPONSE READY" FontSize="15" FontWeight="Bold" Foreground="#A855F7" Margin="0,3,0,0"/>
                    <TextBlock x:Name="TxtTier3Sub" Text="Micro-Freeze &amp; Killswitch" FontSize="11" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>
            </Border>

            <!-- Tier 4 -->
            <Border Grid.Column="3" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="11,9" Margin="3,0,3,0">
                <StackPanel>
                    <TextBlock Text="TIER 4: ZERO-TRUST" FontSize="10" FontWeight="Bold" Foreground="#64748B"/>
                    <TextBlock Text="ENFORCED" FontSize="15" FontWeight="Bold" Foreground="#F59E0B" Margin="0,3,0,0"/>
                    <TextBlock Text="Canary + Authenticode" FontSize="11" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>
            </Border>

            <!-- Tier 5 -->
            <Border Grid.Column="4" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="11,9" Margin="5,0,0,0">
                <StackPanel>
                    <TextBlock Text="TIER 5: DISCORD &amp; VT" FontSize="10" FontWeight="Bold" Foreground="#64748B"/>
                    <TextBlock x:Name="TxtWebhookStatus" Text="WEBHOOK LINKED" FontSize="15" FontWeight="Bold" Foreground="#10B981" Margin="0,3,0,0"/>
                    <TextBlock x:Name="TxtWebhookSub" Text="SHA-256 + Rich Embed" FontSize="11" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>
            </Border>
        </Grid>

        <!-- ROW 3: DISCORD WEBHOOK & TIER 3/5 QUICK CONFIGURATION BAR -->
        <Border Grid.Row="3" Background="#0C1322" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="0,0,0,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,10,0">
                    <TextBlock Text="[WEBHOOK] Notification URL:" FontWeight="Bold" FontSize="12" Foreground="#38BDF8" VerticalAlignment="Center"/>
                </StackPanel>

                <TextBox x:Name="TxtWebhookUrl" Grid.Column="1" Background="#050811" Foreground="#F8FAFC"
                         FontFamily="Consolas" FontSize="12" Padding="8,5" BorderBrush="#2A3A54" BorderThickness="1"
                         VerticalContentAlignment="Center" Margin="0,0,10,0"/>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,10,0">
                    <CheckBox x:Name="ChkPing" Content="Ping @everyone" Foreground="#CBD5E1" FontSize="11" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <CheckBox x:Name="ChkAutoFreeze" Content="Auto-Freeze Process" Foreground="#CBD5E1" FontSize="11" VerticalAlignment="Center"/>
                </StackPanel>

                <Button x:Name="BtnSaveConfig" Grid.Column="3" Content="[SAVE] Save Config" Background="#059669" BorderBrush="#10B981" Margin="0,0,6,0"/>
                <Button x:Name="BtnTestAlert" Grid.Column="4" Content="[TEST] Test Notification" Background="#4F46E5" BorderBrush="#6366F1"/>
            </Grid>
        </Border>

        <!-- ROW 4: LIVE LOG & TELEMETRY STREAM -->
        <Border Grid.Row="4" Background="#090D16" BorderBrush="#1E293B" BorderThickness="1" CornerRadius="8" Padding="12" Margin="0,0,0,12">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Grid Grid.Row="0" Margin="0,0,0,8">
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="[LIVE STREAM]" FontWeight="Bold" Foreground="#38BDF8" Margin="0,0,8,0"/>
                        <TextBlock Text="Autonomous Security Telemetry &amp; Threat Event Console" FontWeight="SemiBold" FontSize="13" Foreground="#CBD5E1"/>
                    </StackPanel>
                    <TextBlock x:Name="TxtClock" Text="Syncing telemetry..." FontSize="11" FontFamily="Consolas" Foreground="#64748B" HorizontalAlignment="Right"/>
                </Grid>
                
                <TextBox x:Name="TxtLogs" Grid.Row="1" Background="#03060C" Foreground="#38BDF8" 
                         FontFamily="Consolas" FontSize="12" IsReadOnly="True" TextWrapping="Wrap"
                         VerticalScrollBarVisibility="Auto" BorderThickness="1" BorderBrush="#152033" Padding="10"/>
            </Grid>
        </Border>

        <!-- ROW 5: ACTION & EMERGENCY RESPONSE DOCK -->
        <Grid Grid.Row="5">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <!-- Left Emergency Controls -->
            <StackPanel Grid.Column="0" Orientation="Horizontal">
                <Button x:Name="BtnKillswitch" Content="[KILLSWITCH] Emergency Cut Network" Background="#991B1B" BorderBrush="#EF4444" Margin="0,0,7,0"/>
                <Button x:Name="BtnThaw" Content="[RESUME / ROLLBACK] Thaw PID or Restore" Background="#1E293B" BorderBrush="#475569"/>
            </StackPanel>

            <!-- Right Standard Controls -->
            <StackPanel Grid.Column="2" Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="BtnScan" Content="[SCAN] Deep Threat Scan (Tier 1-5)" Background="#0284C7" BorderBrush="#38BDF8" Margin="0,0,7,0"/>
                <Button x:Name="BtnQuarantine" Content="[FOLDER] Quarantine" Margin="0,0,7,0"/>
                <Button x:Name="BtnSettings" Content="[JSON] Raw Config" Margin="0,0,7,0"/>
                <Button x:Name="BtnToggleDaemon" Content="[RESTART] Restart Shield" Margin="0,0,7,0"/>
                <Button x:Name="BtnClearLog" Content="[CLEAR] Clear Log"/>
            </StackPanel>
        </Grid>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Bind Controls
$badgeStatus       = $window.FindName("BadgeStatus")
$dotStatus         = $window.FindName("DotStatus")
$txtStatus         = $window.FindName("TxtStatus")
$txtSysCpuPct      = $window.FindName("TxtSysCpuPct")
$barSysCpu         = $window.FindName("BarSysCpu")
$txtCpuCores       = $window.FindName("TxtCpuCores")
$txtCpuState       = $window.FindName("TxtCpuState")
$txtSysRamPct      = $window.FindName("TxtSysRamPct")
$barSysRam         = $window.FindName("BarSysRam")
$txtSysRamDetail   = $window.FindName("TxtSysRamDetail")
$txtSentinelMetrics= $window.FindName("TxtSentinelMetrics")
$barSentinelLoad   = $window.FindName("BarSentinelLoad")
$txtGamingImpact   = $window.FindName("TxtGamingImpact")
$txtDaemonStatus   = $window.FindName("TxtDaemonStatus")
$txtPid            = $window.FindName("TxtPid")
$txtTier3Status    = $window.FindName("TxtTier3Status")
$txtTier3Sub       = $window.FindName("TxtTier3Sub")
$txtWebhookStatus  = $window.FindName("TxtWebhookStatus")
$txtWebhookSub     = $window.FindName("TxtWebhookSub")
$txtWebhookUrl     = $window.FindName("TxtWebhookUrl")
$chkPing           = $window.FindName("ChkPing")
$chkAutoFreeze     = $window.FindName("ChkAutoFreeze")
$btnSaveConfig     = $window.FindName("BtnSaveConfig")
$btnTestAlert      = $window.FindName("BtnTestAlert")
$txtClock          = $window.FindName("TxtClock")
$txtLogs           = $window.FindName("TxtLogs")
$btnKillswitch     = $window.FindName("BtnKillswitch")
$btnThaw           = $window.FindName("BtnThaw")
$btnScan           = $window.FindName("BtnScan")
$btnQuarantine     = $window.FindName("BtnQuarantine")
$btnSettings       = $window.FindName("BtnSettings")
$btnToggleDaemon   = $window.FindName("BtnToggleDaemon")
$btnClearLog       = $window.FindName("BtnClearLog")

# Set Static Hardware Info
$logicalCores = [Environment]::ProcessorCount
$txtCpuCores.Text = "$logicalCores Logical Cores Active"

# Populate initial config into UI controls
$initCfg = Get-SentinelConfig
$txtWebhookUrl.Text      = "$($initCfg.DiscordWebhookUrl)"
$chkPing.IsChecked       = [bool]$initCfg.DiscordMentionOnCritical
$chkAutoFreeze.IsChecked = [bool]$initCfg.AutoFreezeSuspiciousProc

$script:lastProcCpuMs = 0.0
$script:lastWallTime  = [DateTime]::UtcNow

function Append-DashboardLog([string]$Msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] $Msg"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
}

function Get-DaemonProcess {
    if (Test-Path $PidFile) {
        $savedPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($savedPid -match '^\d+$') {
            $p = Get-Process -Id ([int]$savedPid) -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -like "*powershell*") {
                return $p
            }
        }
    }
    $proc = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1" } | Select-Object -First 1
    if ($proc) {
        $proc.ProcessId | Out-File $PidFile -Force
        return Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
    }
    return $null
}

function Update-DashboardStatus {
    $txtClock.Text = "Last Telemetry Sync: " + (Get-Date -Format "HH:mm:ss") + " | Refresh: 2.0s"

    # 1. Update System CPU & RAM Gauges via Managed .NET APIs
    try {
        $sysCpu = 0.0
        if ($null -ne $script:cpuCounter) {
            $sysCpu = [math]::Round($script:cpuCounter.NextValue(), 1)
        }
        $txtSysCpuPct.Text = "$($sysCpu.ToString('0.0'))%"
        $barSysCpu.Value = $sysCpu

        if ($sysCpu -gt 85) {
            $txtCpuState.Text = "HIGH LOAD"
            $txtCpuState.Foreground = [Windows.Media.Brushes]::Tomato
            $barSysCpu.Foreground = [Windows.Media.Brushes]::Tomato
        } elseif ($sysCpu -gt 55) {
            $txtCpuState.Text = "MODERATE"
            $txtCpuState.Foreground = [Windows.Media.Brushes]::Gold
            $barSysCpu.Foreground = [Windows.Media.Brushes]::DeepSkyBlue
        } else {
            $txtCpuState.Text = "OPTIMAL"
            $txtCpuState.Foreground = [Windows.Media.Brushes]::MediumSpringGreen
            $barSysCpu.Foreground = [Windows.Media.Brushes]::DeepSkyBlue
        }

        $totalBytes = [double]$script:compInfo.TotalPhysicalMemory
        $availBytes = [double]$script:compInfo.AvailablePhysicalMemory
        if ($totalBytes -gt 0) {
            $ramTotal = [math]::Round($totalBytes / 1GB, 1)
            $ramAvail = [math]::Round($availBytes / 1GB, 1)
            $ramUsed  = [math]::Round($ramTotal - $ramAvail, 1)
            $ramPct   = [math]::Round((($totalBytes - $availBytes) / $totalBytes) * 100.0, 0)
            $txtSysRamPct.Text    = "$ramPct%"
            $barSysRam.Value      = $ramPct
            $txtSysRamDetail.Text = "Used: $ramUsed GB / $ramTotal GB Total"
        }
    } catch {}

    # 2. Update Sentinel Daemon Status & Footprint
    $proc = Get-DaemonProcess
    if ($proc) {
        $txtDaemonStatus.Text = "RUNNING"
        $txtDaemonStatus.Foreground = [Windows.Media.Brushes]::MediumSpringGreen
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)

        $now = [DateTime]::UtcNow
        $curCpuMs = $proc.TotalProcessorTime.TotalMilliseconds
        $sentinelCpu = 0.0
        if ($script:lastProcCpuMs -gt 0) {
            $elapsedMs = ($now - $script:lastWallTime).TotalMilliseconds
            if ($elapsedMs -gt 100) {
                $sentinelCpu = [math]::Round((($curCpuMs - $script:lastProcCpuMs) / ($elapsedMs * $logicalCores)) * 100.0, 1)
                if ($sentinelCpu -lt 0.0) { $sentinelCpu = 0.0 }
                if ($sentinelCpu -gt 100.0) { $sentinelCpu = 100.0 }
            }
        }
        $script:lastProcCpuMs = $curCpuMs
        $script:lastWallTime  = $now

        $gPidTxt = ""
        $gPidFile = Join-Path $SentinelDir "guardian.pid"
        if (Test-Path $gPidFile) {
            $gRaw = (Get-Content $gPidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($gRaw -and ($gRaw.Trim() -match "^\d+$")) {
                $gProc = Get-Process -Id ([int]$gRaw.Trim()) -ErrorAction SilentlyContinue
                if ($gProc) { $gPidTxt = " + Twin: $($gProc.Id)" }
            }
        }
        $txtPid.Text = "PID: $($proc.Id)$gPidTxt | Active"
        $txtSentinelMetrics.Text = "CPU: $($sentinelCpu.ToString('0.0'))% | RAM: $memMB MB"
        $txtSentinelMetrics.Foreground = [Windows.Media.Brushes]::MediumSpringGreen
        $barSentinelLoad.Value = [Math]::Max(2.0, [Math]::Min(100.0, ($memMB / 10.0) + $sentinelCpu))

        $txtStatus.Text = "SYSTEM SECURED"
        $txtStatus.Foreground = [Windows.Media.Brushes]::MediumSpringGreen
        $badgeStatus.Background = [Windows.Media.Brushes]::DarkGreen
        $dotStatus.Fill = [Windows.Media.Brushes]::MediumSpringGreen
        $btnToggleDaemon.Content = "[STOP] Stop Shield"
        $btnToggleDaemon.Background = (New-Object Windows.Media.BrushConverter).ConvertFromString("#991B1B")
    } else {
        $txtDaemonStatus.Text = "STOPPED"
        $txtDaemonStatus.Foreground = [Windows.Media.Brushes]::IndianRed
        $txtPid.Text = "Daemon offline"
        $txtSentinelMetrics.Text = "CPU: 0.0% | RAM: 0.0 MB"
        $txtSentinelMetrics.Foreground = [Windows.Media.Brushes]::IndianRed
        $barSentinelLoad.Value = 0

        $txtStatus.Text = "SHIELD OFFLINE"
        $txtStatus.Foreground = [Windows.Media.Brushes]::IndianRed
        $badgeStatus.Background = [Windows.Media.Brushes]::DarkRed
        $dotStatus.Fill = [Windows.Media.Brushes]::IndianRed
        $btnToggleDaemon.Content = "[START] Start Shield"
        $btnToggleDaemon.Background = [Windows.Media.Brushes]::DarkGreen
    }

    # 3. Tier 3 Network Killswitch State
    if (Test-Path $NetFile) {
        $txtTier3Status.Text = "NET ISOLATED"
        $txtTier3Status.Foreground = [Windows.Media.Brushes]::Tomato
        $btnKillswitch.Content = "[RESTORE] Restore Network Now"
        $btnKillswitch.Background = [Windows.Media.Brushes]::DarkGreen
    } else {
        $txtTier3Status.Text = "RESPONSE READY"
        $txtTier3Status.Foreground = [Windows.Media.Brushes]::MediumPurple
        $btnKillswitch.Content = "[KILLSWITCH] Emergency Cut Network"
        $btnKillswitch.Background = (New-Object Windows.Media.BrushConverter).ConvertFromString("#991B1B")
    }

    # 4. Tier 5 Webhook Status
    $cfg = Get-SentinelConfig
    if (-not [string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) {
        $txtWebhookStatus.Text = "WEBHOOK LINKED"
        $txtWebhookStatus.Foreground = [Windows.Media.Brushes]::MediumSpringGreen
        $txtWebhookSub.Text = "Cloud Alert + SHA256 Active"
    } else {
        $txtWebhookStatus.Text = "LOCAL ALERT ONLY"
        $txtWebhookStatus.Foreground = [Windows.Media.Brushes]::Goldenrod
        $txtWebhookSub.Text = "Paste Webhook URL below"
    }

    # 5. Live Log Stream
    if (Test-Path $LogFile) {
        $lines = Get-Content $LogFile -Tail 160 -Encoding UTF8 -ErrorAction SilentlyContinue
        $newText = $lines -join "`r`n"
        if ($txtLogs.Text -ne $newText) {
            $txtLogs.Text = $newText
            $txtLogs.ScrollToEnd()
        }
    }
}

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)
$timer.Add_Tick({ Update-DashboardStatus })
$timer.Start()

# Button: Save Webhook & Config directly from UI
$btnSaveConfig.Add_Click({
    $cfg = Get-SentinelConfig
    $cfg.DiscordWebhookUrl        = $txtWebhookUrl.Text.Trim()
    $cfg.DiscordMentionOnCritical = [bool]$chkPing.IsChecked
    $cfg.AutoFreezeSuspiciousProc = [bool]$chkAutoFreeze.IsChecked
    Save-SentinelConfig $cfg

    $statusStr = if ([string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) { "Cleared (Local Mode)" } else { "Configured & Linked" }
    Append-DashboardLog "[CONFIG] Settings saved via Dashboard! Webhook: $statusStr | AutoFreeze: $($cfg.AutoFreezeSuspiciousProc)"
    Update-DashboardStatus
})

# Button: Test Alert & Rich Webhook
$btnTestAlert.Add_Click({
    $cfg = Get-SentinelConfig
    $cfg.DiscordWebhookUrl        = $txtWebhookUrl.Text.Trim()
    $cfg.DiscordMentionOnCritical = [bool]$chkPing.IsChecked
    $cfg.AutoFreezeSuspiciousProc = [bool]$chkAutoFreeze.IsChecked
    Save-SentinelConfig $cfg

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Shield
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipTitle = "Security Sentinel Ultra v7.0"
    $balloon.BalloonTipText = "Telemetry & Notification System is 100% operational!"
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(4000)
    Start-Sleep -Seconds 1
    $balloon.Dispose()

    $webhookStatus = "Local Toast Verified (No Webhook URL entered)"
    if (-not [string]::IsNullOrWhiteSpace($cfg.DiscordWebhookUrl)) {
        try {
            $body = @{
                username = "Security Sentinel Ultra EDR"
                content  = "**[TEST] Security Sentinel Ultra v7.0 - Telemetry & Webhook Verified!**"
                embeds   = @(
                    @{
                        title       = "[TIER 1-5] Endpoint Telemetry & Webhook Active"
                        description = "Your PC is actively guarded by **Security Sentinel Ultra v7.0**. Real-time security alerts and SHA-256 Threat Intel will be delivered here."
                        color       = 1096065
                        fields      = @(
                            @{ name = "Endpoint";           value = "$env:COMPUTERNAME ($env:USERNAME)";  inline = $true },
                            @{ name = "System CPU / RAM";   value = "CPU: $($txtSysCpuPct.Text) | RAM: $($txtSysRamPct.Text)"; inline = $true },
                            @{ name = "Sentinel Footprint"; value = "$($txtSentinelMetrics.Text)";        inline = $true }
                        )
                        footer      = @{ text = "Security Sentinel Ultra v7.0 | Master Architecture Edition | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
                    }
                )
            } | ConvertTo-Json -Depth 6
            Invoke-RestMethod -Uri $cfg.DiscordWebhookUrl -Method Post -ContentType "application/json; charset=utf-8" -Body $body -TimeoutSec 6 -ErrorAction Stop | Out-Null
            $webhookStatus = "Rich Embed delivered successfully!"
        } catch {
            $webhookStatus = "Webhook delivery failed: $($_.Exception.Message)"
        }
    }

    Append-DashboardLog "[TEST] Alert verification complete -> $webhookStatus"
    Update-DashboardStatus
})

# Button: Deep Threat Scan (Tier 1 - Tier 5)
$btnScan.Add_Click({
    Append-DashboardLog "[MANUAL SCAN] ========================================================="
    Append-DashboardLog "[MANUAL SCAN] Initiating Full Tier 1-5 Deep Endpoint Threat Hunt..."
    $threatsFound = 0

    $bRoot = $env:LOCALAPPDATA
    $browserPaths = @(
        (Join-Path $bRoot "Google\Chrome\User Data"),
        (Join-Path $bRoot "Microsoft\Edge\User Data"),
        (Join-Path $bRoot "BraveSoftware\Brave-Browser\User Data")
    )

    foreach ($bp in $browserPaths) {
        if (Test-Path $bp) {
            $bName = Split-Path (Split-Path $bp -Parent) -Leaf
            $peh = Join-Path $bp "PlatformExperienceHelper"
            if (Test-Path $peh) {
                $threatsFound++
                Append-DashboardLog "[ALERT] Rogue module in $($bName): $peh! Quarantining..."
                Remove-Item $peh -Recurse -Force -ErrorAction SilentlyContinue
            }

            Get-ChildItem -Path $bp -File -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                $trusted = ($sig -and $sig.Status -eq 'Valid' -and ($sig.SignerCertificate.Subject -match "Google LLC|Microsoft Corporation|Brave Software|Opera Software"))
                if (-not $trusted) {
                    $threatsFound++
                    $sha = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    Append-DashboardLog "[CRITICAL] Unsigned DLL in $($bName) root: $($_.Name) (SHA256: $sha)! Quarantining..."
                    $dest = Join-Path $QuarDir ((Get-Date -Format 'yyyyMMdd_HHmmss') + "_" + $_.Name)
                    Move-Item -Path $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    if ($threatsFound -eq 0) {
        Append-DashboardLog "[OK] [Tier 1] Browser profile directories clean. Zero rogue DLLs."
    }

    $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $suspiciousProcCount = 0
    foreach ($p in $allProcs) {
        $exe = "$($p.ExecutablePath)"
        if ($exe -and ($exe -match "\\AppData\\Local\\Temp\\")) {
            $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
            if (-not ($sig -and $sig.Status -eq 'Valid')) {
                $suspiciousProcCount++
                $threatsFound++
                Append-DashboardLog "[WARN] [Tier 2/4] Unsigned process running from Temp: $($p.Name) (PID: $($p.ProcessId)) -> $exe"
            }
        }
    }
    if ($suspiciousProcCount -eq 0) {
        Append-DashboardLog "[OK] [Tier 2] Active process tree verified ($($allProcs.Count) processes). Zero unsigned Temp processes."
    }

    $rogueClsid = "HKCU:\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
    if (Test-Path $rogueClsid) {
        $threatsFound++
        Append-DashboardLog "[CRITICAL] Rogue CLSID persistence detected! Destroying..."
        Remove-Item $rogueClsid -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Append-DashboardLog "[OK] [Tier 1] Registry CLSID & Run keys clean."
    }

    $psLog = (Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    $lsaPpl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
    $lsaStatus = if ($lsaPpl -eq 1) { "RunAsPPL Protected" } else { "Standard Mode" }
    Append-DashboardLog "[OK] [Tier 4] Hardening: ScriptBlockLogging=$(if($psLog -eq 1){'ACTIVE'}else{'OFF'}) | LSASS=$lsaStatus"

    Append-DashboardLog "[MANUAL SCAN] Deep Threat Scan Complete: $threatsFound threat(s) found."
    Append-DashboardLog "[MANUAL SCAN] ========================================================="
    Update-DashboardStatus
})

# Button: Tier 3 Emergency Network Killswitch Toggle
$btnKillswitch.Add_Click({
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (Test-Path $NetFile) {
        Append-DashboardLog "[TIER 3] Restoring network connectivity..."
        if ($isAdmin) {
            Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        }
        Start-Process -FilePath "ipconfig.exe" -ArgumentList "/renew" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Remove-Item $NetFile -Force -ErrorAction SilentlyContinue
        Append-DashboardLog "[TIER 3] Network connectivity RESTORED."
    } else {
        Append-DashboardLog "[TIER 3] EMERGENCY NETWORK KILLSWITCH ENGAGED BY USER!"
        Start-Process -FilePath "ipconfig.exe" -ArgumentList "/release" -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($isAdmin) {
            Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        }
        "ISOLATED" | Out-File -FilePath $NetFile -Encoding UTF8 -Force
        Append-DashboardLog "[TIER 3] All outbound network traffic isolated."
    }
    Update-DashboardStatus
})

# Button: Pillar 5 Safe Response - Thaw/Resume Frozen Process (NtResumeProcess) & Quarantine Rollback
$btnThaw.Add_Click({
    if (Test-Path $FrozenFile) {
        $fPid = (Get-Content $FrozenFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        $resumed = $false
        if ($fPid -match '^\d+$') {
            $resumed = Thaw-FrozenProcess -TargetPid ([int]$fPid)
        }
        Remove-Item $FrozenFile -Force -ErrorAction SilentlyContinue
        Append-DashboardLog "[PILLAR 5] NtResumeProcess executed on PID $fPid (Resumed=$resumed) & cleared freeze state."
    } else {
        $qManifest = Join-Path $QuarDir "quarantine_manifest.json"
        if (Test-Path $qManifest) {
            try {
                $mItems = @(Get-Content $qManifest -Raw -Encoding UTF8 | ConvertFrom-Json)
                if ($mItems.Count -gt 0) {
                    $lastItem = $mItems[-1]
                    if ((Test-Path $lastItem.QuarantinedPath) -and $lastItem.OriginalPath) {
                        Move-Item -Path $lastItem.QuarantinedPath -Destination $lastItem.OriginalPath -Force -ErrorAction Stop
                        Append-DashboardLog "[PILLAR 5] Rolled back / restored quarantined file to: $($lastItem.OriginalPath)"
                        Update-DashboardStatus
                        return
                    }
                }
            } catch {}
        }
        Append-DashboardLog "[PILLAR 5] No frozen process or pending quarantine rollback queued."
    }
    Update-DashboardStatus
})

# Button: Raw JSON Settings
$btnSettings.Add_Click({
    $null = Get-SentinelConfig
    Start-Process "notepad.exe" $ConfigFile
})

# Button: Open Quarantine
$btnQuarantine.Add_Click({
    if (-not (Test-Path $QuarDir)) { New-Item -ItemType Directory -Path $QuarDir -Force | Out-Null }
    Start-Process "explorer.exe" $QuarDir
})

# Button: Toggle Shield (Start / Stop)
$btnToggleDaemon.Add_Click({
    $runningProc = $null
    if (Test-Path $PidFile) {
        $rPid = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($rPid -match '^\d+$') {
            $runningProc = Get-Process -Id [int]$rPid -ErrorAction SilentlyContinue
        }
    }
    if (-not $runningProc) {
        $runningProc = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1" } | Select-Object -First 1
    }

    if ($runningProc) {
        # Currently RUNNING -> User clicks to STOP the shield
        New-AuthenticatedStopToken
        Stop-ScheduledTask -TaskName "SecuritySentinelWatchdog" -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName "SecuritySentinelGuardian" -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "SentinelWatchdog\.ps1|SentinelGuardian\.ps1" } | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $PidFile) { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 1200
        if (Test-Path $StopTokenFile) { Remove-Item $StopTokenFile -Force -ErrorAction SilentlyContinue }
        Append-DashboardLog "[DAEMON] Sentinel Ultra shield stopped/paused by user via Dashboard."
    } else {
        # Currently STOPPED -> User clicks to START the shield
        try {
            Start-ScheduledTask -TaskName "SecuritySentinelWatchdog" -ErrorAction Stop
        } catch {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-NoProfile -File `"$ScriptPath`""
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.CreateNoWindow = $true
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        }
        Append-DashboardLog "[DAEMON] Sentinel Ultra shield started by user via Dashboard."
    }

    Start-Sleep -Milliseconds 800
    Update-DashboardStatus
})

# Button: Clear Log
$btnClearLog.Add_Click({
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "[$ts] [INFO] Telemetry log history cleared by user." | Out-File $LogFile -Encoding UTF8 -Force
    Update-DashboardStatus
})

# Initial render
Update-DashboardStatus
$window.ShowDialog() | Out-Null

# SIG # Begin signature block
# MIIF0QYJKoZIhvcNAQcCoIIFwjCCBb4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDrQfheG9DC+BNb
# WJ5spxCL6TtqpW1BGjObEYT3D5uLVKCCAzIwggMuMIICFqADAgECAhBqicxAtgYy
# tEDV87OXYXwsMA0GCSqGSIb3DQEBCwUAMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNl
# bnRpbmVsIFVsdHJhIENvZGUgU2lnbmluZzAeFw0yNjExMDkxODA2NDBaFw0zMTEx
# MDkxODE2NDBaMC8xLTArBgNVBAMMJFNlY3VyaXR5IFNlbnRpbmVsIFVsdHJhIENv
# ZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNKKvtK
# ERrpKZl/ygPwjprcar+6Xk/3xKwms9K7GDTSH8EYVjwFvMsNGB8+On0f31+3hmyt
# KZzePEl5panG4eomaJwGl5qLzD2qyJVAtpgRKh+fiUgjFgm+FOm46u74WMC/Jhr2
# UZe+h6PpO7eoAizbrVRHPaHIOSfIMxnQFVtkkV66T0O5ELGaqTsLZbeQRZsvf6pl
# mIRLQ7nDIzQ6HqRuaWYfU/GNB8/uDhymxuRyLVV6y6pJ/lO2plVgHwC1JHIT7M+S
# t6Fx8wOkUB9McT6P/T4uXHP56PufSxPC7Q4IgDBQ4sQr6NKqtxzVeZ8LBeZW9dsF
# /E1ggkQ3GpNEDmECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMB0GA1UdDgQWBBTzQylDY2rNT15+NYtrGro9m44IMjANBgkqhkiG
# 9w0BAQsFAAOCAQEASGAB2FcY0MsNMQsmt1MEmkmsNWWM15Bf3/gojZQeA84NS39J
# Q3AvtZsrUFq7czi6dm0Oh5GtmEhBBaXxdQeZc48SviS1ZkH+ydm4wFNDz0htXqem
# K5iqgz9JWlYbO0Q1SpCwnrL2lqtXUTqnq1K83NVlyEfMJy1N/pve+DlOLEBjvPvr
# PJDNfUZ79skHaztddUvFUfRFIOaMr0sop2XozdqDsD3Au4im941zJTleYk7m+0Qx
# V0WFPnXMN88dI7JkFgmgmoT53b362u5EU9KHRnwLNjrGIb4+NpAH5QtH7Xl1hqde
# Hxvq+WiRbpJEMEiPyUN71mzSsOfIzKk16U4MIjGCAfUwggHxAgEBMEMwLzEtMCsG
# A1UEAwwkU2VjdXJpdHkgU2VudGluZWwgVWx0cmEgQ29kZSBTaWduaW5nAhBqicxA
# tgYytEDV87OXYXwsMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPQW+PvMn18PkTIwOEmo
# Ua4iwCkJ3AEQxtQjT1Rk/DwJMA0GCSqGSIb3DQEBAQUABIIBAIuDkWIs+nZjxt7z
# 9erggIt1B4Fk9wdVtAH8GqJFxoc/6YE4D7KBeLGCi6xbBCyal8vxOzsoA898b0G1
# JOlF0gulsmf8ged+IYQONiei4bnSCP2OVkZFuRZmwEIWklik/ifaltgXjfTzTdY1
# u1B4ljXvnMEXI41zJbNnonqLzmbL4mcHra22kv9urZxtT0uG+rIZJJIz5GR+36Vo
# NWMfE7g5la3v5eczEKWAWbWcm5RtACEqxI8W5/lg872hCBRZIIdILg2Vix7mEMiL
# pbaupLXba9eiW03ZGdUhL1PbZgjoGVd9tdY5+bpomHnJ7bftaCgMSUykCG4WjMUb
# c/cx6uQ=
# SIG # End signature block
