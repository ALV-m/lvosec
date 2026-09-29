# ============================================================================
# Lab Command Center - client agent (Windows / PowerShell 5.1+)
#
# Zero-dependency agent that runs on each lab PC. It:
#   * registers with the server and keeps a token in config.json
#   * runs as a SYSTEM boot task so it covers ALL users on the machine
#   * reports heartbeats (status, console user, OS, antivirus, firewall,
#     live scan state)
#   * tracks the interactive (console) user for attendance
#   * detects USB storage insertion, scans it with Defender, and reports it
#   * in strict USB modes it disables newly inserted flash drives/phones at the
#     device level (they cannot be used or charged) until approved by the admin
#   * inventories keyboard/mouse/monitor peripherals, warns on-screen (full
#     screen overlay) when a baseline device is disconnected, and reports
#     connect/disconnect to the server with the current user
#   * shows a non-bypassable full-screen login form (Student and Administrator
#     tabs) when a user session starts or after an administrator lock, and
#     records it with the server
#   * monitors the Security log for local account password changes (4723) and
#     password resets (4724) and reports them as alerts/events
#   * applies the lab sign-in method: by default it disables Windows auto-login
#     so PCs land on the Windows password page; with the "login form instead of
#     password" method it creates a local account and enables auto-login so the
#     login form is the only barrier at boot
#   * logs the console user out automatically after a configurable idle time
#   * runs antivirus scans as background jobs and reports scanning status
#   * executes remote actions (lock, restart, message, file push/delete, AV
#     scan/update/toggle, firewall enable/disable, Remote Desktop enable,
#     Wake-on-LAN relay, remote-view screenshot upload)
#   * reports the physical MAC address and IP so the server can send
#     Wake-on-LAN packets through another online PC on the same network
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File lab-agent.ps1 -ServerUrl https://YOUR-APP.onrender.com
#   powershell -NoProfile -ExecutionPolicy Bypass -File lab-agent.ps1 -ServerUrl https://YOUR-APP.onrender.com -Install
#
#   -Install copies the script into ProgramData and registers a scheduled
#   task that starts it at boot as the SYSTEM account (before any user logs
#   in), so one install covers every user on the PC. It also registers a
#   logon task that shows the sign-in gate immediately whenever the current
#   user logs in. Run it from an elevated PowerShell window.
# ============================================================================

param(
  # Renamed from LCC_SERVER_URL. The old variable is still honoured so an
  # existing per-machine environment variable keeps working after the update.
  [string]$ServerUrl = $(if ($env:LVOSEC_SERVER_URL) { $env:LVOSEC_SERVER_URL } else { $env:LCC_SERVER_URL }),
  [switch]$Install,
  [int]$IntervalSeconds = 10
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:AgentVersion = '1.21.0'

# Storage identity. Renamed from LabCommandCenter to LvOsSec. Because this
# directory holds config.json (which carries the agent token), the old one
# cannot simply be abandoned: Invoke-StorageMigration copies the config across
# before anything reads it, and re-points the scheduled tasks. A PC whose
# migration cannot complete keeps running from the old directory rather than
# dropping off the dashboard.
$ConfigDir = Join-Path $env:ProgramData 'LvOsSec'
$ConfigPath = Join-Path $ConfigDir 'config.json'
$PendingPath = Join-Path $ConfigDir 'pending\checkins.json'
$AgentPath = Join-Path $ConfigDir 'lab-agent.ps1'
$LockPath = Join-Path $ConfigDir 'agent.lock'
$TaskName = 'LVOSEC Agent'
$LogonTaskName = 'LVOSEC Logon'

# Pre-1.20.0 identities, read-only. Used solely by the migration.
$script:LegacyConfigDir = Join-Path $env:ProgramData 'LabCommandCenter'
$script:LegacyConfigPath = Join-Path $script:LegacyConfigDir 'config.json'
$script:LegacyTaskName = 'LabCommandCenter Agent'
$script:LegacyLogonTaskName = 'LabCommandCenter Logon'

function Write-Log {
  param([string]$Message)
  $ts = Get-Date -Format 'HH:mm:ss'
  Write-Host ("[{0}] {1}" -f $ts, $Message)
}

function Save-Config {
  param($Config)
  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
  $Config | ConvertTo-Json -Compress | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
}

function Get-Config {
  if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
  try {
    $raw = Get-Content -LiteralPath $ConfigPath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
  } catch { return $null }
}

function Invoke-ApiJson {
  param(
    [string]$Method,
    [string]$Path,
    $Body = $null
  )
  $url = "$ServerUrl$Path"
  $params = @{ Method = $Method; Uri = $url; TimeoutSec = 30 }
  if ($null -ne $Body) {
    $params.ContentType = 'application/json'
    $params.Body = ($Body | ConvertTo-Json -Compress -Depth 6)
  }
  return Invoke-RestMethod @params
}

function Register-Agent {
  if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    throw 'Server URL is required. Pass -ServerUrl https://YOUR-APP.onrender.com'
  }
  $hostname = $env:COMPUTERNAME
  $osName = 'Windows'
  try { $osName = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
  $hw = Get-HardwareFingerprint
  $reg = Invoke-ApiJson -Method 'POST' -Path '/api/agent/register' -Body @{
    name = $hostname
    os = $osName
    agentVersion = $script:AgentVersion
    macAddress = Get-LocalMacAddress
    ipAddress = Get-LocalIpAddress
    manufacturer = $hw.manufacturer
    model = $hw.model
    serialNumber = $hw.serialNumber
    biosSerial = $hw.biosSerial
    systemUUID = $hw.systemUUID
    totalRAM = $hw.totalRAM
    cpuName = $hw.cpuName
    cpuCores = $hw.cpuCores
  }
  $cfg = @{
    serverUrl = $ServerUrl
    token = $reg.token
    computerId = $reg.computerId
    name = $reg.name
    os = $osName
  }
  Save-Config $cfg
  return $cfg
}

function Get-IsSystem {
  try {
    $who = (whoami 2>$null)
    if ($who) { return ($who -match '(?i)nt authority\\system') }
  } catch {}
  return $false
}

function Get-CurrentUser {
  # The interactive (console) user, even when the agent runs as SYSTEM.
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.UserName) { return $cs.UserName.Trim() }
  } catch {}
  try {
    $lines = @(& quser 2>$null)
    if ($lines.Count -eq 0) { $lines = @(& query.exe user 2>$null) }
    foreach ($line in $lines | Select-Object -Skip 1) {
      if ($line -match '^\s*>?(?<user>\S+)\s+(?<session>\S+)\s+(?<id>\d+)\s+(?<state>\S+)') {
        if ($Matches['session'] -eq 'console' -or $Matches['state'] -eq 'Active') {
          return $Matches['user']
        }
      }
    }
  } catch {}
  try {
    $p = Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p -and $p.UserName) { return $p.UserName }
  } catch {}
  if (-not (Get-IsSystem)) {
    try {
      $user = (whoami 2>$null)
      if ($user) { return $user.Trim() }
    } catch {}
  }
  return ''
}

function Get-HardwareFingerprint {
  $hw = @{}
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $hw.manufacturer = $cs.Manufacturer
    $hw.model = $cs.Model
    $hw.totalRAM = [math]::Round($cs.TotalPhysicalMemory / 1MB)
    $hw.cpuName = $cs.Name
    $hw.cpuCores = $cs.NumberOfLogicalProcessors
  } catch {}
  try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $hw.serialNumber = $bios.SerialNumber
  } catch {}
  try {
    $baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    $hw.biosSerial = $baseboard.SerialNumber
  } catch {}
  try {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
    $hw.systemUUID = $uuid
  } catch {}
  return $hw
}

function Ensure-LaunchHelper {
  $helper = @'
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
cmd = ""
p = WScript.Arguments(0)
If fso.FileExists(p) Then
  Set f = fso.OpenTextFile(p, 1)
  cmd = f.ReadAll()
  f.Close()
  fso.DeleteFile p
End If
If Len(cmd) > 0 Then sh.Run cmd, 0, False
'@
  try {
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    Set-Content -LiteralPath $script:LauncherPath -Value $helper -Encoding ASCII
  } catch {
    Write-Log ('Launch helper write failed: {0}' -f $_.Exception.Message)
  }
}

function Invoke-Interactive {
  # Run a command in the logged-on user's interactive desktop with no visible
  # window. The actual command line is written to a temp file and executed by a
  # hidden wscript wrapper, so nothing ever pops up on the desktop.
  param([string]$FilePath, [string]$ArgumentList = '')
  $user = Get-CurrentUser
  if (-not $user -or $user -match '(?i)^nt authority\\' -or $user -match '\$$') {
    Write-Log 'No interactive user session; skipping interactive action.'
    return
  }
  Ensure-LaunchHelper
  try {
    $cmdline = '"{0}" {1}' -f $FilePath, $ArgumentList
    [System.IO.File]::WriteAllText($script:InteractiveCmdPath, $cmdline)
  } catch {
    Write-Log ('Interactive command file write failed: {0}' -f $_.Exception.Message)
    return
  }
  $launchArgs = '"{0}" "{1}"' -f $script:LauncherPath, $script:InteractiveCmdPath
  if (-not (Get-IsSystem)) {
    try {
      Start-Process -FilePath 'wscript.exe' -ArgumentList $launchArgs -WindowStyle Hidden -ErrorAction Stop
    } catch {}
    return
  }
  $taskName = 'LabCC-Interactive-' + [Guid]::NewGuid().ToString('N')
  try {
    try {
      $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument $launchArgs
      $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
      $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
      Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
      Start-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
      Start-Sleep -Seconds 2
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
      return
    } catch {
      Write-Log ('Interactive task failed for {0} ({1}); trying schtasks.exe.' -f $user, $_.Exception.Message)
    }
    $tr = 'wscript.exe {0}' -f $launchArgs
    & schtasks.exe /Create /TN $taskName /TR $tr /SC ONCE /ST 00:00 /RU $user /IT /RL HIGHEST /F 2>$null | Out-Null
    Start-Sleep -Milliseconds 400
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
      & schtasks.exe /Run /TN $taskName 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) { break }
      Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Milliseconds 800
    & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
  } catch {}
}

function Get-AvStatus {
  $result = @{ enabled = $null; signature = $null; lastScan = $null; scanState = $script:avScanState }
  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $result.enabled = ($mp.AntivirusEnabled -eq $true)
    if ($mp.AntivirusSignatureVersion) { $result.signature = $mp.AntivirusSignatureVersion }
    if ($mp.AntivirusScanEndTime) { $result.lastScan = $mp.AntivirusScanEndTime.ToString('o') }
  } catch {}
  if ($script:avLastScanAt) { $result.lastScan = $script:avLastScanAt.ToString('o') }
  return $result
}

function Get-FirewallStatus {
  $result = @{ enabled = $null; profiles = '' }
  try {
    $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($fw.Count -gt 0) {
      $parts = @()
      $allOn = $true
      foreach ($p in $fw) {
        $on = ($p.Enabled -eq $true)
        if (-not $on) { $allOn = $false }
        $state = if ($on) { 'On' } else { 'Off' }
        $parts += ('{0}={1}' -f $p.Name, $state)
      }
      $result.enabled = $allOn
      $result.profiles = ($parts -join ', ')
    }
  } catch {}
  return $result
}

# ---------------------------------------------------------------------------
# Security posture signals
# ---------------------------------------------------------------------------
# A snapshot of cheap, read-only checks consumed by the server's posture engine
# (blue-team/posture.ts). The engine treats a missing member as "unknown",
# never as "pass", so a check that cannot run on a given machine simply leaves
# that key absent -- it never turns a blind spot into a clean bill of health.
#
# The expensive checks (BitLocker, TPM, Secure Boot, local admins) refresh on a
# 5-minute timer; the rest are registry reads that run every refresh too. The
# heartbeat attaches the cached snapshot to every request, so the server always
# sees the full picture without the 10-second loop paying for the cost.
# ---------------------------------------------------------------------------

$script:SecuritySignalsCache = $null
$script:SecuritySignalsCacheAt = (Get-Date).AddMinutes(-10)

function Read-RegDword {
  param([string]$Path, [string]$Name, [int]$Default = $null)
  try {
    $v = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    return [int]$v
  } catch { return $Default }
}

function Get-SecuritySignals {
  # Refresh at most every five minutes.
  $elapsed = (Get-Date) - $script:SecuritySignalsCacheAt
  if ($script:SecuritySignalsCache -and $elapsed.TotalMinutes -lt 5) {
    return $script:SecuritySignalsCache
  }
  $script:SecuritySignalsCacheAt = Get-Date

  $s = @{}

  # --- Defender -------------------------------------------------------------
  try {
    $pref = Get-MpPreference -ErrorAction Stop
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $s.avRealtimeProtection = -not [bool]$pref.DisableRealtimeMonitoring
    $s.avTamperProtection = [bool]$mp.IsTamperProtected
    $excl = @($pref.ExclusionPath) + @($pref.ExclusionExtension) + @($pref.ExclusionProcess)
    $s.avExclusionCount = @($excl | Where-Object { $_ }).Count
    if ($mp.AntivirusSignatureLastUpdated) {
      $s.avSignatureAgeDays = [int]([Math]::Floor(((Get-Date) - $mp.AntivirusSignatureLastUpdated.ToLocalTime()).TotalDays))
      if ($s.avSignatureAgeDays -lt 0) { $s.avSignatureAgeDays = 0 }
    }
    # A policy entry that disables the product is different from a student
    # turning it off locally -- it means something is forcing it back off.
    $policyRealtime = Read-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0
    $policyAntiSpy = Read-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 0
    $s.avDisabledByPolicy = ($policyRealtime -eq 1) -or ($policyAntiSpy -eq 1)
  } catch {}

  # --- Firewall -------------------------------------------------------------
  try {
    $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
    $s.firewallAllProfiles = ($fw.Count -gt 0) -and (@($fw | Where-Object { $_.Enabled -ne $true }).Count -eq 0)
  } catch {}

  # --- SMB / network --------------------------------------------------------
  $smb1 = Read-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0
  if ($smb1 -ne $null) { $s.smb1Enabled = ($smb1 -eq 1) }
  $smbSigning = Read-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 0
  if ($smbSigning -ne $null) { $s.smbSigningRequired = ($smbSigning -eq 1) }
  $rdpDeny = Read-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' $null
  if ($rdpDeny -ne $null) { $s.rdpEnabled = ($rdpDeny -eq 0) }

  # --- Encryption / hardware ------------------------------------------------
  try {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $s.bitlockerEnabled = ($vol.ProtectionStatus -eq 'On')
  } catch {}
  try {
    $tpm = Get-Tpm -ErrorAction Stop
    $s.tpmPresent = [bool]$tpm.TpmPresent
  } catch {}
  try {
    $s.secureBootEnabled = [bool](Confirm-SecureBootUEFI)
  } catch {
    # Non-UEFI machines throw here; Secure Boot genuinely cannot be evaluated.
    $s.secureBootEnabled = $null
  }

  # --- OS configuration -----------------------------------------------------
  $uac = Read-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
  $s.uacEnabled = ($uac -eq 1)
  $noLockScreen = Read-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreen' 0
  $s.screenLockEnabled = -not [bool]$noLockScreen
  $noAutoRun = Read-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 0
  $s.autorunEnabled = (($noAutoRun -band 0xFF) -eq 0)
  $auPolicy = Read-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 0
  $auCurrent = Read-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'NoAutoUpdate' 0
  $s.windowsUpdateDisabled = ([bool]$auPolicy) -or ([bool]$auCurrent)
  $autoLogon = try { [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop).AutoAdminLogon } catch { '' }
  $s.autoLogonEnabled = ($autoLogon -eq '1')

  try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    $s.guestAccountEnabled = [bool]$guest.Enabled
  } catch {}
  try {
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
    $s.localAdminCount = $admins.Count
  } catch {}

  $script:SecuritySignalsCache = $s
  return $s
}

function Get-Peripherals {
  $result = @()
  $classes = @('Keyboard', 'Mouse', 'Monitor')
  $kindMap = @{ 'Keyboard' = 'keyboard'; 'Mouse' = 'mouse'; 'Monitor' = 'monitor' }
  try {
    foreach ($cls in $classes) {
      $devices = @(Get-PnpDevice -Class $cls -ErrorAction SilentlyContinue)
      foreach ($dev in $devices) {
        if (-not $dev.InstanceId) { continue }
        $present = ($dev.Status -eq 'OK') -and ($dev.Present -eq $true)
        $name = if ($dev.FriendlyName) { $dev.FriendlyName } else { $dev.InstanceId }
        $serial = ''
        try {
          $idu = Get-CimInstance -ClassName Win32_PnPEntity -Filter ("DeviceID='{0}'" -f $dev.InstanceId.Replace("'", "''")) -ErrorAction SilentlyContinue
          if ($idu -and $idu.PNPDeviceID) {
            $parts = @($idu.PNPDeviceID -split '\\')
            if ($parts.Count -ge 3) { $serial = $parts[-1] }
          }
          if (-not $serial -and $dev.InstanceId -match '\\[^\\]+\\[^\\]+\\(?<serial>[^\\]+)$') {
            $serial = $Matches['serial']
          }
        } catch {}
        $result += [PSCustomObject]@{
          kind = $kindMap[$cls]
          name = $name
          instanceId = $dev.InstanceId
          serial = $serial
          present = $present
        }
      }
    }
  } catch {}
  return $result
}

function Get-IdleSeconds {
  try {
    if (-not $script:idleHelperLoaded) {
      Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class LccIdleHelper {
  [DllImport("user32.dll")]
  public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
  [StructLayout(LayoutKind.Sequential)]
  public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
}
"@ -ErrorAction Stop
      $script:idleHelperLoaded = $true
    }
    $lii = New-Object LccIdleHelper+LASTINPUTINFO
    $lii.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($lii)
    [LccIdleHelper]::GetLastInputInfo([ref]$lii) | Out-Null
    $idle = ([Environment]::TickCount - [int]$lii.dwTime) / 1000
    if ($idle -lt 0) { $idle = 0 }
    return [int]$idle
  } catch { return 0 }
}

$script:WarningScriptPath = Join-Path $ConfigDir 'peripheral-warning.ps1'
$script:MessageScriptPath = Join-Path $ConfigDir 'message.ps1'
$script:CheckinScriptPath = Join-Path $ConfigDir 'checkin-gate.ps1'
$script:TaskbarScriptPath = Join-Path $ConfigDir 'taskbar.ps1'
$script:CaptureLoopScriptPath = Join-Path $ConfigDir 'capture-loop.ps1'
$script:CaptureLoopPidPath = Join-Path $ConfigDir 'frame-loop.pid'
$script:FramePath = Join-Path $ConfigDir 'frame.jpg'
$script:LauncherPath = Join-Path $ConfigDir 'LabCC-LaunchHidden.vbs'
$script:InteractiveCmdPath = Join-Path $ConfigDir 'interactive.cmd'
$script:InputScriptPath = Join-Path $ConfigDir 'remote-input.ps1'
$script:GateLauncherPath = Join-Path $ConfigDir 'gate-launcher.ps1'
$script:GateMarkerPath = Join-Path $ConfigDir 'pending\gate-request'
$script:logonGateRegisteredFor = ''
$script:lastGateRetryAt = $null
$script:lastUpdateAttemptAt = $null
$script:lastGateTaskError = ''
$script:lastFrameUploadedKey = ''
$script:lastWarningKey = $null
$script:warningActive = $false
$script:idleHelperLoaded = $false
$script:avScanState = 'idle'
$script:avLastScanAt = $null
$script:scanJob = $null
$script:scanAction = $null
$script:lastAuditCheck = $null

function Ensure-WarningScript {
  $content = @'
param([string]$Devices = '')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$devices = @($Devices -split ';' | Where-Object { $_ -and $_.Trim() })
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Lab Command Center'
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::Black
$title = New-Object System.Windows.Forms.Label
$title.Text = 'DEVICE DISCONNECTED'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 36, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(224, 32, 32)
$title.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$title.Dock = [System.Windows.Forms.DockStyle]::Top
$title.Height = 160
$msg = New-Object System.Windows.Forms.Label
$msg.Text = "One or more peripheral devices are disconnected.`nPlease return the following device(s) so the computer stays under supervision:"
$msg.Font = New-Object System.Drawing.Font('Segoe UI', 16)
$msg.ForeColor = [System.Drawing.Color]::White
$msg.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$msg.Dock = [System.Windows.Forms.DockStyle]::Top
$msg.Height = 140
$list = New-Object System.Windows.Forms.Label
$list.Text = if ($devices.Count -gt 0) { ($devices -join "`n`n") } else { 'Unknown device' }
$list.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$list.ForeColor = [System.Drawing.Color]::Yellow
$list.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$list.Dock = [System.Windows.Forms.DockStyle]::Fill
$form.Controls.Add($list)
$form.Controls.Add($msg)
$form.Controls.Add($title)
[System.Windows.Forms.Application]::Run($form)
'@
  Set-Content -LiteralPath $script:WarningScriptPath -Value $content -Encoding UTF8
}

function Ensure-MessageScript {
  $content = @'
param([string]$Text = '')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Information
$notify.Visible = $true
$notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
$notify.BalloonTipTitle = 'Lab Command Center'
$notify.BalloonTipText = $Text
$notify.ShowBalloonTip(10000)
Start-Sleep -Seconds 10
$notify.Dispose()
'@
  Set-Content -LiteralPath $script:MessageScriptPath -Value $content -Encoding UTF8
}

function Show-PeripheralWarning {
  param([string[]]$Devices)
  Ensure-WarningScript
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Devices "{1}"' -f $script:WarningScriptPath, ($Devices -join ';')
  Invoke-Interactive -FilePath 'powershell.exe' -ArgumentList $argLine
  $script:warningActive = $true
}

function Stop-PeripheralWarning {
  try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
      if ($proc.CommandLine -like '*peripheral-warning.ps1*') {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {}
  $script:warningActive = $false
  $script:lastWarningKey = $null
}

function Save-Baseline {
  param([string[]]$InstanceIds)
  $cfg = Get-Config
  if (-not $cfg) { return }
  $cfg | Add-Member -NotePropertyName baselinePeripherals -NotePropertyValue @($InstanceIds) -Force
  Save-Config $cfg
}

function Get-RemovableDrives {
  $result = @()
  try {
    $disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 2' -ErrorAction SilentlyContinue
    foreach ($disk in $disks) {
      if (-not $disk.DeviceID) { continue }
      $serial = ''
      try {
        $volume = Get-CimInstance Win32_Volume -Filter ("DeviceID='{0}'" -f $disk.DeviceID) -ErrorAction SilentlyContinue
        if ($volume -and $volume.SerialNumber) { $serial = $volume.SerialNumber }
      } catch {}
      $result += [PSCustomObject]@{
        Letter = $disk.DeviceID.TrimEnd(':')
        Label = $disk.VolumeName
        Serial = $serial
      }
    }
  } catch {}
  return $result
}

function Get-UsbKey {
  param($Drive)
  if ($Drive.Serial) { return ('serial={0}' -f $Drive.Serial) }
  return ('letter={0}' -f $Drive.Letter)
}

function Show-Message {
  param([string]$Text)
  Ensure-MessageScript
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Text "{1}"' -f $script:MessageScriptPath, ($Text -replace '"', '""')
  Invoke-Interactive -FilePath 'powershell.exe' -ArgumentList $argLine
}

function Get-LocalMacAddress {
  try {
    $adapter = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress } | Select-Object -First 1
    if ($adapter -and $adapter.MacAddress) { return ($adapter.MacAddress -replace '[-:]', '').ToLower() }
  } catch {}
  try {
    $adapter = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetConnectionStatus -eq 2 -and $_.MACAddress } | Select-Object -First 1
    if ($adapter -and $adapter.MACAddress) { return ($adapter.MACAddress -replace '[-:]', '').ToLower() }
  } catch {}
  return ''
}

function Get-LocalIpAddress {
  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
      $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254*' -and $_.IPAddress -notlike 'fe80:*'
    } | Select-Object -First 1
    if ($ip) { return $ip.IPAddress }
  } catch {}
  return ''
}

function Send-WakeOnLan {
  param([string]$Mac, [int]$Port = 9)
  $macHex = ($Mac -replace '[^0-9a-fA-F]', '').ToLower()
  if ($macHex.Length -ne 12) { throw "Invalid MAC address: $Mac" }
  $payload = New-Object byte[] (6 + 16 * 6)
  for ($i = 0; $i -lt 6; $i++) { $payload[$i] = 0xFF }
  for ($i = 0; $i -lt 16; $i++) {
    for ($j = 0; $j -lt 6; $j++) {
      $payload[6 + $i * 6 + $j] = [Convert]::ToByte($macHex.Substring($j * 2, 2), 16)
    }
  }

  $broadcasts = New-Object System.Collections.Generic.HashSet[string]
  [void]$broadcasts.Add('255.255.255.255')
  try {
    $localIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
      $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254*'
    }
    foreach ($local in $localIps) {
      try {
        $mask = (New-Object System.Net.IPAddress ([UInt32](0xFFFFFFFF -shl (32 - $local.PrefixLength)))).GetAddressBytes()
        $addr = [System.Net.IPAddress]::Parse($local.IPAddress).GetAddressBytes()
        $bc = New-Object byte[] 4
        for ($i = 0; $i -lt 4; $i++) { $bc[$i] = $addr[$i] -bor (-bnot $mask[$i]) }
        [void]$broadcasts.Add([string]::Join('.', $bc))
      } catch {}
    }
  } catch {}

  $sent = 0
  foreach ($target in $broadcasts) {
    try {
      $client = New-Object System.Net.Sockets.UdpClient
      try {
        $client.EnableBroadcast = $true
        [void]$client.Send($payload, $payload.Length, $target, $Port)
        $sent++
      } finally { $client.Close() }
    } catch {}
  }
  if ($sent -eq 0) { throw 'Could not send the wake packet on any network interface' }
  return $sent
}

function Get-DriveInstanceId {
  param([string]$Letter)
  if (-not $Letter) { return '' }
  try {
    $part = Get-CimInstance -Query ("ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{0}:'}} WHERE AssocClass=Win32_LogicalDiskToPartition" -f $Letter) -ErrorAction Stop | Select-Object -First 1
    if ($part) {
      $disk = Get-CimInstance -Query ("ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{0}'}} WHERE AssocClass=Win32_DiskToPartition" -f $part.DeviceID) -ErrorAction Stop | Select-Object -First 1
      if ($disk -and $disk.PNPDeviceID) { return [string]$disk.PNPDeviceID }
    }
  } catch {}
  return ''
}

function Get-PhoneDevices {
  $result = @()
  try {
    $devices = @(Get-PnpDevice -Class 'WPD', 'Image', 'PortableDevices' -PresentOnly -ErrorAction SilentlyContinue)
    foreach ($dev in $devices) {
      if (-not $dev.InstanceId) { continue }
      $name = if ($dev.FriendlyName) { $dev.FriendlyName } else { $dev.InstanceId }
      $result += [PSCustomObject]@{
        InstanceId = $dev.InstanceId
        Name = $name
      }
    }
  } catch {}
  return $result
}

function Block-UsbDevice {
  param([string]$InstanceId)
  try {
    Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
    return $true
  } catch {}
  try {
    & pnputil.exe /disable-device "$InstanceId" 2>$null | Out-Null
    return $true
  } catch {}
  return $false
}

function Enable-UsbDevice {
  param([string]$InstanceId)
  try {
    Enable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
    return $true
  } catch {}
  try {
    & pnputil.exe /enable-device "$InstanceId" 2>$null | Out-Null
    return $true
  } catch {}
  return $false
}

function Ensure-CaptureLoopScript {
  $content = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$dir = __CONFIG_DIR__
$frame = Join-Path $dir 'frame.jpg'
$pidFile = Join-Path $dir 'frame-loop.pid'
try {
  [System.IO.File]::WriteAllText($pidFile, [string]$PID)
} catch {}
$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$quality = New-Object System.Drawing.Imaging.EncoderParameters(1)
$quality.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]60)
while ($true) {
  try {
    $bounds = [System.Drawing.Rectangle]::Empty
    foreach ($screen in [System.Windows.Forms.Screen]::AllScreens) {
      $bounds = [System.Drawing.Rectangle]::Union($bounds, $screen.Bounds)
    }
    $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
      $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    } finally {
      $g.Dispose()
    }
    $bmp.Save($frame, $codec, $quality)
    $bmp.Dispose()
  } catch {}
  Start-Sleep -Milliseconds 250
}
'@
  # The capture loop is a separate process, so it cannot see $ConfigDir. It is
  # stamped with the real path here rather than recomputing it, which keeps the
  # loop writing frames exactly where the agent reads them -- including after a
  # storage migration, where the old hardcoded directory no longer exists.
  $content = $content.Replace('__CONFIG_DIR__', ("'" + ($ConfigDir -replace "'", "''") + "'"))
  Set-Content -LiteralPath $script:CaptureLoopScriptPath -Value $content -Encoding UTF8
}

function Start-CaptureLoop {
  Ensure-CaptureLoopScript
  $running = $false
  if (Test-Path -LiteralPath $script:CaptureLoopPidPath) {
    try {
      $loopPid = [int](Get-Content -LiteralPath $script:CaptureLoopPidPath -Raw)
      if (Get-Process -Id $loopPid -ErrorAction SilentlyContinue) {
        $procInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $loopPid" -ErrorAction SilentlyContinue
        if ($procInfo -and $procInfo.CommandLine -and $procInfo.CommandLine -like '*capture-loop.ps1*') {
          $running = $true
        }
      }
    } catch {}
  }
  if ($running) { return }
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $script:CaptureLoopScriptPath
  Invoke-Interactive -FilePath 'powershell.exe' -ArgumentList $argLine
}

function Stop-CaptureLoop {
  if (-not (Test-Path -LiteralPath $script:CaptureLoopPidPath)) { return }
  try {
    $loopPid = [int](Get-Content -LiteralPath $script:CaptureLoopPidPath -Raw)
    Stop-Process -Id $loopPid -Force -ErrorAction SilentlyContinue
  } catch {}
  Remove-Item -LiteralPath $script:CaptureLoopPidPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $script:FramePath -Force -ErrorAction SilentlyContinue
}

function Upload-Frame {
  Start-CaptureLoop
  $deadline = (Get-Date).AddSeconds(2)
  $frameItem = $null
  while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $script:FramePath) {
      $frameItem = Get-Item -LiteralPath $script:FramePath
      if (((Get-Date) - $frameItem.LastWriteTime).TotalSeconds -lt 1.5) { break }
    }
    Start-Sleep -Milliseconds 150
  }
  if (-not $frameItem) {
    return @{ success = $false; detail = 'Could not capture the screen (no interactive session?).' }
  }
  $frameKey = $frameItem.LastWriteTimeUtc.Ticks.ToString()
  if ($script:lastFrameUploadedKey -eq $frameKey) {
    return @{ success = $true; detail = 'No new frame yet.' }
  }
  try {
    $url = '{0}/api/agent/screenshot?token={1}' -f $ServerUrl, $config.token
    Invoke-RestMethod -Uri $url -Method Post -InFile $script:FramePath -ContentType 'image/jpeg' -TimeoutSec 60 | Out-Null
    $script:lastFrameUploadedKey = $frameKey
    return @{ success = $true; detail = 'Frame captured and uploaded.' }
  } catch {
    return @{ success = $false; detail = $_.Exception.Message }
  }
}

function Capture-Screenshot {
  return Upload-Frame
}

function Ensure-CheckinScript {
  $content = @'
param([string]$ServerUrl = '', [string]$ConfigPath = '', [string]$UserName = '', [string]$PendingPath = '')
$ErrorActionPreference = 'Stop'
$script:GateLogPath = Join-Path (Split-Path $ConfigPath -Parent) 'gate-log.txt'
function Write-GateLog {
  param([string]$Message)
  try {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $script:GateLogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
  } catch {}
}
Write-GateLog ("gate start user={0} config={1}" -f $UserName, $ConfigPath)
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
} catch {
  Write-GateLog ("gate startup error: {0}" -f $_.Exception.Message)
  exit 1
}
$script:submitted = $false
$script:photoFileId = ''
$script:role = 'student'
$script:idRequired = $true

# Only one sign-in gate at a time.
try {
  $gateProcs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*checkin-gate.ps1*' -and $_.ProcessId -ne $PID })
  if ($gateProcs.Count -gt 0) { Write-GateLog 'gate start skipped (another gate is already running)'; exit 0 }
} catch {}

function Read-Token {
  try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return '' }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    return [string]$cfg.token
  } catch { return '' }
}

function Upload-Photo {
  param([string]$Path)
  try {
    $token = Read-Token
    $url = '{0}/api/agent/upload?token={1}' -f $ServerUrl, $token
    $resp = Invoke-RestMethod -Uri $url -Method Post -InFile $Path -ContentType 'image/jpeg' -TimeoutSec 60
    return [string]$resp.fileId
  } catch { return '' }
}

function Save-PendingCheckin {
  param([hashtable]$Body)
  if (-not $PendingPath) { return }
  $entry = $Body.Clone()
  $entry.savedAt = (Get-Date).ToString('o')
  $list = @()
  if (Test-Path -LiteralPath $PendingPath) {
    try {
      $existing = Get-Content -LiteralPath $PendingPath -Raw | ConvertFrom-Json
      if ($existing) { $list = @($existing) }
    } catch { $list = @() }
  }
  $list += $entry
  New-Item -ItemType Directory -Force -Path (Split-Path $PendingPath -Parent) | Out-Null
  $list | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath $PendingPath -Encoding UTF8
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Sign in to use this computer'
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 242, 245)
$form.KeyPreview = $true

$form.Add_KeyDown({
  param($sender, $e)
  if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F4) { $e.SuppressKeyPress = $true }
  if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) { $e.SuppressKeyPress = $true }
})

$form.Add_FormClosing({
  param($sender, $e)
  if (-not $script:submitted) { $e.Cancel = $true }
})

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = [System.Windows.Forms.DockStyle]::Fill
$panel.Padding = New-Object System.Windows.Forms.Padding(24)
$form.Controls.Add($panel)

$flow = New-Object System.Windows.Forms.FlowLayoutPanel
$flow.Dock = [System.Windows.Forms.DockStyle]::Fill
$flow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$flow.WrapContents = $false
$flow.AutoScroll = $true
$panel.Controls.Add($flow)

function New-Heading {
  param([string]$Text, [System.Drawing.Color]$Color, [int]$Size)
  $label = New-Object System.Windows.Forms.Label
  $label.Text = $Text
  $label.Font = New-Object System.Drawing.Font('Segoe UI', $Size, [System.Drawing.FontStyle]::Bold)
  $label.ForeColor = $Color
  $label.AutoSize = $true
  $label.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 4)
  return $label
}

function New-Textbox {
  $box = New-Object System.Windows.Forms.TextBox
  $box.Font = New-Object System.Drawing.Font('Segoe UI', 14)
  $box.Width = 380
  $box.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 4)
  return $box
}

function New-RoleButton {
  param([string]$Text)
  $btn = New-Object System.Windows.Forms.Button
  $btn.Text = $Text
  $btn.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
  $btn.Width = 150
  $btn.Height = 44
  $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
  $btn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
  return $btn
}

$flow.Controls.Add((New-Heading -Text 'SIGN IN TO USE THIS COMPUTER' -Color ([System.Drawing.Color]::FromArgb(200, 30, 30)) -Size 28))
$flow.Controls.Add((New-Heading -Text 'Choose your user type and complete the form before using this computer.' -Color ([System.Drawing.Color]::FromArgb(80, 80, 90)) -Size 13))

$roleRow = New-Object System.Windows.Forms.FlowLayoutPanel
$roleRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$roleRow.AutoSize = $true
$roleRow.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$btnStudent = New-RoleButton -Text 'Student'
$btnTeacher = New-RoleButton -Text 'Teacher'
$btnVisitor = New-RoleButton -Text 'Visitor'
$btnAdmin = New-RoleButton -Text 'Administrator'

$roleRow.Controls.Add($btnStudent)
$roleRow.Controls.Add($btnTeacher)
$roleRow.Controls.Add($btnVisitor)
$roleRow.Controls.Add($btnAdmin)
$flow.Controls.Add($roleRow)

$nameHeading = New-Heading -Text 'Full name *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$nameBox = New-Textbox
$phoneHeading = New-Heading -Text 'Phone number *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$phoneBox = New-Textbox
$idHeading = New-Heading -Text 'Admission / ID number *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$idBox = New-Textbox
$courseHeading = New-Heading -Text 'Course *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$courseBox = New-Textbox
$classHeading = New-Heading -Text 'Class *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$classBox = New-Textbox
$reasonHeading = New-Heading -Text 'Reason for using this computer *' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$reasonBox = New-Textbox
$emailHeading = New-Heading -Text 'Email (optional)' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 12
$emailBox = New-Textbox

$flow.Controls.Add($nameHeading)
$flow.Controls.Add($nameBox)
$flow.Controls.Add($phoneHeading)
$flow.Controls.Add($phoneBox)
$flow.Controls.Add($idHeading)
$flow.Controls.Add($idBox)
$flow.Controls.Add($courseHeading)
$flow.Controls.Add($courseBox)
$flow.Controls.Add($classHeading)
$flow.Controls.Add($classBox)
$flow.Controls.Add($reasonHeading)
$flow.Controls.Add($reasonBox)
$flow.Controls.Add($emailHeading)
$flow.Controls.Add($emailBox)

$photoRow = New-Object System.Windows.Forms.FlowLayoutPanel
$photoRow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$photoRow.AutoSize = $true
$photoRow.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)

$photoBox = New-Object System.Windows.Forms.PictureBox
$photoBox.Size = New-Object System.Drawing.Size(120, 120)
$photoBox.BackColor = [System.Drawing.Color]::White
$photoBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
$photoBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$photoBox.Visible = $false

$photoButton = New-Object System.Windows.Forms.Button
$photoButton.Text = 'Take photo (optional)'
$photoButton.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$photoButton.Width = 200
$photoButton.Height = 40
$photoButton.Add_Click({
  try {
    $dm = New-Object -ComObject WIA.DeviceManager
    $cam = $dm.DeviceInfos | Where-Object { $_.Type -eq 3 } | Select-Object -First 1
    if (-not $cam) { [System.Windows.Forms.MessageBox]::Show('No camera was found on this computer.', 'Lab Command Center') | Out-Null; return }
    $device = $cam.Connect()
    $captured = $device.ExecuteCommand('{AF933CAC-AC7D-4D13-9E27-84A7C3E4D5C4}')
    $shotPath = Join-Path $env:TEMP ('labcc-photo-{0}.jpg' -f [guid]::NewGuid().ToString('N'))
    $captured.SaveFile($shotPath)
    $script:photoFileId = Upload-Photo $shotPath
    $photoBox.Image = [System.Drawing.Image]::FromFile($shotPath)
    $photoBox.Visible = $true
    Remove-Item -LiteralPath $shotPath -Force -ErrorAction SilentlyContinue
  } catch {
    [System.Windows.Forms.MessageBox]::Show(('Could not take a photo: {0}' -f $_.Exception.Message), 'Lab Command Center') | Out-Null
  }
})

$photoRow.Controls.Add($photoButton)
$photoRow.Controls.Add($photoBox)
$flow.Controls.Add($photoRow)

$adminRow = New-Object System.Windows.Forms.FlowLayoutPanel
$adminRow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$adminRow.AutoSize = $true
$adminRow.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$adminHeading = New-Heading -Text 'Administrator sign-in' -Color ([System.Drawing.Color]::FromArgb(60, 60, 70)) -Size 16
$adminNote = New-Heading -Text 'The administrator uses their own Windows account on this PC. Clicking below locks the screen and shows the Windows sign-in, where the administrator logs into that account. It is not the shared account students, teachers, and visitors use.' -Color ([System.Drawing.Color]::FromArgb(120, 120, 130)) -Size 11

$adminLockButton = New-Object System.Windows.Forms.Button
$adminLockButton.Text = 'Sign in as administrator'
$adminLockButton.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$adminLockButton.BackColor = [System.Drawing.Color]::FromArgb(120, 50, 160)
$adminLockButton.ForeColor = [System.Drawing.Color]::White
$adminLockButton.Width = 280
$adminLockButton.Height = 46
$adminLockButton.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)
$adminLockButton.Add_Click({
  Write-GateLog 'admin lock requested'
  try {
    Start-Process -FilePath 'rundll32.exe' -ArgumentList 'user32.dll,LockWorkStation' -WindowStyle Hidden -ErrorAction SilentlyContinue
  } catch {}
  $script:submitted = $true
  $form.Close()
})

$adminRow.Controls.Add($adminHeading)
$adminRow.Controls.Add($adminNote)
$adminRow.Controls.Add($adminLockButton)
$flow.Controls.Add($adminRow)

$status = New-Object System.Windows.Forms.Label
$status.ForeColor = [System.Drawing.Color]::FromArgb(200, 30, 30)
$status.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$status.AutoSize = $true
$status.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
$flow.Controls.Add($status)

function Select-Role {
  param([string]$Role)
  $script:role = $Role
  $isAdmin = ($Role -eq 'admin')
  $isStudent = ($Role -eq 'student')
  $isPerson = -not $isAdmin
  $nameHeading.Visible = $isPerson
  $nameBox.Visible = $isPerson
  $phoneHeading.Visible = $isPerson
  $phoneBox.Visible = $isPerson
  $idHeading.Visible = $isPerson
  $idBox.Visible = $isPerson
  $courseHeading.Visible = $isStudent
  $courseBox.Visible = $isStudent
  $classHeading.Visible = $isStudent
  $classBox.Visible = $isStudent
  $reasonHeading.Visible = $isPerson
  $reasonBox.Visible = $isPerson
  $emailHeading.Visible = $isPerson
  $emailBox.Visible = $isPerson
  $photoRow.Visible = $isPerson
  $adminRow.Visible = $isAdmin
  $submit.Visible = $isPerson
  $selected = [System.Drawing.Color]::FromArgb(24, 108, 220)
  $idle = [System.Drawing.Color]::FromArgb(228, 231, 236)
  foreach ($b in @($btnStudent, $btnTeacher, $btnVisitor, $btnAdmin)) {
    if ($b.Tag -eq $Role) {
      $b.BackColor = $selected
      $b.ForeColor = [System.Drawing.Color]::White
    } else {
      $b.BackColor = $idle
      $b.ForeColor = [System.Drawing.Color]::FromArgb(40, 40, 50)
    }
  }
  if ($Role -eq 'teacher') {
    $idHeading.Text = 'Staff / Employee ID *'
    $script:idRequired = $true
  } elseif ($Role -eq 'visitor') {
    $idHeading.Text = 'Visitor ID (optional)'
    $script:idRequired = $false
  } else {
    $idHeading.Text = 'Admission / ID number *'
    $script:idRequired = $true
  }
  $status.Text = ''
}

$btnStudent.Tag = 'student'
$btnTeacher.Tag = 'teacher'
$btnVisitor.Tag = 'visitor'
$btnAdmin.Tag = 'admin'
$btnStudent.Add_Click({ Select-Role 'student' })
$btnTeacher.Add_Click({ Select-Role 'teacher' })
$btnVisitor.Add_Click({ Select-Role 'visitor' })
$btnAdmin.Add_Click({ Select-Role 'admin' })

$submit = New-Object System.Windows.Forms.Button
$submit.Text = 'Sign in'
$submit.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$submit.BackColor = [System.Drawing.Color]::FromArgb(24, 108, 220)
$submit.ForeColor = [System.Drawing.Color]::White
$submit.Width = 200
$submit.Height = 46
$submit.Margin = New-Object System.Windows.Forms.Padding(0, 14, 0, 0)
$submit.Add_Click({
  $name = $nameBox.Text.Trim()
  $phone = $phoneBox.Text.Trim()
  $id = $idBox.Text.Trim()
  $reason = $reasonBox.Text.Trim()
  if (-not $name -or -not $phone) {
    $status.Text = 'Please fill in your name and phone number.'
    return
  }
  if ($script:idRequired -and -not $id) {
    $status.Text = 'Please fill in your ID number.'
    return
  }
  if ($script:role -eq 'student') {
    if (-not $courseBox.Text.Trim()) { $status.Text = 'Please fill in your course.'; return }
    if (-not $classBox.Text.Trim()) { $status.Text = 'Please fill in your class.'; return }
  }
  if (-not $reason) {
    $status.Text = 'Please enter the reason you are using this computer.'
    return
  }
  $submit.Enabled = $false
  $status.Text = 'Submitting…'
  try {
    $token = Read-Token
    $body = @{
      token = $token
      userName = $UserName
      role = $script:role
      studentName = $name
      phone = $phone
      admissionNo = $id
      course = $courseBox.Text.Trim()
      class = $classBox.Text.Trim()
      reason = $reason
      email = ($emailBox.Text.Trim() -replace '\s+', ' ')
      photoFileId = $script:photoFileId
    }
    $json = $body | ConvertTo-Json -Compress -Depth 4
    $resp = Invoke-RestMethod -Uri ('{0}/api/agent/checkin' -f $ServerUrl) -Method Post -ContentType 'application/json' -Body $json -TimeoutSec 60
    if ($resp.ok) {
      Write-GateLog ("submitted role={0} name={1}" -f $script:role, $name)
      $script:submitted = $true
      $form.Close()
    } else {
      Write-GateLog ("submit rejected: {0}" -f [string]$resp.error)
      $status.Text = [string]$resp.error
      $submit.Enabled = $true
    }
  } catch {
    if ($PendingPath) {
      try {
        Save-PendingCheckin -Body $body
        Write-GateLog 'offline check-in saved to pending queue'
        $status.Text = 'No internet — saved on this computer. It will sync to the dashboard automatically when back online.'
        $script:submitted = $true
        $form.Close()
        return
      } catch {}
    }
    Write-GateLog ("submit error: {0}" -f $_.Exception.Message)
    $status.Text = 'Could not reach the server. Try again in a moment.'
    $submit.Enabled = $true
  }
})
$flow.Controls.Add($submit)

Select-Role 'student'

try {
  Write-GateLog 'form running'
  [System.Windows.Forms.Application]::Run($form)
  Write-GateLog 'form closed'
} catch {
  Write-GateLog ("form error: {0}" -f $_.Exception.Message)
  exit 1
}
'@
  Set-Content -LiteralPath $script:CheckinScriptPath -Value $content -Encoding UTF8
}

function Ensure-TaskbarScript {
  param([int]$IdleTimeoutMinutes = 15)
  $content = @'
param([string]$ServerUrl = '', [string]$ConfigPath = '', [int]$IdleTimeoutMinutes = 15)
$ErrorActionPreference = 'Stop'
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TaskbarIdleHelper {
  [DllImport("user32.dll")]
  public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
  [StructLayout(LayoutKind.Sequential)]
  public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
}
"@
} catch { exit 1 }

function Get-IdleSeconds {
  try {
    $lii = New-Object TaskbarIdleHelper+LASTINPUTINFO
    $lii.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($lii)
    [TaskbarIdleHelper]::GetLastInputInfo([ref]$lii) | Out-Null
    $idle = ([Environment]::TickCount - [int]$lii.dwTime) / 1000
    if ($idle -lt 0) { $idle = 0 }
    return [int]$idle
  } catch { return 0 }
}

$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$barHeight = 48

$form = New-Object System.Windows.Forms.Form
$form.Text = 'LabCC Taskbar'
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point(0, ($screen.Height - $barHeight))
$form.Size = New-Object System.Drawing.Size($screen.Width, $barHeight)
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 28)
$form.ShowInTaskbar = $false
$form.KeyPreview = $true

$form.Add_KeyDown({
  param($s, $e)
  if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) { $e.SuppressKeyPress = $true }
  if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F4) { $e.SuppressKeyPress = $true }
})
$form.Add_FormClosing({ param($s, $e) $e.Cancel = $true })

$accentColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$hoverColor = [System.Drawing.Color]::FromArgb(55, 55, 62)
$textColor = [System.Drawing.Color]::FromArgb(220, 220, 225)
$dimTextColor = [System.Drawing.Color]::FromArgb(140, 140, 150)

function New-TaskbarButton {
  param([string]$Text, [System.Drawing.Color]$BgColor, [int]$W = 0, [int]$H = 0)
  $btn = New-Object System.Windows.Forms.Button
  $btn.Text = $Text
  $btn.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
  $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
  $btn.FlatAppearance.BorderSize = 0
  $btn.BackColor = $BgColor
  $btn.ForeColor = [System.Drawing.Color]::White
  if ($H -gt 0) { $btn.Height = $H } else { $btn.Height = $barHeight - 12 }
  if ($W -gt 0) { $btn.Width = $W; $btn.AutoSize = $false } else { $btn.AutoSize = $true }
  $btn.Padding = New-Object System.Windows.Forms.Padding(14, 0, 14, 0)
  $btn.Margin = New-Object System.Windows.Forms.Padding(2, 0, 2, 0)
  $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
  $btn.Add_MouseEnter({ $this.BackColor = $hoverColor })
  $btn.Add_MouseLeave({ $this.BackColor = $BgColor })
  return $btn
}

function New-IconAppButton {
  param([string]$ToolTip, [string]$ExePath, [string]$Label)
  $btn = New-Object System.Windows.Forms.Button
  $btn.Text = $Label
  $btn.Font = New-Object System.Drawing.Font('Segoe UI', 9)
  $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
  $btn.FlatAppearance.BorderSize = 0
  $btn.BackColor = [System.Drawing.Color]::Transparent
  $btn.ForeColor = $textColor
  $btn.Height = $barHeight - 8
  $btn.AutoSize = $true
  $btn.Padding = New-Object System.Windows.Forms.Padding(10, 0, 10, 0)
  $btn.Margin = New-Object System.Windows.Forms.Padding(1, 0, 1, 0)
  $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
  $btn.Add_Click({ Start-Process -FilePath $ExePath -ErrorAction SilentlyContinue })
  $btn.Add_MouseEnter({ $this.BackColor = $hoverColor })
  $btn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::Transparent })
  return $btn
}

$leftPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$leftPanel.Dock = [System.Windows.Forms.DockStyle]::Left
$leftPanel.AutoSize = $true
$leftPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$leftPanel.WrapContents = $false
$leftPanel.BackColor = [System.Drawing.Color]::Transparent
$leftPanel.Padding = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)
$leftPanel.Height = $barHeight

# --- Start button ---
$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = [char]0x25CF + ' Start'
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnStart.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnStart.FlatAppearance.BorderSize = 0
$btnStart.BackColor = $accentColor
$btnStart.ForeColor = [System.Drawing.Color]::White
$btnStart.Height = $barHeight - 12
$btnStart.AutoSize = $true
$btnStart.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
$btnStart.Margin = New-Object System.Windows.Forms.Padding(4, 0, 8, 0)
$btnStart.Cursor = [System.Windows.Forms.Cursors]::Hand

# --- Start menu (popup) ---
$startMenu = New-Object System.Windows.Forms.ContextMenuStrip
$startMenu.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 38)
$startMenu.ForeColor = $textColor
$startMenu.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$startMenu.Renderer = New-Object System.Windows.Forms.ToolStripProfessionalRenderer
$startMenu.ShowImageMargin = $false

$apps = @(
  @{ Label = 'File Explorer'; Exe = 'explorer.exe' },
  @{ Label = 'Microsoft Edge'; Exe = 'msedge.exe' },
  @{ Label = 'Notepad'; Exe = 'notepad.exe' },
  @{ Label = 'Calculator'; Exe = 'calc.exe' },
  @{ Label = 'Paint'; Exe = 'mspaint.exe' },
  @{ Label = 'Task Manager'; Exe = 'taskmgr.exe' },
  @{ Label = 'Command Prompt'; Exe = 'cmd.exe' },
  @{ Label = 'Settings'; Exe = 'ms-settings:' }
)
foreach ($app in $apps) {
  $item = $startMenu.Items.Add($app.Label)
  $item.Tag = $app.Exe
  $item.ForeColor = $textColor
  $item.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 38)
  $item.Font = New-Object System.Drawing.Font('Segoe UI', 11)
  $item.Add_Click({
    param($s, $e)
    $exe = $s.Tag
    Start-Process -FilePath $exe -ErrorAction SilentlyContinue
  })
}
$startMenu.Items.Add('-')
$shutdownItem = $startMenu.Items.Add('Shut Down')
$shutdownItem.ForeColor = [System.Drawing.Color]::FromArgb(255, 80, 80)
$shutdownItem.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$shutdownItem.Add_Click({ try { & shutdown.exe /s /t 0 /f } catch {} })

$btnStart.Add_Click({
  $pt = New-Object System.Drawing.Point(0, $btnStart.Height)
  $point = $btnStart.PointToScreen($pt)
  $startMenu.Show($point)
})
$leftPanel.Controls.Add($btnStart)

# --- Pinned apps ---
$pinned = @(
  @{ Label = 'Explorer'; Exe = 'explorer.exe' },
  @{ Label = 'Edge'; Exe = 'msedge.exe' },
  @{ Label = 'Notepad'; Exe = 'notepad.exe' },
  @{ Label = 'Terminal'; Exe = 'wt.exe' }
)
foreach ($app in $pinned) {
  $btn = New-IconAppButton -ToolTip $app.Label -ExePath $app.Exe -Label $app.Label
  $leftPanel.Controls.Add($btn)
}

# --- Separator ---
$sep = New-Object System.Windows.Forms.Label
$sep.Text = '|'
$sep.ForeColor = $dimTextColor
$sep.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$sep.AutoSize = $true
$sep.Margin = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
$sep.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$leftPanel.Controls.Add($sep)

# --- Open windows list label ---
$lblWindows = New-Object System.Windows.Forms.Label
$lblWindows.Text = ''
$lblWindows.ForeColor = $dimTextColor
$lblWindows.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lblWindows.AutoSize = $true
$lblWindows.Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)
$lblWindows.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$leftPanel.Controls.Add($lblWindows)

# --- Right panel (controls + clock) ---
$rightPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$rightPanel.Dock = [System.Windows.Forms.DockStyle]::Right
$rightPanel.AutoSize = $true
$rightPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
$rightPanel.WrapContents = $false
$rightPanel.BackColor = [System.Drawing.Color]::Transparent
$rightPanel.Padding = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
$rightPanel.Height = $barHeight
$rightPanel.Width = 500

# --- Clock ---
$lblClock = New-Object System.Windows.Forms.Label
$lblClock.Text = Get-Date -Format 'HH:mm'
$lblClock.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$lblClock.ForeColor = $textColor
$lblClock.AutoSize = $true
$lblClock.Margin = New-Object System.Windows.Forms.Padding(12, 0, 8, 0)
$lblClock.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$rightPanel.Controls.Add($lblClock)

# --- Control buttons ---
$btnSleep = New-TaskbarButton -Text 'Sleep' -BgColor ([System.Drawing.Color]::FromArgb(44, 44, 50))
$btnSleep.Add_Click({ try { & rundll32.exe powrprof.dll,SetSuspendState 0,1,0 } catch {} })
$rightPanel.Controls.Add($btnSleep)

$btnSwitch = New-TaskbarButton -Text 'Switch User' -BgColor ([System.Drawing.Color]::FromArgb(44, 44, 50))
$btnSwitch.Add_Click({ try { & rundll32.exe user32.dll,LockWorkStation } catch {} })
$rightPanel.Controls.Add($btnSwitch)

$btnLogout = New-TaskbarButton -Text 'Logout' -BgColor ([System.Drawing.Color]::FromArgb(160, 35, 35))
$btnLogout.Add_Click({ try { & logoff.exe } catch {} })
$rightPanel.Controls.Add($btnLogout)

$form.Controls.Add($leftPanel)
$form.Controls.Add($rightPanel)

# --- Clock timer ---
$clockTimer = New-Object System.Windows.Forms.Timer
$clockTimer.Interval = 30000
$clockTimer.Add_Tick({ $lblClock.Text = Get-Date -Format 'HH:mm' })
$clockTimer.Start()

# --- Open windows counter ---
$winTimer = New-Object System.Windows.Forms.Timer
$winTimer.Interval = 5000
$winTimer.Add_Tick({
  try {
    $procs = @(Get-Process | Where-Object { $_.MainWindowTitle -ne '' -and $_.ProcessName -notin @('explorer','SearchHost','ShellExperienceHost','ApplicationFrameHost','Microsoft.Photos','Settings','lockapp') })
    $count = $procs.Count
    if ($count -gt 0) { $lblWindows.Text = ('{0} app(s) open' -f $count) } else { $lblWindows.Text = '' }
  } catch { $lblWindows.Text = '' }
})
$winTimer.Start()

# --- Idle timeout ---
$idleTimer = New-Object System.Windows.Forms.Timer
$idleTimer.Interval = 30000
$idleTimer.Add_Tick({
  if ($IdleTimeoutMinutes -le 0) { return }
  $idle = Get-IdleSeconds
  if ($idle -ge $IdleTimeoutMinutes * 60) {
    $idleTimer.Stop()
    try { & rundll32.exe powrprof.dll,SetSuspendState 0,1,0 } catch {}
  }
})
$idleTimer.Start()

try { [System.Windows.Forms.Application]::Run($form) } catch { exit 1 }
'@
  Set-Content -LiteralPath $script:TaskbarScriptPath -Value $content -Encoding UTF8
}

function Get-TaskbarRunning {
  try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
      if ($proc.CommandLine -like '*taskbar.ps1*') { return $true }
    }
  } catch {}
  return $false
}

function Stop-Taskbar {
  try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
      if ($proc.CommandLine -like '*taskbar.ps1*') {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {}
  Show-NativeTaskbar
}

function Hide-NativeTaskbar {
  try {
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
    if (-not (Test-Path -LiteralPath $regPath)) { return }
    $settings = Get-ItemProperty -LiteralPath $regPath -Name Settings -ErrorAction Stop
    $bytes = [byte[]]$settings.Settings
    if ($bytes.Length -ge 9) {
      $bytes[8] = $bytes[8] -bor 0x02
      Set-ItemProperty -LiteralPath $regPath -Name Settings -Value $bytes -Force -ErrorAction Stop
    }
    # Also disable taskbar thumbnail previews and edge swipe
    $policies = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer'
    if (-not (Test-Path -LiteralPath $policies)) {
      New-Item -ItemType Directory -Force -Path $policies -ErrorAction SilentlyContinue | Out-Null
    }
    Set-ItemProperty -LiteralPath $policies -Name 'NoPinningLibraryToTaskbar' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    # Restart Explorer to apply
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process explorer -ErrorAction SilentlyContinue
  } catch {}
}

function Show-NativeTaskbar {
  try {
    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
    if (-not (Test-Path -LiteralPath $regPath)) { return }
    $settings = Get-ItemProperty -LiteralPath $regPath -Name Settings -ErrorAction Stop
    $bytes = [byte[]]$settings.Settings
    if ($bytes.Length -ge 9) {
      $bytes[8] = $bytes[8] -band (-bnot 0x02)
      Set-ItemProperty -LiteralPath $regPath -Name Settings -Value $bytes -Force -ErrorAction Stop
    }
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process explorer -ErrorAction SilentlyContinue
  } catch {}
}

function Start-Taskbar {
  param([string]$UserName, [int]$IdleTimeoutMinutes = 15)
  if (-not $UserName) { return }
  if (Get-TaskbarRunning) { return }
  Ensure-TaskbarScript -IdleTimeoutMinutes $IdleTimeoutMinutes
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ServerUrl "{1}" -ConfigPath "{2}" -IdleTimeoutMinutes {3}' -f $script:TaskbarScriptPath, $ServerUrl, $ConfigPath, $IdleTimeoutMinutes
  $taskName = 'LabCC-Taskbar-' + [Guid]::NewGuid().ToString('N')
  if (-not (New-InteractiveGateTask -TaskName $taskName -UserName $UserName -ArgumentList $argLine)) { return }
  try {
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Hide-NativeTaskbar
  } catch {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
}

function Get-CheckinGateRunning {
  try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
      if ($proc.CommandLine -like '*checkin-gate.ps1*') { return $true }
    }
  } catch {}
  return $false
}

function Stop-CheckinGate {
  try {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
      if ($proc.CommandLine -like '*checkin-gate.ps1*') {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {}
}

function New-InteractiveGateTask {
  # Registers an interactive scheduled task that runs a PowerShell command in a
  # specific logged-on user's session. Uses the PowerShell ScheduledTasks
  # cmdlets first because they encode the command line correctly in the task
  # XML; schtasks.exe mis-parses /TR values that contain embedded quotes (the
  # agent paths/URLs are quoted), which makes /Create fail on some Windows 11
  # builds. Returns $true on success.
  param(
    [string]$TaskName,
    [string]$UserName,
    [string]$ArgumentList,
    [switch]$AtLogon
  )
  if (-not $UserName) { return $false }
  $script:lastGateTaskError = ''
  try {
    try {
      $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $ArgumentList
      if ($AtLogon) {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserName
      } else {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
      }
      $principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Interactive -RunLevel Highest
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
      Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
      Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
      return $true
    } catch {
      $script:lastGateTaskError = 'ScheduledTask cmdlet: ' + $_.Exception.Message
      Write-Log ('ScheduledTask cmdlet failed for {0} ({1}); trying schtasks.exe.' -f $TaskName, $_.Exception.Message)
    }
    $tr = '"powershell.exe" {0}' -f $ArgumentList
    $schArgs = @('/Create', '/TN', $TaskName, '/TR', $tr, '/SC', $(if ($AtLogon) { 'ONLOGON' } else { 'ONCE' }), '/RU', $UserName, '/RL', 'HIGHEST', '/IT', '/F')
    if (-not $AtLogon) { $schArgs += @('/ST', '00:00') }
    $schOutput = (& schtasks.exe @schArgs 2>&1) | Out-String
    if ($LASTEXITCODE -eq 0) { return $true }
    $script:lastGateTaskError = ('schtasks (exit {0}): {1}' -f $LASTEXITCODE, ($schOutput.Trim()))
    Write-Log ('schtasks failed to register {0} (exit {1}): {2}' -f $TaskName, $LASTEXITCODE, ($schOutput.Trim()))
  } catch {
    $script:lastGateTaskError = $_.Exception.Message
    Write-Log ('Could not create interactive task {0}: {1}' -f $TaskName, $_.Exception.Message)
  }
  return $false
}

function Start-GateTask {
  # Runs the gate in a specific logged-on user's session via an interactive
  # scheduled task. This is the most reliable way to show a WinForms form on
  # the desktop when the agent runs as SYSTEM.
  param([string]$UserName, [string]$ArgumentList)
  if (-not $UserName) { return $false }
  $taskName = 'LabCC-Gate-' + [Guid]::NewGuid().ToString('N')
  if (-not (New-InteractiveGateTask -TaskName $taskName -UserName $UserName -ArgumentList $ArgumentList)) { return $false }
  try {
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    # The definition is no longer needed once the gate is running; removing it
    # does not stop the running instance, it just prevents task accumulation.
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    return $true
  } catch {
    Write-Log ('Could not run gate task {0}: {1}' -f $taskName, $_.Exception.Message)
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
  return $false
}

function Show-CheckinGate {
  param([string]$UserName)
  Ensure-CheckinScript
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ServerUrl "{1}" -ConfigPath "{2}" -UserName "{3}" -PendingPath "{4}"' -f $script:CheckinScriptPath, $ServerUrl, $ConfigPath, ($UserName -replace '"', '""'), ($PendingPath -replace '"', '""')
  if ($UserName -and $UserName -notmatch '(?i)^nt authority\\') {
    Start-GateTask -UserName $UserName -ArgumentList $argLine
    return
  }
  Invoke-Interactive -FilePath 'powershell.exe' -ArgumentList $argLine
}

function Ensure-GateLauncher {
  # Logon launcher: brings up the sign-in gate as soon as a user logs on so
  # it appears at PC startup without waiting for the next agent pass.
  $content = @'
param(
  [string]$ServerUrl,
  [string]$ConfigPath,
  [string]$GateScriptPath,
  [string]$PendingPath,
  [string]$ConfigDir
)
$ErrorActionPreference = 'Continue'
$markerPath = Join-Path $ConfigDir 'pending\gate-request'

$sessionToken = ''
try {
  $explorerProc = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -ne 0 } | Select-Object -First 1
  if ($explorerProc) { $sessionToken = $explorerProc.CreationDate.ToString('o') }
} catch {}

$cfg = $null
if (Test-Path -LiteralPath $ConfigPath) {
  try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch {}
}
$checkinRequired = $false
if ($cfg -and $cfg.PSObject.Properties.Name -contains 'lastCheckinRequired') { $checkinRequired = [bool]$cfg.lastCheckinRequired }
$gateSession = ''
if ($cfg -and $cfg.PSObject.Properties.Name -contains 'gateSession') { $gateSession = [string]$cfg.gateSession }
$gateNeeded = $checkinRequired -or ($gateSession -ne $sessionToken)
try {
  Add-Content -LiteralPath (Join-Path $ConfigDir 'gate-log.txt') -Value ("[{0}] launcher ran user={1} sessionToken={2} gateSession={3} checkinRequired={4} gateNeeded={5}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:USERNAME, $sessionToken, $gateSession, $checkinRequired, $gateNeeded) -Encoding UTF8 -ErrorAction SilentlyContinue
} catch {}
if (-not $gateNeeded) { exit 0 }

try {
  New-Item -ItemType Directory -Force -Path (Join-Path $ConfigDir 'pending') | Out-Null
  Set-Content -LiteralPath $markerPath -Value (Get-Date).ToString('o') -Encoding UTF8 -ErrorAction SilentlyContinue
} catch {}

if ($cfg -and $sessionToken) {
  try {
    $cfg | Add-Member -NotePropertyName gateSession -NotePropertyValue $sessionToken -Force
    $cfg | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
  } catch {}
}

try {
  $already = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*checkin-gate.ps1*' -and $_.ProcessId -ne $PID })
  if ($already.Count -eq 0) {
    $user = (whoami 2>$null)
    if (-not $user) { $user = $env:USERDOMAIN + '\' + $env:USERNAME }
    $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ServerUrl "{1}" -ConfigPath "{2}" -UserName "{3}" -PendingPath "{4}"' -f $GateScriptPath, $ServerUrl, $ConfigPath, ($user -replace '"', '""'), ($PendingPath -replace '"', '""')
    try {
      Add-Content -LiteralPath (Join-Path $ConfigDir 'gate-log.txt') -Value ("[{0}] launcher starting gate for {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $user) -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -WindowStyle Hidden
  }
} catch {}
exit 0
'@
  Set-Content -LiteralPath $script:GateLauncherPath -Value $content -Encoding UTF8
}

function Register-LogonGate {
  # Registers (or refreshes) the ONLOGON task that brings the sign-in gate up
  # right when a specific user logs on. This is how the shared auto-login
  # account lands directly on the login form at every boot instead of the
  # Windows login page. Re-registering is cheap and idempotent, so we skip it
  # when the task is already registered for the same user.
  param([string]$UserName)
  if (-not $UserName) { return $false }
  if ($script:logonGateRegisteredFor -eq $UserName) { return $true }
  try {
    Ensure-GateLauncher
    $launcherCmd = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ServerUrl "{1}" -ConfigPath "{2}" -GateScriptPath "{3}" -PendingPath "{4}" -ConfigDir "{5}"' -f $script:GateLauncherPath, $ServerUrl, $ConfigPath, $script:CheckinScriptPath, $script:PendingPath, $ConfigDir
    if (New-InteractiveGateTask -TaskName $LogonTaskName -UserName $UserName -ArgumentList $launcherCmd -AtLogon) {
      $script:logonGateRegisteredFor = $UserName
      Write-Log ('Logon gate registered for {0} so the sign-in gate appears at every logon.' -f $UserName)
      return $true
    }
    Write-Log ('Could not register the logon gate for {0}; the agent will still show the gate after login.' -f $UserName)
    if ($config -and $config.token) {
      $errBody = @{ token = $config.token; type = 'gate'; message = ('Logon gate registration failed for {0} on {1}' -f $UserName, $env:COMPUTERNAME); detail = $script:lastGateTaskError }
      try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $errBody | Out-Null } catch {}
    }
  } catch {
    Write-Log ('Could not register the logon gate for {0}: {1}' -f $UserName, $_.Exception.Message)
  }
  return $false
}

function Sync-PendingCheckins {
  if (-not (Test-Path -LiteralPath $PendingPath)) { return }
  try {
    $queue = Get-Content -LiteralPath $PendingPath -Raw | ConvertFrom-Json
    if (-not $queue -or @($queue).Count -eq 0) { return }
    $remaining = @()
    $synced = 0
    foreach ($entry in @($queue)) {
      try {
        $resp = Invoke-ApiJson -Method 'POST' -Path '/api/agent/checkin' -Body $entry
        if ($resp.ok) { $synced++; continue }
      } catch {}
      $remaining += $entry
    }
    if ($remaining.Count -eq 0) {
      Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
    } else {
      $remaining | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $PendingPath -Encoding UTF8
    }
    if ($synced -gt 0) { Write-Log ('Synced {0} offline check-in(s) to the dashboard.' -f $synced) }
  } catch {
    Write-Log ('Pending check-in sync failed: {0}' -f $_.Exception.Message)
  }
}

function Set-LegacyStorage {
  # Points every storage variable back at the pre-1.20.0 layout. Used as the
  # failure path of Invoke-StorageMigration: a PC that cannot complete the move
  # keeps running exactly as it was, which is always better than a PC that
  # comes up with no config and re-registers as a new machine.
  $script:ConfigDir = $script:LegacyConfigDir
  $script:ConfigPath = $script:LegacyConfigPath
  $script:PendingPath = Join-Path $script:LegacyConfigDir 'pending\checkins.json'
  $script:AgentPath = Join-Path $script:LegacyConfigDir 'lab-agent.ps1'
  $script:LockPath = Join-Path $script:LegacyConfigDir 'agent.lock'
  $script:TaskName = $script:LegacyTaskName
  $script:LogonTaskName = $script:LegacyLogonTaskName
  $script:CheckinScriptPath = Join-Path $script:LegacyConfigDir 'checkin-gate.ps1'
  $script:GateLauncherPath = Join-Path $script:LegacyConfigDir 'gate-launcher.ps1'
  $script:logonGateRegisteredFor = ''
}

function Invoke-StorageMigration {
  # Moves agent state from ProgramData\LabCommandCenter to ProgramData\LvOsSec.
  #
  # Why this cannot just be a rename: config.json holds the agent token that
  # authenticates this machine, and the scheduled tasks hold an absolute path
  # to the script. A machine whose config did not come across would re-register
  # as a brand new computer and orphan its history.
  #
  # Ordering matters. This is called before the single-instance lock check and
  # before Get-Config, because the lock file and config.json both live in the
  # directory being moved.
  #
  # Idempotent: returns immediately when there is nothing to migrate or when the
  # new layout is already valid. Any failure falls back to the legacy directory
  # and task names, so the worst case is "the rename did not happen", never
  # "the machine is offline".
  if ($ConfigDir -eq $script:LegacyConfigDir) { return }
  if (-not (Test-Path -LiteralPath $script:LegacyConfigPath)) { return }

  # Already done? A new config that parses and carries a token is authoritative.
  if (Test-Path -LiteralPath $ConfigPath) {
    $have = $null
    try { $have = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $have = $null }
    if ($have -and $have.token) { return }
    # Present but unusable (truncated write, partial copy). Fall through and
    # repair it from the legacy copy.
    Write-Log 'Existing LvOsSec config is unreadable; repairing it from the previous directory.'
  }

  Write-Log ('Migrating agent storage to {0} ...' -f $ConfigDir)
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

    # 1. config.json. Everything else is rebuildable; this is not.
    Copy-Item -LiteralPath $script:LegacyConfigPath -Destination $ConfigPath -Force

    # 2. The script itself, so the next self-update has something to replace.
    $legacyScript = Join-Path $script:LegacyConfigDir 'lab-agent.ps1'
    if ((Test-Path -LiteralPath $legacyScript) -and -not (Test-Path -LiteralPath $AgentPath)) {
      Copy-Item -LiteralPath $legacyScript -Destination $AgentPath -Force
    }

    # 3. The sign-in gate script, for labs that use the check-in gate.
    $legacyCheckin = Join-Path $script:LegacyConfigDir 'pending\checkins.json'
    if ((Test-Path -LiteralPath $legacyCheckin) -and -not (Test-Path -LiteralPath $PendingPath)) {
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PendingPath) | Out-Null
      Copy-Item -LiteralPath $legacyCheckin -Destination $PendingPath -Force
    }

    # 4. Prove the new config is usable before touching any task. If the token
    #    did not come across, the machine is about to go dark, so stop here.
    $migrated = $null
    try { $migrated = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { $migrated = $null }
    if (-not ($migrated -and $migrated.token)) {
      throw 'the copied config has no agent token'
    }

    # 5. Re-point the scheduled tasks. Register the new one before removing the
    #    old, so there is never a window with no boot task.
    $taskCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $AgentPath -ServerUrl $ServerUrl"
    $createOutput = & schtasks.exe /Create /TN $TaskName /TR $taskCmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw ('could not register "{0}": {1}' -f $TaskName, (($createOutput | Out-String).Trim()))
    }
    & schtasks.exe /Delete /TN $script:LegacyTaskName /F 2>$null | Out-Null
    # The logon gate is re-registered by the main loop against the new paths, so
    # retire the old registration rather than leaving it pointing at the old
    # directory. Best effort: a failure here only affects gate timing.
    & schtasks.exe /Delete /TN $script:LegacyLogonTaskName /F 2>$null | Out-Null
    $script:logonGateRegisteredFor = ''

    Write-Log ('Migrated agent storage to {0}; boot task is now "{1}".' -f $ConfigDir, $TaskName)

    # 6. Retire the old directory. Renamed rather than deleted so nothing is
    #    destroyed, and a later run of an old script is visibly inert.
    try {
      $retired = $script:LegacyConfigDir + '.migrated'
      if (Test-Path -LiteralPath $retired) { Remove-Item -LiteralPath $retired -Recurse -Force -ErrorAction SilentlyContinue }
      Rename-Item -LiteralPath $script:LegacyConfigDir -NewName (Split-Path -Leaf $retired) -ErrorAction Stop
      Write-Log ('Previous agent directory kept as {0}.' -f (Split-Path -Leaf $retired))
    } catch {
      Write-Log ('Could not retire the previous directory (harmless): {0}' -f $_.Exception.Message)
    }
  } catch {
    Write-Log ('Storage migration failed, staying on {0}: {1}' -f $script:LegacyConfigDir, $_.Exception.Message)
    Set-LegacyStorage
  } finally {
    $ErrorActionPreference = $prevEap
  }
}

function Update-Self {
  # Downloads the agent script served by the server and replaces this copy when
  # a newer version is available, so agents pick up updates automatically
  # without being reinstalled. Runs from the main loop when the server's
  # heartbeat says an update is required. The current process hands off to a
  # fresh process running the new script and exits.
  param([string]$LatestVersion)
  if (-not $LatestVersion) { return }
  if ($LatestVersion -eq $script:AgentVersion) { return }
  $now = Get-Date
  if ($script:lastUpdateAttemptAt -and (($now - $script:lastUpdateAttemptAt).TotalMinutes -lt 5)) { return }
  $script:lastUpdateAttemptAt = $now
  $tmp = Join-Path $ConfigDir 'lab-agent.update.ps1'
  $backup = $AgentPath + '.bak'
  try {
    Invoke-WebRequest -Uri ($ServerUrl + '/api/agent/download') -OutFile $tmp -UseBasicParsing -TimeoutSec 120 | Out-Null
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
      throw ('downloaded agent failed the PowerShell syntax check ({0} error(s))' -f $errors.Count)
    }
    $newVer = $null
    foreach ($line in (Get-Content -LiteralPath $tmp -TotalCount 150 -ErrorAction Stop)) {
      if ($line -match '\$script:AgentVersion\s*=\s*''([^'']+)''') { $newVer = $Matches[1]; break }
    }
    if (-not $newVer) { throw 'downloaded agent has no version marker' }
    if ($newVer -eq $script:AgentVersion) {
      # Server advertises a newer version but is still serving our build; skip
      # this round instead of re-downloading every pass.
      Write-Log ('Agent download served v{0} (same as running); skipping update.' -f $newVer)
      Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
      return
    }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
    Copy-Item -LiteralPath $AgentPath -Destination $backup -Force
    Copy-Item -LiteralPath $tmp -Destination $AgentPath -Force
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    Write-Log ('Agent self-updated v{0} -> v{1}.' -f $script:AgentVersion, $newVer)
    try {
      Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body @{
        token = $config.token
        type = 'agent_update'
        message = ('Agent updated to v{0} on {1}' -f $newVer, $env:COMPUTERNAME)
        detail = ('previous={0}' -f $script:AgentVersion)
      } | Out-Null
    } catch {}
    # Release the single-instance lock, start the freshly installed script, and
    # exit so the new version takes over without a reboot or reinstall.
    Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath 'powershell.exe' -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ServerUrl "{1}"' -f $AgentPath, $ServerUrl) -WindowStyle Hidden
    exit 0
  } catch {
    Write-Log ('Agent self-update failed: {0}' -f $_.Exception.Message)
    if (Test-Path -LiteralPath $backup) {
      Copy-Item -LiteralPath $backup -Destination $AgentPath -Force
      Write-Log 'Restored the previous agent version after the update failed.'
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

function Update-CheckinGate {
  # Decides whether the sign-in gate must be shown. Works even when the server
  # is unreachable by using the last known check-in requirement cached locally.
  param($Hb)
  try {
    $user = Get-CurrentUser
    $isSystemUser = ($user -match '(?i)^nt authority\\') -or ($user -match '\$$')
    if (-not $user -or $isSystemUser) { return }

    $cfgNow = Get-Config

    # Cache the server's check-in requirement so the gate can appear offline.
    if ($cfgNow -and $Hb -and $null -ne $Hb.computer.checkinRequired) {
      $cfgNow | Add-Member -NotePropertyName lastCheckinRequired -NotePropertyValue ([bool]$Hb.computer.checkinRequired) -Force
      Save-Config $cfgNow
    }
    $checkinRequired = $false
    if ($Hb -and $null -ne $Hb.computer.checkinRequired) {
      $checkinRequired = [bool]$Hb.computer.checkinRequired
    } elseif ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'lastCheckinRequired') {
      $checkinRequired = [bool]$cfgNow.lastCheckinRequired
    }

    $sessionToken = ''
    try {
      $explorerProc = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -ne 0 } | Select-Object -First 1
      if ($explorerProc) { $sessionToken = $explorerProc.CreationDate.ToString('o') }
    } catch {}
    $gateSession = ''
    if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'gateSession') { $gateSession = [string]$cfgNow.gateSession }
    $gateNeeded = $checkinRequired -or ($gateSession -ne $sessionToken)

    # A logon launcher drops this marker so the gate appears right at PC
    # startup without waiting for a session change. Consumed once so it
    # cannot re-trigger the gate on later loop passes.
    if (Test-Path -LiteralPath $script:GateMarkerPath) {
      $gateNeeded = $true
      Remove-Item -LiteralPath $script:GateMarkerPath -Force -ErrorAction SilentlyContinue
    }

    $adminWindowsUser = ''
    if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'adminWindowsUser') { $adminWindowsUser = [string]$cfgNow.adminWindowsUser }
    $adminSession = $false
    if ($adminWindowsUser) {
      $consoleName = $user
      if ($consoleName -match '\\(?<name>[^\\]+)$') { $consoleName = $Matches['name'] }
      $adminName = $adminWindowsUser
      if ($adminName -match '\\(?<name>[^\\]+)$') { $adminName = $Matches['name'] }
      if ($adminName -and $adminName -ieq $consoleName) { $adminSession = $true }
    }

    # The custom taskbar is a student-only feature. A console session also
    # counts as an admin session when the account is a member of the local
    # Administrators group, even if no gate admin account is configured.
    $taskbarUserIsAdmin = $adminSession
    if (-not $taskbarUserIsAdmin -and $user) {
      try {
        $bareConsole = $user
        if ($bareConsole -match '\\(?<name>[^\\]+)$') { $bareConsole = $Matches['name'] }
        foreach ($m in @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)) {
          if ($m.ObjectClass -ne 'User') { continue }
          $mn = [string]$m.Name
          if ($mn -match '\\(?<name>[^\\]+)$') { $mn = $Matches['name'] }
          if ($mn -and $mn -ieq $bareConsole) { $taskbarUserIsAdmin = $true; break }
        }
      } catch {}
    }

    if ($gateNeeded -and $adminSession) {
      try {
        $body = @{ token = $config.token; userName = $user; role = 'admin'; studentName = $user }
        $resp = Invoke-ApiJson -Method 'POST' -Path '/api/agent/checkin' -Body $body
        if ($resp.ok) {
          $cfgNow | Add-Member -NotePropertyName gateSession -NotePropertyValue $sessionToken -Force
          Save-Config $cfgNow
          Write-Log ('Administrator check-in recorded for {0}' -f $user)
        } else {
          Write-Log ('Administrator check-in rejected: {0}' -f $resp.error)
        }
      } catch {
        Write-Log ('Administrator check-in failed: {0}' -f $_.Exception.Message)
      }
    } elseif ($gateNeeded -and (Get-CheckinGateRunning)) {
      # The gate is already up (started by the logon launcher or a previous
      # attempt). Remember the session so it is not re-shown right after this
      # one is submitted.
      $cfgNow | Add-Member -NotePropertyName gateSession -NotePropertyValue $sessionToken -Force
      Save-Config $cfgNow
    } elseif ($gateNeeded) {
      Stop-Taskbar
      Show-CheckinGate -UserName $user
      # Give the gate a moment to come up. Only remember the session as
      # "gated" once a checkin-gate process is actually running, so a launch
      # that did not take effect (desktop still starting, task race) is retried
      # on the next pass instead of being marked as shown and never appearing.
      Start-Sleep -Seconds 3
      if (Get-CheckinGateRunning) {
        $cfgNow | Add-Member -NotePropertyName gateSession -NotePropertyValue $sessionToken -Force
        Save-Config $cfgNow
        Write-Log ('Check-in gate shown for user {0}' -f $user)
        $evBody = @{ token = $config.token; type = 'gate'; message = ('Check-in gate shown for {0} on {1}' -f $user, $env:COMPUTERNAME); detail = ('checkinRequired={0}' -f $checkinRequired) }
        try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $evBody | Out-Null } catch {}
      } else {
        Write-Log ('Check-in gate launch did not take effect yet; will retry for {0}' -f $user)
        $now = Get-Date
        if (-not $script:lastGateRetryAt -or (($now - $script:lastGateRetryAt).TotalSeconds -ge 120)) {
          $script:lastGateRetryAt = $now
          $evBody = @{ token = $config.token; type = 'gate'; message = ('Check-in gate launch pending, will retry (user {0} on {1})' -f $user, $env:COMPUTERNAME); detail = ('gateNeeded={0} sessionToken={1} gateSession={2}' -f $gateNeeded, $sessionToken, $gateSession) }
          try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $evBody | Out-Null } catch {}
        }
      }
    }

    # Start taskbar after successful check-in (gate no longer needed). It is a
    # student-only feature: never start (or keep) it for an admin session.
    if ($taskbarUserIsAdmin) {
      Stop-Taskbar
    } elseif (-not $gateNeeded -and $user -and -not $isSystemUser) {
      if (-not (Get-TaskbarRunning)) {
        $idleMinutes = 15
        if ($Hb -and $null -ne $Hb.computer -and $Hb.computer.idleLogoutMinutes -and ([int]$Hb.computer.idleLogoutMinutes) -gt 0) {
          $idleMinutes = [int]$Hb.computer.idleLogoutMinutes
        }
        Start-Taskbar -UserName $user -IdleTimeoutMinutes $idleMinutes
      }
    }
  } catch {
    Write-Log ('Check-in gate update failed: {0}' -f $_.Exception.Message)
  }
}

function Set-DownloadBlock {
  # Apply or remove the Software Restriction Policy that blocks executables and
  # installers from user download/desktop/temp locations. PolicyScope = 1 keeps
  # local administrators exempt so the Windows admin account is unaffected.
  param([bool]$Enabled)
  $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
  if (-not $Enabled) {
    try {
      Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop
      Write-Log 'Download/install block policy removed.'
    } catch {
      Write-Log ('Could not remove download/install block policy: {0}' -f $_.Exception.Message)
    }
    return
  }
  try {
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -Path $base -Force | Out-Null
    New-ItemProperty -Path $base -Name 'DefaultLevel' -PropertyType DWord -Value 262144 -Force | Out-Null
    New-ItemProperty -Path $base -Name 'PolicyScope' -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $base -Name 'TransparentEnabled' -PropertyType DWord -Value 2 -Force | Out-Null
    $pathsKey = Join-Path $base '0\Paths'
    New-Item -Path $pathsKey -Force | Out-Null
    $blocked = New-Object System.Collections.Generic.List[string]
    $profileRoot = Join-Path $env:SystemDrive 'Users'
    if (Test-Path -LiteralPath $profileRoot) {
      Get-ChildItem -LiteralPath $profileRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match '(?i)^(public|default|all users)$') { return }
        $blocked.Add((Join-Path $_.FullName 'Downloads'))
        $blocked.Add((Join-Path $_.FullName 'Desktop'))
        $blocked.Add((Join-Path $_.FullName 'AppData\Local\Temp'))
      }
    }
    $blocked.Add((Join-Path $env:SystemRoot 'Temp'))
    $count = 0
    foreach ($path in ($blocked | Sort-Object -Unique)) {
      if (-not $path) { continue }
      $ruleName = [guid]::NewGuid().ToString('B').ToUpper()
      $ruleKey = Join-Path $pathsKey $ruleName
      New-Item -Path $ruleKey -Force | Out-Null
      New-ItemProperty -Path $ruleKey -Name 'ItemData' -PropertyType String -Value $path -Force | Out-Null
      New-ItemProperty -Path $ruleKey -Name 'SaferFlags' -PropertyType DWord -Value 0 -Force | Out-Null
      New-ItemProperty -Path $ruleKey -Name 'Description' -PropertyType String -Value 'Lab Command Center: blocked download/install path' -Force | Out-Null
      $count++
    }
    Write-Log ('Download/install block policy applied ({0} path rules).' -f $count)
  } catch {
    Write-Log ('Download/install block policy failed: {0}' -f $_.Exception.Message)
  }
}

function Enable-RemoteDesktop {
  $notes = @()
  # 1. Enable RDP via registry
  try {
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $notes += 'RDP registry enabled.'
  } catch {
    $notes += 'RDP registry failed (needs admin).'
  }
  # 2. Enable the Windows Firewall rule for Remote Desktop (all profiles)
  try {
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop | Out-Null
    $notes += 'Firewall rule enabled.'
  } catch {
    try {
      netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes 2>$null | Out-Null
      $notes += 'Firewall rule enabled (netsh).'
    } catch {
      $notes += 'Firewall rule enable failed.'
    }
  }
  # 3. Ensure RDP Windows feature is enabled (non-destructive)
  try {
    $rdpFeature = Get-WindowsOptionalFeature -Online -FeatureName 'RemoteDesktop' -ErrorAction SilentlyContinue
    if ($rdpFeature -and $rdpFeature.State -ne 'Enabled') {
      Enable-WindowsOptionalFeature -Online -FeatureName 'RemoteDesktop' -NoRestart -ErrorAction Stop | Out-Null
      $notes += 'RDP feature enabled.'
    }
  } catch {}
  # 4. Allow remote connections via Group Policy key (RDP wrapper compat)
  try {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
  } catch {}
  # 5. Set NLA to optional so older clients can connect
  try {
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $notes += 'NLA relaxed.'
  } catch {}
  # 6. Get IP for reporting
  $ip = ''
  try {
    $ipObj = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
      $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.*'
    } | Select-Object -First 1
    if ($ipObj) { $ip = $ipObj.IPAddress }
  } catch {}
  return @{ success = $true; detail = ('RDP enabled on {0} ({1}). {2}' -f $env:COMPUTERNAME, $ip, ($notes -join ' ')) }
}

function Disable-RemoteDesktop {
  $notes = @()
  try {
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $notes += 'RDP registry disabled.'
  } catch {
    $notes += 'RDP registry disable failed (needs admin).'
  }
  try {
    Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop | Out-Null
    $notes += 'Firewall rule disabled.'
  } catch {
    try {
      netsh advfirewall firewall set rule group="Remote Desktop" new enable=no 2>$null | Out-Null
      $notes += 'Firewall rule disabled (netsh).'
    } catch {
      $notes += 'Firewall rule disable failed.'
    }
  }
  try {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDenyTSConnections' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
  } catch {}
  return @{ success = $true; detail = ('RDP disabled on {0}. {1}' -f $env:COMPUTERNAME, ($notes -join ' ')) }
}

function Ensure-InputScript {
  $content = @'
param(
  [string]$Action = 'move',
  [string]$X = '',
  [string]$Y = '',
  [string]$Button = 'left',
  [string]$Key = '',
  [string]$Text = '',
  [string]$Mods = '',
  [string]$Delta = '0'
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class LccRemoteInput {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint flags, UIntPtr extraInfo);
}
"@

function Get-Vk {
  param([string]$K)
  switch ($K) {
    'Enter' { return 0x0D }
    'Tab' { return 0x09 }
    'Esc' { return 0x1B }
    'Backspace' { return 0x08 }
    'Delete' { return 0x2E }
    'Home' { return 0x24 }
    'End' { return 0x23 }
    'PageUp' { return 0x21 }
    'PageDown' { return 0x22 }
    'Space' { return 0x20 }
    'Up' { return 0x26 }
    'Down' { return 0x28 }
    'Left' { return 0x25 }
    'Right' { return 0x27 }
    'CapsLock' { return 0x14 }
    'NumLock' { return 0x90 }
    'PrtSc' { return 0x2C }
    'F1' { return 0x70 }
    'F2' { return 0x71 }
    'F3' { return 0x72 }
    'F4' { return 0x73 }
    'F5' { return 0x74 }
    'F6' { return 0x75 }
    'F7' { return 0x76 }
    'F8' { return 0x77 }
    'F9' { return 0x78 }
    'F10' { return 0x79 }
    'F11' { return 0x7A }
    'F12' { return 0x7B }
    'Win' { return 0x5B }
    'Ctrl' { return 0x11 }
    'Alt' { return 0x12 }
    'Shift' { return 0x10 }
    default {
      if ($K.Length -eq 1) { return [int][char]::ToUpper($K[0]) }
      return 0
    }
  }
}

function Send-MouseButton {
  param([string]$Btn, [string]$Phase)
  $down = 0x0002
  $up = 0x0004
  if ($Btn -eq 'right') { $down = 0x0008; $up = 0x0010 }
  if ($Btn -eq 'middle') { $down = 0x0020; $up = 0x0040 }
  if ($Phase -eq 'up') {
    [LccRemoteInput]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero)
  } else {
    [LccRemoteInput]::mouse_event($down, 0, 0, 0, [UIntPtr]::Zero)
  }
}

function Send-Key {
  param([string]$Key, [string[]]$ModKeys)
  $vk = Get-Vk $Key
  if ($vk -eq 0) { return }
  $modVks = @()
  foreach ($m in $ModKeys) {
    $mv = Get-Vk $m
    if ($mv -ne 0) { $modVks += $mv }
  }
  foreach ($mv in $modVks) { [LccRemoteInput]::keybd_event([byte]$mv, 0, 0, [UIntPtr]::Zero) }
  [LccRemoteInput]::keybd_event([byte]$vk, 0, 0, [UIntPtr]::Zero)
  [LccRemoteInput]::keybd_event([byte]$vk, 0, 2, [UIntPtr]::Zero)
  foreach ($mv in $modVks) { [LccRemoteInput]::keybd_event([byte]$mv, 0, 2, [UIntPtr]::Zero) }
}

function Send-Text {
  param([string]$Txt)
  $sh = New-Object -ComObject WScript.Shell
  $escaped = ($Txt.ToCharArray() | ForEach-Object {
    $c = $_
    if ('{}()^%+~[]'.Contains($c)) { '{' + $c + '}' } else { [string]$c }
  }) -join ''
  $sh.SendKeys($escaped)
}

$modList = @()
if ($Mods) { $modList = @($Mods -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
switch ($Action) {
  'move' {
    if ($X -ne '' -and $Y -ne '') { [LccRemoteInput]::SetCursorPos([int]$X, [int]$Y) | Out-Null }
  }
  'click' {
    if ($X -ne '' -and $Y -ne '') { [LccRemoteInput]::SetCursorPos([int]$X, [int]$Y) | Out-Null }
    Send-MouseButton -Btn $Button -Phase 'down'
    Start-Sleep -Milliseconds 40
    Send-MouseButton -Btn $Button -Phase 'up'
  }
  'dblclick' {
    if ($X -ne '' -and $Y -ne '') { [LccRemoteInput]::SetCursorPos([int]$X, [int]$Y) | Out-Null }
    1..2 | ForEach-Object {
      Send-MouseButton -Btn $Button -Phase 'down'
      Start-Sleep -Milliseconds 40
      Send-MouseButton -Btn $Button -Phase 'up'
      Start-Sleep -Milliseconds 60
    }
  }
  'down' {
    if ($X -ne '' -and $Y -ne '') { [LccRemoteInput]::SetCursorPos([int]$X, [int]$Y) | Out-Null }
    Send-MouseButton -Btn $Button -Phase 'down'
  }
  'up' {
    if ($X -ne '' -and $Y -ne '') { [LccRemoteInput]::SetCursorPos([int]$X, [int]$Y) | Out-Null }
    Send-MouseButton -Btn $Button -Phase 'up'
  }
  'scroll' {
    $delta = 0
    if ($Delta -ne '') { $delta = [int]$Delta }
    $data = 0
    if ($delta -lt 0) { $data = [uint32](0xFFFFFFFF - [math]::Min([math]::Abs($delta), 2147483647)) }
    else { $data = [uint32]$delta }
    [LccRemoteInput]::mouse_event(0x0800, 0, 0, $data, [UIntPtr]::Zero)
  }
  'key' {
    Send-Key -Key $Key -ModKeys $modList
  }
  'type' {
    if ($Text) { Send-Text -Txt $Text }
  }
}
'@
  Set-Content -LiteralPath $script:InputScriptPath -Value $content -Encoding UTF8
}

function Send-RemoteInput {
  param($Payload)
  Ensure-InputScript
  $type = [string]$Payload.type
  if (-not $type) { return @{ success = $false; detail = 'Missing input type.' } }
  $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Action "{1}" -X "{2}" -Y "{3}" -Button "{4}" -Key "{5}" -Text "{6}" -Mods "{7}" -Delta "{8}"' -f `
    $script:InputScriptPath,
    ($type -replace '"', '""'),
    ([string]$Payload.x -replace '"', '""'),
    ([string]$Payload.y -replace '"', '""'),
    ([string]$Payload.button -replace '"', '""'),
    ([string]$Payload.key -replace '"', '""'),
    ([string]$Payload.text -replace '"', '""'),
    ([string]$Payload.mods -replace '"', '""'),
    ([string]$Payload.delta -replace '"', '""')
  Invoke-Interactive -FilePath 'powershell.exe' -ArgumentList $argLine
  return @{ success = $true; detail = ('Remote input sent: {0}' -f $type) }
}

function Receive-PushedFile {
  param($Payload)
  if (-not $Payload.fileId) { return @{ success = $false; detail = 'Missing fileId' } }
  $fileName = 'downloaded'
  if ($Payload.fileName) { $fileName = (Split-Path $Payload.fileName -Leaf) }
  # A name from the server must never escape the destination directory.
  $fileName = [System.IO.Path]::GetFileName($fileName)
  if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -eq '.' -or $fileName -eq '..') {
    return @{ success = $false; detail = 'Invalid file name' }
  }
  $dest = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
  if ($Payload.destination) {
    $custom = [string]$Payload.destination
    if ([System.IO.Path]::IsPathRooted($custom)) {
      $dest = $custom
    } else {
      $dest = Join-Path $dest $custom
    }
  }
  if (-not (Test-AllowedWritePath -Path $dest)) {
    Write-GateLog ('Blocked push outside allowed roots: {0}' -f $dest)
    return @{ success = $false; detail = ('Refused: destination is outside the allowed file-operation roots: {0}' -f $dest) }
  }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  $destPath = Join-Path $dest $fileName
  $url = '{0}/api/agent/files/download/{1}?token={2}' -f $ServerUrl, $Payload.fileId, $config.token
  Invoke-WebRequest -Uri $url -OutFile $destPath -UseBasicParsing -TimeoutSec 120
  return @{ success = $true; detail = ('Saved to {0}' -f $destPath) }
}

function Get-DriveListing {
  $entries = @()
  try {
    $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady })
    foreach ($drive in $drives) {
      $label = ''
      try { $label = [string]$drive.VolumeLabel } catch {}
      $entries += @{
        name = $drive.Name
        isDir = $true
        size = 0
        modifiedAt = $null
        label = $label
        capacity = [long]$drive.TotalSize
        freeSpace = [long]$drive.TotalFreeSpace
      }
    }
  } catch {}
  return @{ path = '\'; entries = $entries }
}

function Get-DirListing {
  param([string]$Path)
  if (-not $Path -or $Path -eq '\' -or $Path -eq '/') {
    return Get-DriveListing
  }
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw ('Directory not found: {0}' -f $Path)
  }
  $entries = @()
  Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $isDir = $_.PSIsContainer
    $size = 0
    $modified = $null
    try {
      if (-not $isDir) { $size = [long]$_.Length }
      $modified = $_.LastWriteTime.ToString('o')
    } catch {}
    $entries += @{
      name = $_.Name
      isDir = $isDir
      size = $size
      modifiedAt = $modified
    }
  }
  return @{ path = $Path; entries = $entries }
}

# --- File operation confinement ---------------------------------------------
# `delete_file` and `push_file` act on a path supplied by whoever controls the
# dashboard session (or, if a token ever leaks, whoever steals it). Destructive
# operations are therefore confined to an allowlist of roots. Read-only
# browsing stays unrestricted because it is a legitimate admin function and is
# now behind authentication.
#
# `SYSTEM_DENY_ROOTS` is a hard block applied regardless of configuration, so a
# misconfigured allowlist can never open up the OS.

$script:SystemDenyRoots = @(
  $env:SystemRoot,
  (Join-Path $env:SystemRoot 'System32'),
  (Join-Path $env:SystemRoot 'SysWOW64'),
  (Join-Path $env:SystemRoot 'Boot'),
  (Join-Path $env:SystemRoot 'Boot\System Partition'),
  (Join-Path $env:SystemDrive 'Boot'),
  (Join-Path $env:SystemDrive 'Recovery'),
  (Join-Path $env:SystemDrive '$Recycle.Bin'),
  (Join-Path $env:SystemDrive 'System Volume Information')
) | Where-Object { $_ }

# Roots a destructive file operation may touch. Defaults to the signed-in
# user's own profile folders, which is where pushed files legitimately land.
function Get-AllowedWriteRoots {
  $roots = New-Object System.Collections.Generic.List[string]
  $profile = [Environment]::GetFolderPath('UserProfile')
  if ($profile) {
    foreach ($folder in @('Desktop', 'Documents', 'Downloads', 'Pictures')) {
      $p = Join-Path $profile $folder
      if (Test-Path -LiteralPath $p) { $roots.Add($p) }
    }
    $roots.Add($profile)
  }
  $temp = [System.IO.Path]::GetTempPath()
  if ($temp) { $roots.Add($temp) }
  return $roots
}

# Returns $true when $Path is inside one of the allowed write roots and outside
# every system deny root. Comparison is done on fully-resolved paths so `..`
# segments and relative paths cannot escape the allowlist.
function Test-AllowedWritePath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
  } catch {
    # Not present yet (a push destination, for example). Fall back to the
    # parent so the destination's directory is still checked.
    try {
      $parent = Split-Path -Parent $Path
      if ([string]::IsNullOrWhiteSpace($parent)) { return $false }
      $resolved = Join-Path (Resolve-Path -LiteralPath $parent -ErrorAction Stop).ProviderPath ([System.IO.Path]::GetFileName($Path))
    } catch {
      return $false
    }
  }
  if (-not $resolved) { return $false }

  $norm = $resolved.TrimEnd('\','/')
  foreach ($deny in $script:SystemDenyRoots) {
    $d = $deny.TrimEnd('\','/')
    if ($norm -eq $d -or $norm.StartsWith($d + '\', 'OrdinalIgnoreCase') -or $norm.StartsWith($d + '/', 'OrdinalIgnoreCase')) {
      return $false
    }
  }
  foreach ($root in (Get-AllowedWriteRoots)) {
    $r = $root.TrimEnd('\','/')
    if ($norm -eq $r -or $norm.StartsWith($r + '\', 'OrdinalIgnoreCase') -or $norm.StartsWith($r + '/', 'OrdinalIgnoreCase')) {
      return $true
    }
  }
  return $false
}

function Remove-TargetFile {
  param($Payload)
  if (-not $Payload.path) { return @{ success = $false; detail = 'No path provided' } }
  $target = [string]$Payload.path
  if (-not (Test-Path -LiteralPath $target)) {
    return @{ success = $false; detail = ('Path not found: {0}' -f $target) }
  }
  if (-not (Test-AllowedWritePath -Path $target)) {
    Write-GateLog ('Blocked delete outside allowed roots: {0}' -f $target)
    try {
      $body = @{ token = $config.token; type = 'file_op_blocked'; message = ('Blocked delete outside allowed roots on {0}' -f $env:COMPUTERNAME); detail = $target }
      Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $body | Out-Null
    } catch {}
    return @{ success = $false; detail = ('Refused: path is outside the allowed file-operation roots: {0}' -f $target) }
  }
  Remove-Item -LiteralPath $target -Force -Recurse -ErrorAction Stop
  return @{ success = $true; detail = ('Deleted {0}' -f $target) }
}

function Invoke-SyncScan {
  param($Payload)
  $scanPath = $Payload.path
  try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if ($status.AntivirusEnabled -ne $true) {
      return @{ success = $false; detail = 'Windows Defender is not enabled' }
    }
    if ($scanPath) {
      Start-MpScan -ScanPath $scanPath -ScanType QuickScan -ErrorAction Stop
      return @{ success = $true; detail = ('Defender scan completed on {0}' -f $scanPath) }
    }
    Start-MpScan -ScanType QuickScan -ErrorAction Stop
    return @{ success = $true; detail = 'Defender quick scan completed' }
  } catch {
    return @{ success = $false; detail = $_.Exception.Message }
  }
}

function Start-ScanJob {
  param([string]$Type)
  $resultPath = Join-Path $ConfigDir 'scan-result.json'
  Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
  return Start-Job -ArgumentList $Type, $resultPath -ScriptBlock {
    param($scanType, $outPath)
    try {
      Import-Module Defender -ErrorAction SilentlyContinue
      if ($scanType -eq 'full') {
        Start-MpScan -ScanType FullScan -ErrorAction Stop
      } else {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
      }
      @{ success = $true; detail = if ($scanType -eq 'full') { 'Defender full scan completed' } else { 'Defender quick scan completed' } } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $outPath -Encoding UTF8
    } catch {
      @{ success = $false; detail = $_.Exception.Message } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $outPath -Encoding UTF8
    }
  }
}

function Poll-ScanJob {
  # Called once per loop; finishes a background scan and reports the result.
  if (-not $script:scanJob) { return }
  if ($script:scanJob.State -eq 'Completed') {
    $out = Receive-Job -Job $script:scanJob
    Remove-Job -Job $script:scanJob -Force
    $script:scanJob = $null
    $script:avScanState = 'idle'
    $script:avLastScanAt = Get-Date
    $result = @{ success = $false; detail = 'Scan job completed with no result' }
    $resultPath = Join-Path $ConfigDir 'scan-result.json'
    if (Test-Path -LiteralPath $resultPath) {
      try { $result = (Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json) } catch {}
      Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    }
    if ($script:scanAction) {
      $body = @{ token = $config.token; success = ([bool]$result.success) }
      if ($result.detail) { $body.detail = $result.detail }
      try {
        Invoke-ApiJson -Method 'POST' -Path ('/api/agent/actions/{0}/complete' -f $script:scanAction.id) -Body $body | Out-Null
      } catch {}
      $script:scanAction = $null
      if ($result.success) {
        Write-Log ('Action "av_scan" completed - {0}' -f $result.detail)
      } else {
        Write-Log ('Action "av_scan" FAILED: {0}' -f $result.detail)
      }
    }
  } elseif ($script:scanJob.State -in @('Failed', 'Stopped')) {
    Remove-Job -Job $script:scanJob -Force
    $script:scanJob = $null
    $script:avScanState = 'idle'
    if ($script:scanAction) {
      $body = @{ token = $config.token; success = $false; detail = 'Scan job stopped unexpectedly' }
      try {
        Invoke-ApiJson -Method 'POST' -Path ('/api/agent/actions/{0}/complete' -f $script:scanAction.id) -Body $body | Out-Null
      } catch {}
      $script:scanAction = $null
      Write-Log ('Action "av_scan" FAILED: Scan job stopped')
    }
  } else {
    $script:avScanState = 'scanning'
  }
}

function Eject-RemovableDrives {
  try {
    $shell = New-Object -ComObject Shell.Application
    $drives = Get-RemovableDrives
    foreach ($drive in $drives) {
      try {
        $item = $shell.Namespace(17).ParseName(('{0}:' -f $drive.Letter))
        if ($item) { $item.InvokeVerb('Eject') }
      } catch {}
    }
  } catch {}
}

function Ensure-AuditPolicy {
  try {
    & auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable 2>$null | Out-Null
  } catch {}
}

function Get-SecurityAccount {
  param($Event, [string]$Field)
  try {
    $xml = [xml]$Event.ToXml()
    foreach ($prop in $xml.Event.EventData.Data) {
      if ($prop.Name -eq $Field) {
        $val = [string]$prop.'#text'
        if ($val) { return $val }
      }
    }
  } catch {}
  return ''
}

function Read-PasswordEvents {
  # Returns new 4723/4724 events since the last cursor, updating it on disk.
  $cfg = Get-Config
  if (-not $cfg) { return }
  $cursor = $null
  if ($cfg.PSObject.Properties.Name -contains 'securityCursor') { $cursor = $cfg.securityCursor }
  $lastRecord = 0
  if ($cfg.PSObject.Properties.Name -contains 'securityLastRecord') { $lastRecord = [long]$cfg.securityLastRecord }

  $found = @()
  try {
    $filter = @{ LogName = 'Security'; Id = 4723, 4724; ErrorAction = 'SilentlyContinue' }
    if ($cursor) {
      try { $filter.StartTime = ([datetime]$cursor).AddMinutes(-1) } catch {}
    }
    $found = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -in 4723, 4724 -and $_.RecordId -gt $lastRecord } |
      Sort-Object TimeCreated)
  } catch {}

  foreach ($ev in $found) {
    $actor = Get-SecurityAccount $ev 'SubjectUserName'
    $actorDomain = Get-SecurityAccount $ev 'SubjectDomainName'
    $target = Get-SecurityAccount $ev 'TargetUserName'
    $targetDomain = Get-SecurityAccount $ev 'TargetDomainName'
    if (-not $actor) { $actor = 'unknown' }
    if ($target -match '\$$' -or $target -eq 'SYSTEM' -or $target -eq '') { continue }
    $actorFull = if ($actorDomain) { '{0}\{1}' -f $actorDomain, $actor } else { $actor }
    $targetFull = if ($targetDomain) { '{0}\{1}' -f $targetDomain, $target } else { $target }
    $isReset = ($ev.Id -eq 4724)
    $type = if ($isReset) { 'password_reset' } else { 'password_change' }
    $message = if ($isReset) {
      'Password reset on {0} by {1} (account: {2})' -f $env:COMPUTERNAME, $actorFull, $targetFull
    } else {
      'Password changed on {0} by {1} (account: {2})' -f $env:COMPUTERNAME, $actorFull, $targetFull
    }
    $detail = 'actor={0} target={1}' -f $actorFull, $targetFull
    $body = @{ token = $config.token; type = $type; message = $message; detail = $detail }
    try {
      Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $body | Out-Null
      Write-Log $message
    } catch {}
  }

  if ($found.Count -gt 0) {
    $last = $found[-1]
    $cfg | Add-Member -NotePropertyName securityCursor -NotePropertyValue $last.TimeCreated.ToString('o') -Force
    $cfg | Add-Member -NotePropertyName securityLastRecord -NotePropertyValue $last.RecordId -Force
    Save-Config $cfg
  }
}

function Remove-AutoLogon {
  $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $changed = $false
  try {
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if ($props.PSObject.Properties.Name -contains 'AutoAdminLogon' -and [string]$props.AutoAdminLogon -ne '0') {
      Set-ItemProperty -LiteralPath $key -Name 'AutoAdminLogon' -Value '0' -Type String -Force
      $changed = $true
    }
  } catch {}
  foreach ($name in @('DefaultUserName', 'DefaultPassword', 'DefaultDomainName', 'AltDefaultUserName', 'AltDefaultPassword', 'AltDefaultDomainName')) {
    try {
      $props = Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
      if ($props.PSObject.Properties.Name -contains $name) {
        Remove-ItemProperty -LiteralPath $key -Name $name -Force
        $changed = $true
      }
    } catch {}
  }
  return $changed
}

function Ensure-SharedAccount {
  param([string]$UserName, [string]$Password)
  try {
    if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
      New-LocalUser -Name $UserName -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires | Out-Null
      Write-Log ('Created shared local account {0}' -f $UserName)
    }
    Add-LocalGroupMember -Group 'Users' -Member $UserName -ErrorAction SilentlyContinue
    # Prevent the user from changing their own password
    try {
      net user $UserName /passwordchg:no 2>$null | Out-Null
    } catch {}
    return $true
  } catch {
    Write-Log ('Could not ensure shared account {0}: {1}' -f $UserName, $_.Exception.Message)
    return $false
  }
}

function Block-PasswordChangeUI {
  $gpoKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  try {
    if (-not (Test-Path -LiteralPath $gpoKey)) { New-Item -Path $gpoKey -Force | Out-Null }
    # Disable Ctrl+Alt+Del requirement entirely (no security screen at logon)
    Set-ItemProperty -LiteralPath $gpoKey -Name 'DisableCad' -Value 1 -Type DWord -Force
    # Hide "Change a password" from Ctrl+Alt+Del if it ever appears
    Set-ItemProperty -LiteralPath $gpoKey -Name 'DisableChangePassword' -Value 1 -Type DWord -Force
    # Hide "Switch user"
    Set-ItemProperty -LiteralPath $gpoKey -Name 'HideFastUserSwitching' -Value 1 -Type DWord -Force
    # Disable logon screen background image (faster boot to login form)
    Set-ItemProperty -LiteralPath $gpoKey -Name 'DisableLogonBackgroundImage' -Value 1 -Type DWord -Force
    Write-Log 'Disabled Ctrl+Alt+Del, password change, switch user, and login background.'
  } catch {
    Write-Log ('Could not block password change UI: {0}' -f $_.Exception.Message)
  }
  # Disable the Windows lock screen entirely
  $personalKey = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
  try {
    if (-not (Test-Path -LiteralPath $personalKey)) { New-Item -Path $personalKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $personalKey -Name 'NoLockScreen' -Value 1 -Type DWord -Force
  } catch {}
  $machineKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
  try {
    if (-not (Test-Path -LiteralPath $machineKey)) { New-Item -Path $machineKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $machineKey -Name 'NoLockScreen' -Value 1 -Type DWord -Force
  } catch {}
  # Skip the "Last interactive user" screen — go straight to login form
  try {
    if (-not (Test-Path -LiteralPath $winlogonKey)) { New-Item -Path $winlogonKey -Force | Out-Null }
    Set-ItemProperty -LiteralPath $winlogonKey -Name 'DisplayLastLogonInfo' -Value 0 -Type DWord -Force
  } catch {}
}

function Unblock-PasswordChangeUI {
  $gpoKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  try {
    if (Test-Path -LiteralPath $gpoKey) {
      Remove-ItemProperty -LiteralPath $gpoKey -Name 'DisableCad' -Force -ErrorAction SilentlyContinue
      Remove-ItemProperty -LiteralPath $gpoKey -Name 'DisableChangePassword' -Force -ErrorAction SilentlyContinue
      Remove-ItemProperty -LiteralPath $gpoKey -Name 'HideFastUserSwitching' -Force -ErrorAction SilentlyContinue
      Remove-ItemProperty -LiteralPath $gpoKey -Name 'DisableLogonBackgroundImage' -Force -ErrorAction SilentlyContinue
    }
  } catch {}
  try { Remove-ItemProperty -LiteralPath $winlogonKey -Name 'DisplayLastLogonInfo' -Force -ErrorAction SilentlyContinue } catch {}
  $personalKey = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
  try { Remove-ItemProperty -LiteralPath $personalKey -Name 'NoLockScreen' -Force -ErrorAction SilentlyContinue } catch {}
  $machineKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
  try { Remove-ItemProperty -LiteralPath $machineKey -Name 'NoLockScreen' -Force -ErrorAction SilentlyContinue } catch {}
}

function Set-SharedAutoLogon {
  param([string]$UserName, [string]$Password)
  $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $changed = $false
  try {
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    $currentAuto = if ($props.PSObject.Properties.Name -contains 'AutoAdminLogon') { [string]$props.AutoAdminLogon } else { '' }
    $currentUser = if ($props.PSObject.Properties.Name -contains 'DefaultUserName') { [string]$props.DefaultUserName } else { '' }
    $currentPass = if ($props.PSObject.Properties.Name -contains 'DefaultPassword') { [string]$props.DefaultPassword } else { '' }
    $currentDomain = if ($props.PSObject.Properties.Name -contains 'DefaultDomainName') { [string]$props.DefaultDomainName } else { '' }
    $targetDomain = $env:COMPUTERNAME
    if ($currentAuto -ne '1' -or $currentUser -ne $UserName -or $currentPass -ne $Password -or $currentDomain -ne $targetDomain) {
      Set-ItemProperty -LiteralPath $key -Name 'AutoAdminLogon' -Value '1' -Type String -Force
      Set-ItemProperty -LiteralPath $key -Name 'DefaultUserName' -Value $UserName -Type String -Force
      Set-ItemProperty -LiteralPath $key -Name 'DefaultPassword' -Value $Password -Type String -Force
      Set-ItemProperty -LiteralPath $key -Name 'DefaultDomainName' -Value $targetDomain -Type String -Force
      $changed = $true
    }
    # Windows 10/11: Windows Hello "passwordless sign-in" silently blocks
    # AutoAdminLogon on password-protected accounts. Force the build version
    # value to 0 so the account still auto-logs in and the login form shows.
    $pwLessKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
    $pwLessProps = Get-ItemProperty -LiteralPath $pwLessKey -ErrorAction SilentlyContinue
    $currentPwLess = if ($pwLessProps -and $pwLessProps.PSObject.Properties.Name -contains 'DevicePasswordLessBuildVersion') { [int]$pwLessProps.DevicePasswordLessBuildVersion } else { $null }
    if ($currentPwLess -ne 0) {
      if (-not (Test-Path -LiteralPath $pwLessKey)) { New-Item -Path $pwLessKey -Force | Out-Null }
      Set-ItemProperty -LiteralPath $pwLessKey -Name 'DevicePasswordLessBuildVersion' -Value 0 -Type DWord -Force
      $changed = $true
    }
  } catch {
    Write-Log ('Could not configure auto-login: {0}' -f $_.Exception.Message)
  }
  return $changed
}

function Apply-SigninMethod {
  # Enforces the lab's sign-in method: "login form instead of password"
  # auto-login when configured, otherwise it disables auto-login so the PC
  # always shows the Windows password page.
  $cfg = Get-Config
  if (-not $cfg) { return }
  $method = ''
  if ($cfg.PSObject.Properties.Name -contains 'signinMethod') { $method = [string]$cfg.signinMethod }
  $user = ''
  if ($cfg.PSObject.Properties.Name -contains 'sharedAccountUser') { $user = [string]$cfg.sharedAccountUser }
  $pass = ''
  if ($cfg.PSObject.Properties.Name -contains 'sharedAccountPassword') { $pass = [string]$cfg.sharedAccountPassword }
  if ($method -eq 'shared_account' -and $user -and $pass) {
    if (Ensure-SharedAccount -UserName $user -Password $pass) {
      $enabled = Set-SharedAutoLogon -UserName $user -Password $pass
      $cfg | Add-Member -NotePropertyName autoLogonCleaned -NotePropertyValue $false -Force
      Save-Config $cfg
      # Block password change UI so users only see the login form
      Block-PasswordChangeUI
      # The shared account auto-logs in at boot, so its ONLOGON task is what
      # brings the login form up directly instead of the Windows login page.
      Register-LogonGate -UserName $user | Out-Null
      if ($enabled) {
        $body = @{ token = $cfg.token; type = 'autologon'; message = 'Auto-login enabled on {0}' -f $env:COMPUTERNAME; detail = ('Auto-login set for {0}' -f $user) }
        try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $body | Out-Null } catch {}
        Write-Log ('Auto-login configured for {0}' -f $user)
      }
    }
  } else {
    Unblock-PasswordChangeUI
    $cleaned = Remove-AutoLogon
    $alreadyCleaned = ($cfg.PSObject.Properties.Name -contains 'autoLogonCleaned') -and $cfg.autoLogonCleaned
    if ($cleaned) {
      if (-not $alreadyCleaned) {
        $body = @{ token = $cfg.token; type = 'autologon'; message = 'Auto-login disabled on {0}' -f $env:COMPUTERNAME; detail = 'Removed AutoAdminLogon/Default* values from Winlogon' }
        try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $body | Out-Null } catch {}
        Write-Log 'Auto-login was enabled; disabled so the PC shows the login page.'
      }
      $cfg | Add-Member -NotePropertyName autoLogonCleaned -NotePropertyValue $true -Force
    } else {
      $cfg | Add-Member -NotePropertyName autoLogonCleaned -NotePropertyValue $false -Force
    }
    Save-Config $cfg
  }
}

function Execute-Action {
  param($Action)
  $actionName = $Action.action
  $payload = @{}
  if ($Action.payload) {
    try { $payload = ($Action.payload | ConvertFrom-Json) } catch {}
  }

  $result = $null
  $defer = $false
  try {
    switch ($actionName) {
      'lock' {
        & rundll32.exe user32.dll,LockWorkStation 2>$null
        $result = @{ success = $true; detail = 'Workstation locked; check-in will be required to use it again.' }
        break
      }
      'unlock' {
        Stop-CheckinGate
        $result = @{ success = $true; detail = 'Computer unlocked; check-in requirement cleared.' }
        break
      }
      'restart' {
        & shutdown.exe /r /t 30 /c "Lab Command Center: restart requested" /f 2>$null
        $result = @{ success = $true; detail = 'Restart scheduled in 30 seconds.' }
        break
      }
      'wake' {
        $result = @{ success = $true; detail = 'Wake-on-LAN is relayed by another online computer.' }
        break
      }
      'wol_relay' {
        try {
          $targetMac = [string]$payload.targetMac
          if (-not $targetMac) { $result = @{ success = $false; detail = 'Missing target MAC.' } ; break }
          $sent = Send-WakeOnLan -Mac $targetMac
          $result = @{ success = $true; detail = ('Wake packet for {0} sent on {1} interface(s).' -f $targetMac, $sent) }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      'send_message' {
        $msg = $Action.message
        if (-not $msg -and $payload.message) { $msg = $payload.message }
        if ($msg) { Show-Message $msg }
        $result = @{ success = $true; detail = 'Message displayed.' }
        break
      }
      'remote_view' {
        $result = Capture-Screenshot
        break
      }
      'remote_control' {
        $result = Enable-RemoteDesktop
        break
      }
      'disable_rdp' {
        $result = Disable-RemoteDesktop
        break
      }
      'remote_input' {
        $result = Send-RemoteInput $payload
        break
      }
      'block_usb' {
        Eject-RemovableDrives
        $result = @{ success = $true; detail = 'Removable drives ejected; policy recorded.' }
        break
      }
      'allow_usb' {
        $result = @{ success = $true; detail = 'USB allowed; policy recorded.' }
        break
      }
      'push_file' {
        $result = Receive-PushedFile $payload
        break
      }
      'delete_file' {
        $result = Remove-TargetFile $payload
        break
      }
      'list_files' {
        $target = ''
        if ($payload.path) { $target = [string]$payload.path }
        try {
          $listing = Get-DirListing -Path $target
          $body = @{ token = $config.token; path = $listing.path; entries = $listing.entries }
          Invoke-ApiJson -Method 'POST' -Path '/api/agent/files/list' -Body $body | Out-Null
          $result = @{ success = $true; detail = ('Listed {0} item(s) in {1}' -f @($listing.entries).Count, $listing.path) }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      'av_scan' {
        if ($payload.path) {
          $result = Invoke-SyncScan $payload
          break
        }
        if ($script:scanJob) {
          $result = @{ success = $false; detail = 'A scan is already running; wait for it to finish.' }
          break
        }
        $type = 'quick'
        if ($payload.type -eq 'full') { $type = 'full' }
        $script:scanJob = Start-ScanJob -Type $type
        $script:scanAction = $Action
        $script:avScanState = 'scanning'
        $defer = $true
        Write-Log ('{0} scan started.' -f $(if ($type -eq 'full') { 'Full' } else { 'Quick' }))
        break
      }
      'av_update' {
        try {
          Update-MpSignature -ErrorAction Stop | Out-Null
          $result = @{ success = $true; detail = 'Antivirus definitions updated.' }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      'av_toggle' {
        $enabled = $true
        if ($payload.enabled -is [bool]) { $enabled = $payload.enabled }
        try {
          Set-MpPreference -DisableRealtimeMonitoring (-not $enabled) -ErrorAction Stop
          $detail = if ($enabled) { 'Real-time protection enabled.' } else { 'Real-time protection disabled.' }
          $result = @{ success = $true; detail = $detail }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      'shutdown' {
        & shutdown.exe /s /t 0 /f 2>$null
        $result = @{ success = $true; detail = 'Shutdown initiated.' }
        break
      }
      'sleep' {
        & rundll32.exe powrprof.dll,SetSuspendState 0,1,0 2>$null
        $result = @{ success = $true; detail = 'Computer entering sleep mode.' }
        break
      }
      'fw_enable' {
        try {
          Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
          $result = @{ success = $true; detail = 'Windows Firewall enabled on all profiles.' }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      'fw_disable' {
        try {
          Set-NetFirewallProfile -All -Enabled False -ErrorAction Stop
          $result = @{ success = $true; detail = 'Windows Firewall disabled on all profiles.' }
        } catch {
          $result = @{ success = $false; detail = $_.Exception.Message }
        }
        break
      }
      default {
        $result = @{ success = $true; detail = ('Unknown action: {0}' -f $actionName) }
        break
      }
    }
  } catch {
    $result = @{ success = $false; detail = $_.Exception.Message }
  }

  if ($defer) { return }
  if (-not $result) { $result = @{ success = $false; detail = 'No result' } }

  $body = @{ token = $config.token; success = $result.success }
  if ($result.detail) { $body.detail = $result.detail }
  try {
    Invoke-ApiJson -Method 'POST' -Path ('/api/agent/actions/{0}/complete' -f $Action.id) -Body $body | Out-Null
  } catch {}
  if ($result.success) {
    Write-Log ('Action "{0}" completed{1}' -f $actionName, $(if ($result.detail) { ' - ' + $result.detail } else { '' }))
  } else {
    Write-Log ('Action "{0}" FAILED: {1}' -f $actionName, $result.detail)
  }
}

# ---------------------------------------------------------------------------
# Install mode: copy the script and register a SYSTEM boot task that covers
# every user (runs before anyone logs in).
# ---------------------------------------------------------------------------
if ($Install) {
  if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    throw 'Server URL is required with -Install: -Install -ServerUrl https://YOUR-APP.onrender.com'
  }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log 'Install requires an elevated PowerShell. Right-click PowerShell, choose "Run as administrator", then paste the command again.'
    exit 1
  }
  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
  Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $AgentPath -Force
  Ensure-CheckinScript
  $taskCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $AgentPath -ServerUrl $ServerUrl"
  # The scheduled task may already exist (re-install) or not (first install);
  # schtasks returns a non-zero exit code in both cases, which under
  # $ErrorActionPreference='Stop' would abort the install. Run them with
  # native-command errors suppressed and check the result explicitly.
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
    $createOutput = & schtasks.exe /Create /TN $TaskName /TR $taskCmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F 2>&1
    if ($LASTEXITCODE -ne 0) {
      $ErrorActionPreference = $prevEap
      Write-Log ("Could not register the scheduled task: {0}" -f (($createOutput | Out-String).Trim()))
      exit 1
    }
    & schtasks.exe /Run /TN $TaskName 2>$null | Out-Null

    # Logon launcher: brings up the sign-in gate as soon as a user logs on so
    # it appears at PC startup without waiting for the next agent pass. It is
    # registered for the user running the install; once the sign-in method is
    # "login form instead of password", Apply-SigninMethod re-registers it for
    # the shared auto-login account so the gate is the first thing at boot.
    Ensure-GateLauncher
    $who = (whoami 2>$null)
    if ($who) { Register-LogonGate -UserName $who | Out-Null }
  } finally {
    $ErrorActionPreference = $prevEap
  }
  Write-Log 'Installed as a SYSTEM boot task. The agent covers all users and starts before anyone logs in.'
  exit 0
}

# ---------------------------------------------------------------------------
# Storage migration (pre-1.20.0 -> LvOsSec)
# ---------------------------------------------------------------------------
# Must run before the single-instance guard, which reads the lock file out of
# $ConfigDir, and before Get-Config, which reads the token. On an already-current
# machine both of those directories are the same one, so this is a no-op.
Invoke-StorageMigration

# ---------------------------------------------------------------------------
# Single-instance guard
# ---------------------------------------------------------------------------
# The lock holds the PID of the last agent process. If that process was killed
# without cleaning up, the PID can later be reused by an unrelated process
# (e.g. svchost), so only treat it as a running instance when the process is
# actually executing lab-agent.ps1. Otherwise clear the stale lock.
$existingPid = Get-Content -LiteralPath $LockPath -ErrorAction SilentlyContinue
$anotherRunning = $false
if ($existingPid -match '^\d+$') {
  try {
    $lockProc = Get-CimInstance Win32_Process -Filter "ProcessId = $existingPid" -ErrorAction Stop
    if ($lockProc -and $lockProc.Name -match '^(powershell|pwsh)\.exe$' -and $lockProc.CommandLine -match 'lab-agent\.ps1') { $anotherRunning = $true }
  } catch {}
}
if ($anotherRunning) {
  Write-Log ('Another instance is running (PID {0}). Exiting.' -f $existingPid)
  exit 0
}
if ($existingPid) {
  Write-Log ('Clearing stale agent lock (PID {0}).' -f $existingPid)
  Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
Set-Content -LiteralPath $LockPath -Value $PID -Encoding UTF8 -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Load or create configuration
# ---------------------------------------------------------------------------
$config = Get-Config
if (-not $config) {
  $config = Register-Agent
  Write-Log ('Registered as {0} (computer id {1}).' -f $config.name, $config.computerId)
}
$ServerUrl = $config.serverUrl
$script:seenUsb = @()

Write-Log ('Agent v{0} running for {1} -> {2}' -f $script:AgentVersion, $config.name, $ServerUrl)

# ---------------------------------------------------------------------------
# WebSocket listener for instant action dispatch (background runspace).
# The server can push actions to the agent over WS instead of waiting for the
# next heartbeat cycle.  Results are sent back over WS *and* via the normal
# HTTP complete endpoint so the audit trail is always up to date.
# ---------------------------------------------------------------------------
$script:WsConnected = $false
$script:WsActionQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()

function Start-WsListener {
  $wsBase = ($ServerUrl -replace '^http', 'ws') + '/ws/tunnel'
  $tokenEnc = [System.Uri]::EscapeDataString($config.token)
  $compId = [long]$config.computerId

  $ps = [powershell]::Create()
  $ps.Runspace = [runspacefactory]::CreateRunspace()
  $ps.Runspace.Open()
  $ps.Runspace.SessionStateProxy.SetVariable('wsBase', $wsBase)
  $ps.Runspace.SessionStateProxy.SetVariable('tokenEnc', $tokenEnc)
  $ps.Runspace.SessionStateProxy.SetVariable('compId', $compId)
  $ps.Runspace.SessionStateProxy.SetVariable('WsActionQueue', $script:WsActionQueue)

  [void]$ps.AddScript({
    $reconnectDelay = 2
    while ($true) {
      $ws = $null
      try {
        $ws = [System.Net.WebSockets.ClientWebSocket]::new()
        $uri = [System.Uri]::new('{0}?role=agent&token={1}' -f $wsBase, $tokenEnc)
        $cts = [System.Threading.CancellationTokenSource]::new()
        $ws.ConnectAsync($uri, $cts.Token).GetAwaiter().GetResult()

        $hello = [System.Text.Encoding]::UTF8.GetBytes('{"type":"hello","computerId":' + $compId + '}')
        $null = $ws.SendAsync([System.ArraySegment[byte]]::new($hello), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).GetAwaiter().GetResult()

        $script:WsConnected = $true
        $reconnectDelay = 2

        $buf = New-Object byte[] 65536
        while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
          $result = $ws.ReceiveAsync([System.ArraySegment[byte]]::new($buf), $cts.Token).GetAwaiter().GetResult()
          if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { break }
          if ($result.Count -gt 0) {
            $json = [System.Text.Encoding]::UTF8.GetString($buf, 0, $result.Count)
            try {
              $msg = $json | ConvertFrom-Json
              if ($msg.type -eq 'action' -and $msg.actionId) {
                $WsActionQueue.Enqueue(@{
                  actionId = [long]$msg.actionId
                  action   = [string]$msg.action
                  message  = [string]$msg.message
                  payload  = [string]$msg.payload
                })
              }
            } catch {}
          }
        }
      } catch {}
      $script:WsConnected = $false
      try { if ($ws -and $ws.State -ne 'Closed') { $ws.Dispose() } } catch {}
      Start-Sleep -Seconds $reconnectDelay
      if ($reconnectDelay -lt 30) { $reconnectDelay = [Math]::Min($reconnectDelay * 2, 30) }
    }
  })
  $ps.BeginInvoke()
}

Start-WsListener

# Boot-time tasks: enable security auditing and apply the lab sign-in method.
Ensure-AuditPolicy
$script:lastAuditCheck = Get-Date
Apply-SigninMethod

try {
  while ($true) {
    try {
      Poll-ScanJob

      # ---- drain WS instant-action queue ------------------------------------
      while ($true) {
        $wsAction = $null
        if (-not $script:WsActionQueue.TryDequeue([ref]$wsAction)) { break }
        $actObj = @{
          id      = $wsAction.actionId
          action  = $wsAction.action
          message = $wsAction.message
          payload = $wsAction.payload
        }
        Execute-Action $actObj
      }

      $osDriveName = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd(':') } else { $null }
      $osDrive = if ($osDriveName) { Get-PSDrive -Name $osDriveName -ErrorAction SilentlyContinue } else { $null }

      $user = Get-CurrentUser
      $av = Get-AvStatus
      $fw = Get-FirewallStatus
      Get-SecuritySignals | Out-Null

      $hbBody = @{
        token = $config.token
        userName = $user
        os = $config.os
        agentVersion = $script:AgentVersion
        macAddress = Get-LocalMacAddress
        ipAddress = Get-LocalIpAddress
        security = $script:SecuritySignalsCache
      }
      $hw = Get-HardwareFingerprint
      if ($hw.manufacturer) { $hbBody.manufacturer = $hw.manufacturer }
      if ($hw.model) { $hbBody.model = $hw.model }
      if ($hw.serialNumber) { $hbBody.serialNumber = $hw.serialNumber }
      if ($hw.biosSerial) { $hbBody.biosSerial = $hw.biosSerial }
      if ($hw.systemUUID) { $hbBody.systemUUID = $hw.systemUUID }
      if ($hw.totalRAM) { $hbBody.totalRAM = $hw.totalRAM }
      if ($hw.cpuName) { $hbBody.cpuName = $hw.cpuName }
      if ($hw.cpuCores) { $hbBody.cpuCores = $hw.cpuCores }
      if ($osDrive -and $null -ne $osDrive.Free) {
        $hbBody.diskFree = [long]$osDrive.Free
        $hbBody.diskTotal = [long]($osDrive.Used + $osDrive.Free)
      }
      if ($null -ne $av.enabled) { $hbBody.avEnabled = $av.enabled }
      if ($av.signature) { $hbBody.avSignature = $av.signature }
      if ($av.lastScan) { $hbBody.avLastScanAt = $av.lastScan }
      if ($av.scanState) { $hbBody.avScanState = $av.scanState }
      if ($null -ne $fw.enabled) { $hbBody.firewallEnabled = $fw.enabled }
      if ($fw.profiles) { $hbBody.firewallProfiles = $fw.profiles }

      $hb = Invoke-ApiJson -Method 'POST' -Path '/api/agent/heartbeat' -Body $hbBody

      if ($hb.pendingActions) {
        foreach ($action in $hb.pendingActions) {
          Execute-Action $action
        }
      }

      # ---- agent self-update ----------------------------------------------
      # The server advertises the agent version bundled with its build; when it
      # is newer than the version this copy reports, download and replace
      # ourselves in place so no reinstall is ever needed again.
      if ($hb.agentUpdateRequested -and $hb.latestAgentVersion) {
        Update-Self -LatestVersion ([string]$hb.latestAgentVersion)
      }

      # ---- sign-in method (auto-login) --------------------------------------
      $cfgNow = Get-Config
      if ($cfgNow -and $null -ne $hb.computer.signinMethod) {
        $cfgNow | Add-Member -NotePropertyName signinMethod -NotePropertyValue ([string]$hb.computer.signinMethod) -Force
        $cfgNow | Add-Member -NotePropertyName sharedAccountUser -NotePropertyValue ([string]$hb.computer.sharedAccountUser) -Force
        $cfgNow | Add-Member -NotePropertyName sharedAccountPassword -NotePropertyValue ([string]$hb.computer.sharedAccountPassword) -Force
        Save-Config $cfgNow
      }
      Apply-SigninMethod

      # ---- Windows admin account + download/install block policy ------------
      $cfgNow = Get-Config
      if ($cfgNow) {
        $didSave = $false
        if ($null -ne $hb.computer.adminWindowsUser) {
          $cfgNow | Add-Member -NotePropertyName adminWindowsUser -NotePropertyValue ([string]$hb.computer.adminWindowsUser) -Force
          $didSave = $true
        }
        if ($null -ne $hb.computer.blockDownloads) {
          $cfgNow | Add-Member -NotePropertyName blockDownloads -NotePropertyValue ([bool]$hb.computer.blockDownloads) -Force
          $didSave = $true
        }
        if ($didSave) { Save-Config $cfgNow }
      }
      $cfgNow = Get-Config
      $blockDownloads = $false
      if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'blockDownloads') { $blockDownloads = [bool]$cfgNow.blockDownloads }
      if ($null -eq $script:blockDownloadsApplied -or $script:blockDownloadsApplied -ne $blockDownloads) {
        Set-DownloadBlock -Enabled $blockDownloads
        $script:blockDownloadsApplied = $blockDownloads
      }

      # ---- check-in gate -----------------------------------------------------
      Update-CheckinGate -Hb $hb

      # ---- sync check-ins saved while offline -------------------------------
      Sync-PendingCheckins

      # ---- live remote view -----------------------------------------------
      $script:remoteViewActive = $false
      if ($hb -and $hb.computer -and $hb.computer.remoteViewActive) {
        $script:remoteViewActive = [bool]$hb.computer.remoteViewActive
      }
      if ($script:remoteViewActive) {
        $streamUser = Get-CurrentUser
        $streamUserOk = ($streamUser -and -not ($streamUser -match '(?i)^nt authority\\') -and $streamUser -notmatch '\$$')
        if ($streamUserOk) {
          Upload-Frame | Out-Null
        }
      } else {
        Stop-CaptureLoop
      }

      # ---- USB handling ---------------------------------------------------
      $restrictive = ($hb.computer.usbState -eq 'blocked') -or ($hb.computer.usbState -eq 'review')
      $approvedIds = @()
      if ($hb.allowedDeviceIds) { $approvedIds = @($hb.allowedDeviceIds) }

      # Re-enable devices the administrator has approved
      $cfgNow = Get-Config
      $blockedDevices = @()
      if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'blockedUsbDevices') { $blockedDevices = @($cfgNow.blockedUsbDevices) }
      if ($blockedDevices.Count -gt 0) {
        $remaining = @()
        foreach ($entry in $blockedDevices) {
          $instanceId = [string]$entry.instanceId
          if ($instanceId -and ($approvedIds -contains $instanceId)) {
            Enable-UsbDevice -InstanceId $instanceId
            Write-Log ('USB device approved and re-enabled: {0}' -f $instanceId)
          } else {
            $remaining += $entry
          }
        }
        if ($cfgNow) {
          $cfgNow | Add-Member -NotePropertyName blockedUsbDevices -NotePropertyValue @($remaining) -Force
          Save-Config $cfgNow
        }
      }

      $drives = Get-RemovableDrives
      $currentKeys = @()
      foreach ($drive in $drives) {
        $key = Get-UsbKey $drive
        $currentKeys += $key
        if ($script:seenUsb -notcontains $key) {
          $script:seenUsb += $key
          $allowedByLetter = $hb.allowedUsb -and ($hb.allowedUsb -contains $drive.Letter)
          $detail = 'Drive {0}: {1} serial={2}' -f $drive.Letter, $drive.Label, $drive.Serial
          $scanNote = ''
          try {
            $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($mp -and ($mp.AntivirusEnabled -eq $true)) {
              Start-MpScan -ScanPath ('{0}:\' -f $drive.Letter) -ScanType QuickScan -ErrorAction SilentlyContinue | Out-Null
              $scanNote = ' Defender scan completed.'
            }
          } catch {}
          if ($restrictive -and -not $allowedByLetter) {
            $instanceId = Get-DriveInstanceId -Letter $drive.Letter
            if ($instanceId) {
              Block-UsbDevice -InstanceId $instanceId
              $cfgNow = Get-Config
              $existing = @()
              if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'blockedUsbDevices') { $existing = @($cfgNow.blockedUsbDevices) }
              $existing += [PSCustomObject]@{ instanceId = $instanceId; key = $key; letter = $drive.Letter }
              if ($cfgNow) {
                $cfgNow | Add-Member -NotePropertyName blockedUsbDevices -NotePropertyValue @($existing) -Force
                Save-Config $cfgNow
              }
              $detail += ' instanceId={0} (blocked, awaiting approval)' -f $instanceId
              Show-Message ('USB drive {0}: ({1}) was detected and is blocked. An administrator must approve it before it can be used.' -f $drive.Letter, $drive.Label)
              Write-Log ('USB drive blocked: {0}' -f $detail)
            } else {
              try {
                $shell = New-Object -ComObject Shell.Application
                $item = $shell.Namespace(17).ParseName(('{0}:' -f $drive.Letter))
                if ($item) { $item.InvokeVerb('Eject') }
              } catch {}
              $detail += ' (ejected, awaiting approval)'
              Show-Message ('USB drive {0}: ({1}) was detected and was not allowed to start. An administrator must approve it before it can be used.' -f $drive.Letter, $drive.Label)
            }
          }
          $eventBody = @{ token = $config.token; type = 'usb_connected'; detail = $detail; message = $scanNote }
          try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $eventBody | Out-Null } catch {}
          Write-Log ('USB device detected: {0}' -f $detail)
        }
      }
      $script:seenUsb = @($script:seenUsb | Where-Object { $currentKeys -contains $_ })

      # Phones / portable devices (no drive letter): block usage when restrictive
      foreach ($phone in (Get-PhoneDevices)) {
        $key = ('instanceId={0}' -f $phone.InstanceId)
        if ($script:seenUsb -notcontains $key) {
          $script:seenUsb += $key
          if ($restrictive -and ($approvedIds -notcontains $phone.InstanceId)) {
            Block-UsbDevice -InstanceId $phone.InstanceId
            $cfgNow = Get-Config
            $existing = @()
            if ($cfgNow -and $cfgNow.PSObject.Properties.Name -contains 'blockedUsbDevices') { $existing = @($cfgNow.blockedUsbDevices) }
            $existing += [PSCustomObject]@{ instanceId = $phone.InstanceId; key = $key; letter = '' }
            if ($cfgNow) {
              $cfgNow | Add-Member -NotePropertyName blockedUsbDevices -NotePropertyValue @($existing) -Force
              Save-Config $cfgNow
            }
            Write-Log ('Portable device blocked: {0}' -f $phone.Name)
          }
          $detail = 'Portable device: {0} instanceId={1}' -f $phone.Name, $phone.InstanceId
          if ($restrictive -and ($approvedIds -notcontains $phone.InstanceId)) { $detail += ' (blocked, awaiting approval)' }
          $eventBody = @{ token = $config.token; type = 'usb_connected'; detail = $detail; message = '' }
          try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/events' -Body $eventBody | Out-Null } catch {}
        }
      }

      # Eject any remaining unapproved removable drives
      if ($restrictive) {
        foreach ($drive in $drives) {
          if ($hb.allowedUsb -and ($hb.allowedUsb -contains $drive.Letter)) { continue }
          try {
            $shell = New-Object -ComObject Shell.Application
            $item = $shell.Namespace(17).ParseName(('{0}:' -f $drive.Letter))
            if ($item) { $item.InvokeVerb('Eject') }
            Write-Log ('Ejected unapproved USB drive {0}:' -f $drive.Letter)
          } catch {}
        }
      }

      # ---- idle auto-logout -------------------------------------------------
      $isSystemUser = ($user -match '(?i)^nt authority\\') -or ($user -match '\$$')
      if ($hb.idleLogoutMinutes -and ([int]$hb.idleLogoutMinutes) -gt 0 -and $user -and -not $isSystemUser) {
        $idleSeconds = Get-IdleSeconds
        if ($idleSeconds -ge ([int]$hb.idleLogoutMinutes) * 60) {
          Write-Log ('Idle {0}s exceeds limit of {1} min. Logging off {2}.' -f $idleSeconds, $hb.idleLogoutMinutes, $user)
          Show-Message 'Lab Command Center: this computer was idle too long and will now log off.'
          Invoke-Interactive -FilePath 'logoff.exe'
        }
      }

      # ---- peripherals ------------------------------------------------------
      $peripherals = @(Get-Peripherals)
      if ($peripherals.Count -gt 0) {
        $pBody = @{ token = $config.token; user = $user }
        $pBody.devices = @()
        foreach ($dev in $peripherals) {
          $pBody.devices += @{ kind = $dev.kind; name = $dev.name; instanceId = $dev.instanceId; serial = $dev.serial; present = $dev.present }
        }
        try { Invoke-ApiJson -Method 'POST' -Path '/api/agent/peripherals' -Body $pBody | Out-Null } catch {}
      }

      $baseline = @($config.baselinePeripherals)
      if ($baseline.Count -eq 0) {
        $present = @($peripherals | Where-Object { $_.present } | ForEach-Object { $_.instanceId })
        if ($present.Count -gt 0) {
          Save-Baseline $present
          $baseline = $present
          Write-Log ('Peripheral baseline captured: {0} device(s).' -f $present.Count)
        }
      }

      $missing = @()
      if ($baseline.Count -gt 0) {
        foreach ($instanceId in $baseline) {
          $dev = $peripherals | Where-Object { $_.instanceId -eq $instanceId }
          if (-not $dev -or -not $dev.present) {
            $name = if ($dev) { $dev.name } else { $instanceId }
            $missing += $name
          }
        }
      }

      if ($missing.Count -gt 0) {
        $missingKey = ($missing | Sort-Object) -join '|'
        if (-not $script:warningActive -or $script:lastWarningKey -ne $missingKey) {
          Stop-PeripheralWarning
          Show-PeripheralWarning -Devices $missing
          $script:lastWarningKey = $missingKey
          Write-Log ('Peripheral warning shown for: {0}' -f ($missing -join ', '))
        }
      } else {
        Stop-PeripheralWarning
      }

      # ---- password change/reset monitoring ----------------------------------
      if (-not $script:lastAuditCheck -or ((Get-Date) - $script:lastAuditCheck).TotalMinutes -ge 10) {
        Ensure-AuditPolicy
        $script:lastAuditCheck = Get-Date
      }
      Read-PasswordEvents
    } catch {
      $statusCode = 0
      if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
      if ($statusCode -eq 401) {
        Write-Log 'Agent token rejected. Re-registering...'
        Remove-Item -LiteralPath $ConfigPath -Force -ErrorAction SilentlyContinue
        $config = Register-Agent
        $ServerUrl = $config.serverUrl
      } else {
        Write-Log ('Heartbeat failed: {0}' -f $_.Exception.Message)
      }
      # Keep the sign-in gate working while offline (uses the last known
      # check-in requirement cached locally).
      Update-CheckinGate -Hb $null
    }

    if ($script:remoteViewActive) {
      Start-Sleep -Milliseconds 300
    } else {
      Start-Sleep -Seconds $IntervalSeconds
    }
  }
} finally {
  Stop-Taskbar
  Stop-PeripheralWarning
  Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
}
