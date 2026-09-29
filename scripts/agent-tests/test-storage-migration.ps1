#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Verifies the 1.20.0 agent storage migration: ProgramData\LabCommandCenter ->
  ProgramData\LvOsSec.

.DESCRIPTION
  A machine that loses its config.json comes up as a brand new computer with no
  history, so the migration is the one piece of the rename that can cause
  visible damage. This test builds a fake legacy install, runs the real
  Invoke-StorageMigration out of the shipped agent script, and asserts the
  machine stays authenticated, keeps its identity, and re-points its scheduled
  tasks.

  It also asserts the failure path: if the move cannot complete, the agent falls
  back to the legacy directory and task names rather than coming up with no
  config at all.

  Only the storage half of the agent is exercised -- the rest of it needs
  Windows, Postgres and a running server. The functions are pulled from the real
  script via the AST, so this tests shipped code rather than a copy of it.

.EXAMPLE
  pwsh -File scripts/agent-tests/test-storage-migration.ps1
#>

$ErrorActionPreference = 'Stop'

$agent = Join-Path $PSScriptRoot '../../artifacts/api-server/src/assets/lab-agent.ps1'
if (-not (Test-Path -LiteralPath $agent)) { throw "agent script not found at $agent" }
$src = Get-Content -LiteralPath $agent -Raw

$script:pass = 0
$script:fail = 0
function Check($name, $cond, $detail) {
  if ($cond) { $script:pass++; Write-Output ("  PASS  {0}" -f $name) }
  else { $script:fail++; Write-Output ("  FAIL  {0}  <- {1}" -f $name, $detail) }
}

# Pull the real functions out of the agent via the AST.
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ('agent failed to parse: ' + $errors[0].Message) }

$wanted = @('Write-Log', 'Set-LegacyStorage', 'Invoke-StorageMigration')
$found = @()
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($wanted -contains $fn.Name) { Invoke-Expression $fn.Extent.Text; $found += $fn.Name }
}
foreach ($name in $wanted) {
  if ($found -notcontains $name) { throw "function $name not found in the agent script" }
}

# Stub schtasks: the test records intent instead of touching the task scheduler.
$script:schtasksCalls = New-Object System.Collections.Generic.List[string]
function schtasks.exe {
  param([Parameter(ValueFromRemainingArguments = $true)]$Rest)
  $script:schtasksCalls.Add(($Rest -join ' '))
  $global:LASTEXITCODE = 0
  return ''
}

function New-FakeMachine {
  param([string]$ConfigJson)
  $root = Join-Path ([System.IO.Path]::GetTempPath()) ('lvosec-mig-' + [guid]::NewGuid().ToString('N'))
  $programData = Join-Path $root 'ProgramData'
  $legacyDir = Join-Path $programData 'LabCommandCenter'
  New-Item -ItemType Directory -Force -Path (Join-Path $legacyDir 'pending') | Out-Null
  Set-Content -LiteralPath (Join-Path $legacyDir 'config.json') -Value $ConfigJson -Encoding UTF8
  Set-Content -LiteralPath (Join-Path $legacyDir 'lab-agent.ps1') -Value '# legacy 1.19.0 body' -Encoding UTF8
  Set-Content -LiteralPath (Join-Path $legacyDir 'pending\checkins.json') -Value '{}' -Encoding UTF8
  # A stale lock: exactly the file the migration must run before touching.
  Set-Content -LiteralPath (Join-Path $legacyDir 'agent.lock') -Value '12345' -Encoding UTF8
  return @{ root = $root; programData = $programData; legacyDir = $legacyDir }
}

function Set-NewLayoutVars {
  param([string]$ProgramData)
  $script:ConfigDir = Join-Path $ProgramData 'LvOsSec'
  $script:ConfigPath = Join-Path $script:ConfigDir 'config.json'
  $script:PendingPath = Join-Path $script:ConfigDir 'pending\checkins.json'
  $script:AgentPath = Join-Path $script:ConfigDir 'lab-agent.ps1'
  $script:LockPath = Join-Path $script:ConfigDir 'agent.lock'
  $script:TaskName = 'LVOSEC Agent'
  $script:LogonTaskName = 'LVOSEC Logon'
  $script:CheckinScriptPath = Join-Path $script:ConfigDir 'checkin-gate.ps1'
  $script:GateLauncherPath = Join-Path $script:ConfigDir 'gate-launcher.ps1'
  $script:logonGateRegisteredFor = ''
}

$ServerUrl = 'https://example.onrender.com'

# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- legacy machine, clean migration ---'
$m = New-FakeMachine -ConfigJson (@{ token = 'legacy-secret-token'; computerId = 42 } | ConvertTo-Json -Compress)
$env:ProgramData = $m.programData
$script:LegacyConfigDir = $m.legacyDir
$script:LegacyConfigPath = Join-Path $m.legacyDir 'config.json'
$script:LegacyTaskName = 'LabCommandCenter Agent'
$script:LegacyLogonTaskName = 'LabCommandCenter Logon'
Set-NewLayoutVars -ProgramData $m.programData

Invoke-StorageMigration

$after = Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json
Check 'token carried across (machine stays authenticated)' ($after.token -eq 'legacy-secret-token') "config at $script:ConfigPath"
Check 'computerId carried across (no re-registration as a new PC)' ($after.computerId -eq 42) 'computerId lost'
Check 'agent script present for future self-updates' (Test-Path -LiteralPath $script:AgentPath) 'no lab-agent.ps1'
Check 'queued checkins carried across' (Test-Path -LiteralPath $script:PendingPath) 'no pending/checkins.json'
Check 'new boot task registered' (($script:schtasksCalls | Where-Object { $_ -match '/Create' -and $_ -match 'LVOSEC Agent' }).Count -eq 1) ($script:schtasksCalls -join ' | ')
Check 'boot task points at the NEW path' (($script:schtasksCalls | Where-Object { $_ -match '/Create' }) -join ' ' -match [regex]::Escape((Join-Path $m.programData 'LvOsSec'))) 'task still references the old directory'
Check 'legacy boot task removed' (($script:schtasksCalls | Where-Object { $_ -match '/Delete' -and $_ -match 'LabCommandCenter Agent' }).Count -eq 1) 'legacy boot task not deleted'
Check 'legacy logon task removed' (($script:schtasksCalls | Where-Object { $_ -match '/Delete' -and $_ -match 'LabCommandCenter Logon' }).Count -eq 1) 'legacy logon task not deleted'
Check 'legacy directory retired, not deleted' (Test-Path -LiteralPath ($m.legacyDir + '.migrated')) 'old directory neither renamed nor left alone'

Write-Output ''
Write-Output '--- rerun is a no-op ---'
$before = $script:schtasksCalls.Count
Invoke-StorageMigration
Check 'second run touches no tasks' ($script:schtasksCalls.Count -eq $before) ("extra calls: " + (($script:schtasksCalls[$before..($script:schtasksCalls.Count - 1)]) -join ' | '))
Check 'second run leaves the token alone' ((Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json).token -eq 'legacy-secret-token') 'token changed on rerun'

Write-Output ''
Write-Output '--- migration fails -> falls back to legacy, machine stays up ---'
$m2 = New-FakeMachine -ConfigJson 'not json at all'
$env:ProgramData = $m2.programData
$script:LegacyConfigDir = $m2.legacyDir
$script:LegacyConfigPath = Join-Path $m2.legacyDir 'config.json'
$script:LegacyTaskName = 'LabCommandCenter Agent'
$script:LegacyLogonTaskName = 'LabCommandCenter Logon'
Set-NewLayoutVars -ProgramData $m2.programData
Invoke-StorageMigration
Check 'falls back to the legacy directory' ($ConfigDir -eq $m2.legacyDir) "ConfigDir is $ConfigDir"
Check 'falls back to the legacy boot task name' ($TaskName -eq 'LabCommandCenter Agent') "TaskName is $TaskName"
Check 'agent still has a readable config' (Test-Path -LiteralPath $ConfigPath) 'no config at the fallback path'
Check 'legacy directory left intact' (Test-Path -LiteralPath $m2.legacyDir) 'legacy directory was destroyed on failure'

Write-Output ''
Write-Output '--- fresh machine (no legacy directory) ---'
$root3 = Join-Path ([System.IO.Path]::GetTempPath()) ('lvosec-mig-' + [guid]::NewGuid().ToString('N'))
$programData3 = Join-Path $root3 'ProgramData'
New-Item -ItemType Directory -Force -Path $programData3 | Out-Null
$env:ProgramData = $programData3
$script:LegacyConfigDir = Join-Path $programData3 'LabCommandCenter'
$script:LegacyConfigPath = Join-Path $script:LegacyConfigDir 'config.json'
$script:LegacyTaskName = 'LabCommandCenter Agent'
$script:LegacyLogonTaskName = 'LabCommandCenter Logon'
Set-NewLayoutVars -ProgramData $programData3
$before3 = $script:schtasksCalls.Count
Invoke-StorageMigration
Check 'no legacy dir -> no task churn' ($script:schtasksCalls.Count -eq $before3) 'fresh install should be a no-op'
Check 'stays on the new layout' ($ConfigDir -eq (Join-Path $programData3 'LvOsSec')) "ConfigDir is $ConfigDir"

Remove-Item -Recurse -Force $m.root, $m2.root, $root3 -ErrorAction SilentlyContinue

Write-Output ''
Write-Output ("storage migration: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
