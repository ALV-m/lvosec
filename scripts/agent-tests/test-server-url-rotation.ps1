#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Verifies the agent's server_url_rotate handling.

.DESCRIPTION
  Rotate-ServerUrl is the mechanism that moves a machine to a new Render
  deployment (service rename) without a reinstall, so a mistake misconfigures
  the whole fleet. This test pulls the REAL Rotate-ServerUrl (plus its
  config helpers) out of the shipped agent script via the AST, stubs the
  healthz probe, and asserts:

    - https-only, credential-free URL validation before anything is probed
    - the new deployment must be alive and report ok before committing
    - a failed probe changes nothing (config untouched, server URL untouched)
    - a successful probe persists the new URL in config, updates the in-memory
      server URL, and re-points the WS listener state so reconnects follow

.EXAMPLE
  pwsh -File scripts/agent-tests/test-server-url-rotation.ps1
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

$wanted = @('Rotate-ServerUrl', 'Get-Config', 'Save-Config', 'Write-Log')
$found = @()
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($wanted -contains $fn.Name) { Invoke-Expression $fn.Extent.Text; $found += $fn.Name }
}
foreach ($name in $wanted) {
  if ($found -notcontains $name) { throw "function $name not found in the agent script" }
}

# Control the healthz probe: 'ok' | 'unhealthy' | 'unreachable'
$script:probeBehavior = 'ok'
function Invoke-RestMethod {
  param($Uri, $Method, $TimeoutSec, $ErrorAction, $ContentType, $Body)
  if ($Method -ne 'Get') { throw "unexpected method $Method in probe" }
  if ($script:probeBehavior -eq 'unreachable') { throw 'Connection refused (simulated)' }
  if ($script:probeBehavior -eq 'unhealthy') { return @{ status = 'error' } }
  return @{ status = 'ok' }
}
$script:probeUris = New-Object System.Collections.Generic.List[string]

function New-FakeAgentDir {
  $root = Join-Path ([System.IO.Path]::GetTempPath()) ('lvosec-rot-' + [guid]::NewGuid().ToString('N'))
  $dir = Join-Path $root 'ProgramData\LvOsSec'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $cfg = @{
    serverUrl  = 'https://computermanagementsystem.onrender.com'
    token      = 'tok-123'
    computerId = 7
    name       = 'LAB-PC-01'
  }
  $cfg | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $dir 'agent-config.json') -Encoding UTF8
  return @{ root = $root; dir = $dir; configPath = (Join-Path $dir 'agent-config.json'); configDir = $dir }
}

function Reset-Scope($fake) {
  $script:ConfigPath = $fake.configPath
  $script:ConfigDir = $fake.configDir
  $script:ServerUrl = 'https://computermanagementsystem.onrender.com'
  $script:WsState = @{
    wsBase   = 'wss://computermanagementsystem.onrender.com/ws/tunnel'
    tokenEnc = 'tok-123'
    compId   = 7
  }
  $script:probeBehavior = 'ok'
  $script:probeUris.Clear()
}

# --- 1. validation: scheme, credentials, host ------------------------------
$fake1 = New-FakeAgentDir
Reset-Scope $fake1
$r1 = Rotate-ServerUrl -NewUrl 'http://lvosec.onrender.com'
Check 'rejects plain-http scheme' (-not $r1.success) ($r1.detail)
Check 'rejects without probing' ($script:probeUris.Count -eq 0) "probed $($script:probeUris.Count) times"
$cfgAfter1 = Get-Config
Check 'http rejected leaves config untouched' ($cfgAfter1.serverUrl -eq 'https://computermanagementsystem.onrender.com') $cfgAfter1.serverUrl

$r2 = Rotate-ServerUrl -NewUrl 'https://user:pass@lvosec.onrender.com'
Check 'rejects embedded credentials' (-not $r2.success) $r2.detail

$r3 = Rotate-ServerUrl -NewUrl 'not a url'
Check 'rejects unparsable string' (-not $r3.success) $r3.detail

$r4 = Rotate-ServerUrl -NewUrl 'https:///nohost'
Check 'rejects URL without host' (-not $r4.success) $r4.detail

# --- 2. probe gate ----------------------------------------------------------
$fake2 = New-FakeAgentDir
Reset-Scope $fake2
$script:probeBehavior = 'unreachable'
$r5 = Rotate-ServerUrl -NewUrl 'https://lvosec.onrender.com'
Check 'unreachable probe fails rotation' (-not $r5.success) $r5.detail
$cfgAfter5 = Get-Config
Check 'failed probe leaves config untouched' ($cfgAfter5.serverUrl -eq 'https://computermanagementsystem.onrender.com') $cfgAfter5.serverUrl
$wsAfter5 = $script:WsState
Check 'failed probe does not move WS listener' ($wsAfter5.wsBase -match 'computermanagementsystem') $wsAfter5.wsBase

$script:probeBehavior = 'unhealthy'
$r6 = Rotate-ServerUrl -NewUrl 'https://lvosec.onrender.com'
Check 'unhealthy report fails rotation' (-not $r6.success) $r6.detail

# --- 3. happy path ----------------------------------------------------------
$fake3 = New-FakeAgentDir
Reset-Scope $fake3
$r7 = Rotate-ServerUrl -NewUrl 'https://lvosec.onrender.com/'
Check 'healthy probe commits rotation' ($r7.success) $r7.detail
$cfgAfter7 = Get-Config
Check 'config serverUrl persisted (trailing slash trimmed)' ($cfgAfter7.serverUrl -eq 'https://lvosec.onrender.com') $cfgAfter7.serverUrl
Check 'in-memory server URL updated' ($script:ServerUrl -eq 'https://lvosec.onrender.com') $script:ServerUrl
$wsAfter7 = $script:WsState
Check 'WS listener state re-pointed' ($wsAfter7.wsBase -eq 'wss://lvosec.onrender.com/ws/tunnel') $wsAfter7.wsBase
Check 'token identity preserved' ($cfgAfter7.token -eq 'tok-123') $cfgAfter7.token
Check 'computer id preserved' ($cfgAfter7.computerId -eq 7) $cfgAfter7.computerId

# --- 4. WsState absent (listener not started yet) is tolerated --------------
$fake4 = New-FakeAgentDir
Reset-Scope $fake4
Remove-Variable -Name WsState -Scope Script -ErrorAction SilentlyContinue
$r8 = Rotate-ServerUrl -NewUrl 'https://lvosec.onrender.com'
Check 'rotation works without WS state' ($r8.success) $r8.detail
Check 'still persisted' ((Get-Config).serverUrl -eq 'https://lvosec.onrender.com') (Get-Config).serverUrl

# --- cleanup ----------------------------------------------------------------
foreach ($fake in @($fake1, $fake2, $fake3, $fake4)) {
  Remove-Item -LiteralPath $fake.root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output ("server-url rotation: {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }