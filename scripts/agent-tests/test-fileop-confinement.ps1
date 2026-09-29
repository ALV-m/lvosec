#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Verifies the agent's file-operation confinement.

.DESCRIPTION
  delete_file and push_file act on a path chosen by whoever holds the dashboard
  session, and on any machine that leaks an agent token, by whoever steals it.
  delete_file runs Remove-Item -Recurse -Force, so where it is allowed to point
  is the whole blast radius. This asserts it stays inside the allowed write
  roots and outside the OS locations, using the real functions from the shipped
  agent script.

  The prefix-boundary cases matter as much as the obvious ones: a naive
  "starts with" check would let "C:\Windows\System32Backup" through as being
  "inside" C:\Windows\System32.

.EXAMPLE
  pwsh -File scripts/agent-tests/test-fileop-confinement.ps1
#>

$ErrorActionPreference = 'Stop'

$agent = Join-Path $PSScriptRoot '../../artifacts/api-server/src/assets/lab-agent.ps1'
if (-not (Test-Path -LiteralPath $agent)) { throw "agent script not found at $agent" }
$src = Get-Content -LiteralPath $agent -Raw

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ('agent failed to parse: ' + $errors[0].Message) }

$wanted = @('Get-AllowedWriteRoots', 'Test-AllowedWritePath')
$found = @()
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($wanted -contains $fn.Name) { Invoke-Expression $fn.Extent.Text; $found += $fn.Name }
}
foreach ($name in $wanted) {
  if ($found -notcontains $name) { throw "function $name not found in the agent script" }
}

$env:SystemRoot = 'C:\Windows'
$env:SystemDrive = 'C:'
$script:SystemDenyRoots = @(
  'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64', 'C:\Windows\Boot',
  'C:\Windows\Boot\System Partition', 'C:\Boot', 'C:\Recovery',
  'C:\$Recycle.Bin', 'C:\System Volume Information'
)

# Stub Resolve-Path. On a non-Windows box the real cmdlet cannot resolve
# Windows paths, and the security decision under test is the string containment
# logic layered on top of it. This stub also collapses ".." so traversal
# cases behave as they would on Windows.
function Resolve-Path {
  param([string]$LiteralPath, $ErrorAction)
  $clean = ($LiteralPath -replace '/', '\')
  while ($clean -match '^(.*)\\\.\.(\\|\.*)$') { $clean = $Matches[1] + $Matches[2] }
  while ($clean -match '^(.*\\)\.(\\|\.*)$') { $clean = $Matches[1] + $Matches[2] }
  [pscustomobject]@{ ProviderPath = $clean }
}

# Deterministic allowlist roots so the cases below are readable.
function Get-AllowedWriteRoots {
  @('C:\Users\student\Desktop', 'C:\Users\student\Documents',
    'C:\Users\student\Downloads', 'C:\Users\student\Pictures',
    'C:\Users\student', 'C:\Windows\Temp')
}

$cases = @(
  @{ p = 'C:\Users\student\Downloads\slides.pptx';   expect = $true;  why = 'ordinary push target' }
  @{ p = 'C:\Users\student\Desktop\exam.docx';       expect = $true;  why = 'ordinary push target' }
  @{ p = 'C:\Users\student\Downloads\sub\a.txt';     expect = $true;  why = 'nested under an allowed root' }
  @{ p = 'C:\Users\student\Downloads';                expect = $true;  why = 'the allowed root itself' }
  @{ p = 'C:\Users\student\Downloads\..\..\Windows\Temp\x'; expect = $true; why = 'traversal resolving into an allowed root' }
  @{ p = 'C:\Windows\System32\cmd.exe';              expect = $false; why = 'MUST BLOCK: system binary' }
  @{ p = 'C:\Windows\System32\drivers\etc\hosts';    expect = $false; why = 'MUST BLOCK: nested system file' }
  @{ p = 'C:\Windows\System32';                      expect = $false; why = 'MUST BLOCK: all of System32' }
  @{ p = 'C:\Windows\System32Backup';                expect = $false; why = 'prefix must respect the separator' }
  @{ p = 'C:\Windows';                                expect = $false; why = 'MUST BLOCK: OS root' }
  @{ p = 'C:\Boot\BCD';                              expect = $false; why = 'MUST BLOCK: boot config' }
  @{ p = 'C:\$Recycle.Bin\stuff';                    expect = $false; why = 'MUST BLOCK: recycle bin' }
  @{ p = 'C:\Users\other\Desktop\x.txt';             expect = $false; why = 'MUST BLOCK: another user profile' }
  @{ p = 'C:\Users\studentX\Desktop\x.txt';          expect = $false; why = 'prefix must respect the separator' }
  @{ p = '';                                          expect = $false; why = 'empty path refused' }
  @{ p = '   ';                                       expect = $false; why = 'whitespace path refused' }
)

$pass = 0; $fail = 0
foreach ($c in $cases) {
  $got = Test-AllowedWritePath -Path $c.p
  if ($got -eq $c.expect) {
    $pass++
    Write-Output ("  PASS  allow={0,-5} {1}" -f $got, $c.why)
  } else {
    $fail++
    Write-Output ("  FAIL  allow={0,-5} expected={1,-5} {2}  <- {3}" -f $got, $c.expect, $c.why, $c.p)
  }
}

Write-Output ''
Write-Output ("file-operation confinement: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
