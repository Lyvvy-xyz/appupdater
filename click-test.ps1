<#
Smoke-tests host.ps1 over the Chrome DevTools Protocol; UI Automation can't see inside WebView2.
Usage: .\click-test.ps1 [-HostPath <path to host.ps1>] [-Port 9333]
#>
param(
  [string]$HostPath = (Join-Path $PSScriptRoot 'host.ps1'),
  [int]$Port = 9333,
  [switch]$Reset
)

$ErrorActionPreference = 'Stop'
$logFile = Join-Path (Split-Path $HostPath) 'AppUpdater.log'
$script:fails = @()

function Assert($cond, $msg) {
  if ($cond) { Write-Host "OK   $msg" -ForegroundColor Green }
  else {
    Write-Host "FAIL $msg" -ForegroundColor Red; $script:fails += $msg
    # Annotations are readable on a public repo without a token (job logs are not).
    if ($env:GITHUB_ACTIONS) { Write-Host "::error::$msg" }
  }
}

$originalNoElevate = $env:APPUPDATER_NO_ELEVATE
$originalDebugPort = $env:APPUPDATER_DEBUG_PORT
$originalProgramData = $env:ProgramData
$originalLocalAppData = $env:LOCALAPPDATA
$proc = $ws = $null
$redirect = @{}
try {
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Not elevated - launching host.ps1 with APPUPDATER_NO_ELEVATE=1 to skip the UAC prompt."
  $env:APPUPDATER_NO_ELEVATE = '1'
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('appupdater-click-' + [guid]::NewGuid().ToString('N'))
$env:ProgramData = Join-Path $testRoot 'ProgramData'
$env:LOCALAPPDATA = Join-Path $testRoot 'LocalAppData'
New-Item -ItemType Directory -Path (Join-Path $env:ProgramData 'AppUpdater'), $env:LOCALAPPDATA -Force | Out-Null
$seed = @{ OfflineMode = $true; WorkerURL = ''; ManifestToken = ''; OrgName = 'Test organisation'; OnboardingSeen = $true; DisableReleaseCheck = $true }
$seed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:ProgramData 'AppUpdater/.appupdater-config') -Encoding UTF8

$logStartLen = 0
if (Test-Path $logFile) { $logStartLen = (Get-Item $logFile).Length }

$env:APPUPDATER_DEBUG_PORT = "$Port"
$redirect = @{}
if ($env:GITHUB_ACTIONS) {
  $redirect = @{ RedirectStandardOutput = "$env:RUNNER_TEMP\host.out.txt"; RedirectStandardError = "$env:RUNNER_TEMP\host.err.txt" }
}
$proc = Start-Process -FilePath 'powershell.exe' `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$HostPath`"") `
  -PassThru @redirect
  $target = $null
  for ($i = 0; $i -lt 120; $i++) {
    if ($proc.HasExited) { throw "AppUpdater exited before becoming ready (exit $($proc.ExitCode))." }
    Start-Sleep -Milliseconds 500
    try {
      $list = Invoke-RestMethod "http://127.0.0.1:$Port/json/list" -TimeoutSec 2
      $target = $list | Where-Object { $_.type -eq 'page' } | Select-Object -First 1
      if ($target) { break }
    } catch {}
  }
  if (-not $target) { throw "CDP endpoint never came up on port $Port after 60s - app may not have launched (check for a stuck UAC prompt, or WebView2 runtime missing)." }

  $ws = [System.Net.WebSockets.ClientWebSocket]::new()
  $connectTimeout = [Threading.CancellationTokenSource]::new(15000)
  try { $ws.ConnectAsync([Uri]$target.webSocketDebuggerUrl, $connectTimeout.Token).GetAwaiter().GetResult() }
  finally { $connectTimeout.Dispose() }

  $script:cdpId = 0
  function Send-Cdp([string]$method, [hashtable]$cdpParams = @{}) {
    $script:cdpId++
    $payload = @{ id = $script:cdpId; method = $method; params = $cdpParams } | ConvertTo-Json -Depth 10 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $timeout = [Threading.CancellationTokenSource]::new(15000)
    try {
      $ws.SendAsync([ArraySegment[byte]]::new($bytes), 'Text', $true, $timeout.Token).GetAwaiter().GetResult() | Out-Null
      $buffer = [byte[]]::new(65536)
      do {
        $message = [IO.MemoryStream]::new()
        try {
          do {
            $result = $ws.ReceiveAsync([ArraySegment[byte]]::new($buffer), $timeout.Token).GetAwaiter().GetResult()
            if ($result.MessageType -eq 'Close') { throw 'Browser connection closed.' }
            $message.Write($buffer, 0, $result.Count)
            if ($message.Length -gt 8mb) { throw 'Browser response exceeds the test limit.' }
          } until ($result.EndOfMessage)
          $response = [Text.Encoding]::UTF8.GetString($message.ToArray()) | ConvertFrom-Json
        } finally { $message.Dispose() }
        # CDP events may arrive between a request and its matching reply.
      } until ($response.id -eq $script:cdpId)
      if ($response.error) { throw ($response.error | ConvertTo-Json -Compress) }
      return $response
    } finally { $timeout.Dispose() }
  }

  function Eval-Js([string]$expr) {
    $r = Send-Cdp 'Runtime.evaluate' @{ expression = $expr; returnByValue = $true; awaitPromise = $false }
    if ($r.result.exceptionDetails) { throw "JS eval threw: $($r.result.exceptionDetails.text)" }
    return $r.result.result.value
  }

  function Wait-Js([string]$Expression, [int]$TimeoutSeconds = 15) {
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    do {
      if (Eval-Js $Expression) { return }
      Start-Sleep -Milliseconds 100
    } while ($elapsed.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw "Timed out waiting for browser condition: $Expression"
  }
  Wait-Js "typeof window.send === 'function' && window._defaultOrgName !== undefined"

  Assert ([bool](Eval-Js "typeof window.chrome.webview !== 'undefined'")) "WebView2 bridge object exists"

  Eval-Js @"
window.__log = [];
(function () {
  const orig = window.send;
  window.send = function (action, payload) { window.__log.push(action); return orig(action, payload); };
})();
"@ | Out-Null

  foreach ($screen in 'fleet', 'profiles', 'history', 'worker') {
    Eval-Js "goTo('$screen')" | Out-Null
    Start-Sleep -Milliseconds 500
    Assert ([bool](Eval-Js "document.getElementById('screen-$screen').classList.contains('on')")) "goTo('$screen') shows its screen"
  }

  Assert ([bool](Eval-Js "window.__log.includes('get-fleet')")) "'fleet' screen requested fleet data"
  Assert ([bool](Eval-Js "window._gotFleetData === true")) "fleet-data response was received and rendered"
  Assert ([bool](Eval-Js "window.__log.includes('get-config')")) "'worker' screen requested config"
  Assert ([bool](Eval-Js "window._defaultOrgName !== undefined")) "config-data response was received"
  Eval-Js "toast('Test', '<img src=x onerror=window.__injected=true>', true)" | Out-Null
  Assert (-not [bool](Eval-Js "!!document.querySelector('#toasts img') || window.__injected === true")) 'Messages render as text, not executable HTML'
  Eval-Js "window._defaultOrgName = undefined; window.chrome.webview.postMessage(null)" | Out-Null
  Eval-Js "send('get-config', {})" | Out-Null
  Wait-Js "document.getElementById('toasts').textContent.includes('Invalid application message')"
  Wait-Js "window._defaultOrgName !== undefined"
  Assert ([bool](Eval-Js "window._defaultOrgName !== undefined")) 'Bridge survives malformed input'

  Eval-Js "send('minimize-window', {})" | Out-Null
  Start-Sleep -Milliseconds 500
  $clientErrors = Eval-Js "window.__log.filter(a => a === 'client-error').length"
  Assert ($clientErrors -eq 0) "no client-error events fired during the run"

  # Last: close-window tears down the page, so nothing can be evaluated after it.
  try { Eval-Js "send('close-window', {})" | Out-Null }
  catch { if (-not $proc.WaitForExit(15000)) { throw } }
  Assert ($proc.WaitForExit(15000)) "close-window exits the app"

} catch {
  if ($env:GITHUB_ACTIONS) {
    $chain = @(); $ex = $_.Exception; while ($ex) { $chain += "$($ex.GetType().Name): $($ex.Message)"; $ex = $ex.InnerException }
    Write-Host "::error::click-test threw: $($chain -join '%0A  <- ')%0Aat: $($_.InvocationInfo.PositionMessage -replace "`r?`n", '%0A')"
    $wins = Get-Process | Where-Object MainWindowTitle | ForEach-Object { "$($_.ProcessName): $($_.MainWindowTitle)" }
    Write-Host "::notice title=Open windows::$($wins -join '%0A')"
    # Tell the main window apart from a same-titled MessageBox by its text.
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $root = [Windows.Automation.AutomationElement]::RootElement
    $cond = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $names = foreach ($w in $root.FindAll('Children', $cond)) {
      $w.FindAll('Descendants', [Windows.Automation.Condition]::TrueCondition) | Select-Object -First 25 |
        ForEach-Object { "$($_.Current.ControlType.ProgrammaticName) '$($_.Current.Name)'" }
    }
    Write-Host "::notice title=AppUpdater window contents::$($names -join '%0A')"
    $wv2Dlls = @(Get-ChildItem (Join-Path (Split-Path $HostPath) 'wv2') -ErrorAction SilentlyContinue).Name -join ', '
    $edgeProcs = @(Get-Process msedgewebview2 -ErrorAction SilentlyContinue).Count
    Write-Host "::notice title=WebView2 state::wv2 dlls: [$wv2Dlls]; msedgewebview2 processes: $edgeProcs"
    $edgeIds = @(Get-Process msedgewebview2 -ErrorAction SilentlyContinue).Id
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $edgeIds -contains $_.OwningProcess } |
      ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }
    $cmd = (Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | Select-Object -First 1).CommandLine
    Write-Host "::notice title=WebView2 CDP::listening: [$($listen -join ', ')]; env port: $env:APPUPDATER_DEBUG_PORT%0Acmdline: $cmd"
  }
  throw
} finally {
  if ($env:GITHUB_ACTIONS) {
    Write-Host "::notice::host.ps1 exited: $($proc.HasExited)"
    foreach ($f in $redirect.Values) {
      if ((Test-Path $f) -and (Get-Item $f).Length) {
        Write-Host "::error title=$(Split-Path $f -Leaf)::$((Get-Content $f -Tail 30) -join '%0A')"
      }
    }
  }
  if ($ws) { $ws.Abort(); $ws.Dispose() }
  if ($proc) { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }; $proc.Dispose() }
  $env:ProgramData = $originalProgramData
  $env:LOCALAPPDATA = $originalLocalAppData
  $env:APPUPDATER_NO_ELEVATE = $originalNoElevate
  $env:APPUPDATER_DEBUG_PORT = $originalDebugPort
}

if (Test-Path $logFile) {
  $newText = ''
  $fs = [System.IO.File]::Open($logFile, 'Open', 'Read', 'ReadWrite')
  try {
    $fs.Seek($logStartLen, 'Begin') | Out-Null
    $sr = New-Object System.IO.StreamReader($fs)
    $newText = $sr.ReadToEnd()
  } finally { $fs.Dispose() }
  Assert ($newText -notmatch '\[FATAL\]|\[ERROR\]') "AppUpdater.log has no new FATAL/ERROR entries from this run"
  if ($newText -match '\[FATAL\]|\[ERROR\]') { Write-Host ($newText -split "`n" | Where-Object { $_ -match '\[FATAL\]|\[ERROR\]' } | Out-String) }
}

Write-Host ""
if ($script:fails.Count -gt 0) {
  Write-Host "$($script:fails.Count) check(s) FAILED" -ForegroundColor Red
  exit 1
}
Write-Host "All checks passed" -ForegroundColor Green
exit 0

# Not covered: native file dialogs, async package builds, OS-level window state.
