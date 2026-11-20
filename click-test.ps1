<#
Smoke-tests host.ps1 over the Chrome DevTools Protocol; UI Automation can't see inside WebView2.
Usage: .\click-test.ps1 [-HostPath <path to host.ps1>] [-Port 9333] [-InstallerPath <real installer>]
Without an installer the 7-Zip build flows are skipped; the printer, zip and MSIX flows use fixtures of their own.
Screenshots go to $env:CLICK_TEST_SHOTS, or a folder under the test root.
#>
param(
  [string]$HostPath = (Join-Path $PSScriptRoot 'host.ps1'),
  [int]$Port = 9333,
  [switch]$Reset,
  [string]$InstallerPath = $env:CLICK_TEST_INSTALLER
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
$originalTestInstaller = $env:APPUPDATER_TEST_INSTALLER
$originalTestScript = $env:APPUPDATER_TEST_SCRIPT
$originalTestImage = $env:APPUPDATER_TEST_IMAGE
$proc = $ws = $null
$redirect = @{}
try {
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
  Write-Host "Not elevated - launching host.ps1 with APPUPDATER_NO_ELEVATE=1 to skip the UAC prompt."
  $env:APPUPDATER_NO_ELEVATE = '1'
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('appupdater-click-' + [guid]::NewGuid().ToString('N'))
$env:ProgramData = Join-Path $testRoot 'ProgramData'
$env:LOCALAPPDATA = Join-Path $testRoot 'LocalAppData'
New-Item -ItemType Directory -Path (Join-Path $env:ProgramData 'AppUpdater'), $env:LOCALAPPDATA -Force | Out-Null
$seed = @{ OfflineMode = $true; WorkerURL = ''; ManifestToken = ''; OrgName = 'Test organisation'; OnboardingSeen = $true; DisableReleaseCheck = $true }
$configFile = Join-Path $env:ProgramData 'AppUpdater/.appupdater-config'
$seed | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding UTF8

# An app marked deployed before this launch, with a recorded build, is asked about on the home screen.
$feedbackId = 'click-test-feedback'
$past = (Get-Date).AddDays(-2).ToString('o')
@{ $feedbackId = @{ name = 'Feedback Sample'; target = 'intunewin'; profile = ''; outputDir = ''; builtAt = $past; deployedAt = $past } } |
  ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $env:ProgramData 'AppUpdater/deploy-status.json') -Encoding UTF8
$memoryFile = Join-Path $env:ProgramData 'AppUpdater/app-memory.json'
@{ $feedbackId = @{ settings = @{ AppID = $feedbackId; DisplayName = 'Feedback Sample' }; keys = @{}; builds = @(@{ version = '1.2.3'; at = $past }) } } |
  ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $memoryFile -Encoding UTF8

$shotDir = if ($env:CLICK_TEST_SHOTS) { $env:CLICK_TEST_SHOTS } else { Join-Path $testRoot 'screenshots' }
New-Item -ItemType Directory -Path $shotDir -Force | Out-Null
$script:shotCount = 0

# The host's test seams answer its file dialogs with these files.
$hookScript = Join-Path $testRoot 'hook.ps1'
Set-Content -LiteralPath $hookScript -Value '# Intentionally empty.' -Encoding UTF8
$env:APPUPDATER_TEST_SCRIPT = $hookScript

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem, System.Drawing
$fixtureDir = Join-Path $testRoot 'fixtures'
New-Item -ItemType Directory -Path $fixtureDir -Force | Out-Null
$logoFile = Join-Path $fixtureDir 'logo.png'
$bmp = New-Object Drawing.Bitmap 64, 64
try {
  $g = [Drawing.Graphics]::FromImage($bmp); $g.Clear([Drawing.Color]::SteelBlue); $g.Dispose()
  $bmp.Save($logoFile, [Drawing.Imaging.ImageFormat]::Png)
} finally { $bmp.Dispose() }
$env:APPUPDATER_TEST_IMAGE = $logoFile
$portableZip = Join-Path $fixtureDir 'portable-tool.zip'
$zip = [IO.Compression.ZipFile]::Open($portableZip, 'Create')
try { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $env:SystemRoot 'System32\notepad.exe'), 'Tool/tool.exe') | Out-Null }
finally { $zip.Dispose() }
$msixFile = Join-Path $fixtureDir 'Vendor.ClickTest.msix'
$zip = [IO.Compression.ZipFile]::Open($msixFile, 'Create')
try {
  $w = New-Object IO.StreamWriter ($zip.CreateEntry('AppxManifest.xml').Open())
  try { $w.Write('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Vendor.ClickTest" Version="1.2.3.0" Publisher="CN=Vendor"/><Properties><DisplayName>Click Test</DisplayName><PublisherDisplayName>Vendor</PublisherDisplayName></Properties></Package>') }
  finally { $w.Dispose() }
} finally { $zip.Dispose() }

$installer = $null
# Any existing file switches the installer seam on; the page can then name the file it wants.
$env:APPUPDATER_TEST_INSTALLER = $portableZip
if ($InstallerPath -and (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
  # A folder of its own keeps "Bundle the whole folder" available and small.
  $installerDir = Join-Path $testRoot 'installer'
  New-Item -ItemType Directory -Path $installerDir -Force | Out-Null
  $installer = Join-Path $installerDir (Split-Path $InstallerPath -Leaf)
  Copy-Item -LiteralPath $InstallerPath -Destination $installer
  $env:APPUPDATER_TEST_INSTALLER = $installer
} else {
  $skipNote = "No installer at '$InstallerPath' - skipping the 7-Zip build, local test and repeat-packaging flows."
  Write-Host $skipNote -ForegroundColor Yellow
  if ($env:GITHUB_ACTIONS) { Write-Host "::notice::$skipNote" }
}
# The engine keeps the winget catalogue at a fixed path, outside the test ProgramData.
$wingetIndex = 'C:\ProgramData\AppUpdater\winget\index.db'

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

  function Save-Shot([string]$Name, [string]$ScrollTo, [switch]$KeepToasts) {
    try {
      # Screens animate in, and earlier toasts would cover the content.
      if ($ScrollTo) { Eval-Js "(function () { const el = document.querySelector('$ScrollTo'); if (el) el.scrollIntoView({ block: 'center' }); })()" | Out-Null }
      if (-not $KeepToasts) { Eval-Js "document.getElementById('toasts').innerHTML = ''" | Out-Null }
      Start-Sleep -Milliseconds 900
      $shot = Send-Cdp 'Page.captureScreenshot' @{ format = 'png' }
      $script:shotCount++
      [IO.File]::WriteAllBytes((Join-Path $shotDir ('{0:D2}-{1}.png' -f $script:shotCount, $Name)), [Convert]::FromBase64String($shot.result.data))
    } catch { Write-Host "Screenshot '$Name' failed: $($_.Exception.Message)" -ForegroundColor Yellow }
  }

  # Selectors are embedded in single-quoted JS strings, so they must not contain single quotes.
  function Invoke-Click([string]$Selector) {
    if (-not (Eval-Js "(function () { const el = document.querySelector('$Selector'); if (!el) return false; el.click(); return true; })()")) {
      throw "No element matches $Selector"
    }
  }
  function Test-Shown([string]$Selector) {
    return [bool](Eval-Js "(function () { const el = document.querySelector('$Selector'); return !!el && el.getClientRects().length > 0; })()")
  }
  function Test-ScreenOn([string]$Screen) {
    return [bool](Eval-Js "document.getElementById('screen-$Screen').classList.contains('on')")
  }
  function Get-Value([string]$Selector) { return [string](Eval-Js "document.querySelector('$Selector').value") }
  function Write-Field([string]$Selector, [string]$Value) { Eval-Js "document.querySelector('$Selector').value = $(ConvertTo-Json $Value)" | Out-Null }
  function Get-Text([string]$Selector) { return [string](Eval-Js "document.querySelector('$Selector').textContent") }
  function Get-ChipText { return [string](Eval-Js "Array.from(document.querySelectorAll('#inspect-chips .chip')).map(function (c) { return c.textContent + ': ' + (c.dataset.detail || ''); }).join(' | ')") }
  function Test-Toast([string]$Title) {
    return [bool](Eval-Js "Array.from(document.querySelectorAll('#toasts .toast b')).some(function (b) { return b.textContent === $(ConvertTo-Json $Title); })")
  }

  # A failing flow is recorded with a screenshot and the sweep moves on to the next one.
  function Invoke-Flow([string]$Name, [scriptblock]$Body) {
    Write-Host "--- $Name"
    try { & $Body }
    catch {
      Assert $false "$Name threw: $($_.Exception.Message)"
      Save-Shot (($Name -replace '[^A-Za-z0-9]+', '-').Trim('-') + '-failure')
    }
  }

  function Send-Input([string]$Selector) { Eval-Js "document.querySelector('$Selector').dispatchEvent(new Event('input'))" | Out-Null }
  function Select-Option([string]$Selector, [string]$Value) {
    Eval-Js "(function () { const el = document.querySelector('$Selector'); el.value = $(ConvertTo-Json $Value); el.dispatchEvent(new Event('change')); })()" | Out-Null
  }
  function Test-On([string]$Selector) { return [bool](Eval-Js "document.querySelector('$Selector').classList.contains('on')") }
  function Set-Toggle([string]$Selector, [bool]$On) {
    if ((Test-On $Selector) -ne $On) {
      Eval-Js "window.__msgs = []" | Out-Null
      Invoke-Click $Selector
      Wait-Js "window.__msgs.indexOf('settings-saved') >= 0"
    }
    Assert ((Test-On $Selector) -eq $On) "$Selector is $(if ($On) { 'on' } else { 'off' })"
  }
  function Write-Notice([string]$Text) {
    Write-Host $Text -ForegroundColor Yellow
    if ($env:GITHUB_ACTIONS) { Write-Host "::notice::$Text" }
  }

  # Picking an installer fills only empty identity fields, so another app needs them cleared first.
  function Clear-AppFields { foreach ($f in '#f-appid', '#f-displayname', '#f-registryname', '#f-download-url') { Write-Field $f '' } }

  # Without a path the drop zone is clicked and the seam answers with its default file.
  function Select-TestInstaller([string]$Path) {
    Eval-Js "window.__msgs = []" | Out-Null
    if ($Path) { Eval-Js "send('browse-installer', { testPath: $(ConvertTo-Json $Path) })" | Out-Null }
    else { Invoke-Click '#drop' }
    Wait-Js "window.__msgs.indexOf('browse-installer-result') >= 0" 120
    # The folder count and winget lookup arrive separately and enable the bundle toggle.
    Wait-Js "window.__msgs.indexOf('installer-winget-result') >= 0" 120
  }

  function Wait-Build([string]$Label) {
    Wait-Js "document.getElementById('screen-done').classList.contains('on') || document.getElementById('progress-error').style.display === 'block'" 600
    $buildError = if (Test-Shown '#progress-error') { ': ' + (Get-Text '#progress-error') } else { '' }
    Assert (Test-ScreenOn 'done') "$Label reaches the done screen$buildError"
  }

  function Test-BuildGuard([string]$Title, [string]$Label) {
    Eval-Js "document.getElementById('toasts').innerHTML = ''; window.__log = window.__log.filter(function (a) { return a !== 'build-package'; })" | Out-Null
    Invoke-Click '#btn-build'
    Assert (Test-Toast $Title) "$Label shows the '$Title' toast"
    Assert ((Test-ScreenOn 'build') -and -not (Eval-Js "window.__log.indexOf('build-package') >= 0")) "$Label does not start a build"
  }

  Wait-Js "typeof window.send === 'function' && window._defaultOrgName !== undefined"

  Assert ([bool](Eval-Js "typeof window.chrome.webview !== 'undefined'")) "WebView2 bridge object exists"

  Eval-Js @"
window.__log = [];
window.__msgs = [];
window.__errors = [];
(function () {
  const orig = window.send;
  window.send = function (action, payload) { window.__log.push(action); return orig(action, payload); };
  window.chrome.webview.addEventListener('message', function (e) {
    window.__msgs.push(e.data.type);
    if (e.data.type === 'error') window.__errors.push(String(e.data.payload && e.data.payload.message));
  });
})();
"@ | Out-Null

  Invoke-Flow 'Deploy feedback in the Home queue' {
    Wait-Js "!!document.querySelector('#home-queue [data-feedback=$feedbackId]')" 30
    Assert ((Get-Text '#home-queue') -like '*Feedback Sample*1.2.3*did it install*') 'Home asks about the app deployed before this launch'
    Save-Shot 'home-queue' '#screen-home'
    Invoke-Click "#home-queue [data-feedback=$feedbackId][data-outcome=ok]"
    Assert (-not [bool](Eval-Js "!!document.querySelector('#home-queue [data-feedback=$feedbackId]')")) 'Answering Yes removes the question from the queue'
    $outcome = $null
    for ($i = 0; $i -lt 50 -and $outcome -ne 'ok'; $i++) {
      Start-Sleep -Milliseconds 200
      try { $outcome = @((Get-Content -LiteralPath $memoryFile -Raw -Encoding UTF8 | ConvertFrom-Json).$feedbackId.builds)[-1].deployOutcome } catch {}
    }
    Assert ($outcome -eq 'ok') 'The Yes answer is recorded in app-memory.json'
  }

  foreach ($screen in 'home', 'build', 'fleet', 'profiles', 'history', 'worker', 'docs') {
    Invoke-Click ".nav-btn[data-go=$screen]"
    Start-Sleep -Milliseconds 500
    Assert ((Test-ScreenOn $screen) -and (Get-Text "#screen-$screen").Trim().Length -gt 0) "nav '$screen' shows its screen"
    Save-Shot "screen-$screen"
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

  Invoke-Flow 'NIST vulnerability check setting' {
    Invoke-Click '.nav-btn[data-go=worker]'
    Wait-Js "window.__msgs.indexOf('settings-data') >= 0"
    Assert (Test-Shown '#tgl-nvd') 'Settings show the NIST vulnerability check toggle'
    Assert (-not (Eval-Js "document.getElementById('tgl-nvd').classList.contains('on')")) 'The NIST vulnerability check is off by default'
    Eval-Js "window.__msgs = []" | Out-Null
    Invoke-Click '#tgl-nvd'
    Wait-Js "window.__msgs.indexOf('settings-saved') >= 0"
    Assert ([bool](Eval-Js "document.getElementById('tgl-nvd').classList.contains('on')")) 'Clicking the NIST toggle switches it on'
    Eval-Js "document.getElementById('tgl-nvd').classList.remove('on'); window.__msgs = []; send('get-settings', {})" | Out-Null
    Wait-Js "window.__msgs.indexOf('settings-data') >= 0"
    Assert ([bool](Eval-Js "document.getElementById('tgl-nvd').classList.contains('on')")) 'The NIST setting survives a settings reload'
    # The config file is readable only by administrators and SYSTEM.
    if ($elevated) {
      Assert ((Get-Content -LiteralPath $configFile -Raw -Encoding UTF8 | ConvertFrom-Json).NvdLookups -eq $true) 'The NIST setting is saved to the config file'
    }
    Save-Shot 'settings-nvd-on'
    Eval-Js "window.__msgs = []" | Out-Null
    Invoke-Click '#tgl-nvd'
    Wait-Js "window.__msgs.indexOf('settings-saved') >= 0"
    Assert (-not (Eval-Js "document.getElementById('tgl-nvd').classList.contains('on')")) 'Clicking the NIST toggle again switches it off'
  }

  Invoke-Flow 'Vendor release checks without a worker' {
    Invoke-Click '.nav-btn[data-go=worker]'
    Wait-Js "window.__msgs.indexOf('epm-state') >= 0"
    Assert ((Get-Text '#epm-status-t') -eq 'Needs the Cloudflare worker') 'Release checks ask for the worker first'
    Eval-Js "window.__msgs = []" | Out-Null
    Invoke-Click '#epm-setup'
    Wait-Js "window.__msgs.indexOf('epm-code') >= 0"
    Assert ((Get-Text '#epm-status') -like '*Cloudflare worker*') 'GitHub sign-in waits for the worker'
    Assert (-not (Eval-Js "document.getElementById('epm-setup').disabled")) 'The sign-in button is usable again'
  }

  Invoke-Flow 'Cloudflare connect' {
    # The connect wizard is a native WPF window, so UI Automation finds and closes it.
    Invoke-Click '.nav-btn[data-go=worker]'
    Wait-Js "document.getElementById('btn-worker-connect').getClientRects().length > 0"
    $label = Get-Text '#btn-worker-connect'
    Invoke-Click '#btn-worker-connect'
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $byProcess = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $byTitle = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, 'Worker Options')
    $bySub = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, 'Choose an action')
    $dialog = $null
    for ($i = 0; $i -lt 60 -and -not $dialog; $i++) {
      Start-Sleep -Milliseconds 250
      foreach ($w in [Windows.Automation.AutomationElement]::RootElement.FindAll('Children', $byProcess)) {
        if ($w.FindFirst('Descendants', $byTitle)) { $dialog = $w }
      }
    }
    Assert ([bool]$dialog) "'$label' opens the Worker Options window"
    if (-not $dialog) { return }
    Assert ([bool]$dialog.FindFirst('Descendants', $bySub)) "The Worker Options window shows 'Choose an action'"
    try {
      $r = $dialog.Current.BoundingRectangle
      $bmp = New-Object Drawing.Bitmap ([int]$r.Width), ([int]$r.Height)
      try {
        $g = [Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size); $g.Dispose()
        $script:shotCount++
        $bmp.Save((Join-Path $shotDir ('{0:D2}-cloudflare-connect.png' -f $script:shotCount)), [Drawing.Imaging.ImageFormat]::Png)
      } finally { $bmp.Dispose() }
    } catch { Write-Host "Screenshot 'cloudflare-connect' failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    $dialog.GetCurrentPattern([Windows.Automation.WindowPattern]::Pattern).Close()
    Wait-Js "document.getElementById('btn-worker-connect').textContent === $(ConvertTo-Json $label) && !document.getElementById('btn-worker-connect').disabled" 30
    Assert ($proc -and -not $proc.HasExited) 'Closing the Worker Options window leaves the app running'
    Save-Shot 'worker-after-connect-cancel'
  }

  if ($installer) {
    $script:appId = $script:registryName = $script:builtVersion = $script:suggestedVersion = ''

    Invoke-Flow 'Build form' {
      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Assert ((Get-Text '#inspect-name') -eq (Split-Path $installer -Leaf)) 'The picked installer is shown on the build form'
      Assert ([int](Eval-Js "document.querySelectorAll('#inspect-chips .chip').length") -gt 0) 'Inspection chips are shown'
      Assert ((Get-Value '#f-displayname') -ne '') 'Display name is filled from the installer'
      Assert ((Get-Value '#f-registryname') -ne '') 'Registry name is filled from the installer'
      Assert ((Get-Value '#f-silentargs') -ne '') 'Silent switch is filled from the installer'
      if (-not (Get-Value '#f-silentargs')) { Write-Field '#f-silentargs' '/S' }
      $script:appId = Get-Value '#f-appid'
      $script:registryName = Get-Value '#f-registryname'
      $script:builtVersion = [string](Eval-Js "window._selectedVersion")

      Invoke-Click '#segMode button[data-val=simple]'
      Assert (Test-Shown '#detectversion-wrap') 'Simple mode shows the minimum version for detection'
      if (-not (Test-Shown '#extras-panel')) { Invoke-Click '#extras-toggle' }
      Assert (Test-Shown '#scripts-wrap') 'Simple mode shows the scripts section'
      foreach ($selector in '.tgl[data-val=RemoveOlderVersions]', '#f-prehook', '#f-posthook', '#f-postuninstallhook',
                            '[data-browse-script=f-prehook]', '[data-browse-script=f-posthook]', '[data-browse-script=f-postuninstallhook]') {
        Assert (Test-Shown $selector) "Simple mode shows $selector"
      }
      Invoke-Click '[data-browse-script=f-posthook]'
      Wait-Js "document.getElementById('f-posthook').value !== ''" 30
      Assert ((Get-Value '#f-posthook') -eq $hookScript) 'Browse fills the after-install script path'
      Save-Shot 'build-form-simple'
      Write-Field '#f-posthook' ''

      Invoke-Click '#segMode button[data-val=runtime]'
      Assert (-not (Test-Shown '#detectversion-wrap')) 'Runtime mode hides the minimum version for detection'
      Assert (-not (Test-Shown '#scripts-wrap')) 'Runtime mode hides the scripts section'
      Save-Shot 'build-form-runtime'
    }

    Invoke-Flow 'Build guards' {
      Wait-Js "!document.querySelector('.tgl[data-val=BundleFolder]').disabled" 60
      Invoke-Click '.tgl[data-val=BundleFolder]'
      Test-BuildGuard 'Folder bundling is Simple only' 'Runtime mode with folder bundling'
      Save-Shot 'guard-bundle-runtime' -KeepToasts
      Invoke-Click '.tgl[data-val=BundleFolder]'

      Invoke-Click '#segMode button[data-val=simple]'
      Write-Field '#f-detectversion' ''
      Invoke-Click '.tgl[data-val=RemoveOlderVersions]'
      Test-BuildGuard 'Minimum version needed' 'Removing older versions without a minimum version'
      Invoke-Click '.tgl[data-val=RemoveOlderVersions]'

      Write-Field '#f-detectversion' 'latest'
      Test-BuildGuard 'Minimum version' 'A minimum version without digits'
      Save-Shot 'guard-minimum-version' -KeepToasts
      Write-Field '#f-detectversion' ''
    }

    Invoke-Flow 'Simple intunewin build' {
      Invoke-Click '#segTarget button[data-val=intunewin]'
      Invoke-Click '#btn-build'
      Wait-Build 'Simple .intunewin build'
      $sheet = Get-Text '#done-sheet'
      foreach ($row in 'Install command', 'Uninstall command', 'Detection', 'Install behaviour', 'EPM elevation rules') {
        Assert ($sheet -like "*$row*") "Done sheet has a '$row' row"
      }
      Save-Shot 'done-simple-intunewin' '#done-sheet'
    }

    Invoke-Flow 'Fleet and local test' {
      $idJs = ConvertTo-Json $script:appId
      Invoke-Click '.nav-btn[data-go=fleet]'
      Wait-Js "!!document.querySelector('#fleet-table [data-test=' + JSON.stringify($idJs) + ']')" 30
      $row = [string](Eval-Js "document.querySelector('#fleet-table [data-test=' + JSON.stringify($idJs) + ']').closest('tr').textContent")
      Assert ($row -like "*$($script:appId)*" -and (-not $script:builtVersion -or $row -like "*$($script:builtVersion)*")) "Fleet lists $($script:appId) with version $($script:builtVersion)"
      Save-Shot 'fleet-built-app'
      Invoke-Click ('#fleet-table [data-test=' + $idJs + ']')
      Assert (Test-Shown '#test-modal') 'Test locally opens the test modal'
      Save-Shot 'test-modal'
      if (-not $elevated) {
        Write-Host 'Not elevated - skipping the local install test, which runs as SYSTEM.' -ForegroundColor Yellow
        return
      }
      Eval-Js "document.getElementById('test-also-uninstall').checked = true; document.getElementById('test-simulate-system').checked = true" | Out-Null
      Invoke-Click '#test-modal-start'
      Wait-Js "/\u2713 Done|\u2717 Failed/.test(document.getElementById('test-log').textContent)" 300
      $testLog = Get-Text '#test-log'
      $passed = $testLog.Contains("$([char]0x2713) Done")
      Assert $passed "Local install and uninstall test succeeds$(if (-not $passed) { ': ' + $testLog })"
      $fixLabel = [string](Eval-Js "(Array.from(document.querySelectorAll('#test-log button')).find(function (b) { return /^Require version .+ or newer$/.test(b.textContent); }) || {}).textContent || ''")
      Assert ($fixLabel -ne '') 'The test offers a minimum version for detection'
      Save-Shot 'test-modal-done'
      if ($fixLabel) {
        $script:suggestedVersion = $fixLabel -replace '^Require version (.+) or newer$', '$1'
        Eval-Js "Array.from(document.querySelectorAll('#test-log button')).find(function (b) { return /^Require version /.test(b.textContent); }).click()" | Out-Null
        Assert ((Test-ScreenOn 'build') -and (Get-Value '#f-detectversion') -eq $script:suggestedVersion) "The suggestion returns to the build form with minimum version $($script:suggestedVersion)"
      }
    }

    Invoke-Flow 'Repeat packaging' {
      Invoke-Click '.nav-btn[data-go=build]'
      Write-Field '#f-appid' 'placeholder-id'
      Write-Field '#f-registryname' 'placeholder name'
      Select-TestInstaller
      Assert ((Get-ChipText) -like '*packaged before*') "The 'packaged before' chip is shown"
      Assert ((Get-Value '#f-appid') -eq $script:appId) 'App ID is restored from the last build'
      Assert ((Get-Value '#f-registryname') -eq $script:registryName) 'Registry name is restored from the last build'
      if ($script:suggestedVersion) {
        Assert ((Get-Value '#f-detectversion') -eq $script:suggestedVersion) 'The minimum version from the test survives picking the installer again'
      }
      Save-Shot 'repeat-packaging'
    }

    Invoke-Flow 'PSADT v4 build' {
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=psadt]'
      Invoke-Click '#segPsadtVersion button[data-val=v4]'
      Invoke-Click '#btn-build'
      Wait-Build 'PSADT v4 build'
      Assert ((Get-Text '#done-sheet') -like '*PSADT package*') 'Done sheet names the PSADT target'
      Save-Shot 'done-psadt-v4' '#done-sheet'
    }

    # A finished build resets the installer, so every build below picks it again; that also restores the last build's settings.
    Invoke-Flow 'PSADT v3 build' {
      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=psadt]'
      Invoke-Click '#segPsadtVersion button[data-val=v3]'
      Invoke-Click '#btn-build'
      Wait-Build 'PSADT v3 build'
      $sheet = Get-Text '#done-sheet'
      Assert ($sheet -like '*PSADT package*' -and $sheet -like '*Deploy-Application.ps1*') 'Done sheet names the PSADT v3 target'
      Save-Shot 'done-psadt-v3' '#done-sheet'
    }

    Invoke-Flow 'Runtime build' {
      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Invoke-Click '#segMode button[data-val=runtime]'
      Invoke-Click '#segTarget button[data-val=intunewin]'
      Write-Field '#f-download-url' 'https://www.7-zip.org/a/7z2408-x64.exe'
      Invoke-Click '#btn-build'
      Wait-Build 'Runtime .intunewin build'
      $sheet = Get-Text '#done-sheet'
      Assert ($sheet -like '*AppUpdater Runtime*') 'Done sheet names the Runtime type'
      Assert ($sheet -like '*As a dependency*Detection confirms the AppUpdater agent*') "Done sheet has the Runtime 'As a dependency' row"
      Save-Shot 'done-runtime' '#done-sheet'
    }

    Invoke-Flow 'Client profile' {
      $profileName = 'Click Test Client'
      Invoke-Click '.nav-btn[data-go=profiles]'
      Invoke-Click '#new-profile-card'
      Write-Field '#pf-name' $profileName; Send-Input '#pf-name'
      Write-Field '#pf-orgname' 'Click Test Org'; Send-Input '#pf-orgname'
      Invoke-Click '#pf-logo-browse'
      Wait-Js "document.getElementById('pf-logo').value !== ''" 30
      Assert ((Get-Value '#pf-logo') -eq $logoFile) 'Browse fills the profile logo path'
      Eval-Js "document.getElementById('toasts').innerHTML = ''" | Out-Null
      Invoke-Click '#pf-save'
      Wait-Js "!!document.querySelector('#profiles-strip [data-edit-profile=`"$profileName`"]')"
      Assert (Test-Toast 'Profile saved') "Saving shows the 'Profile saved' toast"
      Assert ([bool](Eval-Js "Array.from(document.querySelectorAll('#f-profile option')).some(function (o) { return o.value === '$profileName'; })")) 'The saved profile is offered on the build form'
      Save-Shot 'profiles-saved'

      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Select-Option '#f-profile' $profileName
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=psadt]'
      Invoke-Click '#segPsadtVersion button[data-val=v4]'
      Assert ((Get-Text '#manifest') -like '*Click Test Org branding*') 'The manifest names the profile organisation'
      if (Test-Shown '#bp-disclosure') {
        Invoke-Click '#bp-disclosure'
        Save-Shot 'build-branding-preview' '#bp-panel'
      }
      Invoke-Click '#btn-build'
      Wait-Build 'PSADT v4 build with a client profile'
      Assert ((Get-Text '#done-sheet') -like '*PSADT package*') 'Done sheet names the PSADT target'
      Save-Shot 'done-psadt-v4-profile' '#done-sheet'
    }

    Invoke-Flow 'Online lookups and NIST check' {
      Invoke-Click '.nav-btn[data-go=worker]'
      Set-Toggle '#tgl-release-check' $true
      Set-Toggle '#tgl-nvd' $true
      Save-Shot 'settings-online-lookups-on'
      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Select-Option '#f-profile' ''
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=intunewin]'
      Invoke-Click '#btn-build'
      Wait-Build 'Simple build with online lookups'
      # Either row proves the setting reached the build: NIST answered, or it was unreachable.
      $nvdRow = [string](Eval-Js "Array.from(document.querySelectorAll('#done-sheet .srow')).map(function (r) { return r.querySelector('.sk').textContent + ': ' + r.querySelector('.sv').textContent; }).filter(function (t) { return /^Check: .*NVD/.test(t); }).join(' | ')")
      Assert ($nvdRow -ne '') "Done sheet has an NVD check row$(if ($nvdRow) { ': ' + $nvdRow })"
      Save-Shot 'done-nvd-check' '#done-sheet'
    }

    Invoke-Flow 'winget contribution' {
      if (-not $elevated) { Write-Notice 'Not elevated - skipping the winget contribution, which needs a local test as SYSTEM.'; return }
      $waited = [Diagnostics.Stopwatch]::StartNew()
      while (-not (Test-Path -LiteralPath $wingetIndex) -and $waited.Elapsed.TotalMinutes -lt 5) { Start-Sleep -Seconds 5 }
      if (-not (Test-Path -LiteralPath $wingetIndex)) { Write-Notice 'The winget catalogue did not download within 5 minutes - skipping the winget contribution flow.'; return }

      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      $wingetId = [string](Eval-Js "(window._identity && window._identity.wingetId) || ''")
      Assert ($wingetId -ne '') "The winget catalogue matches the installer$(if ($wingetId) { ': ' + $wingetId } else { ': ' + (Get-Text '#inspect-chips') })"
      if (-not $wingetId) { return }
      Select-Option '#f-profile' ''
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=intunewin]'
      Invoke-Click '#btn-build'
      Wait-Build 'Simple build matched in winget'

      $idJs = ConvertTo-Json $script:appId
      Invoke-Click '.nav-btn[data-go=fleet]'
      Wait-Js "!!document.querySelector('#fleet-table [data-test=' + JSON.stringify($idJs) + ']')" 30
      Invoke-Click ('#fleet-table [data-test=' + $idJs + ']')
      Eval-Js "document.getElementById('test-also-uninstall').checked = true; document.getElementById('test-simulate-system').checked = true" | Out-Null
      Invoke-Click '#test-modal-start'
      Wait-Js "/\u2713 Done|\u2717 Failed/.test(document.getElementById('test-log').textContent)" 300
      $contributeJs = "Array.from(document.querySelectorAll('#test-log button')).find(function (b) { return b.textContent === 'Contribute what this test verified to winget'; })"
      $offered = [bool](Eval-Js "!!$contributeJs")
      Assert $offered "The passed test offers to contribute to winget$(if (-not $offered) { ': ' + (Get-Text '#test-log') })"
      if (-not $offered) { return }
      Eval-Js "window.__msgs = []; $contributeJs.click()" | Out-Null
      Wait-Js "window.__msgs.indexOf('winget-prepared') >= 0" 120
      # The submit button is never clicked: it would open a real pull request.
      $prepared = [string](Eval-Js "document.getElementById('winget-submit') ? 'preview' : (/winget already has/.test(document.getElementById('test-log').textContent) ? 'nothing to add' : '')")
      $log = Get-Text '#test-log'
      Assert ($prepared -ne '') "The winget contribution shows a pull request preview or says winget has the data: $(if ($prepared) { $prepared } else { $log.Substring([Math]::Max(0, $log.Length - 300)) })"
      Save-Shot 'winget-contribution' '#test-log'
      Invoke-Click '#test-modal-close'
    }

    Invoke-Flow 'Online lookups off' {
      Invoke-Click '.nav-btn[data-go=worker]'
      Set-Toggle '#tgl-nvd' $false
      Set-Toggle '#tgl-release-check' $false
    }

    Invoke-Flow 'Pre-deploy block' {
      # An earlier build signed by someone else makes this installer's signature a red finding.
      $memory = Get-Content -LiteralPath $memoryFile -Raw -Encoding UTF8 | ConvertFrom-Json
      $entry = $memory.($script:appId)
      if (-not $entry) { throw "app-memory.json has no entry for $($script:appId)" }
      $entry.builds = @($entry.builds) + [pscustomobject]@{
        version = $script:builtVersion; at = (Get-Date).ToString('o'); signed = 'Valid'; signer = 'CN=Someone Else, O=Other'
      }
      $memory | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $memoryFile -Encoding UTF8

      Invoke-Click '.nav-btn[data-go=build]'
      Select-TestInstaller
      Invoke-Click '#segMode button[data-val=simple]'
      Invoke-Click '#segTarget button[data-val=intunewin]'
      Invoke-Click '#btn-build'
      Wait-Js "document.getElementById('screen-done').classList.contains('on') || document.getElementById('progress-error').style.display === 'block'" 300
      Assert ((Get-Text '#progress-error-title') -eq 'Build stopped by pre-deploy checks') 'A changed signer stops the build'
      Assert (Test-Shown '#preflight-override') "The stopped build offers 'Build anyway'"
      Save-Shot 'predeploy-blocked'
      Invoke-Click '#preflight-override'
      Wait-Build "'Build anyway'"
      Assert ((Get-Text '#done-sheet') -like '*Check overridden*') "Done sheet has a 'Check overridden' row"
      Save-Shot 'done-check-overridden' '#done-sheet'
    }
  }

  Invoke-Flow 'Printer package' {
    $driver = $null
    try { $driver = Get-PrinterDriver -Name 'Microsoft Print To PDF' -ErrorAction Stop } catch {}
    if (-not $driver) { Write-Notice "The inbox 'Microsoft Print To PDF' driver is missing - skipping the printer flow."; return }
    Invoke-Click '.nav-btn[data-go=build]'
    Invoke-Click '#segKind button[data-val=printer]'
    Assert ((Test-Shown '#printer-source-card') -and -not (Test-Shown '#app-source-card')) 'Printer kind swaps the installer card for the printer card'
    Clear-AppFields
    Write-Field '#f-printername' 'Click Test Printer'; Send-Input '#f-printername'
    Write-Field '#f-drivername' $driver.Name
    Write-Field '#f-driversourcepath' (Split-Path -Parent $driver.InfPath)
    Write-Field '#f-driverinf' (Split-Path -Leaf $driver.InfPath)
    Write-Field '#f-porthost' '127.0.0.1'
    Write-Field '#f-portnumber' '9100'
    Write-Field '#f-printerlocation' 'CI rack'
    Invoke-Click '#segMode button[data-val=runtime]'
    Invoke-Click '#segTarget button[data-val=intunewin]'
    Save-Shot 'build-form-printer' '#printer-source-card'
    Invoke-Click '#btn-build'
    Wait-Build 'Printer package build'
    Assert ((Get-Text '#done-sheet') -like '*As a dependency*Detection confirms the AppUpdater agent*') "Done sheet has the printer 'As a dependency' row"
    Save-Shot 'done-printer' '#done-sheet'
  }

  Invoke-Flow 'Portable zip' {
    Invoke-Click '.nav-btn[data-go=build]'
    Invoke-Click '#segKind button[data-val=app]'
    Clear-AppFields
    Select-TestInstaller $portableZip
    Assert ((Get-ChipText) -like '*portable app*Tool\tool.exe*') "The zip shows the 'portable app' chip"
    Invoke-Click '#segMode button[data-val=simple]'
    Invoke-Click '#segTarget button[data-val=psadt]'
    Test-BuildGuard 'Simple .intunewin only' 'A zip with the PSADT target'
    Save-Shot 'guard-zip-psadt' -KeepToasts
    Invoke-Click '#segTarget button[data-val=intunewin]'
    Assert (-not (Test-Shown '#scripts-wrap')) 'A zip hides the scripts section'
    Invoke-Click '#btn-build'
    Wait-Build 'Portable zip build'
    Save-Shot 'done-portable-zip' '#done-sheet'
  }

  Invoke-Flow 'MSIX package' {
    Invoke-Click '.nav-btn[data-go=build]'
    Clear-AppFields
    Select-TestInstaller $msixFile
    Assert ((Get-ChipText) -like '*All users*provisioned for every user*') 'The MSIX shows its provisioning chip'
    Invoke-Click '#segMode button[data-val=simple]'
    Invoke-Click '#segTarget button[data-val=intunewin]'
    Assert (-not (Test-Shown '#detectversion-wrap')) 'MSIX hides the minimum version for detection'
    Assert (-not (Test-Shown '#scripts-wrap')) 'MSIX hides the scripts section'
    Save-Shot 'build-form-msix'
    Invoke-Click '#btn-build'
    Wait-Build 'MSIX build'
    Save-Shot 'done-msix' '#done-sheet'
  }

  $unexpected = [string](Eval-Js "window.__errors.filter(function (m) { return m !== 'Invalid application message.'; }).join(' | ')")
  Assert ($unexpected -eq '') "no unexpected error messages reached the page$(if ($unexpected) { ': ' + $unexpected })"

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
  $env:APPUPDATER_TEST_INSTALLER = $originalTestInstaller
  $env:APPUPDATER_TEST_SCRIPT = $originalTestScript
  $env:APPUPDATER_TEST_IMAGE = $originalTestImage
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

Write-Host "Screenshots: $shotDir"
Write-Host ""
if ($script:fails.Count -gt 0) {
  Write-Host "$($script:fails.Count) check(s) FAILED" -ForegroundColor Red
  exit 1
}
Write-Host "All checks passed" -ForegroundColor Green
exit 0

# Not covered: OS-level window state; the Cloudflare setup past its first window; submitting to winget.
# File dialogs are answered by the APPUPDATER_TEST_* seams.
