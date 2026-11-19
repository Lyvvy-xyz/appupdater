param(
  [string]$Name = $env:APP_NAME,
  [string]$Url = $env:APP_URL,
  [ValidateSet('', 'simple', 'psadt-v3', 'psadt-v4', 'runtime', 'printer', 'dependency')][string]$Scenario = $env:APP_SCENARIO,
  [string]$DependentUrl = $env:APP_URL2,
  [string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1')
)
# Packages real installers the way the app does and deploys them on this machine as Intune would, by scenario:
#   simple      .intunewin: install, detect, uninstall, detect again (as SYSTEM, or as the user for per-user installers)
#   psadt-v3/4  branded PSADT package with a close-apps list that holds a running app, a missing name and a protected one
#   runtime     AppUpdater agent: deploy, detect, then run the agent task and confirm it installs the app
#   printer     printer package using the inbox Microsoft Print To PDF driver
#   dependency  the app stays installed and detected while a dependent PSADT app installs and uninstalls
$ErrorActionPreference = 'Stop'
if (-not $Scenario) { $Scenario = 'simple' }
if ($env:OS -ne 'Windows_NT') { throw 'Real installs need Windows.' }
if (-not $Name -or ($Scenario -ne 'printer' -and $Url -notmatch '^https://')) { throw 'Pass -Name and an https -Url (or APP_NAME and APP_URL).' }

$hostSource = [IO.File]::ReadAllText((Resolve-Path $HostPath))
$block = [regex]::Match($hostSource, '(?ms)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)').Groups[1].Value
$coreSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((([regex]::Matches($block, "'([A-Za-z0-9+/=]+)'") | ForEach-Object { $_.Groups[1].Value }) -join '')))
foreach ($source in @($coreSource, $hostSource)) {
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
  foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
    if ($node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -match '^\$script:(Install|Detect|Uninstall)PrinterScriptSrc$') { . ([scriptblock]::Create($node.Extent.Text)) }
  }
}
# Not $name: PowerShell variables ignore case, so it would overwrite $Name.
foreach ($sourceVariable in @('ArpMatchFnText', 'WingetSqliteSource')) {
  Set-Variable -Scope Global -Name $sourceVariable -Value ([regex]::Match($coreSource, "(?ms)^\`$global:$sourceVariable = @'\r?\n(.*?)^'@").Groups[1].Value)
}
Invoke-Expression $global:ArpMatchFnText
function Write-AppLog { param($Message, $Level = 'INFO') Write-Host "[$Level] $Message" }
function Show-WpfMsg { param($Title, $Message, $Type, [switch]$Confirm, $Detail, $YesLabel, $NoLabel)
  if ($Type -eq 'error') { throw "$Title $Message" }
  if ($Confirm) { return $true }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('appupdater-real-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$OutputBase = Join-Path $root 'output'
$TempBase = Join-Path $root 'temp'
$XmlFile = Join-Path $root 'appVersions.xml'
$IntuneWinUtilPath = Join-Path $root 'IntuneWinAppUtil.exe'
$IntuneWinUtilURL = 'https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe'
$WingetCacheDir = Join-Path $root 'winget'
$WingetCacheURL = 'https://cdn.winget.microsoft.com/cache'
$WingetIndexURL = 'https://cdn.winget.microsoft.com/cache/source.msix'
$PSADTCacheDir = Join-Path $root 'psadt'
$PSADTv3URL = 'https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/releases/latest/download/PSAppDeployToolkit_Template_v3.zip'
$PSADTModOnlyURL = 'https://github.com/PSAppDeployToolkit/PSAppDeployToolkit/releases/latest/download/PSAppDeployToolkit_ModuleOnly.zip'
$DriverStoreBase = Join-Path $root 'drivers'
$DriverLibraryFile = Join-Path $root 'driverLibrary.json'
$config = @{ OfflineMode = $true; WorkerURL = ''; ManifestToken = ''; OrgName = 'CI' }
$summary = [ordered]@{ App = "$Name ($Scenario)"; Type = ''; Winget = ''; Switch = ''; Registry = ''; Result = 'FAIL'; Detail = '' }
$exitCode = 1
$worker = (Get-Item Function:\Start-LocalTestJob).ScriptBlock.Ast.Find({ param($node)
  $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'AddScript' }, $true).Arguments[0].ScriptBlock.Extent.Text

function Get-Installer([string]$From, [string]$Label) {
  $download = Join-Path $root "$Label.download"
  # Vendor mirrors fail now and then (502s, refused connections); that is not a packaging result.
  for ($try = 1; ; $try++) {
    try { Invoke-WebRequest -Uri $From -OutFile $download -UseBasicParsing -UserAgent 'Mozilla/5.0' -TimeoutSec 900; break }
    catch { if ($try -ge 4) { throw }; Write-Host "Download attempt $try failed: $($_.Exception.Message)"; Start-Sleep -Seconds (30 * $try) }
  }
  $magic = [byte[]]::new(8)
  $stream = [IO.File]::OpenRead($download)
  try { [void]$stream.Read($magic, 0, 8) } finally { $stream.Dispose() }
  $leaf = [Uri]::UnescapeDataString(([Uri]$From).Segments[-1])
  $leafExt = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
  $extension = if ([BitConverter]::ToString($magic) -eq 'D0-CF-11-E0-A1-B1-1A-E1') { '.msi' }
               elseif ($magic[0] -eq 0x50 -and $magic[1] -eq 0x4B) { if ($leafExt -in '.msix', '.msixbundle', '.appx', '.appxbundle') { $leafExt } else { '.zip' } }
               else { '.exe' }
  if ($leafExt -ne $extension) { $leaf = "$Label$extension" }
  $folder = Join-Path $root "src-$Label"
  [IO.Directory]::CreateDirectory($folder) | Out-Null
  $path = Join-Path $folder $leaf
  Move-Item -LiteralPath $download -Destination $path
  $inspection = Invoke-InstallerInspector -InstallerPath $path
  $index = Update-WingetIndex -CacheDir $WingetCacheDir
  $winget = Find-WingetInstaller -InstallerPath $path -ProductCode $inspection.ProductCode -Name $inspection.DisplayName `
    -Publisher $inspection.Publisher -Version $inspection.Version -IndexPath $index
  $app = @{
    Path = $path; Inspection = $inspection; AppId = ($Label -replace '[^A-Za-z0-9._-]', '')
    Silent = $(if ($winget -and $winget.SilentArgs) { $winget.SilentArgs } else { $inspection.SilentArgs })
    Registry = $(if ($inspection.PackageName) { $inspection.PackageName } elseif ($winget -and $winget.ArpName) { $winget.ArpName } else { $inspection.RegistryName })
    PerUser = ($inspection.InstallerType -eq 'Squirrel') -or ($winget -and $winget.Scope -eq 'user')
    Winget = $(if ($winget) { "$($winget.Id) $($winget.Version) ($($winget.Match)$(if ($winget.Scope) { ", $($winget.Scope)" }))" } else { '' })
  }
  Write-Host "[$Label] inspector: $($inspection.InstallerType) '$($inspection.DisplayName)' $($inspection.Version) by '$($inspection.Publisher)'"
  Write-Host "[$Label] winget: $(if ($app.Winget) { $app.Winget } else { 'no match' }); switch '$($app.Silent)'; registry name '$($app.Registry)'"
  return $app
}

function New-AppForm($App, [hashtable]$Overrides = @{}) {
  $form = @{ AppID = $App.AppId; DisplayName = $App.Inspection.DisplayName; PackageKind = 'App'; Mode = 'simple'; SimplePkgTarget = 'intunewin'
             PSADTVersion = 'v3'; InstallerPath = $App.Path; RegistryName = $App.Registry; SilentArgs = $App.Silent
             EntryExe = $App.Inspection.EntryExe; Version = $App.Inspection.Version; AllowDefer = $true }
  foreach ($key in $Overrides.Keys) { $form[$key] = $Overrides[$key] }
  return $form
}

function Invoke-LocalTest([string]$OutputDir, [string]$AppId, [string]$Target, [bool]$Uninstall, [bool]$AsSystem) {
  $log = [Collections.Queue]::Synchronized([Collections.Queue]::new())
  $done = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $runspace = [runspacefactory]::CreateRunspace()
  $powershell = [powershell]::Create()
  try {
    $runspace.Open()
    $variables = @{ _tq = $log; _td = $done; _out = $OutputDir; _appId = $AppId; _target = $Target; _alsoUninstall = $Uninstall; _simulateSystem = $AsSystem }
    foreach ($key in $variables.Keys) { $runspace.SessionStateProxy.SetVariable($key, $variables[$key]) }
    $powershell.Runspace = $runspace
    [void]$powershell.AddScript($worker.Substring(1, $worker.Length - 2))
    $handle = $powershell.BeginInvoke()
    do {
      Start-Sleep -Milliseconds 500
      while ($log.Count) { $line = [string]$log.Dequeue(); Write-Host $line; if ($line -match 'Add/Remove Programs|WARNING|ERROR|Suggested') { $summary.Detail += "$($line.Trim()) " } }
    } while (-not $handle.IsCompleted -or $log.Count)
    $powershell.EndInvoke($handle) | Out-Null
  } finally { $powershell.Dispose(); $runspace.Dispose() }
  if ($done.Count -ne 1) { return @{ Ok = $false; Suggestion = '' } }
  return @{ Ok = [bool]$done[0].ok; Suggestion = [string]$done[0].suggestedRegistryName }
}

function Test-Package($App, [hashtable]$Overrides = @{}, [bool]$Uninstall = $true, [hashtable]$Brand = @{}) {
  # Learns the registry name the way an admin does in the app: take the suggestion, rebuild, test again.
  $registry = $App.Registry
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    $form = New-AppForm $App ($Overrides + @{ RegistryName = $registry })
    $build = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile $Brand
    $target = if ($form.SimplePkgTarget -eq 'psadt') { "psadt-$($form.PSADTVersion)" } else { 'intunewin' }
    $outcome = Invoke-LocalTest $build.OutputDir $App.AppId $target $Uninstall (-not $App.PerUser)
    $outcome.Build = $build; $outcome.Learned = ($attempt -eq 2)
    if ($outcome.Ok -or -not $outcome.Suggestion) { return $outcome }
    Write-Host "Rebuilding with the suggested registry name '$($outcome.Suggestion)'"
    $summary.Registry = "$registry -> $($outcome.Suggestion)"
    $registry = $outcome.Suggestion; $App.Registry = $registry
  }
  return $outcome
}

function Invoke-AgentTask([string]$AppId) {
  $task = "AppUpdater_$AppId"
  Start-ScheduledTask -TaskName $task
  $deadline = (Get-Date).AddMinutes(20)
  do { Start-Sleep -Seconds 5 } while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and (Get-Date) -lt $deadline)
  $result = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
  Write-Host "Agent task $task finished with result $result"
  Get-ChildItem -Path "C:\ProgramData\AppUpdater\$AppId" -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "--- $($_.Name)"; Get-Content -LiteralPath $_.FullName -Tail 25 | ForEach-Object { Write-Host "    $_" } }
  return $result
}

function New-Png([string]$Path, [int]$Width, [int]$Height) {
  Add-Type -AssemblyName System.Drawing
  $bitmap = New-Object Drawing.Bitmap $Width, $Height
  $graphics = [Drawing.Graphics]::FromImage($bitmap)
  try { $graphics.Clear([Drawing.Color]::SteelBlue); $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png) }
  finally { $graphics.Dispose(); $bitmap.Dispose() }
}

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  switch ($Scenario) {
    'printer' {
      $driver = Get-PrinterDriver -Name 'Microsoft Print To PDF' -ErrorAction Stop
      $form = @{ AppID = 'CIPrinter'; DisplayName = 'CI Printer'; PackageKind = 'Printer'; Mode = 'runtime'; SimplePkgTarget = 'intunewin'; PSADTVersion = 'v3'
                 PrinterName = 'CI Printer'; DriverName = $driver.Name; DriverSourcePath = (Split-Path -Parent $driver.InfPath)
                 DriverInfRelativePath = (Split-Path -Leaf $driver.InfPath); PortHostAddress = '127.0.0.1'; PortNumber = '9100'; Location = 'CI rack' }
      $summary.Type = 'Printer'; $summary.Registry = $driver.Name
      $build = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
      $outcome = Invoke-LocalTest $build.OutputDir 'CIPrinter' 'intunewin' $false $true
      $task = Invoke-AgentTask 'CIPrinter'
      $printer = Get-Printer -Name 'CI Printer' -ErrorAction SilentlyContinue
      Write-Host "Printer present: $([bool]$printer)$(if ($printer) { " (driver '$($printer.DriverName)', port '$($printer.PortName)')" })"
      if ($outcome.Ok -and $printer -and $task -eq 0) { $summary.Result = 'PASS'; $exitCode = 0 }
      elseif (-not $printer) {
        $summary.Detail += 'The printer was not created. '
        Write-Host '--- Install-Printer.ps1 run directly'
        $agentDir = 'C:\ProgramData\AppUpdater\CIPrinter'
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$agentDir\Install-Printer.ps1" -ConfigPath "$agentDir\printer-config.json" -DriverPackageDir "$agentDir\driver" 2>&1 |
          Select-Object -Last 30 | ForEach-Object { Write-Host "    $_" }
        Write-Host "    exit code $LASTEXITCODE"
      }
    }
    'runtime' {
      $app = Get-Installer $Url $Name
      $summary.Type = $app.Inspection.InstallerType; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $form = New-AppForm $app @{ Mode = 'runtime'; DownloadURL = $Url }
      $build = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
      $outcome = Invoke-LocalTest $build.OutputDir $app.AppId 'intunewin' $false $true
      $task = Invoke-AgentTask $app.AppId
      $installed = Find-ARPEntry -Target $app.Registry
      Write-Host "Agent installed the app: $([bool]$installed)$(if ($installed) { " ('$($installed.DisplayName)' $($installed.DisplayVersion))" })"
      if ($outcome.Ok -and $installed) { $summary.Result = 'PASS'; $exitCode = 0 }
      elseif (-not $installed) { $summary.Detail += "The agent task (result $task) did not install the app. " }
    }
    { $_ -in 'psadt-v3', 'psadt-v4' } {
      $app = Get-Installer $Url $Name
      $summary.Type = $app.Inspection.InstallerType; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $logo = Join-Path $root 'logo.png'; $banner = Join-Path $root 'banner.png'
      New-Png $logo 64 64; New-Png $banner 450 50
      $brand = @{ OrgName = 'Contoso CI'; LogoImagePath = $logo; BannerImagePath = $banner }
      $running = Start-Process notepad.exe -PassThru
      Write-Host "Started notepad (pid $($running.Id)) for the close-apps check"
      $overrides = @{ SimplePkgTarget = 'psadt'; PSADTVersion = $Scenario.Substring(6); AllowDefer = $false; ProcessesToKill = 'notepad,doesnotexist,explorer' }
      $outcome = Test-Package $app $overrides $true $brand
      $deploy = Get-Content -LiteralPath (Join-Path $outcome.Build.OutputDir 'Deploy-Application.ps1') -Raw
      $closed = -not (Get-Process -Id $running.Id -ErrorAction SilentlyContinue)
      $explorerKept = $deploy -notmatch 'InstallationWelcome[^\r\n]*explorer'
      Write-Host "notepad closed by PSADT: $closed; explorer left out of the close list: $explorerKept"
      if (-not $closed) { $summary.Detail += 'PSADT did not close the running app. ' }
      if (-not $explorerKept) { $summary.Detail += 'explorer is in the close list. ' }
      if ($outcome.Ok -and $closed -and $explorerKept) { $summary.Result = $(if ($outcome.Learned) { 'PASS (learned name)' } else { 'PASS' }); $exitCode = 0 }
    }
    'dependency' {
      $dependency = Get-Installer $Url "$Name-dependency"
      $dependent = Get-Installer $DependentUrl "$Name-dependent"
      $summary.Type = "$($dependency.Inspection.InstallerType) -> $($dependent.Inspection.InstallerType)"; $summary.Registry = "$($dependency.Registry) / $($dependent.Registry)"
      Write-Host '=== Dependency: install and keep'
      $first = Test-Package $dependency @{} $false
      Write-Host '=== Dependent app (PSADT v4, deferral off): install, detect, uninstall'
      $second = Test-Package $dependent @{ SimplePkgTarget = 'psadt'; PSADTVersion = 'v4'; AllowDefer = $false } $true
      $stillThere = Find-ARPEntry -Target $dependency.Registry
      Write-Host "Dependency still installed after the dependent app was removed: $([bool]$stillThere)"
      if ($first.Ok -and $second.Ok -and $stillThere) { $summary.Result = 'PASS'; $exitCode = 0 }
      elseif (-not $stillThere) { $summary.Detail += 'Removing the dependent app removed the dependency. ' }
    }
    default {
      $app = Get-Installer $Url $Name
      $summary.Type = "$($app.Inspection.InstallerType)$(if ($app.PerUser) { ' (per-user)' })"; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $outcome = Test-Package $app
      if ($outcome.Ok) { $summary.Result = $(if ($outcome.Learned) { 'PASS (learned name)' } else { 'PASS' }); $exitCode = 0 }
    }
  }
  if ($exitCode -ne 0) {
    # Burn and many EXE installers log to the SYSTEM or user temp folder; error lines usually name the failing step.
    Get-ChildItem -Path (Join-Path $env:windir 'Temp'), $env:TEMP -Filter '*.log' -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-45) } | Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
      ForEach-Object {
        Write-Host "--- $($_.FullName)"
        $lines = @(Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue)
        @($lines | Where-Object { $_ -match 'error|fail|return value 3|0x8' } | Select-Object -First 30) + @($lines | Select-Object -Last 10) | ForEach-Object { Write-Host "    $_" }
      }
  }
} catch {
  $summary.Detail += $_.Exception.Message
  Write-Host "ERROR: $($_.Exception.Message)"
  Write-Host $_.ScriptStackTrace
  if ($_.Exception.Message -match 'IntuneWinAppUtil') {
    # Rerun the packager on the kept staging folder with its output visible.
    foreach ($staged in @(Get-ChildItem -Path $OutputBase -Directory -Force -Filter '.building-*' | ForEach-Object { Get-ChildItem -Path (Join-Path $_.FullName 'output') -Directory })) {
      Write-Host "--- packaging $($staged.FullName) again"
      Get-ChildItem -LiteralPath $staged.FullName -Recurse -File -Force | Where-Object { $_.IsReadOnly -or $_.FullName.Length -gt 240 } |
        Select-Object -First 10 | ForEach-Object { Write-Host "    readonly=$($_.IsReadOnly) length=$($_.FullName.Length) $($_.FullName)" }
      $probe = Join-Path $root 'probe-out'
      [IO.Directory]::CreateDirectory($probe) | Out-Null
      & $IntuneWinUtilPath -c $staged.FullName -s 'Deploy-Application.ps1' -o $probe -q *>&1 | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" }
      Write-Host "    exit code $LASTEXITCODE"
    }
  }
} finally {
  if ($env:GITHUB_STEP_SUMMARY) {
    $cells = $summary.Values | ForEach-Object { ([string]$_).Replace('|', '\|').Replace("`n", ' ') }
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "| App | Detected | winget | Switch | Registry name | Result | Notes |`n|---|---|---|---|---|---|---|`n| $($cells -join ' | ') |"
  }
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
exit $exitCode
