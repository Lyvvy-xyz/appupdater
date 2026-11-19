param(
  [string]$Name = $env:APP_NAME,
  [string]$Url = $env:APP_URL,
  [ValidateSet('', 'simple', 'psadt-v3', 'psadt-v4', 'runtime', 'printer', 'dependency', 'upgrade', 'user', 'java')][string]$Scenario = $env:APP_SCENARIO,
  [string]$DependentUrl = $env:APP_URL2,
  # How a plain app is deployed: Simple .intunewin by default, or PSADT v3/v4 or Runtime in the weekly full run.
  [ValidateSet('', 'psadt-v3', 'psadt-v4', 'runtime')][string]$DeployType = $env:APP_DEPLOY,
  [string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1')
)
# Packages real installers the way the app does and deploys them on this machine as Intune would, by scenario:
#   simple      .intunewin: install, detect, uninstall, detect again (as SYSTEM, or as the user for per-user installers)
#   psadt-v3/4  branded PSADT package with a close-apps list that holds a running app, a missing name and a protected one
#   runtime     AppUpdater agent: deploy, detect, then run the agent task and confirm it installs the app
#   printer     printer package using the inbox Microsoft Print To PDF driver
#   upgrade     an older copy is installed first; it must not count as installed, and the package must upgrade it
#   user        a per-user installer installed, detected and uninstalled as a standard user
#   java        an MSI with properties, pre/post scripts and removal of an older side-by-side version
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
  # Vendor mirrors fail now and then (502s, refused connections) and old versions get removed; neither is a packaging
  # result. A fresh download is preferred; the copy cached by an earlier run is the fallback.
  $cached = if ($env:INSTALLER_CACHE) {
    $key = [BitConverter]::ToString([Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($From))).Replace('-', '').Substring(0, 16)
    Join-Path $env:INSTALLER_CACHE "$Label-$key"
  }
  for ($try = 1; ; $try++) {
    try {
      Invoke-WebRequest -Uri $From -OutFile $download -UseBasicParsing -UserAgent 'Mozilla/5.0' -TimeoutSec 900
      if ($cached) { [IO.Directory]::CreateDirectory($env:INSTALLER_CACHE) | Out-Null; Copy-Item -LiteralPath $download -Destination $cached -Force }
      break
    } catch {
      Write-Host "Download attempt $try failed: $($_.Exception.Message)"
      if ($try -lt 4) { Start-Sleep -Seconds (30 * $try); continue }
      if ($cached -and (Test-Path -LiteralPath $cached)) { Write-Host "Using the copy cached by an earlier run"; Copy-Item -LiteralPath $cached -Destination $download -Force; break }
      throw
    }
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
  # Pre-deploy checks against the real vendor file: a red finding on a genuine installer is a false alarm.
  $sig = Get-AuthenticodeSignature -LiteralPath $path
  $fingerprint = @{ sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; status = [string]$sig.Status; signer = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject }) }
  $kevPath = try { Update-KevCatalogue -CacheDir (Join-Path $root 'kev') -Url 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' } catch { Write-Host "CISA catalogue unavailable: $($_.Exception.Message)"; '' }
  $findings = @(Get-PreflightFindings -FormData @{ Version = $inspection.Version; InstallerPath = $path; Winget = $winget; KevPath = $kevPath
    Identity = @{ name = $inspection.DisplayName; publisher = $inspection.Publisher } } -Installer $fingerprint)
  # 7-Zip has a CISA entry (CVE-2025-0411), so its job also proves the awareness check matches real data.
  if ($Label -eq '7zip' -and $kevPath -and -not @($findings | Where-Object code -eq 'known-exploited').Count) { throw 'The CISA check found no entry for 7-Zip.' }
  Write-Host "[$Label] signature $($fingerprint.status) $(Get-SignerName $fingerprint.signer); pre-deploy findings: $(if ($findings.Count) { @($findings | ForEach-Object { "$($_.level) $($_.code)" }) -join ', ' } else { 'none' })"
  if (@($findings | Where-Object level -eq 'red').Count) { throw "Pre-deploy checks blocked a genuine installer: $(@($findings.message) -join ' ')" }
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

function Invoke-LocalTest([string]$OutputDir, [string]$AppId, [string]$Target, [bool]$Uninstall, [bool]$AsSystem, [hashtable]$RunAs = $null) {
  $log = [Collections.Queue]::Synchronized([Collections.Queue]::new())
  $done = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $runspace = [runspacefactory]::CreateRunspace()
  $powershell = [powershell]::Create()
  try {
    $runspace.Open()
    $variables = @{ _tq = $log; _td = $done; _out = $OutputDir; _appId = $AppId; _target = $Target; _alsoUninstall = $Uninstall; _simulateSystem = $AsSystem; _runAs = $RunAs; _epmFn = "function Write-EpmRules {`n$((Get-Item Function:\Write-EpmRules).ScriptBlock)`n}" }
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
  return @{ Ok = [bool]$done[0].ok; Suggestion = [string]$done[0].suggestedRegistryName; Version = [string]$done[0].suggestedDetectVersion }
}

function Test-Package($App, [hashtable]$Overrides = @{}, [bool]$Uninstall = $true, [hashtable]$Brand = @{}, [hashtable]$RunAs = $null) {
  # Learns the registry name the way an admin does in the app: take the suggestion, rebuild, test again.
  $registry = $App.Registry
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    $form = New-AppForm $App ($Overrides + @{ RegistryName = $registry })
    $build = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile $Brand
    $target = if ($form.SimplePkgTarget -eq 'psadt') { "psadt-$($form.PSADTVersion)" } else { 'intunewin' }
    $outcome = Invoke-LocalTest $build.OutputDir $App.AppId $target $Uninstall (-not $App.PerUser -and -not $RunAs) $RunAs
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
  if ($DeployType -eq 'runtime') { $Scenario = 'runtime' }
  $deployOverrides = if ($DeployType -like 'psadt-*') { @{ SimplePkgTarget = 'psadt'; PSADTVersion = $DeployType.Substring(6); AllowDefer = $false } } else { @{} }
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
      $outcome = Test-Package $app @{ Mode = 'runtime'; DownloadURL = $Url } $false
      $task = Invoke-AgentTask $app.AppId
      $installed = Find-ARPEntry -Target $app.Registry
      Write-Host "Agent installed the app: $([bool]$installed)$(if ($installed) { " ('$($installed.DisplayName)' $($installed.DisplayVersion))" })"
      if ($outcome.Ok -and $installed) { $summary.Result = $(if ($outcome.Learned) { 'PASS (learned name)' } else { 'PASS' }); $exitCode = 0 }
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
    'upgrade' {
      # An older copy is installed; the package must not count it as installed, and must upgrade it.
      $old = Get-Installer $DependentUrl "$Name-old"
      $app = Get-Installer $Url $Name
      $summary.Type = $app.Inspection.InstallerType; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $oldRun = Start-Process -FilePath $old.Path -ArgumentList $old.Silent -Wait -PassThru
      $oldEntry = Find-ARPEntry -Target $old.Registry
      Write-Host "Older copy installed (exit $($oldRun.ExitCode)): $($oldEntry.DisplayName) $($oldEntry.DisplayVersion)"
      $build = Invoke-HeadlessPackageBuild -Config $config -FormData (New-AppForm $app @{ DetectVersion = $app.Inspection.Version }) -Profile @{}
      $before = (Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $build.OutputDir 'detect.ps1')`"" -Wait -PassThru -NoNewWindow).ExitCode
      Write-Host "Detection with the older copy installed: exit $before (1 means not installed, so Intune upgrades it)"
      $outcome = Invoke-LocalTest $build.OutputDir $app.AppId 'intunewin' $true $true
      if ($before -ne 1) { $summary.Detail += 'The older copy counted as installed. ' }
      if ($oldEntry -and $before -eq 1 -and $outcome.Ok) { $summary.Result = 'PASS'; $exitCode = 0 }
    }
    'user' {
      # Intune's User install behaviour: install, detect and uninstall as a standard user, not as an administrator.
      $app = Get-Installer $Url $Name
      $summary.Type = "$($app.Inspection.InstallerType) (per-user)"; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $password = 'Ci-' + [guid]::NewGuid().ToString('N').Substring(0, 20) + '!a1'
      $secure = New-Object Security.SecureString
      foreach ($char in $password.ToCharArray()) { $secure.AppendChar($char) }
      New-LocalUser -Name 'ciuser' -Password $secure -PasswordNeverExpires | Out-Null
      # Scheduled tasks need "log on as a batch job", which Windows Server gives only to administrators by default.
      $sid = (Get-LocalUser -Name 'ciuser').SID.Value
      $exported = Join-Path $root 'rights.inf'
      secedit /export /cfg $exported /areas USER_RIGHTS | Out-Null
      $current = @(Get-Content -LiteralPath $exported | Where-Object { $_ -like 'SeBatchLogonRight*' }) | Select-Object -First 1
      $right = if ($current) { "$current,*$sid" } else { "SeBatchLogonRight = *$sid" }
      $policy = Join-Path $root 'batch.inf'
      Set-Content -LiteralPath $policy -Encoding Unicode -Value @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]', $right)
      secedit /configure /db (Join-Path $root 'batch.sdb') /cfg $policy /areas USER_RIGHTS | Out-Null
      Write-Host "ciuser can run scheduled tasks: secedit exit $LASTEXITCODE"
      $App.PerUser = $true
      $outcome = Test-Package $app @{ PerUser = $true } $true @{} @{ User = "$env:COMPUTERNAME\ciuser"; Password = $password }
      if ($outcome.Ok) { $summary.Result = $(if ($outcome.Learned) { 'PASS (learned name)' } else { 'PASS' }); $exitCode = 0 }
    }
    'java' {
      # An older JRE is already installed; the new package sets MSI features, runs scripts and removes the older copy.
      $old = Get-Installer $DependentUrl "$Name-old"
      $app = Get-Installer $Url $Name
      $summary.Type = $app.Inspection.InstallerType; $summary.Winget = $app.Winget; $summary.Registry = $app.Registry
      $oldInstall = Start-Process msiexec.exe -ArgumentList "/i `"$($old.Path)`" /qn /norestart" -Wait -PassThru
      $oldEntry = Find-ARPEntry -Target $old.Registry
      Write-Host "Older JRE installed (exit $($oldInstall.ExitCode)): $($oldEntry.DisplayName) $($oldEntry.DisplayVersion)"
      $markers = Join-Path $env:ProgramData 'ci-java'
      [IO.Directory]::CreateDirectory($markers) | Out-Null
      $hooks = @{}
      foreach ($hook in @(@{ Key = 'PreInstallHookPath'; Name = 'pre' }, @{ Key = 'PostInstallHookPath'; Name = 'post' }, @{ Key = 'PostUninstallHookPath'; Name = 'uninstalled' })) {
        $path = Join-Path $root "$($hook.Name).ps1"
        Set-Content -LiteralPath $path -Value "Set-Content -LiteralPath '$markers\$($hook.Name).txt' -Value ([Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine'))"
        $hooks[$hook.Key] = $path
      }
      $summary.Switch = 'ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJavaHome'
      $outcome = Test-Package $app ($hooks + @{ SimplePkgTarget = 'psadt'; PSADTVersion = 'v4'; AllowDefer = $false; SilentArgs = $summary.Switch
                                                RemoveOlderVersions = $true; DetectVersion = $app.Inspection.Version }) $true
      $oldGone = -not (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $oldEntry.DisplayName })
      $javaHome = if (Test-Path "$markers\post.txt") { (Get-Content "$markers\post.txt" -Raw).Trim() } else { '' }
      Write-Host "Older JRE removed: $oldGone; pre-install ran: $(Test-Path "$markers\pre.txt"); JAVA_HOME after install: '$javaHome'; post-uninstall ran: $(Test-Path "$markers\uninstalled.txt")"
      if (-not $oldGone) { $summary.Detail += 'The older JRE is still installed. ' }
      if (-not $javaHome) { $summary.Detail += 'JAVA_HOME was not set by the MSI feature. ' }
      if (-not ((Test-Path "$markers\pre.txt") -and (Test-Path "$markers\uninstalled.txt"))) { $summary.Detail += 'A pre-install or post-uninstall script did not run. ' }
      if ($outcome.Ok -and $oldGone -and $javaHome -and (Test-Path "$markers\pre.txt") -and (Test-Path "$markers\uninstalled.txt")) { $summary.Result = 'PASS'; $exitCode = 0 }
    }
    default {
      $app = Get-Installer $Url $Name
      $summary.Type = "$($app.Inspection.InstallerType)$(if ($app.PerUser) { ' (per-user)' })"; $summary.Winget = $app.Winget; $summary.Switch = $app.Silent; $summary.Registry = $app.Registry
      $outcome = Test-Package $app $deployOverrides
      if ($outcome.Ok -and $outcome.Version) {
        # Take the version the test read, as an admin would, and check detection accepts the app with it required.
        Write-Host "=== Rebuilding with minimum version $($outcome.Version)"
        $summary.Detail += "minimum version $($outcome.Version). "
        # Uninstalling was proven by the first pass; some uninstallers leave work for a reboot that a second one would trip over.
        $outcome = Test-Package $app ($deployOverrides + @{ DetectVersion = $outcome.Version }) $false
      }
      $epm = @(Import-Csv -LiteralPath (Join-Path $outcome.Build.OutputDir 'EPM-rules.csv') -ErrorAction SilentlyContinue)
      $epm | ForEach-Object { Write-Host "EPM: $($_.Role) $($_.FileName) $($_.SHA256) [$($_.SuggestedRule)] $($_.Signer)" }
      if (-not @($epm | Where-Object Role -eq 'installer').Count) { $summary.Detail += 'EPM-rules.csv has no installer row. '; $outcome.Ok = $false }
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
