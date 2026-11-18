param(
  [string]$Name = $env:APP_NAME,
  [string]$Url = $env:APP_URL,
  [string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1')
)
# Packages one real installer the way the app does, then installs, detects and uninstalls it as SYSTEM.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Real installs need Windows.' }
if (-not $Name -or $Url -notmatch '^https://') { throw 'Pass -Name and an https -Url (or APP_NAME and APP_URL).' }

$hostSource = [IO.File]::ReadAllText((Resolve-Path $HostPath))
$block = [regex]::Match($hostSource, '(?ms)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)').Groups[1].Value
$coreSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((([regex]::Matches($block, "'([A-Za-z0-9+/=]+)'") | ForEach-Object { $_.Groups[1].Value }) -join '')))
foreach ($source in @($coreSource, $hostSource)) {
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$null)
  foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
  }
}
foreach ($name in @('ArpMatchFnText', 'WingetSqliteSource')) {
  Set-Variable -Scope Global -Name $name -Value ([regex]::Match($coreSource, "(?ms)^\`$global:$name = @'\r?\n(.*?)^'@").Groups[1].Value)
}
Invoke-Expression $global:ArpMatchFnText
function Write-AppLog { param($Message, $Level = 'INFO') Write-Host "[$Level] $Message" }

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
$summary = [ordered]@{ App = $Name; Type = ''; Winget = ''; Switch = ''; Registry = ''; Result = 'FAIL'; Detail = '' }
$exitCode = 1
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $download = Join-Path $root 'download.bin'
  Invoke-WebRequest -Uri $Url -OutFile $download -UseBasicParsing -UserAgent 'Mozilla/5.0' -TimeoutSec 900
  $magic = [byte[]]::new(8)
  $stream = [IO.File]::OpenRead($download)
  try { [void]$stream.Read($magic, 0, 8) } finally { $stream.Dispose() }
  $leaf = [Uri]::UnescapeDataString(([Uri]$Url).Segments[-1])
  $leafExt = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
  $extension = if ([BitConverter]::ToString($magic) -eq 'D0-CF-11-E0-A1-B1-1A-E1') { '.msi' }
               elseif ($magic[0] -eq 0x50 -and $magic[1] -eq 0x4B) { if ($leafExt -in '.msix', '.msixbundle', '.appx', '.appxbundle') { $leafExt } else { '.zip' } }
               else { '.exe' }
  if ($leafExt -ne $extension) { $leaf = "$Name$extension" }
  $installer = Join-Path $root $leaf
  Move-Item -LiteralPath $download -Destination $installer

  $inspection = Invoke-InstallerInspector -InstallerPath $installer
  $summary.Type = $inspection.InstallerType
  $index = Update-WingetIndex -CacheDir $WingetCacheDir
  $winget = Find-WingetInstaller -InstallerPath $installer -ProductCode $inspection.ProductCode -Name $inspection.DisplayName `
    -Publisher $inspection.Publisher -Version $inspection.Version -IndexPath $index
  if ($winget) { $summary.Winget = "$($winget.Id) $($winget.Version) ($($winget.Match)$(if ($winget.Scope) { ", $($winget.Scope)" }))" }
  $silent = if ($winget -and $winget.SilentArgs) { $winget.SilentArgs } else { $inspection.SilentArgs }
  $registry = if ($inspection.PackageName) { $inspection.PackageName } elseif ($winget -and $winget.ArpName) { $winget.ArpName } else { $inspection.RegistryName }
  $summary.Switch = $silent; $summary.Registry = $registry
  Write-Host "Inspector: $($inspection.InstallerType) '$($inspection.DisplayName)' $($inspection.Version) by '$($inspection.Publisher)'"
  Write-Host "winget: $(if ($winget) { $summary.Winget } else { 'no match' })"
  Write-Host "Building with switch '$silent' and registry name '$registry'"

  $appId = ($Name -replace '[^A-Za-z0-9._-]', '')
  $form = @{ AppID = $appId; DisplayName = $inspection.DisplayName; PackageKind = 'App'; Mode = 'simple'; SimplePkgTarget = 'intunewin'
             PSADTVersion = 'v3'; InstallerPath = $installer; RegistryName = $registry; SilentArgs = $silent
             EntryExe = $inspection.EntryExe; Version = $inspection.Version }
  $build = Invoke-HeadlessPackageBuild -Config @{ OfflineMode = $true; WorkerURL = ''; ManifestToken = ''; OrgName = 'CI' } -FormData $form -Profile @{}

  $worker = (Get-Item Function:\Start-LocalTestJob).ScriptBlock.Ast.Find({ param($node)
    $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'AddScript' }, $true).Arguments[0].ScriptBlock.Extent.Text
  $log = [Collections.Queue]::Synchronized([Collections.Queue]::new())
  $done = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $runspace = [runspacefactory]::CreateRunspace()
  $powershell = [powershell]::Create()
  try {
    $runspace.Open()
    $variables = @{ _tq = $log; _td = $done; _out = $build.OutputDir; _appId = $appId; _target = 'intunewin'; _alsoUninstall = $true; _simulateSystem = $true }
    foreach ($key in $variables.Keys) { $runspace.SessionStateProxy.SetVariable($key, $variables[$key]) }
    $powershell.Runspace = $runspace
    [void]$powershell.AddScript($worker.Substring(1, $worker.Length - 2))
    $handle = $powershell.BeginInvoke()
    while (-not $handle.IsCompleted) {
      while ($log.Count) { Write-Host $log.Dequeue() }
      Start-Sleep -Milliseconds 500
    }
    $powershell.EndInvoke($handle) | Out-Null
    while ($log.Count) { $line = $log.Dequeue(); Write-Host $line; if ($line -match 'Add/Remove Programs|WARNING|ERROR') { $summary.Detail += "$($line.Trim()) " } }
  } finally { $powershell.Dispose(); $runspace.Dispose() }
  if ($done.Count -eq 1 -and $done[0].ok) { $summary.Result = 'PASS'; $exitCode = 0 }
} catch {
  $summary.Detail += $_.Exception.Message
  Write-Host "ERROR: $($_.Exception.Message)"
} finally {
  if ($env:GITHUB_STEP_SUMMARY) {
    $cells = $summary.Values | ForEach-Object { ([string]$_).Replace('|', '\|').Replace("`n", ' ') }
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "| App | Detected | winget | Switch | Registry name | Result | Notes |`n|---|---|---|---|---|---|---|`n| $($cells -join ' | ') |"
  }
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
exit $exitCode
