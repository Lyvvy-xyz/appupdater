param([string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1'))
$ErrorActionPreference = 'Stop'
$hostSource = [IO.File]::ReadAllText((Resolve-Path $HostPath))
$block = [regex]::Match($hostSource, '(?ms)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)').Groups[1].Value
$encoded = ([regex]::Matches($block, "'([A-Za-z0-9+/=]+)'") | ForEach-Object { $_.Groups[1].Value }) -join ''
$coreSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
foreach ($testScript in @('../click-test.ps1','package-roundtrip.ps1','real-installs.ps1')) {
  $tokens = $null; $parseErrors = $null
  [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $testScript), [ref]$tokens, [ref]$parseErrors) | Out-Null
  if ($parseErrors) { throw ($parseErrors.Message -join '; ') }
}
foreach ($source in @($coreSource, $hostSource)) {
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors) { throw ($parseErrors.Message -join '; ') }
  foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) {
      . ([scriptblock]::Create($node.Extent.Text))
    }
    if ($node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -match '^\$script:(Install|Detect|Uninstall)PrinterScriptSrc$') {
      . ([scriptblock]::Create($node.Extent.Text))
    }
  }
}
function Assert($Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
  Write-Host "PASS $Message"
}
function Assert-Throws([scriptblock]$Body, [string]$Message) {
  $thrown = $false
  try { & $Body } catch { $thrown = $true }
  Assert $thrown $Message
}
function Write-AppLog { param($Message, $Level) }
function Invoke-TestWorker([string]$FunctionName, [hashtable]$Variables, [string]$Setup = '') {
  $definition = Get-Item "Function:\$FunctionName"
  $call = $definition.ScriptBlock.Ast.Find({ param($node)
    $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'AddScript'
  }, $true)
  $body = $call.Arguments[0].ScriptBlock.Extent.Text
  $runspace = [runspacefactory]::CreateRunspace()
  $powershell = [powershell]::Create()
  try {
    $runspace.Open()
    foreach ($key in $Variables.Keys) { $runspace.SessionStateProxy.SetVariable($key, $Variables[$key]) }
    $powershell.Runspace = $runspace
    [void]$powershell.AddScript($Setup + "`n" + $body.Substring(1, $body.Length - 2))
    $handle = $powershell.BeginInvoke()
    if (-not $handle.AsyncWaitHandle.WaitOne(30000)) { $powershell.Stop(); throw "$FunctionName timed out" }
    $powershell.EndInvoke($handle) | Out-Null
    if ($powershell.Streams.Error.Count -gt 0) { throw ($powershell.Streams.Error -join '; ') }
  } finally { $powershell.Dispose(); $runspace.Dispose() }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('appupdater-tests-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $DeployStatusFile = Join-Path $root 'deploy-status.json'
  $DeployHistoryFile = Join-Path $root 'deploy-history.json'
  $DeployHistoryMaxEvents = 500
  Set-DeployStatus -AppID 'Example' -AppName "O'Brien & Sons" -Target 'intunewin' -OutputDir 'example'
  Set-DeployStatus -AppID 'Example' -MarkDeployed
  $store = Get-DeployStatusStore
  Assert ($store.Example -is [hashtable] -and $store.Example.deployedAt) 'Deployment status survives save/reload/update'
  Assert (@(Get-DeployHistory).Count -eq 2) 'History appends after reload'
  $savedStatusWriter = (Get-Item Function:\Save-DeployStatusStore).ScriptBlock
  function Save-DeployStatusStore { param($Store) throw 'Simulated write failure' }
  Assert-Throws { Set-DeployStatus -AppID Example -MarkDeployed } 'Status write failure reaches the caller'
  Assert (@(Get-DeployHistory).Count -eq 2) 'Failed status writes do not create successful history entries'
  Set-Item Function:\Save-DeployStatusStore -Value $savedStatusWriter
  Assert (Test-Path "$DeployStatusFile.bak") 'Atomic writes retain previous state'
  [IO.File]::WriteAllText($DeployStatusFile, '{broken')
  Assert-Throws { Set-DeployStatus -AppID Example -MarkDeployed } 'Corrupt state blocks writes instead of erasing records'
  Assert ([IO.File]::ReadAllText($DeployStatusFile) -eq '{broken') 'Corrupt input remains available for recovery'
  Write-AtomicText -Path $DeployHistoryFile -Text '[]'
  Assert (@(Get-DeployHistory).Count -eq 0) 'Empty history remains an array'

  $file = Join-Path $root 'locked.json'
  Write-AtomicText -Path $file -Text '{"v":1}'
  $stream = [IO.File]::Open($file, 'Open', 'Read', 'None')
  try {
    if ($env:OS -eq 'Windows_NT') {
      Assert-Throws { Write-AtomicText -Path $file -Text '{"v":2}' } 'Locked state replacement fails safely'
    }
  } finally { $stream.Dispose() }
  Assert (@(Get-ChildItem $root -Filter '.write-*' -Force).Count -eq 0) 'Temporary state writes are cleaned up'

  $OutputBase = Join-Path $root 'output'
  $TempBase = Join-Path $root 'temp'
  $XmlFile = Join-Path $root 'appVersions.xml'
  $IntuneWinUtilPath = Join-Path $root 'fake-packager.exe'
  $IntuneWinUtilURL = 'https://invalid.example.test/never-used'
  $installer = Join-Path $root 'sample.exe'
  [IO.File]::WriteAllText($installer, 'Nullsoft fixture')
  [IO.File]::WriteAllText($IntuneWinUtilPath, 'fixture')
  $global:ArpMatchFnText = [regex]::Match($coreSource, "(?ms)^\`$global:ArpMatchFnText = @'\r?\n(.*?)^'@").Groups[1].Value
  $global:_DpapiPrefix = 'DPAPI:'; $global:_CredMgrSentinel = 'CREDMGR'
  $PSADTCacheDir = Join-Path $root 'toolkit'
  $config = @{ OfflineMode = $true; WorkerURL = ''; ManifestToken = ''; OrgName = "O'Brien" }
  $form = @{ AppID = 'Example'; DisplayName = "O'Brien & Sons"; PackageKind = 'App'; Mode = 'simple'; SimplePkgTarget = 'intunewin'; PSADTVersion = 'v3'; InstallerPath = $installer; RegistryName = "O'Brien & Sons" }
  function Test-DownloadAuthenticode { param($FilePath, $ExpectedPublisher) }
  if ($env:OS -ne 'Windows_NT') {
    function Unblock-File { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process {} }
  }
  function New-FakeProcess([int]$Code) {
    $process = [pscustomobject]@{ ExitCode = $Code; HasExited = $true }
    $process | Add-Member ScriptMethod WaitForExit { param($Timeout) return $true }
    $process | Add-Member ScriptMethod Refresh {}
    $process | Add-Member ScriptMethod Dispose {}
    return $process
  }
  function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle)
    $destination = [regex]::Match($ArgumentList, '-o "([^"]+)"').Groups[1].Value
    $setup = [regex]::Match($ArgumentList, '-s "([^"]+)"').Groups[1].Value
    [IO.File]::WriteAllText((Join-Path $destination ([IO.Path]::GetFileNameWithoutExtension($setup) + '.intunewin')), 'fixture artifact')
    return New-FakeProcess 0
  }
  function Show-WpfMsg { param($Title, $Message, $Type, [switch]$Confirm, $Detail, $YesLabel, $NoLabel)
    if ($Type -eq 'error') { throw "$Title $Message" }
    if ($Confirm) { return $true }
  }
  function Write-Host { param($Object, $ForegroundColor, [switch]$NoNewline) Microsoft.PowerShell.Utility\Write-Host $Object }
  $result = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert (Test-Path (Join-Path $result.OutputDir 'install.ps1')) 'Simple mode uses the simple generator'
  Assert (Test-Path (Join-Path $result.OutputDir 'detect.ps1')) 'Simple packages include detection'
  Assert ((Get-Content (Join-Path $result.OutputDir 'detect.ps1') -Raw) -match 'function Find-ARPEntry') 'Generated detection includes the shared registry matcher'
  $installText = Get-Content (Join-Path $result.OutputDir 'install.ps1') -Raw
  Assert ($installText -match '/S') 'Detected installer arguments reach generated install script'
  Assert ($installText.Contains('$proc.WaitForExit()') -and $installText -notmatch 'Wait = \$true') 'Install waits for the installer, not for programs it launches'
  Assert ($result.OutputDir -notmatch '\.building-') 'Only completed outputs are published'
  $ManifestPath = $XmlFile
  Write-AtomicText -Path $DeployStatusFile -Text '{}'
  Set-DeployStatus -AppID Example -AppName 'Simple Example' -Target intunewin -OutputDir $result.OutputDir
  Assert (@((Get-FleetPayload -Config $config).apps | Where-Object id -eq Example).Count -eq 1) 'Simple builds appear in Fleet without a runtime manifest'
  $form.Mode = 'runtime'
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{} } 'Runtime without an installer URL is rejected'
  $form.DownloadURL = 'https://vendor.example.test/example.exe'
  $form.Version = '1.2.3'
  $runtime = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert (Test-Path (Join-Path $runtime.OutputDir 'Deploy-Example.ps1')) 'Runtime build creates a deploy script'
  Assert (Test-Path $XmlFile) 'Runtime manifest is published after packaging'
  Assert (@(Get-ChildItem $OutputBase -Directory -Filter '.building-*' -Force).Count -eq 0) 'Successful builds remove their staging copies'
  $script:packagedErrors = @(); $script:packagedUninstall = ''
  function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle)
    $destination = [regex]::Match($ArgumentList, '-o "([^"]+)"').Groups[1].Value
    $setup = [regex]::Match($ArgumentList, '-s "([^"]+)"').Groups[1].Value
    $content = [regex]::Match($ArgumentList, '-c "([^"]+)"').Groups[1].Value
    foreach ($packaged in @(Get-ChildItem -LiteralPath $content -Filter '*.ps1' -File)) {
      $text = [IO.File]::ReadAllText($packaged.FullName)
      $syntax = Test-PSSyntaxErrors -Code $text
      if ($syntax) { $script:packagedErrors += "$($packaged.Name): $syntax" }
      if ($packaged.Name -eq 'uninstall.ps1') { $script:packagedUninstall = $text }
    }
    [IO.File]::WriteAllText((Join-Path $destination ([IO.Path]::GetFileNameWithoutExtension($setup) + '.intunewin')), 'fixture artifact')
    return New-FakeProcess 0
  }
  $awkward = $form.Clone()
  $awkward.DisplayName = 'Cash $1 "Pro" O''Brien'
  $awkward.RegistryName = 'Cash $1 "Pro" O''Brien'
  $awkward.ExpectedPublisher = "O'Brien Ltd"
  $awkward.LaunchExe = 'C:\Program Files\O''Brien $(x) "q"\app.exe'
  $awkward.InstallerSHA256 = 'ab' * 32
  $online = @{ OfflineMode = $false; WorkerURL = 'https://worker.invalid'; ManifestToken = ''; OrgName = 'Test' }
  $onlineBuild = Invoke-HeadlessPackageBuild -Config $online -FormData $awkward -Profile @{}
  $deployText = Get-Content (Join-Path $onlineBuild.OutputDir 'Deploy-Example.ps1') -Raw
  $agent = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([regex]::Match($deployText, "FromBase64String\('([^']+)'\)").Groups[1].Value))
  Assert ($script:packagedErrors.Count -eq 0) "Packaged scripts parse with quotes and dollar signs in form values: $($script:packagedErrors -join '; ')"
  Assert ($agent.Contains("`$ExpectedPublisher = 'O''Brien Ltd'") -and $agent.Contains('O''Brien `$(x) `"q`"\app.exe')) 'Form values are escaped in the endpoint script'
  Assert ($agent -match 'ToUnixTimeSeconds' -and $agent -notmatch '\[double\]::Parse') 'Endpoint telemetry timestamps are UTC'
  $versionRead = $agent.IndexOf('$xmlVersion = ([string]$appEntry.Version)')
  Assert ($versionRead -ge 0 -and $versionRead -lt $agent.IndexOf('$xmlVersion -notmatch')) 'Manifest version is read before it is validated'
  Assert ($agent.Contains("-eq 'NotSigned' -and -not `$ExpectedPublisher")) 'Unsigned installers never satisfy a pinned publisher'
  Assert ($agent.Contains('D0-CF-11-E0-A1-B1-1A-E1') -and $agent.Contains("'msiexec.exe'")) 'MSI downloads run through msiexec'
  Assert ($agent.Contains("ResponseUri.Scheme -ne 'https'") -and $agent.Contains('$bytesRead -ne $totalLen')) 'Downloads reject downgrades and truncation'
  Assert ($agent.Contains('$usRest = $matches[2].Trim()') -and $agent.Contains('"$usRest $usSilent".Trim()')) 'Agent removal keeps the uninstall string arguments'
  Assert ($agent.Contains('the agent stays to retry the removal')) 'Agent removal only removes itself once the app is gone'
  $rootInfo = Get-InstallerFolderInfo -InstallerPath ([IO.Path]::Combine([IO.Path]::GetPathRoot($root), 'setup.exe'))
  Assert ($rootInfo.IsRoot -and $rootInfo.Files -eq 0) 'A drive-root installer is refused without walking the drive'
  [xml]$awkwardManifest = [IO.File]::ReadAllText($XmlFile)
  $awkwardEntry = @($awkwardManifest.AppManifest.App | Where-Object ID -eq Example)
  Assert ($awkwardEntry.Count -eq 1 -and $awkwardEntry[0].DisplayName -ceq $awkward.DisplayName) 'Manifest replacement keeps dollar signs literal'
  Assert ($awkwardEntry[0].SHA256 -eq $awkward.InstallerSHA256) 'Manifest carries the pinned installer hash'
  $awkward.Mode = 'simple'
  Invoke-HeadlessPackageBuild -Config $config -FormData $awkward -Profile @{} | Out-Null
  Assert ($script:packagedErrors.Count -eq 0 -and $script:packagedUninstall.Contains("`$silent = '/S'")) "Simple uninstall uses the installer's own silent switch: $($script:packagedErrors -join '; ')"
  Assert ($script:packagedUninstall.Contains('QuietUninstallString')) 'Simple uninstall prefers the vendor silent command'
  Assert ($script:packagedUninstall.Contains('while ((Find-ARPEntry -Target') -and $script:packagedUninstall.Contains('-lt $deadline')) 'Uninstall waits for uninstallers that finish in the background'
  Assert ($script:packagedUninstall.Contains("-match 'Nullsoft') { `$silent = '/S' }")) 'Simple uninstall checks the uninstaller engine, not only the installer type'
  Invoke-Expression $global:ArpMatchFnText
  Assert ($null -eq (Find-ARPEntry -Target '---')) 'An empty registry name matches nothing'
  $configPath = Join-Path $root 'config.json'
  Write-AtomicText -Path $configPath -Text '{"OrgName":"First"}'
  Write-AtomicText -Path $configPath -Text '{"OrgName":"Second"}'
  [IO.File]::WriteAllText($configPath, '{broken')
  Assert ((Read-PersistedConfig -Path $configPath).OrgName -eq 'First') 'Damaged config falls back to its backup'
  Assert ($null -eq (Read-PersistedConfig -Path (Join-Path $root 'absent.json'))) 'Missing config stays a first run'
  [IO.File]::Delete("$XmlFile.bak")
  $form.Mode = 'simple'
  $manifestBefore = [IO.File]::ReadAllText($XmlFile)
  $result = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert ([IO.File]::ReadAllText($XmlFile) -ceq $manifestBefore -and -not (Test-Path "$XmlFile.bak")) 'Simple builds leave the runtime manifest untouched'

  [IO.Directory]::CreateDirectory((Join-Path $PSADTCacheDir 'AppDeployToolkit')) | Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $PSADTCacheDir 'PSAppDeployToolkit')) | Out-Null
  [IO.File]::WriteAllText((Join-Path $PSADTCacheDir 'AppDeployToolkit/AppDeployToolkitMain.ps1'), '# toolkit fixture')
  [IO.File]::WriteAllText((Join-Path $PSADTCacheDir 'PSAppDeployToolkit/PSAppDeployToolkit.psd1'), "@{ ModuleVersion = '4.1.8' }")
  function Get-PSADTToolkit { return $PSADTCacheDir }
  $form.SimplePkgTarget = 'psadt'; $form.PSADTVersion = 'both'
  $both = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert ($both.OutputDirs.Count -eq 2) 'PSADT both produces two completed variants'
  foreach ($path in $both.OutputDirs) {
    Assert (Test-Path (Join-Path $path 'Deploy-Application.ps1')) "PSADT deployment script exists: $([IO.Path]::GetFileName($path))"
  }
  $form.Mode = 'runtime'
  $bothRuntime = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert ($bothRuntime.OutputDirs.Count -eq 2) 'Runtime PSADT both produces two completed variants'
  $form.Mode = 'simple'
  $form.SimplePkgTarget = 'intunewin'

  $closing = $form.Clone()
  $closing.SimplePkgTarget = 'psadt'; $closing.PSADTVersion = 'both'; $closing.AllowDefer = $false
  $closing.ProcessesToKill = "notepad.exe, o'app;explorer,NOTEPAD,svchost.exe"
  foreach ($mode in @('simple', 'runtime')) {
    $closing.Mode = $mode
    $script:packagedErrors = @()
    $closingBuild = Invoke-HeadlessPackageBuild -Config $config -FormData $closing -Profile @{}
    $v3 = Get-Content (@($closingBuild.OutputDirs) -match 'v3$' | ForEach-Object { Join-Path $_ 'Deploy-Application.ps1' }) -Raw
    $v4 = Get-Content (@($closingBuild.OutputDirs) -match 'v4$' | ForEach-Object { Join-Path $_ 'Deploy-Application.ps1' }) -Raw
    Assert ($v4.Contains("-CloseProcesses @('notepad', 'o''app')") -and $v3.Contains("-CloseApps 'notepad,o''app'")) "PSADT $mode packages pass each process to close separately"
    Assert ($v3 -notmatch 'explorer|svchost' -and $v4 -notmatch 'explorer|svchost') "PSADT $mode packages never close shell or system processes"
    Assert ($v3 -notmatch '-AllowDefer' -and $v4 -notmatch '-AllowDefer' -and $script:packagedErrors.Count -eq 0) "PSADT $mode packages honour Allow deferral being off"
  }
  $closing.AllowDefer = $true; $closing.Mode = 'simple'; $closing.PSADTVersion = 'v4'
  $deferred = Invoke-HeadlessPackageBuild -Config $config -FormData $closing -Profile @{}
  Assert ((Get-Content (Join-Path $deferred.OutputDir 'Deploy-Application.ps1') -Raw).Contains('-AllowDefer -DeferTimes 3')) 'PSADT packages allow deferral by default'

  Assert ((ConvertTo-LooseVersion '1.2.3-beta') -eq [version]'1.2.3' -and (ConvertTo-LooseVersion '2024.10 build 5') -eq [version]'2024.10' -and
          (ConvertTo-LooseVersion '1, 0, 0, 3') -eq [version]'1.0.0.3' -and (ConvertTo-LooseVersion '7') -eq [version]'7.0') 'Loose versions read the leading dotted number'
  Assert ($null -eq (ConvertTo-LooseVersion 'latest') -and $null -eq (ConvertTo-LooseVersion '99999999999.1')) 'Unparseable versions compare as unknown'
  Assert ($runtime -and (Get-Content (Join-Path $runtime.OutputDir 'Deploy-Example.ps1') -Raw) -notmatch '\[version\]\(`?\$fv') 'Runtime agent no longer casts raw file versions'
  foreach ($case in @(@('Advanced Installer', 'AdvancedInstaller', '/exenoui'), @('InstallAware', 'InstallAware', '/s'), @('SquirrelSetup', 'Squirrel', '--silent'))) {
    $marked = Join-Path $root "marked-$($case[1]).exe"
    [IO.File]::WriteAllText($marked, "MZ fixture $($case[0]) fixture")
    $type = Get-InstallerType -Path $marked
    Assert ($type -eq $case[1] -and (Get-SilentArgs -Type $type).StartsWith($case[2])) "$($case[1]) installers are recognised"
  }
  $deepInno = Join-Path $root 'deep-inno.exe'
  [IO.File]::WriteAllBytes($deepInno, [byte[]](@(0) * 700000) + [Text.Encoding]::ASCII.GetBytes('Inno Setup'))
  Assert ((Get-InstallerType -Path $deepInno) -eq 'InnoSetup') 'Inno markers about 700 KB into the file are found'
  $wideSquirrel = Join-Path $root 'wide-squirrel.exe'
  [IO.File]::WriteAllBytes($wideSquirrel, [Text.Encoding]::Unicode.GetBytes('MZ SquirrelInstall'))
  Assert ((Get-InstallerType -Path $wideSquirrel) -eq 'Squirrel') 'UTF-16 installer markers are found'
  $unknown = Join-Path $root 'mystery.exe'
  [IO.File]::WriteAllText($unknown, 'MZ fixture with no installer marker')
  Assert ((Get-InstallerType -Path $unknown) -eq 'Unknown' -and -not (Get-SilentArgs -Type 'Unknown')) 'Unknown installers get no guessed switch'
  $mystery = $form.Clone(); $mystery.InstallerPath = $unknown; $mystery.SilentArgs = ''
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $mystery -Profile @{} } 'Unknown installers need an explicit silent switch'
  $inspected = Invoke-InstallerInspector -InstallerPath $unknown
  Assert ($inspected.DisplayName -eq 'mystery' -and $inspected.RegistryName -eq 'mystery') 'Installers without version info are named after the file, not another installed app'

  $vendorDir = Join-Path $root "vendor O'Brien"
  [IO.Directory]::CreateDirectory((Join-Path $vendorDir 'cabs')) | Out-Null
  $vendorSetup = Join-Path $vendorDir "setup `$x'.exe"
  [IO.File]::WriteAllText($vendorSetup, 'InstallShield fixture')
  [IO.File]::WriteAllText((Join-Path $vendorDir 'setup.iss'), '[fixture]')
  [IO.File]::WriteAllText((Join-Path $vendorDir 'cabs/data1.cab'), 'fixture')
  $bundle = $form.Clone()
  $bundle.InstallerPath = $vendorSetup; $bundle.BundleFolder = $true; $bundle.SilentArgs = '/s /f1"{pkg}\setup.iss"'
  $script:packagedErrors = @()
  $bundled = Invoke-HeadlessPackageBuild -Config $config -FormData $bundle -Profile @{}
  $bundledInstall = Get-Content (Join-Path $bundled.OutputDir 'install.ps1') -Raw
  Assert ($script:packagedErrors.Count -eq 0) "Bundled-folder scripts parse with awkward file names: $($script:packagedErrors -join '; ')"
  Assert ($bundledInstall.Contains("'src\setup `$x''.exe'") -and $bundledInstall.Contains(".Replace('{pkg}'")) 'Bundled install keeps the vendor file name and expands {pkg}'
  $bundle.SimplePkgTarget = 'psadt'
  $bundledPsadt = Invoke-HeadlessPackageBuild -Config $config -FormData $bundle -Profile @{}
  Assert ($script:packagedErrors.Count -eq 0) "Bundled-folder PSADT scripts parse: $($script:packagedErrors -join '; ')"
  foreach ($path in $bundledPsadt.OutputDirs) {
    Assert ((Test-Path (Join-Path $path 'SupportFiles/src/cabs/data1.cab')) -and (Test-Path (Join-Path $path 'SupportFiles/src/setup.iss'))) "PSADT package carries the whole installer folder: $([IO.Path]::GetFileName($path))"
  }
  $bundle.SimplePkgTarget = 'intunewin'; $bundle.Mode = 'runtime'; $bundle.DownloadURL = 'https://vendor.example.test/setup.exe'
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $bundle -Profile @{} } 'Runtime packages refuse folder bundling'
  $bundle.BundleFolder = $false
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $bundle -Profile @{} } 'Runtime packages refuse {pkg} in the silent switch'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  function New-ZipFixture([string]$Path, [hashtable]$Entries) {
    $zip = [IO.Compression.ZipFile]::Open($Path, 'Create')
    try { foreach ($name in $Entries.Keys) { $w = [IO.StreamWriter]::new($zip.CreateEntry($name).Open()); try { $w.Write($Entries[$name]) } finally { $w.Dispose() } } }
    finally { $zip.Dispose() }
  }
  $msix = Join-Path $root "Vendor O'App.msix"
  New-ZipFixture $msix @{ 'AppxManifest.xml' = "<Package xmlns='http://schemas.microsoft.com/appx/manifest/foundation/windows10'><Identity Name=""Vendor.OApp"" Version=""1.2.3.0"" Publisher=""CN=Vendor O'Brien, O=Vendor""/><Properties><DisplayName>ms-resource:AppName</DisplayName><PublisherDisplayName>Vendor</PublisherDisplayName></Properties></Package>" }
  $msixInfo = Invoke-InstallerInspector -InstallerPath $msix
  Assert ($msixInfo.InstallerType -eq 'MSIX' -and $msixInfo.PackageName -eq 'Vendor.OApp' -and $msixInfo.DisplayName -eq 'Vendor.OApp' -and $msixInfo.Version -eq '1.2.3.0') 'MSIX identity is read from its manifest'
  $msixForm = $form.Clone(); $msixForm.InstallerPath = $msix; $msixForm.SilentArgs = ''; $msixForm.RegistryName = $msixInfo.PackageName; $msixForm.Version = $msixInfo.Version
  $script:packagedErrors = @()
  $msixBuild = Invoke-HeadlessPackageBuild -Config $config -FormData $msixForm -Profile @{}
  $msixDetect = Get-Content (Join-Path $msixBuild.OutputDir 'detect.ps1') -Raw
  Assert ($script:packagedErrors.Count -eq 0 -and (Get-Content (Join-Path $msixBuild.OutputDir 'install.ps1') -Raw).Contains('Add-AppxProvisionedPackage') -and
          $msixDetect.Contains("-eq 'Vendor.OApp'") -and $msixDetect.Contains("'1.2.3.0'")) "MSIX packages provision for all users and detect by package name: $($script:packagedErrors -join '; ')"
  $msixForm.SimplePkgTarget = 'psadt'
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $msixForm -Profile @{} } 'MSIX packages are .intunewin only'

  $portable = Join-Path $root 'portable.zip'
  New-ZipFixture $portable @{ 'Tool/tool.exe' = ('MZ' + ('x' * 4000)); 'Tool/uninstall.exe' = ('MZ' + ('x' * 9000)); 'Tool/readme.txt' = 'fixture' }
  $zipInfo = Invoke-InstallerInspector -InstallerPath $portable
  Assert ($zipInfo.InstallerType -eq 'Zip' -and $zipInfo.EntryExe -eq 'Tool\tool.exe' -and $zipInfo.DisplayName -eq 'tool') 'Portable zips name their main program, skipping helpers'
  $zipForm = $form.Clone(); $zipForm.InstallerPath = $portable; $zipForm.SilentArgs = ''; $zipForm.EntryExe = $zipInfo.EntryExe; $zipForm.Version = '2.0'
  $zipForm.DisplayName = 'Tool: "Pro"'; $zipForm.RegistryName = "Tool O'Pro"
  $script:packagedErrors = @(); $script:packagedUninstall = ''
  $zipBuild = Invoke-HeadlessPackageBuild -Config $config -FormData $zipForm -Profile @{}
  $zipInstall = Get-Content (Join-Path $zipBuild.OutputDir 'install.ps1') -Raw
  Assert ($script:packagedErrors.Count -eq 0 -and $zipInstall.Contains("'Tool\tool.exe'") -and $zipInstall.Contains("DisplayName = 'Tool O''Pro'") -and
          $zipInstall.Contains('Programs\Tool Pro.lnk') -and $script:packagedUninstall.Contains('AppUpdater-Example')) "Portable zips install, register and uninstall themselves: $($script:packagedErrors -join '; ')"
  $zipForm.EntryExe = ''
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $zipForm -Profile @{} } 'A zip without a program is refused'

  $folderInfo = Get-InstallerFolderInfo -InstallerPath $vendorSetup
  Assert ($folderInfo.Files -eq 3 -and -not $folderInfo.IsRoot -and -not $folderInfo.TooMany) 'Folder info counts every bundled file'

  $global:WingetSqliteSource = [regex]::Match($coreSource, "(?ms)^\`$global:WingetSqliteSource = @'\r?\n(.*?)^'@").Groups[1].Value
  if ($env:OS -ne 'Windows_NT') { $global:WingetSqliteSource = $global:WingetSqliteSource.Replace('"winsqlite3.dll"', '"libsqlite3.so.0"') }
  $wingetIndex = Join-Path $PSScriptRoot 'fixtures/winget-index.db'
  $wingetFile = Join-Path $root 'VendorAppSetup.exe'
  [IO.File]::WriteAllText($wingetFile, 'MZ vendor app fixture')
  $wingetSha = (Get-FileHash -LiteralPath $wingetFile -Algorithm SHA256).Hash
  $wingetManifests = @{
    'manifests/v/Vendor/App/1.0.0/aaaa' = @"
PackageIdentifier: Vendor.App
Description: A long description that
  folds onto a second line.
Copyright: "\xA9 Vendor \u00AE"
InstallerType: inno
Scope: machine
InstallerSwitches:
  Custom: /MERGETASKS=!runcode
Installers:
- Architecture: x86
  InstallerSha256: 0000
- Architecture: x64
  InstallerSha256: $wingetSha
  AppsAndFeaturesEntries:
  - DisplayName: 'Vendor App ''One'''
Tags:
- one
- two
"@
    'manifests/v/Vendor/App/2.0.0/bbbb' = @"
InstallerType: exe
Installers:
- Architecture: x64
  Scope: user
  InstallerSwitches:
    Silent: --silent
  InstallerSha256: FFFF
"@
    'manifests/v/Vendor/App/Beta/3.0.0-beta/cccc' = "InstallerType: nullsoft`nInstallers:`n- Architecture: x64`n  InstallerSha256: EEEE"
    'manifests/o/Other/App/2.0.0/dddd' = "InstallerType: msi`nInstallers:`n- Architecture: x64`n  ProductCode: '{11111111-2222-3333-4444-555555555555}'`n  InstallerSha256: DDDD"
  }
  $fetch = { param($Path) $wingetManifests[$Path] }.GetNewClosure()
  $yaml = ConvertFrom-SimpleYaml $wingetManifests['manifests/v/Vendor/App/1.0.0/aaaa']
  Assert ($yaml.Description -eq 'A long description that folds onto a second line.' -and $yaml.Copyright -eq "$([char]0xA9) Vendor $([char]0xAE)") 'YAML reader folds scalars and decodes escapes'
  Assert ($yaml.Installers.Count -eq 2 -and $yaml.Installers[1].AppsAndFeaturesEntries[0].DisplayName -eq "Vendor App 'One'" -and ($yaml.Tags -join ',') -eq 'one,two') 'YAML reader handles lists of maps and scalars'
  $exact = Find-WingetInstaller -InstallerPath $wingetFile -Name 'Vendor App' -Publisher 'Vendor Inc.' -Version '1.0.0' -IndexPath $wingetIndex -GetManifest $fetch
  Assert ($exact.Id -eq 'Vendor.App' -and $exact.Version -eq '1.0.0' -and $exact.Match -eq 'hash' -and $exact.InstallerType -eq 'inno' -and $exact.Scope -eq 'machine') 'winget matches an older version by file hash'
  Assert ($exact.SilentArgs -eq '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /MERGETASKS=!runcode' -and $exact.ArpName -eq "Vendor App 'One'") 'winget switches add Custom to the family default and carry the ARP name'
  $newer = Find-WingetInstaller -InstallerPath $wingetFile -Name 'Vendor App' -Publisher 'Vendor' -Version '9.9' -IndexPath $wingetIndex -GetManifest $fetch
  Assert ($newer.Id -eq 'Vendor.App' -and $newer.Version -eq '2.0.0' -and $newer.Match -eq 'name' -and $newer.SilentArgs -eq '--silent' -and $newer.Scope -eq 'user') 'Channel variants fall back to the main package newest manifest'
  $wingetMsi = Join-Path $root 'other.msi'
  [IO.File]::WriteAllText($wingetMsi, 'msi fixture')
  $byCode = Find-WingetInstaller -InstallerPath $wingetMsi -ProductCode '{11111111-2222-3333-4444-555555555555}' -IndexPath $wingetIndex -GetManifest $fetch
  Assert ($byCode.Id -eq 'Other.App' -and $byCode.Match -eq 'productcode' -and $byCode.SilentArgs -eq '/qn /norestart') 'MSIs match by product code'
  Assert ($null -eq (Find-WingetInstaller -InstallerPath $wingetFile -Name 'Shared Name' -IndexPath $wingetIndex -GetManifest $fetch)) 'Unrelated packages sharing a name are not guessed between'
  Assert ($null -eq (Find-WingetInstaller -InstallerPath $wingetFile -Name 'Vendor App' -IndexPath (Join-Path $root 'absent.db') -GetManifest $fetch)) 'A missing catalogue means no winget data'
  Assert ((ConvertTo-WingetNormalName 'Python 3.12.6 (64-bit)') -eq 'python' -and (ConvertTo-WingetNormalName 'PowerToysSetup-0.83.0-x64') -eq 'powertoys' -and (ConvertTo-WingetNormalName 'Discord - https://discord.com/') -eq 'discord' -and
          (ConvertTo-WingetNormalName 'Slack Technologies, LLC' -Publisher) -eq 'slacktechnologies') 'Names normalise like the winget index'

  $captured = Get-BuildFunctionSource
  $done = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $variables = @{ _bq = [Collections.Queue]::Synchronized([Collections.Queue]::new()); _bd = $done
    _cfg = $config; _fd = $form.Clone(); _profile = @{}; _fnSrc = $captured
    OutputBase = $OutputBase; TempBase = $TempBase; XmlFile = $XmlFile
    IntuneWinUtilPath = $IntuneWinUtilPath; ArpMatchFnText = $global:ArpMatchFnText }
  Invoke-TestWorker 'Start-PackageBuildJob' $variables
  Assert ($done.Count -eq 1 -and $done[0].ok) "Real build runspace returns success: $($done[0].message)"
  $driver = Join-Path $root 'driver'
  [IO.Directory]::CreateDirectory($driver) | Out-Null
  [IO.File]::WriteAllText((Join-Path $driver 'driver.inf'), '[Version]')
  $printerForm = @{ AppID = 'PrinterExample'; DisplayName = "O'Brien printer"; PackageKind = 'Printer'; Mode = 'runtime'
    SimplePkgTarget = 'intunewin'; DriverSourcePath = $driver; DriverInfRelativePath = 'driver.inf'; DriverName = 'Test driver'
    PrinterName = 'Test printer'; PortHostAddress = '192.0.2.1' }
  $done.Clear(); $variables._fd = $printerForm
  foreach ($sourceName in @('InstallPrinterScriptSrc','DetectPrinterScriptSrc','UninstallPrinterScriptSrc')) {
    $variables[$sourceName] = Get-Variable -Name $sourceName -ValueOnly -Scope Script
  }
  Invoke-TestWorker 'Start-PackageBuildJob' $variables
  Assert ($done.Count -eq 1 -and $done[0].ok) "Printer runspace receives its engine scripts: $($done[0].message)"
  Assert (Test-Path (Join-Path $done[0].path 'driver/driver.inf')) 'Printer build retains driver payload'
  $printerForm.SimplePkgTarget = 'psadt'; $printerForm.PSADTVersion = 'v4'
  $variables.PSADTCacheDir = $PSADTCacheDir; $done.Clear()
  Invoke-TestWorker 'Start-PackageBuildJob' $variables
  Assert ($done.Count -eq 1 -and $done[0].ok) "Printer PSADT build succeeds: $($done[0].message)"
  Assert (Test-Path (Join-Path $done[0].path 'SupportFiles/driver/driver.inf')) 'Printer PSADT includes the driver payload'
  $variables._fd = $form.Clone()

  $testFolder = Join-Path $root 'local-test'
  [IO.Directory]::CreateDirectory($testFolder) | Out-Null
  foreach ($name in @('install.ps1','detect.ps1','uninstall.ps1','Deploy-Application.ps1')) {
    [IO.File]::WriteAllText((Join-Path $testFolder $name), '# fixture; execution replaced in test runspace')
  }
  $testDone = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $testCalls = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
  $testVariables = @{ _td = $testDone; _tq = [Collections.Queue]::Synchronized([Collections.Queue]::new())
    _out = $testFolder; _appId = 'Example'; _target = 'intunewin'; _alsoUninstall = $true; _simulateSystem = $false
    Calls = $testCalls; ExitCodes = [Collections.Queue]::new() }
  $processSetup = @'
function Start-Process {
  param($FilePath, $ArgumentList, [switch]$PassThru, [switch]$NoNewWindow)
  [void]$Calls.Add($ArgumentList)
  $process = [pscustomobject]@{ ExitCode = $ExitCodes.Dequeue(); HasExited = $true }
  $process | Add-Member ScriptMethod WaitForExit { param($Timeout) return $true }
  $process | Add-Member ScriptMethod Refresh {}
  $process | Add-Member ScriptMethod Dispose {}
  return $process
}
'@
  foreach ($code in @(1,0,0,0,1)) { $testVariables.ExitCodes.Enqueue($code) }
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and $testDone[0].ok -and $testCalls.Count -eq 5) 'Local test worker reports verified install/uninstall completion'
  $testDone.Clear(); $testCalls.Clear(); $testVariables.ExitCodes.Clear()
  foreach ($code in @(1,23)) { $testVariables.ExitCodes.Enqueue($code) }
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and -not $testDone[0].ok -and $testCalls.Count -eq 2) 'Local test stops and reports installer failure'
  $testDone.Clear(); $testCalls.Clear(); $testVariables.ExitCodes.Clear()
  $testVariables._target = 'psadt'
  foreach ($code in @(0,0,0,1)) { $testVariables.ExitCodes.Enqueue($code) }
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and $testDone[0].ok -and $testCalls.Count -eq 4) 'PSADT local test verifies detection after install and uninstall'
  $testDone.Clear(); $testCalls.Clear()
  [IO.File]::Move((Join-Path $testFolder 'detect.ps1'), (Join-Path $testFolder 'detect.saved'))
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and -not $testDone[0].ok -and $testCalls.Count -eq 0) 'Missing detection fails before installing anything'
  [IO.File]::Move((Join-Path $testFolder 'detect.saved'), (Join-Path $testFolder 'detect.ps1'))
  [IO.File]::WriteAllText((Join-Path $testFolder 'damaged.intunewin'), 'not a package')
  $testDone.Clear(); $testCalls.Clear()
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and -not $testDone[0].ok -and $testCalls.Count -eq 0) 'Damaged archive fails without running loose scripts'
  [IO.File]::Move((Join-Path $testFolder 'damaged.intunewin'), (Join-Path $root 'damaged.saved'))
  # AES-CBC encrypted ZIP fixture.
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $inner = Join-Path $root 'inner'
  $outer = Join-Path $root 'outer'
  [IO.Directory]::CreateDirectory($inner) | Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $outer 'IntuneWinPackage/Metadata')) | Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $outer 'IntuneWinPackage/Contents')) | Out-Null
  [IO.File]::WriteAllText((Join-Path $inner 'Deploy-Example.ps1'), '# packaged fixture')
  $innerZip = Join-Path $root 'inner.zip'
  [IO.Compression.ZipFile]::CreateFromDirectory($inner, $innerZip)
  $aes = [Security.Cryptography.Aes]::Create()
  $encryptor = $aes.CreateEncryptor()
  try {
    $bytes = [IO.File]::ReadAllBytes($innerZip)
    $cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    $header = New-Object byte[] 32
    [IO.File]::WriteAllBytes((Join-Path $outer 'IntuneWinPackage/Contents/contents'), [byte[]]($header + $aes.IV + $cipher))
    $metadata = '<ApplicationInfo><EncryptionInfo><EncryptionKey>' + [Convert]::ToBase64String($aes.Key) + '</EncryptionKey></EncryptionInfo></ApplicationInfo>'
    [IO.File]::WriteAllText((Join-Path $outer 'IntuneWinPackage/Metadata/Detection.xml'), $metadata)
  } finally { $encryptor.Dispose(); $aes.Dispose() }
  [IO.Compression.ZipFile]::CreateFromDirectory($outer, (Join-Path $testFolder 'fixture.intunewin'))
  $testVariables._target = 'intunewin'; $testVariables._alsoUninstall = $false
  $testDone.Clear(); $testCalls.Clear(); $testVariables.ExitCodes.Clear()
  foreach ($code in @(1,0,0)) { $testVariables.ExitCodes.Enqueue($code) }
  Invoke-TestWorker 'Start-LocalTestJob' $testVariables $processSetup
  Assert ($testDone.Count -eq 1 -and $testDone[0].ok -and $testCalls.Count -eq 3) 'Encrypted runtime package uses sidecar detection and real extraction'
  Assert ($testCalls[1] -match 'iwt_extracted_' -and $testCalls[1] -match 'Deploy-Example.ps1') 'Local test runs the extracted deploy script'

  $originalPackage = [IO.File]::ReadAllText((Join-Path $result.OutputDir 'Example-Simple.intunewin'))
  function Start-Process { param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle) return New-FakeProcess 23 }
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{} } 'Packaging failure is reported'
  Assert ([IO.File]::ReadAllText((Join-Path $result.OutputDir 'Example-Simple.intunewin')) -eq $originalPackage) 'Failed rebuild preserves previous package'
  $done.Clear(); $variables._fnSrc = Get-BuildFunctionSource
  Invoke-TestWorker 'Start-PackageBuildJob' $variables
  Assert ($done.Count -eq 1 -and -not $done[0].ok) 'Real build runspace reports packaging failure'
  $form.AppID = '../escape'
  Assert-Throws { Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{} } 'Path traversal rejected before building'

  $captured = Get-BuildFunctionSource
  Assert ($captured -match 'function Invoke-SimpleBuildCore' -and $captured -match 'function ConvertTo-PSDQ' -and $captured -match 'function Test-PSSyntaxErrors') 'Runspace includes transitive build dependencies'
  Assert ($captured -notmatch 'function Show-WpfAppForm') 'Build runspace excludes legacy interactive forms'
  Microsoft.PowerShell.Utility\Write-Host 'All reliability checks passed.'
  $passed = $true
} finally {
  if ($passed) { [IO.Directory]::Delete($root, $true) }
  else { Microsoft.PowerShell.Utility\Write-Host "Failure fixtures retained at $root" }
}
