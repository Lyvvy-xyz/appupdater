param([string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1'))
$ErrorActionPreference = 'Stop'
$hostSource = [IO.File]::ReadAllText((Resolve-Path $HostPath))
$block = [regex]::Match($hostSource, '(?ms)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)').Groups[1].Value
$encoded = ([regex]::Matches($block, "'([A-Za-z0-9+/=]+)'") | ForEach-Object { $_.Groups[1].Value }) -join ''
$coreSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
$tokens = $null; $parseErrors = $null
[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../click-test.ps1'), [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors) { throw ($parseErrors.Message -join '; ') }
foreach ($source in @($coreSource, $hostSource)) {
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors) { throw ($parseErrors.Message -join '; ') }
  # Load declarations only: never elevate, launch the UI, or install software.
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
  # Exercise the real generators; only the external executable is replaced.
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
  $form.Mode = 'simple'
  $manifestBefore = [IO.File]::ReadAllText($XmlFile)
  $result = Invoke-HeadlessPackageBuild -Config $config -FormData $form -Profile @{}
  Assert ([IO.File]::ReadAllText($XmlFile) -ceq $manifestBefore -and -not (Test-Path "$XmlFile.bak")) 'Simple builds leave the runtime manifest untouched'

  # Toolkit fixtures check generation/routing only; no toolkit code executes.
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
  # Build an AES-CBC encrypted ZIP fixture, exercising real streaming extraction.
  # This checks extraction, not Microsoft packager compatibility or signatures.
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
  # Only this test-owned GUID directory; never application data.
  if ($passed) { [IO.Directory]::Delete($root, $true) }
  else { Microsoft.PowerShell.Utility\Write-Host "Failure fixtures retained at $root" }
}
