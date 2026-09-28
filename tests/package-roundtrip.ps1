param([string]$HostPath = (Join-Path $PSScriptRoot '../host.ps1'))
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This test requires Windows Authenticode and IntuneWinAppUtil.' }

$source = [IO.File]::ReadAllText((Resolve-Path $HostPath))
$block = [regex]::Match($source, '(?ms)^\$__CoreB64Chunks = @\(\r?\n(.*?)^\)').Groups[1].Value
$encoded = ([regex]::Matches($block, "'([A-Za-z0-9+/=]+)'") | ForEach-Object { $_.Groups[1].Value }) -join ''
$engine = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
foreach ($text in @($engine, $source)) {
  $tokens = $null; $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
  if ($errors) { throw ($errors.Message -join '; ') }
  foreach ($function in $ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Invoke-VerifiedPackager','Test-DownloadAuthenticode','Expand-IntuneWinForTest')
  }, $true)) {
    . ([scriptblock]::Create($function.Extent.Text))
  }
}
function Write-AppLog { param($Message, $Level) Write-Host "[$Level] $Message" }

$root = Join-Path ([IO.Path]::GetTempPath()) ('appupdater-roundtrip-' + [guid]::NewGuid().ToString('N'))
$inputFolder = Join-Path $root 'source'
$outputFolder = Join-Path $root 'output'
$extracted = Join-Path $root 'extracted'
[IO.Directory]::CreateDirectory($inputFolder) | Out-Null
[IO.Directory]::CreateDirectory($outputFolder) | Out-Null
$IntuneWinUtilPath = Join-Path $root 'IntuneWinAppUtil.exe'
$IntuneWinUtilURL = 'https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe'
try {
  # Package inert files; neither installation nor detection scripts are executed.
  [IO.File]::WriteAllText((Join-Path $inputFolder 'install.ps1'), 'exit 0')
  [IO.Directory]::CreateDirectory((Join-Path $inputFolder 'nested')) | Out-Null
  [IO.File]::WriteAllText((Join-Path $inputFolder 'nested/payload.txt'), "O'Brien & Sons fixture")
  $result = Invoke-VerifiedPackager -Arguments "-c `"$inputFolder`" -s `"install.ps1`" -o `"$outputFolder`" -q"
  if ($result.ExitCode -ne 0) { throw 'Real packaging failed.' }
  $package = Join-Path $outputFolder 'install.intunewin'
  if (-not (Test-Path -LiteralPath $package)) { throw 'Real packager produced no artifact.' }
  Expand-IntuneWinForTest $package $extracted
  foreach ($relativePath in @('install.ps1','nested/payload.txt')) {
    $expected = (Get-FileHash -LiteralPath (Join-Path $inputFolder $relativePath)).Hash
    $actual = (Get-FileHash -LiteralPath (Join-Path $extracted $relativePath)).Hash
    if ($expected -ne $actual) { throw "Package round trip changed $relativePath" }
  }
  Write-Host 'PASS signed Microsoft packager produces an archive our extractor reads without changing files'
  $passed = $true
} finally {
  if ($passed) { [IO.Directory]::Delete($root, $true) }
  else { Write-Host "Failure fixtures retained at $root" }
}
