#Requires -Version 5.1
param([string]$CaseDir = (Join-Path $env:TEMP ("angelia-demo-" + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))))

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$exe = Join-Path $root 'angelia.exe'
$fixture = Join-Path $root 'examples\controlled-events.xml'
if (-not (Test-Path -LiteralPath $exe) -or -not (Test-Path -LiteralPath $fixture)) {
    throw 'Angelia or its controlled example is missing from this package.'
}
if (Test-Path -LiteralPath $CaseDir) { throw "Choose a new case directory: $CaseDir already exists." }

& $exe case init $CaseDir
if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the case.' }
& $exe case import-xml $CaseDir $fixture
if ($LASTEXITCODE -ne 0) { throw 'Could not import the controlled example.' }
& $exe case analyze $CaseDir
if ($LASTEXITCODE -ne 0) { throw 'Could not analyze the case.' }
& $exe case verify $CaseDir
if ($LASTEXITCODE -ne 0) { throw 'Retained evidence failed verification.' }
$report = Join-Path $CaseDir 'report.html'
& $exe case report $CaseDir --out $report
if ($LASTEXITCODE -ne 0) { throw 'Could not export the case report.' }
Write-Host "Demo case: $CaseDir"
Write-Host "Open report: $report"
