#Requires -Version 5.1
param(
    [ValidateSet('run','helper','collect')][string]$Mode = 'run',
    [string]$CaseDir = '',
    [int]$Duration = 30
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $repo 'build\default\bin\angelia.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Build Angelia first: $exe" }
if (-not $CaseDir) { $CaseDir = Join-Path $repo ('cases\snapshot-validation-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')) }
$CaseDir = [IO.Path]::GetFullPath($CaseDir)
$incoming = Join-Path $CaseDir 'incoming'
$ready = Join-Path $incoming 'workload-ready.txt'
$trigger = Join-Path $incoming 'workload-trigger.txt'
$done = Join-Path $incoming 'workload-done.txt'
$cancel = Join-Path $incoming 'workload-cancel.txt'
$exitFile = Join-Path $incoming 'collection-exit.txt'
$log = Join-Path $incoming 'collection.log'

if ($Mode -eq 'helper') {
    Set-Content -LiteralPath $ready -Value $PID -Encoding Ascii
    for ($i=0; $i -lt 600; $i++) {
        if (Test-Path -LiteralPath $cancel) { exit 0 }
        if (Test-Path -LiteralPath $trigger) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $trigger)) { exit 3 }
    $work = Join-Path $incoming 'workload'
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    for ($i=0; $i -lt 30; $i++) {
        $file = Join-Path $work ("sample-$i.txt")
        Set-Content -LiteralPath $file -Value ("Angelia snapshot validation event $i") -Encoding Ascii
        Get-Content -LiteralPath $file | Out-Null
    }
    Rename-Item -LiteralPath (Join-Path $work 'sample-0.txt') -NewName 'renamed-0.txt'
    $reg = 'HKCU:\Software\AngeliaLiveValidation\' + ([IO.Path]::GetFileName($CaseDir))
    New-Item -Path $reg -Force | Out-Null
    New-ItemProperty -Path $reg -Name 'Marker' -PropertyType String -Value 'snapshot-link-check' -Force | Out-Null
    Get-ItemProperty -Path $reg -Name 'Marker' | Out-Null
    Remove-Item -LiteralPath $reg -Force
    Set-Content -LiteralPath $done -Value $PID -Encoding Ascii
    exit 0
}

if ($Mode -eq 'collect') {
    try {
        # Windows PowerShell wraps native stderr as an ErrorRecord. Collector
        # progress uses stderr, so keep it in the log without terminating.
        $ErrorActionPreference = 'Continue'
        & $exe case collect $CaseDir --duration $Duration *> $log
        $result = $LASTEXITCODE
    } catch {
        $_ | Out-File -LiteralPath $log -Append
        $result = 2
    }
    Set-Content -LiteralPath $exitFile -Value $result -Encoding Ascii
    exit $result
}

if ($Duration -lt 10 -or $Duration -gt 120) { throw 'Duration must be 10..120 seconds.' }
if (Test-Path -LiteralPath $CaseDir) { throw "Choose a new case directory: $CaseDir already exists." }
& $exe case init $CaseDir
if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the case.' }
New-Item -ItemType Directory -Path $incoming -Force | Out-Null
$shell = (Get-Command powershell.exe).Source
$script = $PSCommandPath
$quotedScript = '"' + $script + '"'
$quotedCase = '"' + $CaseDir + '"'
$helper = Start-Process -FilePath $shell -WindowStyle Hidden -PassThru -ArgumentList @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',$quotedScript,
    '-Mode','helper','-CaseDir',$quotedCase)
for ($i=0; $i -lt 100 -and -not (Test-Path -LiteralPath $ready); $i++) { Start-Sleep -Milliseconds 100 }
if (-not (Test-Path -LiteralPath $ready)) { throw 'Pre-existing workload process did not start.' }
try {
    Write-Host 'Windows may show a UAC prompt for the 30-second ETW capture.'
    $collector = Start-Process -FilePath $shell -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',$quotedScript,
        '-Mode','collect','-CaseDir',$quotedCase,'-Duration',$Duration)
    Start-Sleep -Seconds 6
    Set-Content -LiteralPath $trigger -Value 'go' -Encoding Ascii
    for ($i=0; $i -lt ($Duration+45) -and -not (Test-Path -LiteralPath $exitFile); $i++) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path -LiteralPath $exitFile)) { throw "Capture did not finish; inspect $log" }
    $result = [int](Get-Content -LiteralPath $exitFile -Raw)
    if ($result -ne 0) { throw "Capture exited $result; inspect $log" }
    if (-not (Test-Path -LiteralPath $done)) { throw 'Known workload did not finish.' }
    Write-Host "Capture case: $CaseDir"
    Write-Host "Pre-existing workload PID: $(Get-Content -LiteralPath $done -Raw)"
    Write-Host "Collector log: $log"
} finally {
    if (-not (Test-Path -LiteralPath $trigger)) { Set-Content -LiteralPath $cancel -Value 'cancel' -Encoding Ascii }
}
