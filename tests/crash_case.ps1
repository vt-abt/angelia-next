#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repo 'build\default\bin\angelia.exe'
$case = Join-Path $repo ('build\default\crash-smoke\' + [guid]::NewGuid().ToString('N'))
$stack = Join-Path $repo 'build\default\bin\vuln_stack_off.exe'
$heap = Join-Path $repo 'build\default\bin\vuln_heap_off.exe'

function Run-Angelia([string[]]$arguments) {
    $output = & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Angelia failed ($LASTEXITCODE): $($arguments -join ' ')" }
    return $output
}

Run-Angelia @('case','init',$case) | Out-Null
Run-Angelia @('case','crash',$case,'--binary',$stack,'--gen-pattern','256') | Out-Null
Run-Angelia @('case','crash',$case,'--binary',$heap,'--gen-pattern','256','--repeat','2') | Out-Null
$crashes = ConvertFrom-Json -InputObject ((Run-Angelia @('case','crashes',$case,'--json')) -join "`n")
if (@($crashes.runs).Count -ne 3) { throw 'Expected three crash runs.' }
if (@($crashes.series).Count -ne 2) { throw 'Expected two binary/input groups.' }
if (@($crashes.series | Where-Object { $_.runs -eq 2 }).Count -ne 1) { throw 'Heap repeat count missing.' }
foreach ($run in $crashes.runs) {
    if (-not $run.capture_source_id -or -not $run.artifact_source_id -or
        -not $run.dump_source_id -or -not $run.binary_source_id -or -not $run.input_source_id) {
        throw 'Crash provenance is incomplete.'
    }
    if (-not $run.artifact.analysis.zydis_disasm -or -not $run.artifact.verdict.bucket -or
        -not $run.artifact.registers.rip -or -not $run.artifact.mitigations) {
        throw 'Crash evidence or verdict is incomplete.'
    }
}
$integrity = ConvertFrom-Json -InputObject ((Run-Angelia @('case','verify',$case,'--json')) -join "`n")
if (-not $integrity.valid) { throw 'Crash evidence did not verify.' }
$report = Join-Path $case 'report.html'
Run-Angelia @('case','report',$case,'--out',$report) | Out-Null
if (-not (Select-String -LiteralPath $report -Pattern 'Crash triage' -Quiet) -or
    -not (Select-String -LiteralPath $report -Pattern 'Instruction:' -Quiet)) {
    throw 'Crash evidence is absent from the HTML report.'
}

$first = $integrity.sources | Where-Object { $_.source_id -eq $crashes.runs[0].capture_source_id } | Select-Object -First 1
$sourcePath = Join-Path $case $first.stored_path
$original = [IO.File]::ReadAllBytes($sourcePath)
try {
    [IO.File]::WriteAllBytes($sourcePath,[byte[]](1,2,3))
    & $exe case verify $case | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Evidence tampering was not detected.' }
} finally {
    [IO.File]::WriteAllBytes($sourcePath,$original)
}
Run-Angelia @('case','verify',$case) | Out-Null
Write-Host "crash case smoke passed: $case"
