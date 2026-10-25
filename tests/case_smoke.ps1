#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repo 'build\default\bin\angelia.exe'
if (-not (Test-Path $exe)) { throw 'build angelia.exe first' }
$python = if ($env:ANGELIA_PYTHON) { $env:ANGELIA_PYTHON } else { (Get-Command python -ErrorAction Stop).Source }
$case = Join-Path $repo ("build\default\case-smoke\" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $case -Force | Out-Null
$pcap = Join-Path $case 'network.pcap'

# One Ethernet/IPv4/TCP packet, 500 ms after the fixture's Sysmon event 3.
$bytes = New-Object 'System.Collections.Generic.List[byte]'
function Add16([uint16]$v) { $bytes.AddRange([BitConverter]::GetBytes($v)) }
function Add32([uint32]$v) { $bytes.AddRange([BitConverter]::GetBytes($v)) }
$bytes.AddRange([byte[]](0xd4,0xc3,0xb2,0xa1))
Add16 2; Add16 4; Add32 0; Add32 0; Add32 65535; Add32 1
$sec = [uint32]([DateTimeOffset]::Parse('2026-01-01T00:00:01Z').ToUnixTimeSeconds())
Add32 $sec; Add32 500000; Add32 54; Add32 54
$packet = [byte[]]::new(54)
$packet[12]=8; $packet[13]=0; $packet[14]=0x45; $packet[17]=40
$packet[22]=64; $packet[23]=6
$packet[26]=10; $packet[27]=0; $packet[28]=0; $packet[29]=2
$packet[30]=203; $packet[31]=0; $packet[32]=113; $packet[33]=9
$packet[34]=0xc3; $packet[35]=0x50; $packet[36]=1; $packet[37]=0xbb
$bytes.AddRange($packet)
[IO.File]::WriteAllBytes($pcap, $bytes.ToArray())

function Run-Angelia([string[]]$arguments) {
    $output = & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "angelia $($arguments -join ' ') failed: $output" }
    return $output
}

Push-Location $repo
try {
    Run-Angelia @('case','init',$case) | Out-Null
    Run-Angelia @('case','import-xml',$case,'tests\fixtures\case_events.xml') | Out-Null
    Run-Angelia @('case','import-pcap',$case,$pcap) | Out-Null
    $rows = ConvertFrom-Json -InputObject ((Run-Angelia @('case','timeline',$case,'--pid','4242','--limit','10','--json')) -join "`n")
    if ($rows.Count -ne 5) { throw "expected 5 timeline rows, got $($rows.Count)" }
    $packetRow = @($rows | Where-Object { $_.type -eq 'packet' })
    if ($packetRow.Count -ne 1 -or $packetRow[0].link_status -ne 'tuple-time' -or
        $packetRow[0].process_key -ne 'sysmon:{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}') {
        throw 'PCAP packet was not linked to the Sysmon process'
    }
    $filtered = ConvertFrom-Json -InputObject ((Run-Angelia @('case','timeline',$case,'--contains','output.bin','--json')) -join "`n")
    if ($filtered.Count -ne 1 -or $filtered[0].kind -ne 'FileCreate') { throw 'timeline text filter failed' }
    Run-Angelia @('case','import-xml',$case,'tests\fixtures\case_events.xml') | Out-Null
    $again = ConvertFrom-Json -InputObject ((Run-Angelia @('case','timeline',$case,'--pid','4242','--json')) -join "`n")
    if ($again.Count -ne 5) { throw 'duplicate source changed the timeline' }
    $report = Join-Path $case 'timeline.html'
    Run-Angelia @('case','report',$case,'--out',$report) | Out-Null
    if (-not (Test-Path $report)) { throw 'HTML timeline was not written' }
    Run-Angelia @('case','import-xml',$case,'tests\fixtures\ambiguous_network.xml') | Out-Null
    $ambiguous = ConvertFrom-Json -InputObject ((Run-Angelia @('case','timeline',$case,'--limit','10','--json')) -join "`n")
    $packetRow = @($ambiguous | Where-Object { $_.type -eq 'packet' })
    if ($packetRow.Count -ne 1 -or $packetRow[0].link_status -ne 'ambiguous' -or
        $packetRow[0].process_key -ne '') { throw 'ambiguous network match was incorrectly attributed' }

    $findingCase = Join-Path $case 'findings-case'
    Run-Angelia @('case','init',$findingCase) | Out-Null
    Run-Angelia @('case','import-xml',$findingCase,'tests\fixtures\case_findings.xml') | Out-Null
    Run-Angelia @('case','analyze',$findingCase) | Out-Null
    $findingOutput = ConvertFrom-Json -InputObject ((Run-Angelia @('case','findings',$findingCase,'--json')) -join "`n")
    $behavior = @($findingOutput.findings | Where-Object { $_.origin -eq 'behavior' })
    if ($behavior.Count -ne 3) { throw "expected 3 behavior findings, got $($behavior.Count)" }
    if (@($behavior | Where-Object { $_.subject -like '*11111111*' }).Count -ne 0) {
        throw 'normal process was flagged'
    }
    if (@($behavior | Where-Object { $_.evidence.events[0].source_record -eq '5' -or
        $_.evidence.events[0].source_record -eq '6' }).Count -ne 2) {
        throw 'finding evidence does not point to source records'
    }
    $findingJson = Join-Path $findingCase 'findings.json'
    [IO.File]::WriteAllText($findingJson, (($findingOutput | ConvertTo-Json -Depth 30)))
    $evalJson = Join-Path $findingCase 'evaluation.json'
    & $python tools/evaluation/eval_case.py --findings $findingJson --labels tests/fixtures/case_findings_labels.json --out $evalJson | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'case evaluation failed' }
    $evaluation = Get-Content $evalJson -Raw | ConvertFrom-Json
    if ($evaluation.counts.tp -ne 1 -or $evaluation.counts.fp -ne 1 -or
        $evaluation.counts.fn -ne 1 -or $evaluation.counts.tn -ne 1) {
        throw 'controlled evaluation did not report expected false alarm and miss'
    }
    $pePath = 'build\default\bin\vuln_stack_off.exe'
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $peHash = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes((Join-Path $repo $pePath)))).Replace('-','') }
    finally { $sha.Dispose() }
    $hashedEvent = Join-Path $case 'hashed-process.xml'
    @"
<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>10</EventRecordID><TimeCreated SystemTime="2026-01-02T00:00:09Z"/></System><EventData><Data Name="ProcessGuid">{55555555-5555-5555-5555-555555555555}</Data><Data Name="ProcessId">500</Data><Data Name="Image">C:\Lab\vuln_stack_off.exe</Data><Data Name="Hashes">SHA256=$peHash</Data></EventData></Event>
"@ | Set-Content -Path $hashedEvent -Encoding UTF8
    Run-Angelia @('case','import-xml',$findingCase,$hashedEvent) | Out-Null
    Run-Angelia @('case','add-pe',$findingCase,$pePath) | Out-Null
    $withStatic = ConvertFrom-Json -InputObject ((Run-Angelia @('case','findings',$findingCase,'--json')) -join "`n")
    if (@($withStatic.findings | Where-Object { $_.origin -eq 'static' }).Count -lt 1) {
        throw 'static PE features were not stored as findings'
    }
    $static = @($withStatic.findings | Where-Object { $_.origin -eq 'static' })[0]
    if (@($static.evidence.matching_processes_by_sha256).Count -ne 1) {
        throw 'static PE hash was not linked to the matching process'
    }
    $findingsReport = Join-Path $findingCase 'report.html'
    Run-Angelia @('case','report',$findingCase,'--out',$findingsReport) | Out-Null
    if (-not (Select-String -Path $findingsReport -Pattern 'run-key-write' -Quiet)) {
        throw 'findings are missing from the HTML report'
    }

    $reverseCase = Join-Path $case 'static-first-case'
    Run-Angelia @('case','init',$reverseCase) | Out-Null
    Run-Angelia @('case','add-pe',$reverseCase,$pePath) | Out-Null
    Run-Angelia @('case','import-xml',$reverseCase,$hashedEvent) | Out-Null
    Run-Angelia @('case','analyze',$reverseCase) | Out-Null
    $refreshed = ConvertFrom-Json -InputObject ((Run-Angelia @('case','findings',$reverseCase,'--json')) -join "`n")
    $refreshedStatic = @($refreshed.findings | Where-Object { $_.origin -eq 'static' })[0]
    if (@($refreshedStatic.evidence.matching_processes_by_sha256).Count -ne 1) {
        throw 'static PE link did not refresh after later process import'
    }

    $snapshotCase = Join-Path $case 'snapshot-case'
    $generated = Join-Path $case 'generated-etw'
    & $python tests/generate_snapshot_etw.py $generated
    if ($LASTEXITCODE -ne 0) { throw 'ETW fixture generation failed' }
    Run-Angelia @('case','init',$snapshotCase) | Out-Null
    Run-Angelia @('case','import-snapshot',$snapshotCase,(Join-Path $generated 'snapshot.json')) | Out-Null
    Run-Angelia @('case','import-etw',$snapshotCase,(Join-Path $generated 'collector.db'),'--snapshot-source','1') | Out-Null
    $snapshotRows = ConvertFrom-Json -InputObject ((Run-Angelia @('case','timeline',$snapshotCase,'--json')) -join "`n")
    if ($snapshotRows.Count -ne 1 -or $snapshotRows[0].process_key -notlike 'snapshot:1:123:*') {
        throw 'pre-existing process was not linked to the preceding snapshot'
    }
    Write-Host "case smoke passed: $case"
} finally { Pop-Location }
