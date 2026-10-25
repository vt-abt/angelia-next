#Requires -Version 5.1
<#
    Packages the Angelia Windows runtime.

    Layout of the produced zip (dist/angelia-<version>.zip):

        angelia-<version>/
            angelia.exe          <- the single consolidated binary
            dbghelp.dll          <- bundled from Windows Kits/Debuggers/x64
            symsrv.dll           <- companion to dbghelp for srv* symbol fetch
            msvcp140.dll, vcruntime140*.dll <- x64 MSVC runtime
            README.md            <- quick-start
            LICENSE              <- GNU AGPLv3 license text
            docs/
                QUICKSTART.md    <- first-use guide
                RELEASE_VALIDATION.md
                CASES.md         <- investigation-case guide
                FINDINGS_VALIDATION.md
                MEMORY_VALIDATION.md
            tools/memory_validation/compare.py
            examples/controlled-events.xml
            demo.ps1

    Usage:
        pwsh -File tools/dist/pack.ps1                  # default version 0.4.0
        pwsh -File tools/dist/pack.ps1 -Version 0.4.0
        pwsh -File tools/dist/pack.ps1 -SkipBuild       # reuse existing build
#>
param(
    [string]$Version   = '0.4.0',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot | Split-Path -Parent
Push-Location $repo
try {
    $bin      = Join-Path $repo 'build\default\bin'
    $exe      = Join-Path $bin  'angelia.exe'

    if (-not $SkipBuild) {
        Write-Host "[pack] building release" -ForegroundColor Cyan
        & (Join-Path $repo 'cmake\build.ps1') -Preset default
        if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
    }
    if (-not (Test-Path $exe)) {
        throw "angelia.exe missing at $exe; run without -SkipBuild"
    }

    $distRoot = Join-Path $repo 'dist'
    $stageDir = Join-Path $distRoot "angelia-$Version"
    $zipPath  = Join-Path $distRoot "angelia-$Version.zip"
    if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z.-]*$' -or $Version.Contains('..')) {
        throw 'Version must contain only letters, numbers, dots and hyphens'
    }
    $distFull = [IO.Path]::GetFullPath($distRoot)
    $stageFull = [IO.Path]::GetFullPath($stageDir)
    $zipFull = [IO.Path]::GetFullPath($zipPath)
    $prefix = $distFull.TrimEnd('\') + '\'
    if (-not $stageFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not $zipFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Package paths must remain inside dist'
    }

    Write-Host "[pack] staging into $stageDir" -ForegroundColor Cyan
    if (Test-Path -LiteralPath $stageFull) { Remove-Item -LiteralPath $stageFull -Recurse -Force }
    if (Test-Path -LiteralPath $zipFull)  { Remove-Item -LiteralPath $zipFull -Force }
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

    # --- exe + runtime DLLs ---
    Copy-Item $exe (Join-Path $stageDir 'angelia.exe')
    foreach ($dll in 'dbghelp.dll','symsrv.dll') {
        $src = Join-Path $bin $dll
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $stageDir $dll)
        } else {
            Write-Warning "[pack] missing runtime dll: $dll (some subcommands will not fetch PDBs)"
        }
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere.exe is required to locate redistributable runtime files' }
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsPath) { throw 'Visual Studio C++ tools were not found' }
    $redistRoot = Join-Path $vsPath 'VC\Redist\MSVC'
    $crtDir = Get-ChildItem -LiteralPath $redistRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Get-ChildItem -LiteralPath (Join-Path $_.FullName 'x64') -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^Microsoft\.VC[0-9]+\.CRT$' } } |
        Select-Object -First 1
    if (-not $crtDir) { throw 'x64 Microsoft VC runtime redistributable directory was not found' }
    foreach ($dll in 'msvcp140.dll','vcruntime140.dll','vcruntime140_1.dll') {
        $src = Join-Path $crtDir.FullName $dll
        if (-not (Test-Path -LiteralPath $src)) { throw "required runtime DLL missing: $src" }
        Copy-Item -LiteralPath $src -Destination (Join-Path $stageDir $dll)
    }

    # --- documentation ---
    Copy-Item (Join-Path $repo 'README.md')    (Join-Path $stageDir 'README.md')
    Copy-Item (Join-Path $repo 'LICENSE')      (Join-Path $stageDir 'LICENSE')
    Copy-Item (Join-Path $repo 'tools\dist\demo.ps1') (Join-Path $stageDir 'demo.ps1')
    New-Item -ItemType Directory -Path (Join-Path $stageDir 'docs') -Force | Out-Null
    Copy-Item (Join-Path $repo 'docs\QUICKSTART.md') (Join-Path $stageDir 'docs\QUICKSTART.md')
    Copy-Item (Join-Path $repo 'docs\RELEASE_VALIDATION.md') (Join-Path $stageDir 'docs\RELEASE_VALIDATION.md')
    Copy-Item (Join-Path $repo 'docs\CASES.md') (Join-Path $stageDir 'docs\CASES.md')
    Copy-Item (Join-Path $repo 'docs\FINDINGS_VALIDATION.md') (Join-Path $stageDir 'docs\FINDINGS_VALIDATION.md')
    Copy-Item (Join-Path $repo 'docs\MEMORY_VALIDATION.md') (Join-Path $stageDir 'docs\MEMORY_VALIDATION.md')
    New-Item -ItemType Directory -Path (Join-Path $stageDir 'tools\memory_validation') -Force | Out-Null
    Copy-Item (Join-Path $repo 'tools\memory_validation\compare.py') (Join-Path $stageDir 'tools\memory_validation\compare.py')
    New-Item -ItemType Directory -Path (Join-Path $stageDir 'examples') -Force | Out-Null
    Copy-Item (Join-Path $repo 'tests\fixtures\case_findings.xml') (Join-Path $stageDir 'examples\controlled-events.xml')

    # --- zip it ---
    Write-Host "[pack] compressing to $zipPath" -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -Force

    $exeSize = (Get-Item $exe).Length
    $zipSize = (Get-Item $zipPath).Length
    Write-Host ""
    Write-Host "[pack] done." -ForegroundColor Green
    Write-Host "  exe    : $exe ($([math]::Round($exeSize/1MB, 2)) MB)"
    Write-Host "  stage  : $stageDir"
    Write-Host "  zip    : $zipPath ($([math]::Round($zipSize/1MB, 2)) MB)"
} finally {
    Pop-Location
}
