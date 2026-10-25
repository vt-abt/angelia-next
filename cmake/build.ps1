#Requires -Version 5.1
<#
    Load vcvars64 into the current process and drive CMake + Ninja through
    the named preset. Bootstraps vcpkg into third_party/vcpkg if missing.

    Written for Windows PowerShell 5.1: never uses `2>&1` on native exes
    (which wraps stderr as ErrorRecords and can fail the script even on
    exit 0). Each native call checks $LASTEXITCODE explicitly.

    Usage:
        pwsh -File cmake/build.ps1                       # configure + build 'default'
        pwsh -File cmake/build.ps1 -Preset debug -Clean  # wipe build dir first
        pwsh -File cmake/build.ps1 -Configure            # configure only
#>
param(
    [string]$Preset    = 'default',
    [string]$Target    = '',
    [switch]$Configure,
    [switch]$Clean,
    [switch]$SkipVcpkg
)

# Non-terminating on script errors; we check every native exit explicitly.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot

function Fail([string]$msg) {
    Write-Host "[build] $msg" -ForegroundColor Red
    exit 1
}

function Run-Native([string]$exe, [string[]]$argv, [string]$what) {
    Write-Host "[build] $what" -ForegroundColor DarkGray
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { Fail "$what failed (exit $LASTEXITCODE)" }
}

function Load-Vcvars {
    if ($env:VSCMD_VER) { return }
    $installerDir = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
    $vswhere = Join-Path $installerDir 'vswhere.exe'
    if (-not (Test-Path $vswhere)) { Fail "vswhere.exe not found at $vswhere" }
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsPath) { Fail 'vswhere: no VS installation with C++ tools' }
    $vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { Fail "vcvars64.bat missing at $vcvars" }
    $cmakeBin = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    $ninjaBin = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'

    $sys32       = Join-Path $env:SystemRoot 'System32'
    $machinePath = [Environment]::GetEnvironmentVariable('PATH','Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('PATH','User')
    $basePath    = @($installerDir, $cmakeBin, $ninjaBin, $sys32, $env:SystemRoot, $machinePath, $userPath) |
                   Where-Object { $_ } | ForEach-Object { $_.TrimEnd(';') }
    $childPath   = ($basePath -join ';')

    Write-Host "[build] loading vcvars from $vcvars" -ForegroundColor DarkGray
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = (Join-Path $sys32 'cmd.exe')
    $psi.Arguments = "/s /c `"`"$vcvars`" >NUL && set`""
    $psi.EnvironmentVariables['PATH']       = $childPath
    $psi.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $proc   = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        Write-Host $stderr -ForegroundColor Red
        Fail "vcvars64 failed (exit $($proc.ExitCode))"
    }
    foreach ($line in $stdout -split "`r?`n") {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
}

function Ensure-Vcpkg {
    $vcpkgDir = Join-Path $root 'third_party\vcpkg'
    $vcpkgExe = Join-Path $vcpkgDir 'vcpkg.exe'
    $vcpkgCommit = '0c2a9ace1964b818b15f7ae50ba1c42404918a7b'
    if (-not (Test-Path $vcpkgDir)) {
        Run-Native 'git' @('clone','--depth','1','https://github.com/microsoft/vcpkg.git', $vcpkgDir) 'cloning vcpkg'
    }
    $currentCommit = & git -c "safe.directory=$vcpkgDir" -C $vcpkgDir rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { Fail 'cannot read vcpkg revision' }
    if ($currentCommit -ne $vcpkgCommit) {
        Run-Native 'git' @('-c',"safe.directory=$vcpkgDir",'-C',$vcpkgDir,'fetch','--depth','1','origin',$vcpkgCommit) 'fetching pinned vcpkg revision'
        Run-Native 'git' @('-c',"safe.directory=$vcpkgDir",'-C',$vcpkgDir,'checkout','--detach',$vcpkgCommit) 'checking out pinned vcpkg revision'
    }
    if (-not (Test-Path $vcpkgExe)) {
        # bootstrap-vcpkg.bat invokes powershell.exe by name; if PATH got
        # truncated by the vcvars capture path, that child cmd can't find
        # powershell. Call scripts/bootstrap.ps1 directly in our current
        # PowerShell session, which is guaranteed to work.
        $bootstrapPs1 = Join-Path $vcpkgDir 'scripts\bootstrap.ps1'
        if (-not (Test-Path $bootstrapPs1)) { Fail "vcpkg bootstrap.ps1 missing at $bootstrapPs1" }
        Write-Host "[build] bootstrapping vcpkg" -ForegroundColor DarkGray
        & $bootstrapPs1 -disableMetrics
        if ($LASTEXITCODE -ne 0) { Fail "bootstrapping vcpkg failed (exit $LASTEXITCODE)" }
        if (-not (Test-Path $vcpkgExe)) { Fail "vcpkg.exe still missing after bootstrap" }
    }
}

Load-Vcvars
if (-not $SkipVcpkg) { Ensure-Vcpkg }

$buildDir = Join-Path $root "build\$Preset"
if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "[build] wiping $buildDir" -ForegroundColor DarkGray
    Remove-Item $buildDir -Recurse -Force
}

Push-Location $root
try {
    Run-Native 'cmake' @('--preset', $Preset) "configure preset=$Preset"
    if ($Configure) { return }
    $argv = @('--build','--preset', $Preset)
    if ($Target) { $argv += @('--target', $Target) }
    Run-Native 'cmake' $argv "build $($argv -join ' ')"
} finally {
    Pop-Location
}

Write-Host "[build] done." -ForegroundColor Green
