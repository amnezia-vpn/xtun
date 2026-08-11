param(
    [string]$Exe = "",
    [string]$Filter = "*",
    [switch]$Direct
)

$ErrorActionPreference = "Stop"

if (-not $Exe) {
    $testsDir = Join-Path $PSScriptRoot "..\build\tests"
    $found = Get-ChildItem -Path $testsDir -Filter "xtun_tests.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { throw "xtun_tests.exe not found under $testsDir; build first or pass -Exe" }
    $Exe = $found.FullName
}
$exe = (Resolve-Path $Exe).Path

function Get-PsExec {
    $tools = Join-Path $PSScriptRoot "..\build\tools"
    $psexec = Join-Path $tools "PsExec64.exe"
    if (-not (Test-Path $psexec)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        New-Item -ItemType Directory -Force -Path $tools | Out-Null
        Invoke-WebRequest -Uri "https://live.sysinternals.com/PsExec64.exe" -OutFile $psexec -UseBasicParsing
    }
    return $psexec
}

$ErrorActionPreference = "Continue"
if ($Direct) {
    & $exe "--gtest_filter=$Filter" | Out-Host
} else {
    & (Get-PsExec) -s -accepteula -nobanner $exe "--gtest_filter=$Filter" | Out-Host
}
$code = $LASTEXITCODE

if ($code -ne 0) { Write-Host "xtun_tests exited with $code" }
exit $code
