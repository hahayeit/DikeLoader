# Bootstrap DikeLoader on Windows (no Visual C++ required).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

if (-not (Test-Path .venv)) {
    py -3.13 -m venv .venv
}

& .\.venv\Scripts\python -m pip install -U pip
& .\.venv\Scripts\python -m pip install -e . --no-deps
& .\.venv\Scripts\python -m pip install -r requirements.txt
& .\.venv\Scripts\python -m pip install pymobiledevice3 --no-deps
& .\.venv\Scripts\python -m dikeloader fetch-zsign
& .\.venv\Scripts\python -m dikeloader doctor

Write-Host ""
Write-Host "Launch with:  .\.venv\Scripts\python -m dikeloader"
