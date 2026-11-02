# 一键跑越权基准集：生成规模用例 → 逐用例隔离扫描 → OWASP 口径计分
# 用法：  pwsh -File tests/benchmark/bac_owasp/run_all.ps1 [-Tag 20261029_1600]
param([string]$Tag = (Get-Date -Format "yyyyMMdd_HHmmss"))

$ErrorActionPreference = "Stop"
$suite = Resolve-Path $PSScriptRoot
$repo = Resolve-Path (Join-Path $suite "..\..\..")
$env:PYTHONPATH = Join-Path $repo "src"
$env:PYTHONIOENCODING = "utf-8"
$out = Join-Path $repo "runs\bac_owasp_$Tag"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "== gen_cases =="
python (Join-Path $suite "gen_cases.py") --clean 2>&1 | Tee-Object -FilePath (Join-Path $out "gen.log")

Write-Host "== run_suite (per-case isolation) =="
python (Join-Path $suite "run_suite.py") --out $out --corpus-mode 2>&1 |
    Tee-Object -FilePath (Join-Path $out "suite.console.log")

Write-Host "== score =="
python (Join-Path $suite "score.py") --run $out 2>&1 |
    Tee-Object -FilePath (Join-Path $out "score.console.log")

Write-Host "done -> $out"
