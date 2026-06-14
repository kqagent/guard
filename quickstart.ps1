# Aegis quickstart (Windows) - zero to a running, self-proven policy gate.
#
#   .\quickstart.ps1            # venv + install + sign bundle + acceptance suite + live PDP demo
#   .\quickstart.ps1 -NoPdp     # acceptance suite only
#
# Needs Python >=3.10 on PATH. Everything else is built here. Ends by PROVING
# the gate works (benign allowed, destructive blocked) so a clean run is a demo.
param([switch]$NoPdp)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Say($m){ Write-Host "== $m ==" -ForegroundColor Cyan }
function OK($m){ Write-Host "OK $m" -ForegroundColor Green }
function Die($m){ Write-Host "FAIL $m" -ForegroundColor Red; exit 1 }

Say "1/6  Checking prerequisites"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Die "python not found (need >=3.10)" }
$ver = & python -c "import sys;print('%d.%d'%sys.version_info[:2])"
& python -c "import sys;sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)"
if ($LASTEXITCODE -ne 0) { Die "python $ver too old; need >=3.10" }
OK "python $ver"

Say "2/6  Creating venv and installing Aegis"
& python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -q --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -q -e ".[signing]"
OK "installed aegis-guardrails (+signing)"

Say "3/6  Building a signed policy bundle"
& .\.venv\Scripts\python.exe aegis\deploy\build_bundle.py .\bundle
if ($LASTEXITCODE -ne 0) { Die "bundle build failed" }
OK "signed bundle in .\bundle"

Say "4/6  Running the acceptance suite (the proof it works)"
& .\.venv\Scripts\python.exe -m aegis.run_all_checks
if ($LASTEXITCODE -ne 0) { Die "acceptance suite failed - do not deploy" }
OK "all core checks passed"

if ($NoPdp) { Say "Done (-NoPdp)"; exit 0 }

Say "5/6  Starting the out-of-process PDP (signed bundle, fail-closed)"
$pub = (Get-Content .\bundle\pubkey.hex).Trim()
New-Item -ItemType Directory -Force .aegis | Out-Null
$pdpArgs = @("-m","aegis.pdp_service","--policy","bundle\policy.json","--sig","bundle\policy.json.sig","--pubkey",$pub,"--audit",".aegis\audit.jsonl","--host","127.0.0.1","--port","8787")
$pdp = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList $pdpArgs -PassThru -WindowStyle Hidden
$up = $false
for ($i=0; $i -lt 20; $i++) {
  try { Invoke-RestMethod "http://127.0.0.1:8787/healthz" -TimeoutSec 2 | Out-Null; $up=$true; break } catch { Start-Sleep -Milliseconds 250 }
}
if (-not $up) { Stop-Process -Id $pdp.Id -Force -ErrorAction SilentlyContinue; Die "PDP did not come up" }
OK "PDP healthy on http://127.0.0.1:8787 (pid $($pdp.Id))"

Say "6/6  Proving the gate decides (live, through the running PDP)"
& .\.venv\Scripts\python.exe tools\prove_gate.py http://127.0.0.1:8787
if ($LASTEXITCODE -ne 0) { Stop-Process -Id $pdp.Id -Force -ErrorAction SilentlyContinue; Die "gate proof failed" }
OK "gate is live and deciding"

Write-Host ""
Write-Host "Aegis is up." -ForegroundColor Green
Write-Host "  PDP:       http://127.0.0.1:8787  (pid $($pdp.Id); audit -> .aegis\audit.jsonl)"
Write-Host "  Integrate: from aegis.guard import Guard;  Guard.remote('http://127.0.0.1:8787')"
Write-Host "  Stop PDP:  Stop-Process -Id $($pdp.Id)"
Write-Host "  Next:      DEPLOY.md (containers, hardening) and PILOT.md (monitor->enforce)"
