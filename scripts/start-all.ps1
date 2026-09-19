# Start all range services (tools, agents, backend). Keycloak started if not running.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1 [-Mode hidden|visible]
param([string]$Mode = "visible")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
$logDir = Join-Path $root "data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# --- load .env and ensure INTERNAL_API_KEY exists ---
$envFile = Join-Path $root ".env"
$cfg = @{}
foreach ($line in [System.IO.File]::ReadAllLines($envFile)) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') { $cfg[$Matches[1]] = $Matches[2].Trim() }
}
if (-not $cfg.ContainsKey("INTERNAL_API_KEY") -or [string]::IsNullOrWhiteSpace($cfg["INTERNAL_API_KEY"])) {
    $key = -join ((48..57) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
    [System.IO.File]::AppendAllText($envFile, "`r`nINTERNAL_API_KEY=$key`r`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[start-all] INTERNAL_API_KEY generated and appended to .env"
}

# --- helper: start a service process ---
function Start-Svc([string]$Name, [int]$Port, [string]$App) {
    $listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Write-Host "[start-all] $Name already running on :$Port (pid $($listening[0].OwningProcess))"; return }
    $cmd = "`$env:PYTHONUTF8='1'; `$env:PYTHONIOENCODING='utf-8'; Set-Location '$root'; & '$py' -m uvicorn $App --host 127.0.0.1 --port $Port"
    if ($Mode -eq "hidden") {
        $out = Join-Path $logDir "$Name.log"; $err = Join-Path $logDir "$Name.err.log"
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile","-Command","$cmd 2>&1 | Out-File -Encoding utf8 '$out'"
    } else {
        Start-Process powershell -ArgumentList "-NoExit","-Command","`$Host.UI.RawUI.WindowTitle='$Name :$Port'; $cmd"
    }
    Write-Host "[start-all] $Name starting on :$Port"
}

# --- keycloak check ---
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8080/realms/master" -UseBasicParsing -TimeoutSec 3 -Proxy $null -ErrorAction Stop
    Write-Host "[start-all] Keycloak already running on :8080"
} catch {
    Write-Host "[start-all] Keycloak not running, starting..."
    if ($Mode -eq "hidden") {
        $out = Join-Path $logDir "keycloak.log"
        Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile","-Command","powershell -ExecutionPolicy Bypass -File '$root\scripts\start-keycloak.ps1' 2>&1 | Out-File -Encoding utf8 '$out'"
    } else {
        Start-Process powershell -ArgumentList "-NoExit","-Command","powershell -ExecutionPolicy Bypass -File '$root\scripts\start-keycloak.ps1'"
    }
    $deadline = (Get-Date).AddSeconds(150)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:8080/realms/master" -UseBasicParsing -TimeoutSec 3 -Proxy $null -ErrorAction Stop
            Write-Host "[start-all] Keycloak ready"; break
        } catch {}
    }
}

# --- start services (tools first, then agents, then backend) ---
Start-Svc "tools" 8300 "services.tools.main:app"
Start-Svc "agent_customer" 8100 "services.agent_customer.main:app"
Start-Svc "agent_refund" 8200 "services.agent_refund.main:app"
Start-Svc "backend" 8000 "services.backend.main:app"

# --- wait for health ---
$targets = @(@{n="backend";p=8000}, @{n="agent_customer";p=8100}, @{n="agent_refund";p=8200}, @{n="tools";p=8300})
$deadline = (Get-Date).AddSeconds(60)
foreach ($t in $targets) {
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:$($t.p)/health" -UseBasicParsing -TimeoutSec 2 -Proxy $null -ErrorAction Stop
            Write-Host "[start-all] $($t.n) healthy on :$($t.p)"; break
        } catch { Start-Sleep -Seconds 2 }
    }
}
Write-Host ""
Write-Host "[start-all] done. UI: http://127.0.0.1:8000  (logs: data\logs\ when hidden)"
