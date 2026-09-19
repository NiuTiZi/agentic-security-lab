# Start Keycloak authorization server (standalone process, loopback only).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\start-keycloak.ps1 [-Port 8080]
# Note: start-dev mode, plain HTTP without TLS. Per requirement doc section 6.2 this is a
# local-demo configuration with transport protection explicitly NOT complete.
param([int]$Port = 8080)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# --- load .env ---
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) { Write-Error ".env missing, copy .env.example first"; exit 1 }
$cfg = @{}
foreach ($line in [System.IO.File]::ReadAllLines($envFile)) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
        $cfg[$Matches[1]] = $Matches[2].Trim()
    }
}
Write-Host ("[start-keycloak] .env keys loaded: " + $cfg.Count)
if (-not $cfg.ContainsKey("KC_ADMIN_USERNAME") -or -not $cfg.ContainsKey("KC_ADMIN_PASSWORD")) {
    Write-Error ".env missing KC_ADMIN_USERNAME / KC_ADMIN_PASSWORD"; exit 1
}

# --- locate Keycloak dist ---
$kcDir = Get-ChildItem (Join-Path $root "auth-server") -Directory -Filter "keycloak-*" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $kcDir) { Write-Error "keycloak-* not found under auth-server, unzip the dist first"; exit 1 }

# --- Java runtime: JDK 17 first, JRE 21 fallback ---
$javaCandidates = @(
    "C:\Program Files\Java\jdk17.0.0.1",
    "$env:APPDATA\TRAE SOLO CN\ModularData\ai-agent\vm\tools\app\jre"
)
$javaHome = $null
foreach ($j in $javaCandidates) {
    if (Test-Path (Join-Path $j "bin\java.exe")) { $javaHome = $j; break }
}
if (-not $javaHome) { Write-Error "no usable Java 17/21 runtime found"; exit 1 }

$env:JAVA_HOME = $javaHome
$env:KC_BOOTSTRAP_ADMIN_USERNAME = $cfg["KC_ADMIN_USERNAME"]
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = $cfg["KC_ADMIN_PASSWORD"]

Write-Host ("[start-keycloak] Keycloak : " + $kcDir.FullName)
Write-Host ("[start-keycloak] JAVA    : " + $javaHome)
Write-Host ("[start-keycloak] port    : $Port (start-dev, HTTP, loopback only)")

& (Join-Path $kcDir.FullName "bin\kc.bat") start-dev "--http-port=$Port"
