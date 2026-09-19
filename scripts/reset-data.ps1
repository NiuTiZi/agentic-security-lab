# Reset experiment data: stop services, delete sqlite dbs, start services again.
# Keycloak (realm/clients) is NOT reset - run scripts\setup_keycloak.py for that.
powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\stop-all.ps1"
Start-Sleep -Seconds 2
$root = Split-Path -Parent $PSScriptRoot
Remove-Item (Join-Path $root "data\*.db") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root "data\*.db-journal") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root "data\*.db-wal") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root "data\*.db-shm") -Force -ErrorAction SilentlyContinue
Write-Host "[reset] data cleared, restarting services (hidden mode)..."
powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start-all.ps1") -Mode hidden
