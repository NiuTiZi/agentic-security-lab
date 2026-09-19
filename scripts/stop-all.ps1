# Stop range services on ports 8000/8100/8200/8300. Add -IncludeKeycloak to also stop 8080.
param([switch]$IncludeKeycloak)

$ports = @(8000, 8100, 8200, 8300)
if ($IncludeKeycloak) { $ports += 8080 }

foreach ($p in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $pids) {
            try {
                $proc = Get-Process -Id $procId -ErrorAction Stop
                # kill the whole process tree (powershell wrapper + python child)
                Stop-Process -Id $procId -Force -ErrorAction Stop
                Write-Host "[stop-all] port $p -> stopped pid $procId ($($proc.ProcessName))"
            } catch { Write-Host "[stop-all] port $p -> pid $procId already gone" }
        }
        # also kill any child python bound via parent powershell window titles
    } else {
        Write-Host "[stop-all] port $p -> not listening"
    }
}
# fallback: kill uvicorn/python processes whose command line references our services
try {
    $mine = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object {
        $_.CommandLine -match "uvicorn" -and $_.CommandLine -match "services\.(tools|backend|agent_customer|agent_refund)"
    }
    foreach ($m in $mine) { Stop-Process -Id $m.ProcessId -Force -ErrorAction SilentlyContinue; Write-Host "[stop-all] killed leftover uvicorn pid $($m.ProcessId)" }
} catch {}
