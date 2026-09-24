<#
.SYNOPSIS
  Local smoke test on ONE Windows machine: server + observer + traffic generator over 127.0.0.1.

.DESCRIPTION
  Proves the whole pipeline works before involving the Kali VM. Uses its own port and log
  directory (logs/demo) so it does not mix with real experiment logs.
  With -Capture it also captures on the Npcap loopback adapter using TShark.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Count 3 -Delay 2
#>
param(
    [int]$Port = 8765,
    [int]$Count = 3,
    [double]$Delay = 2,
    [switch]$Capture,
    [string]$Interface = "\Device\NPF_Loopback",
    [string]$LogDir = "logs/demo"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

# Use the active env's python, otherwise resolve the api-observability env's interpreter.
if ($env:CONDA_DEFAULT_ENV -eq "api-observability") {
    $Python = (Get-Command python).Source
} else {
    $Python = (conda run -n api-observability python -c "import sys; print(sys.executable)").Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Python)) { throw "conda env 'api-observability' not found; run scripts\setup_windows.ps1" }
}
Write-Host "[demo] python: $Python"

$absLogDir = Join-Path $ProjectRoot $LogDir
if (Test-Path $absLogDir) { Get-ChildItem $absLogDir -Filter *.jsonl | Remove-Item }  # only demo logs
New-Item -ItemType Directory -Force $absLogDir | Out-Null

# Settings for the child processes (process-scoped; nothing is written to .env).
$env:LOG_DIR = $LogDir
$env:NODE_NAME = "local-server"
$env:OBSERVER_MERGE_WINDOW_SECONDS = "1"

$mode = if ($Capture) { "both" } else { "app" }
$observerSeconds = [int](6 + $Count * $Delay + 6)

$server = $null; $observer = $null
try {
    $server = Start-Process -PassThru -NoNewWindow -FilePath $Python `
        -ArgumentList "server/api_server.py", "--host", "127.0.0.1", "--port", "$Port" `
        -RedirectStandardOutput "$absLogDir\server.out" -RedirectStandardError "$absLogDir\server.err"

    $observerArgs = @("observer/observer.py", "--mode", $mode, "--filter", "`"tcp port $Port`"", "--duration", "$observerSeconds")
    if ($Capture) { $observerArgs += @("--interface", $Interface, "--backend", "tshark") }
    $observer = Start-Process -PassThru -NoNewWindow -FilePath $Python -ArgumentList $observerArgs `
        -RedirectStandardOutput "$absLogDir\observer.out" -RedirectStandardError "$absLogDir\observer.err"

    # Wait until the server answers /health (max ~10 s).
    $ready = $false
    for ($i = 0; $i -lt 20 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 500
        try { $ready = (Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2).status -eq "ok" } catch { }
    }
    if (-not $ready) { throw "server did not become healthy; see $absLogDir\server.err" }
    Start-Sleep -Seconds 3  # give TShark time to start capturing

    & $Python client/traffic_generator.py --target "http://127.0.0.1:$Port" --sender local-client --count $Count --delay $Delay
    $clientExit = $LASTEXITCODE

    Write-Host "[demo] waiting for observer to finish ($observerSeconds s window) ..."
    $observer.WaitForExit()
} finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
    if ($observer -and -not $observer.HasExited) { Stop-Process -Id $observer.Id }
}

Write-Host "`n===== server log ====="; Get-Content "$absLogDir\server.out"
Write-Host "`n===== observer log ====="; Get-Content "$absLogDir\observer.out"
$errs = Get-Content "$absLogDir\observer.err" -ErrorAction SilentlyContinue
if ($errs) { Write-Host "`n===== observer stderr ====="; $errs }

$eventsFile = Join-Path $absLogDir "api-events.jsonl"
if (Test-Path $eventsFile) {
    $events = Get-Content $eventsFile | ForEach-Object { $_ | ConvertFrom-Json }
    Write-Host "`n===== $eventsFile ($($events.Count) events) ====="
    $events | Select-Object direction, method, endpoint, status_code, latency_ms, latency_source,
        server_processing_ms, wire_latency_ms, tcp_stream, @{n = "evidence"; e = { $_.evidence -join "," } }, request_id |
        Format-Table -AutoSize | Out-String -Width 250 | Write-Host
} else {
    Write-Host "[demo] no events written" -ForegroundColor Red
}
exit $clientExit
