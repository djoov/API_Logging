<#
.SYNOPSIS
  Local smoke test on ONE Windows machine: server + observer + traffic generator over 127.0.0.1.

.DESCRIPTION
  Proves the whole pipeline works before involving the Kali VM. Uses its own port and log
  directory (logs/demo) so it does not mix with real experiment logs.
  With -Capture it also captures on the Npcap loopback adapter using TShark.
  With -Tls it runs over HTTPS (Phase 2) using a throw-away demo CA in logs/demo/certs.
  With -AppEncrypt the client Fernet-encrypts the payload (Phase 3, /api/secure-test) and the
  server holds the demo key = authorized decryption (Test D). Add -ServerNoKey for Test C: the
  server gets no key and accepts the payload without being able to read it.
  The demo ignores the project .env so real lab settings cannot interfere.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Count 3 -Delay 2
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Tls
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Tls -AppEncrypt               # Test D
  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Tls -AppEncrypt -ServerNoKey  # Test C
#>
param(
    [int]$Port = 8765,
    [int]$Count = 3,
    [double]$Delay = 2,
    [switch]$Capture,
    [switch]$Tls,
    [switch]$AppEncrypt,
    [switch]$ServerNoKey,
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
# ENV_FILE points to a file that does not exist, so the real lab .env is not loaded.
$env:ENV_FILE = Join-Path $absLogDir "demo-has-no.env"
$env:LOG_DIR = $LogDir
$env:NODE_NAME = "local-server"
$env:OBSERVER_MERGE_WINDOW_SECONDS = "1"

$mode = if ($Capture) { "both" } else { "app" }
$scheme = "http"
if ($Tls) {
    # Demo-only CA and certificate for 127.0.0.1 (never used for the real two-host lab).
    $certDir = Join-Path $absLogDir "certs"
    if (-not (Test-Path (Join-Path $certDir "ca.pem"))) {
        & $Python scripts/make_certs.py --dir $certDir ca | Out-Null
        & $Python scripts/make_certs.py --dir $certDir server --name local --ip 127.0.0.1 --dns localhost | Out-Null
    }
    $env:TLS_CERT_FILE = Join-Path $certDir "local.pem"
    $env:TLS_KEY_FILE = Join-Path $certDir "local.key"
    $env:TLS_CA_FILE = Join-Path $certDir "ca.pem"
    $scheme = "https"
}
$clientExtra = @()
if ($AppEncrypt) {
    # Demo-only Fernet key (never the real lab key). The CLIENT always gets it; the SERVER only
    # without -ServerNoKey.
    $demoKey = Join-Path $absLogDir "certs\fernet.key"
    if (-not (Test-Path $demoKey)) { & $Python scripts/make_fernet_key.py --file $demoKey | Out-Null }
    $clientExtra = @("--app-encrypt", "--key-file", $demoKey)
    if (-not $ServerNoKey) { $env:FERNET_KEY_FILE = $demoKey }
}
$observerSeconds = [int](70 + $Count * $Delay + 6)  # includes up to 60 s for TShark to start

$server = $null; $observer = $null
try {
    $server = Start-Process -PassThru -NoNewWindow -FilePath $Python `
        -ArgumentList "server/api_server.py", "--host", "127.0.0.1", "--port", "$Port" `
        -RedirectStandardOutput "$absLogDir\server.out" -RedirectStandardError "$absLogDir\server.err"

    $observerArgs = @("observer/observer.py", "--mode", $mode, "--filter", "`"tcp port $Port`"", "--duration", "$observerSeconds")
    if ($Capture) { $observerArgs += @("--interface", $Interface, "--backend", "tshark") }
    if ($Tls) { $observerArgs += @("--transport", "https") }
    $observer = Start-Process -PassThru -NoNewWindow -FilePath $Python -ArgumentList $observerArgs `
        -RedirectStandardOutput "$absLogDir\observer.out" -RedirectStandardError "$absLogDir\observer.err"

    # Wait until the server port accepts connections (max ~10 s). A plain TCP check works for
    # http and https alike, without trusting or skipping certificates here.
    $ready = $false
    for ($i = 0; $i -lt 20 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 500
        $tcp = New-Object System.Net.Sockets.TcpClient
        try { $tcp.Connect("127.0.0.1", $Port); $ready = $true } catch { } finally { $tcp.Close() }
    }
    if (-not $ready) { throw "server did not start; see $absLogDir\server.err" }
    if ($Capture) {
        # TShark can take from 1 s to well over 10 s to start; wait for it instead of guessing.
        $capturing = $false
        for ($i = 0; $i -lt 120 -and -not $capturing; $i++) {
            Start-Sleep -Milliseconds 500
            $capturing = [bool](Select-String -Path "$absLogDir\observer.out" -Pattern "Capturing on" -Quiet -ErrorAction SilentlyContinue)
        }
        if (-not $capturing) { throw "TShark did not start capturing within 60 s; see $absLogDir\observer.out" }
    } else {
        Start-Sleep -Seconds 2
    }

    & $Python client/traffic_generator.py --target "$($scheme)://127.0.0.1:$Port" --sender local-client --count $Count --delay $Delay @clientExtra
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
    $events | Select-Object direction, transport, method, endpoint, status_code, latency_ms,
        server_processing_ms, request_bytes, app_encryption, decryption_status,
        @{n = "message"; e = { $_.payload.message } },
        @{n = "evidence"; e = { $_.evidence -join "," } }, capture_match |
        Format-Table -AutoSize | Out-String -Width 250 | Write-Host
} else {
    Write-Host "[demo] no events written" -ForegroundColor Red
}
exit $clientExit
