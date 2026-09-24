<#
.SYNOPSIS
  Phase 4 smoke test on ONE Windows machine: mock Ollama + HTTPS gateway + observer + LLM client.

.DESCRIPTION
  Everything runs on 127.0.0.1 with a throw-away demo CA (logs/demo/certs) and its own log folder
  (logs/demo-llm), ignoring the project .env. Use -RealOllama to forward to a real Ollama on
  127.0.0.1:11434 instead of starting the mock (then pass -Model with a model you have pulled).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\run_llm_demo.ps1
  powershell -ExecutionPolicy Bypass -File scripts\run_llm_demo.ps1 -Capture -NoStream
  powershell -ExecutionPolicy Bypass -File scripts\run_llm_demo.ps1 -RealOllama -Model llama3.2
#>
param(
    [int]$GatewayPort = 8443,
    [int]$MockPort = 11434,
    [int]$Count = 2,
    [double]$Delay = 2,
    [string]$Model = "mock-llm",
    [switch]$Capture,
    [switch]$NoStream,
    [switch]$RealOllama,
    [string]$Interface = "\Device\NPF_Loopback",
    [string]$LogDir = "logs/demo-llm"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if ($env:CONDA_DEFAULT_ENV -eq "api-observability") {
    $Python = (Get-Command python).Source
} else {
    $Python = (conda run -n api-observability python -c "import sys; print(sys.executable)").Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Python)) { throw "conda env 'api-observability' not found" }
}

$absLogDir = Join-Path $ProjectRoot $LogDir
if (Test-Path $absLogDir) { Get-ChildItem $absLogDir -Filter *.jsonl | Remove-Item }
New-Item -ItemType Directory -Force $absLogDir | Out-Null

# Demo-only CA/certificate for 127.0.0.1 (shared with run_demo.ps1 -Tls).
$certDir = Join-Path $ProjectRoot "logs/demo/certs"
if (-not (Test-Path (Join-Path $certDir "ca.pem"))) {
    & $Python scripts/make_certs.py --dir $certDir ca | Out-Null
    & $Python scripts/make_certs.py --dir $certDir server --name local --ip 127.0.0.1 --dns localhost | Out-Null
}

# Process-scoped settings; the real lab .env is not read.
$env:ENV_FILE = Join-Path $absLogDir "demo-has-no.env"
$env:LOG_DIR = $LogDir
$env:NODE_NAME = "gateway-host"
$env:TLS_CERT_FILE = Join-Path $certDir "local.pem"
$env:TLS_KEY_FILE = Join-Path $certDir "local.key"
$env:TLS_CA_FILE = Join-Path $certDir "ca.pem"
$env:OLLAMA_URL = "http://127.0.0.1:$MockPort"
$env:OBSERVER_MERGE_WINDOW_SECONDS = "1"
$env:OBSERVER_TLS_IDLE_SECONDS = "10"
$env:OBSERVER_INCOMPLETE_TIMEOUT_SECONDS = "300"

$observerSeconds = [int](75 + $Count * ($Delay + 8))  # includes up to 60 s for TShark to start
$procs = @()
function Wait-Port([int]$port) {
    for ($i = 0; $i -lt 40; $i++) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try { $tcp.Connect("127.0.0.1", $port); return } catch { Start-Sleep -Milliseconds 250 } finally { $tcp.Close() }
    }
    throw "nothing listening on port $port"
}

try {
    if (-not $RealOllama) {
        $procs += Start-Process -PassThru -NoNewWindow -FilePath $Python `
            -ArgumentList "tools/mock_ollama.py", "--port", "$MockPort" `
            -RedirectStandardOutput "$absLogDir\mock.out" -RedirectStandardError "$absLogDir\mock.err"
    }
    Wait-Port $MockPort
    $procs += Start-Process -PassThru -NoNewWindow -FilePath $Python `
        -ArgumentList "gateway/ollama_gateway.py", "--host", "127.0.0.1", "--port", "$GatewayPort" `
        -RedirectStandardOutput "$absLogDir\gateway.out" -RedirectStandardError "$absLogDir\gateway.err"
    Wait-Port $GatewayPort

    $observerArgs = @("observer/observer.py", "--mode", $(if ($Capture) { "both" } else { "app" }),
                      "--filter", "`"tcp port $GatewayPort`"", "--duration", "$observerSeconds")
    if ($Capture) { $observerArgs += @("--interface", $Interface, "--backend", "tshark", "--transport", "https") }
    $observer = Start-Process -PassThru -NoNewWindow -FilePath $Python -ArgumentList $observerArgs `
        -RedirectStandardOutput "$absLogDir\observer.out" -RedirectStandardError "$absLogDir\observer.err"
    $procs += $observer
    if ($Capture) {
        # TShark can take from 1 s to well over 10 s to start; wait for it instead of guessing.
        $ready = $false
        for ($i = 0; $i -lt 120 -and -not $ready; $i++) {
            Start-Sleep -Milliseconds 500
            $ready = [bool](Select-String -Path "$absLogDir\observer.out" -Pattern "Capturing on" -Quiet -ErrorAction SilentlyContinue)
        }
        if (-not $ready) { throw "TShark did not start capturing within 60 s; see $absLogDir\observer.out" }
        Write-Host "[llm-demo] capture is running"
    } else {
        Start-Sleep -Seconds 2
    }

    $clientArgs = @("client/llm_client.py", "--target", "https://127.0.0.1:$GatewayPort", "--sender", "client-host",
                    "--model", $Model, "--count", "$Count", "--delay", "$Delay")
    if ($NoStream) { $clientArgs += "--no-stream" }
    & $Python @clientArgs
    $clientExit = $LASTEXITCODE
    Write-Host "[llm-demo] waiting for observer ($observerSeconds s window) ..."
    $observer.WaitForExit()
} finally {
    foreach ($p in $procs) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id } }
}

# Logs are UTF-8; Windows PowerShell 5.1 would otherwise read them as ANSI and garble "…".
Write-Host "`n===== gateway log (host running Ollama) ====="; Get-Content "$absLogDir\gateway.out" -Encoding UTF8
Write-Host "`n===== observer log ====="
Get-Content "$absLogDir\observer.out" -Encoding UTF8 | Select-String -Pattern "OBSERVED|LLM |PROMPT|RESPONSE|WIRE TLS|ERROR|wrote"
exit $clientExit
