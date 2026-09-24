<#
.SYNOPSIS
  Inspect the Windows host and prepare the lab (non-destructive).

.DESCRIPTION
  - Reports Python, Conda, TShark, IPv4 addresses and firewall state.
  - Creates the "api-observability" Conda env if it does not exist yet.
  - Copies .env.example to .env if .env does not exist yet.
  - Only with -AddFirewallRule (run as Administrator): adds ONE inbound allow rule for the
    API port, restricted to the local subnet. The firewall itself is never disabled.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 -AddFirewallRule -Port 8000
  # Peer on a different, routed subnet (LocalSubnet would not match it):
  powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1 -AddFirewallRule -RemoteAddress <KALI_IP>
#>
param(
    [int]$Port = 8000,
    # Who may connect: LocalSubnet (same /24), or the peer IP when it sits on another subnet.
    [string]$RemoteAddress = "LocalSubnet",
    [switch]$AddFirewallRule,
    [switch]$SkipCondaEnv
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvName = "api-observability"
$RuleName = "API Observability Lab TCP $Port"

function Section($title) { Write-Host ""; Write-Host "=== $title ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Info($msg) { Write-Host "         $msg" }

Section "Python / Conda"
$conda = Get-Command conda -ErrorAction SilentlyContinue
if ($conda) {
    Ok "conda: $($conda.Source) ($(conda --version))"
} else {
    Warn "conda not found in this shell. Open 'Anaconda Prompt' or run 'conda init powershell'."
}
$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) { Info "python on PATH: $($py.Source) ($(python --version 2>&1))" }

if ($conda -and -not $SkipCondaEnv) {
    $envs = conda env list | Out-String
    if ($envs -match "(?m)^$EnvName\s") {
        Ok "conda env '$EnvName' already exists (update: conda env update -f environment.yml --prune)"
    } else {
        Info "creating conda env '$EnvName' from environment.yml ..."
        conda env create -f (Join-Path $ProjectRoot "environment.yml")
        if ($LASTEXITCODE -ne 0) { throw "conda env create failed (exit $LASTEXITCODE)" }
        Ok "conda env '$EnvName' created"
    }
    $check = "import fastapi, uvicorn, httpx, pydantic, dotenv, cryptography, pytest; print('fastapi', fastapi.__version__, '| uvicorn', uvicorn.__version__, '| httpx', httpx.__version__)"
    $out = conda run -n $EnvName python -c $check 2>&1
    if ($LASTEXITCODE -eq 0) { Ok "packages: $out" } else { Warn "package check failed: $out" }
}

Section "TShark"
$tshark = (Get-Command tshark -ErrorAction SilentlyContinue).Source
if (-not $tshark) {
    $default = Join-Path $env:ProgramFiles "Wireshark\tshark.exe"
    if (Test-Path $default) { $tshark = $default; Warn "tshark is not on PATH; found $default (the observer finds it automatically)" }
}
if ($tshark) {
    Ok ((& $tshark --version | Select-Object -First 1))
    Info "Capture interfaces (use the number or name as OBSERVER_INTERFACE):"
    & $tshark -D | ForEach-Object { Info "  $_" }
} else {
    Warn "TShark not found. Install Wireshark (with Npcap) or run the observer with --mode app."
}

Section "Network (IPv4)"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    ForEach-Object {
        $desc = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription
        Info ("{0,-28} {1,-16} /{2}  {3}" -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength, $desc)
    }
Info "Pick the address on the adapter that connects to the Kali VM (VirtualBox Host-Only, bridged Wi-Fi, ...)."

Section "Firewall"
Get-NetFirewallProfile | ForEach-Object { Info ("profile {0,-8} enabled={1}" -f $_.Name, $_.Enabled) }
$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    Ok "inbound rule '$RuleName' exists"
} elseif ($AddFirewallRule) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "-AddFirewallRule needs an elevated PowerShell (Run as Administrator)" }
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
        -RemoteAddress $RemoteAddress -Action Allow -Profile Any | Out-Null
    Ok "added inbound rule '$RuleName' (TCP $Port, from $RemoteAddress only)"
    Info "remove later with: Remove-NetFirewallRule -DisplayName '$RuleName'"
} else {
    Warn "no inbound rule for TCP $Port. If Kali cannot reach Windows, re-run as Administrator with -AddFirewallRule"
}

Section ".env"
$envFile = Join-Path $ProjectRoot ".env"
if (Test-Path $envFile) {
    Ok ".env exists (not modified)"
} else {
    Copy-Item (Join-Path $ProjectRoot ".env.example") $envFile
    Ok "created .env from .env.example -> edit NODE_NAME, TARGET_HOST, OBSERVER_INTERFACE"
}

Section "Next steps"
Info "conda activate $EnvName"
Info "python server/api_server.py"
Info "python observer/observer.py --list-interfaces"
