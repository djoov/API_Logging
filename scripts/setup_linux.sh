#!/usr/bin/env bash
# Inspect a Linux host (Ubuntu, Kali, Debian) and prepare the lab (non-destructive).
#   - Reports Python, Conda, tcpdump/TShark, IP addresses and firewall state.
#   - Creates the "api-observability" Conda env if Conda exists and the env is missing;
#     without Conda, prints the venv commands (Ubuntu 23.04+ refuses pip into the system Python).
#   - Copies .env.example to .env (NODE_NAME=<name>) if .env does not exist.
# It never changes firewall rules or capture permissions; it prints the commands instead.
#
# Usage: bash scripts/setup_linux.sh [PORT] [NODE_NAME]      e.g. bash scripts/setup_linux.sh 8000 ubuntu
set -euo pipefail

PORT="${1:-8000}"
NODE="${2:-$(hostname -s | tr '[:upper:]_' '[:lower:]-')}"
ENV_NAME="api-observability"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

section() { printf '\n\033[36m=== %s ===\033[0m\n' "$1"; }
ok()      { printf '  \033[32m[OK]\033[0m   %s\n' "$1"; }
warn()    { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; }
info()    { printf '         %s\n' "$1"; }

section "System"
if [[ -r /etc/os-release ]]; then ok "$(. /etc/os-release && echo "${PRETTY_NAME}")"; fi
info "node name for .env: ${NODE}"

section "Python / Conda"
if command -v python3 >/dev/null 2>&1; then
    ok "python3: $(command -v python3) ($(python3 --version 2>&1))"
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
        warn "the lab is tested on Python 3.12+ (Windows 3.12, Kali 3.14); use Conda (environment.yml) for 3.12"
    fi
else
    warn "python3 not found (sudo apt install python3)"
fi

if command -v conda >/dev/null 2>&1; then
    ok "conda: $(conda --version)"
    if conda env list | grep -qE "^${ENV_NAME}[[:space:]]"; then
        ok "conda env '${ENV_NAME}' already exists (update: conda env update -f environment.yml --prune)"
    else
        info "creating conda env '${ENV_NAME}' from environment.yml ..."
        conda env create -f "${PROJECT_ROOT}/environment.yml"
        ok "conda env '${ENV_NAME}' created"
    fi
    conda run -n "${ENV_NAME}" python -c "import fastapi, uvicorn, httpx, pydantic, dotenv, cryptography, pytest; print('fastapi', fastapi.__version__, '| uvicorn', uvicorn.__version__, '| httpx', httpx.__version__)" \
        && ok "packages importable" || warn "package check failed"
else
    warn "conda not found. environment.yml stays the source of truth; install Miniconda, or use a venv:"
    info "sudo apt install python3-venv          # Ubuntu/Debian"
    info "python3 -m venv .venv && source .venv/bin/activate"
    info "pip install -r requirements.txt"
fi

section "Packet capture tools"
if command -v tcpdump >/dev/null 2>&1; then ok "tcpdump: $(command -v tcpdump) ($(tcpdump --version 2>&1 | head -n1))"; else warn "tcpdump not found (sudo apt install tcpdump)"; fi
if command -v tshark >/dev/null 2>&1; then
    ok "tshark: $(tshark --version 2>/dev/null | head -n1)"
    if id -nG "$USER" | grep -qw wireshark; then
        ok "user '$USER' is in group 'wireshark' (can capture without sudo)"
    else
        warn "user '$USER' is not in group 'wireshark'; capture will need sudo. To allow non-root capture:"
        info "sudo dpkg-reconfigure wireshark-common   # answer Yes (Ubuntu asks this at install time)"
        info "sudo usermod -aG wireshark \"$USER\"   # then log out and back in"
    fi
else
    warn "tshark not found (sudo apt install tshark). The observer falls back to tcpdump."
fi

section "Interfaces"
ip -brief addr show | while read -r line; do info "$line"; done
info "Capture interface names (use as OBSERVER_INTERFACE):"
if command -v tshark >/dev/null 2>&1; then tshark -D 2>/dev/null | while read -r l; do info "  $l"; done
elif command -v tcpdump >/dev/null 2>&1; then tcpdump -D 2>/dev/null | while read -r l; do info "  $l"; done; fi

section "Clock"
if command -v timedatectl >/dev/null 2>&1; then
    info "$(timedatectl show -p NTPSynchronized --value 2>/dev/null | sed 's/^/NTP synchronized: /')"
fi

section "Firewall"
if command -v ufw >/dev/null 2>&1; then
    info "ufw: $(sudo -n ufw status 2>/dev/null | head -n1 || echo 'status needs sudo: sudo ufw status')"
    info "if active, allow the lab port from the OTHER lab host only, e.g.: sudo ufw allow from <WINDOWS_IP> to any port ${PORT} proto tcp"
else
    info "ufw not installed"
fi
if command -v nft >/dev/null 2>&1; then info "nftables rules: sudo nft list ruleset"; fi
if command -v iptables >/dev/null 2>&1; then info "iptables rules: sudo iptables -S INPUT"; fi

section ".env"
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    ok ".env exists (not modified)"
else
    cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
    sed -i "s/^NODE_NAME=.*/NODE_NAME=${NODE}/" "${PROJECT_ROOT}/.env"
    ok "created .env (NODE_NAME=${NODE}) -> edit TARGET_HOST, LLM_TARGET_URL and OBSERVER_INTERFACE"
fi

section "Next steps"
info "conda activate ${ENV_NAME}    (or: source .venv/bin/activate)"
info "python -m pytest"
info "python observer/observer.py --list-interfaces"
