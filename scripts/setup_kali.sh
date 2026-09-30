#!/usr/bin/env bash
# Kali host setup: same as scripts/setup_linux.sh with NODE_NAME=kali (kept for existing instructions).
# Usage: bash scripts/setup_kali.sh [PORT]
exec bash "$(dirname "${BASH_SOURCE[0]}")/setup_linux.sh" "${1:-8000}" kali
