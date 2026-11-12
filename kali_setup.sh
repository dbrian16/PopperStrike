#!/usr/bin/env bash
# Run only on the Kali/Linux machine used for the authorized lab.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    echo 'This setup requires Linux.' >&2
    exit 1
fi

# Resolve all paths relative to this script, even when invoked elsewhere.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$SCRIPT_DIR"
if ! command -v apt-get >/dev/null 2>&1; then
    echo 'This setup requires Kali/Debian with apt-get.' >&2
    exit 1
fi

APT=(apt-get)
if [[ "$EUID" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo 'sudo is required to install system packages.' >&2
        exit 1
    fi
    APT=(sudo apt-get)
fi

# Install venv support independently of whether security tools already exist.
# Use distribution packages instead of an unchecked, architecture-specific ZIP.
"${APT[@]}" update
"${APT[@]}" install -y python3 python3-venv python3-pip ca-certificates nmap gobuster curl jq
if ! command -v subfinder >/dev/null 2>&1; then
    if ! "${APT[@]}" install -y subfinder; then
        echo 'Optional subfinder unavailable; subdomain enumeration requires installing it separately.' >&2
    fi
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo 'Python 3.11 or newer is required.' >&2
    exit 1
fi
if [[ ! -e .venv ]]; then
    python3 -m venv .venv
fi
if [[ ! -x .venv/bin/python ]]; then
    echo 'Existing .venv is not a Linux virtual environment. Move it aside and rerun setup.' >&2
    exit 1
fi
if ! .venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo 'Existing .venv requires Python 3.11 or newer. Recreate it on Kali.' >&2
    exit 1
fi
.venv/bin/python -m pip install -e .

printf '\nCore installation complete. Optional MCP support: .venv/bin/python -m pip install -e ".[mcp]"\n'
printf 'Activate: source "%s/.venv/bin/activate"\n' "$SCRIPT_DIR"
printf 'Dashboard: agentpentest-ui --no-browser\n'
printf 'Deployment instructions: %s/DEPLOY.md\n' "$SCRIPT_DIR"
.venv/bin/agentpentest-lock status
