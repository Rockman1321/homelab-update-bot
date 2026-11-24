#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! .venv/bin/python scripts/check_restart_safe.py; then
    if [[ "${1:-}" != "--force" ]]; then
        echo "Refusing to restart -- pass --force to override (see scripts/check_restart_safe.py's own output above for why that's rarely the right call)." >&2
        exit 1
    fi
    echo "--force given -- restarting anyway." >&2
fi

sudo systemctl restart rbd-update-bot
