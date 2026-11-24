#!/usr/bin/env python3
"""Exits non-zero if restarting the bot now would interrupt an update in progress."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rbd_update_bot.config import load_config
from rbd_update_bot.db import Store


def main() -> int:
    config = load_config()
    store = Store(config.db_path)
    unsafe = [r for r in store.list_active() if r.stage not in Store._RESTART_SAFE_STAGES]
    if not unsafe:
        print("Safe to restart -- nothing in-flight outside staged_pending_approval/approved.")
        return 0

    print("NOT safe to restart -- the following update(s) are actively mid-pipeline:")
    for r in unsafe:
        print(f"  #{r.id} {r.service_name} {r.current_version}->{r.new_version}: stage={r.stage.value}")
    print("\nA restart now will orphan these -- the next startup's reconcile pass will force-fail")
    print("them and you'll need to manually !mark-passed/!investigate afterward. Wait for them to")
    print("clear (or reach staged_pending_approval/approved) before restarting.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
