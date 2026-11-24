#!/usr/bin/env python3
"""One-time setup of an Uptime Kuma maintenance window per service."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from uptime_kuma_api import MaintenanceStrategy, UptimeKumaApi

from rbd_update_bot.config import load_config

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument("--list", action="store_true", help="list every monitor's {id, name}")
parser.add_argument("--create", metavar="SERVICE_NAME", help="create a maintenance window for this service")
parser.add_argument("--monitor-id", type=int, help="the Kuma monitor id to associate (required with --create)")
args = parser.parse_args()

config = load_config()
if not config.uptime_kuma_base_url:
    sys.exit("monitoring.uptime_kuma_base_url isn't set in config.yaml")

api = UptimeKumaApi(config.uptime_kuma_base_url, timeout=10)
api.login(config.uptime_kuma_username, config.uptime_kuma_password)

try:
    if args.list:
        for m in api.get_monitors():
            print(f"{m['id']}: {m['name']}")
    elif args.create:
        if args.monitor_id is None:
            sys.exit("--monitor-id is required with --create (run --list first to find it)")
        result = api.add_maintenance(
            title=f"{args.create} -- bot-initiated maintenance",
            description="Toggled automatically by rbd-update-bot's !patch/!reboot/update pipelines.",
            strategy=MaintenanceStrategy.MANUAL,
            active=False,
        )
        maintenance_id = result["maintenanceID"]
        api.add_monitor_maintenance(maintenance_id, [{"id": args.monitor_id}])
        print(result)
        print(
            f"\nAdd this to services.yaml under '{args.create}:':\n"
            f"  uptime_kuma:\n    maintenance_id: {result['maintenanceID']}"
        )
    else:
        parser.print_help()
finally:
    api.disconnect()
