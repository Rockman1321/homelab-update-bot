"""Break-glass CLI to approve, abort or inspect updates without Matrix."""
from __future__ import annotations

import argparse
import sys

from .config import load_config
from .db import Store
from .models import Stage


def main() -> None:
    parser = argparse.ArgumentParser(prog="rbd-update-bot")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--all", action="store_true", help="include finished/aborted updates")

    p_status = sub.add_parser("status")
    p_status.add_argument("update_id", type=int)

    p_approve = sub.add_parser("approve")
    p_approve.add_argument("update_id", type=int)

    p_abort = sub.add_parser("abort")
    p_abort.add_argument("update_id", type=int)

    args = parser.parse_args()
    config = load_config()
    store = Store(config.db_path)

    if args.command == "list":
        records = _list_all(store) if args.all else store.list_active()
        for r in records:
            print(f"#{r.id:<4} {r.service_name:<12} {r.current_version} -> {r.new_version:<12} [{r.stage.value}]")
        return

    if args.command == "status":
        record = store.get(args.update_id)
        if record is None:
            print(f"no update #{args.update_id}", file=sys.stderr)
            sys.exit(1)
        print(f"#{record.id} {record.service_name} {record.current_version} -> {record.new_version}")
        print(f"stage: {record.stage.value}")
        if record.risk_summary:
            print(f"risk ({record.risk_level}): {record.risk_summary}")
        if record.superseded_by:
            print(f"superseded by: #{record.superseded_by} (a later attempt for this service succeeded)")
        for event in store.events_for(args.update_id):
            print(f"  {event['created_at']}  {event['stage']:<24} {event['message']}")
        return

    if args.command == "abort":
        record = store.get(args.update_id)
        if record is None or record.stage.terminal:
            print(f"update #{args.update_id} not active", file=sys.stderr)
            sys.exit(1)
        store.set_stage(args.update_id, Stage.ABORTED, "aborted via break-glass CLI")
        print(f"update #{args.update_id} aborted")
        return

    if args.command == "approve":
        record = store.get(args.update_id)
        if record is None or record.stage != Stage.STAGED_PENDING_APPROVAL:
            print(f"update #{args.update_id} is not awaiting approval", file=sys.stderr)
            sys.exit(1)
        store.set_approved(args.update_id, "cli-break-glass")
        store.set_stage(args.update_id, Stage.APPROVED, "approved via break-glass CLI")
        print(
            f"update #{args.update_id} approved. The running orchestrator process "
            f"will pick it up within its poll interval (default 5s)."
        )
        return


def _list_all(store: Store):
    misses = 0
    i = 1
    while misses < 50:
        record = store.get(i)
        if record is None:
            misses += 1
        else:
            misses = 0
            yield record
        i += 1


if __name__ == "__main__":
    main()
