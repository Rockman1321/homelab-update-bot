#!/usr/bin/env python3
"""Manual check: send a test message to the configured room."""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rbd_update_bot.config import load_config
from rbd_update_bot.matrix_bot import MatrixBot


async def main() -> None:
    config = load_config()

    async def noop(command: str, update_id: int, sender: str) -> None:
        pass

    bot = MatrixBot(
        homeserver=config.matrix_homeserver,
        user_id=config.matrix_user_id,
        access_token=config.matrix_access_token,
        room_id=config.matrix_room_id,
        on_command=noop,
    )
    print(f"Sending to room_id={config.matrix_room_id!r} as {config.matrix_user_id} ...")
    await bot.notify("rbd-update-bot test message -- if you see this, room_id works as configured.")
    print("Sent without error.")
    await bot.close()


asyncio.run(main())
