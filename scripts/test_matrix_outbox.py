#!/usr/bin/env python3
"""Offline test of the Matrix outbox retry."""
from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nio import RoomSendError, RoomSendResponse

from rbd_update_bot.db import Store
from rbd_update_bot.matrix_bot import MatrixBot


async def _noop(*a, **k):
    return None


class FakeSend:
    def __init__(self):
        self.mode, self.sent, self.tries = "up", [], []

    async def __call__(self, room_id, message_type, content, tx_id=None, ignore_unverified_devices=False):
        self.tries.append(tx_id)
        if self.mode == "raise":
            raise ConnectionError("Cannot connect to host matrix.example.com")
        if self.mode == "error":
            return RoomSendError("M_UNKNOWN: homeserver restarting")
        self.sent.append((room_id, content["body"], tx_id))
        return RoomSendResponse("$ev", room_id)


async def main() -> None:
    store = Store(":memory:")
    bot = MatrixBot("http://hs", "@rbd-update-bot:example.com", "t", "!cmd", _noop, store=store,
                    admin_user_ids=["@owner:example.com"], coordination_room_id="!bots")
    fake = FakeSend()
    bot.client.room_send = fake
    bodies = lambda: [b for _, b, _ in fake.sent]

    await bot.notify("alert 1")
    assert bodies() == ["alert 1"] and store.outbox_pending() == []

    fake.mode = "error"
    await bot.notify("alert 2")
    first_txn = fake.tries[-1]
    fake.mode = "raise"
    await bot.send_bot_message({"msgtype": "m.notice", "body": "maintenance end"})
    fake.mode = "up"
    await bot.notify("alert 3")
    assert bodies() == ["alert 1"] and len(store.outbox_pending()) == 3

    fake.mode = "raise"
    assert await bot.flush_outbox() == 0
    pend = store.outbox_pending()
    assert pend[0]["attempts"] == 1 and pend[1]["attempts"] == 0
    fake.mode = "up"
    assert await bot.flush_outbox() == 3
    assert bodies() == ["alert 1", "alert 2", "maintenance end", "alert 3"]
    assert fake.sent[1][2] == first_txn and fake.sent[2][0] == "!bots"

    fake.mode = "error"
    await bot.send_bot_message({"msgtype": "m.notice", "body": "old status"})
    await bot.notify("still relevant")
    fake.mode = "up"
    store._conn.execute("UPDATE matrix_outbox SET expires_at = '2000-01-01T00:00:00+00:00' "
                        "WHERE content LIKE '%old status%'")
    assert await bot.flush_outbox() == 1 and bodies()[-1] == "still relevant" and "old status" not in bodies()

    nostore = MatrixBot("http://hs", "@x:y", "t", "!cmd", _noop)
    nostore.client.room_send = fake
    fake.mode = "raise"
    await nostore.notify("one-off script")
    print("test_matrix_outbox: all checks passed")


asyncio.run(main())
