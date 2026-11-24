"""Checks whether an email is a known contact in the wedding planning app."""
from __future__ import annotations

import shlex

from . import executor
from .config import ServiceConfig

_QUERY = (
    "SELECT COUNT(*) FROM guests g "
    "JOIN guest_members gm ON gm.guest_id = g.id "
    "WHERE trim(coalesce(gm.wedding_role, '')) != '' "
    "AND (lower(g.email) = lower(?) OR lower(coalesce(gm.email, '')) = lower(?))"
)


def is_known_contact(
    service: ServiceConfig, db_path: str, email: str, *,
    identity_file: str = "", mgmt_host: str = "", mgmt_ssh_user: str = "", timeout: float = 30.0,
) -> bool:
    remote_script = (
        "import sqlite3,sys;"
        f"conn = sqlite3.connect('file:{db_path}?mode=ro', uri=True);"
        f"row = conn.execute({_QUERY!r}, (sys.argv[1], sys.argv[1])).fetchone();"
        "print(1 if row and row[0] > 0 else 0)"
    )
    command = f"python3 -c {shlex.quote(remote_script)} {shlex.quote(email)}"
    ok, output = executor.run_remote_command(
        service, command, identity_file=identity_file,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=timeout,
    )
    if not ok:
        return False
    return output.strip() == "1"
