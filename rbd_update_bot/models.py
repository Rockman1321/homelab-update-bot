"""Core data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Stage(str, Enum):
    RECEIVED = "received"
    RESEARCHING = "researching"
    STAGED_PENDING_APPROVAL = "staged_pending_approval"
    APPROVED = "approved"
    AWAITING_BACKUP_DECISION = "awaiting_backup_decision"
    BACKING_UP_PROXMOX = "backing_up_proxmox"
    BACKING_UP_KOPIA = "backing_up_kopia"
    UPDATING = "updating"
    LOG_WATCH = "log_watch"
    AWAITING_REBOOT_DECISION = "awaiting_reboot_decision"
    REBOOTING = "rebooting"
    DONE_SUCCESS = "done_success"
    DONE_FAILED = "done_failed"
    ABORTED = "aborted"

    @property
    def terminal(self) -> bool:
        return self in {Stage.DONE_SUCCESS, Stage.DONE_FAILED, Stage.ABORTED}


@dataclass
class RiskAssessment:
    risk_level: str
    breaking_changes: bool
    summary: str
    citations: list[str] = field(default_factory=list)
    security_severity: str = "none"


@dataclass
class UpdateRecord:

    id: int | None
    service_name: str
    image: str
    current_version: str
    new_version: str
    diun_entry_id: str
    stage: Stage
    risk_level: str | None = None
    breaking_changes: bool | None = None
    risk_summary: str | None = None
    security_severity: str | None = None
    release_notes_url: str | None = None
    approved_by: str | None = None
    approved_at: str | None = None
    error: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    digest: str | None = None
    backup_decision: str | None = None
    superseded_by: int | None = None
    proposed_repair: list[str] | None = None
    kind: str = "container"
    reboot_decision: str | None = None
