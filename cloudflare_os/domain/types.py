"""Domain types shared across the platform, Gadgets, and tests.

These are plain data shapes. The platform is the only thing that can mint a
Principal, and Gadgets only ever see a principal user id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class SideEffectState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class Principal:
    """A verified caller identity, minted by the platform."""

    user_id: str


@dataclass(frozen=True)
class AclEntry:
    user_id: str
    role: Role


@dataclass(frozen=True)
class GadgetMeta:
    id: str
    name: str
    app: str
    owner_id: str
    created_at: int
    acl: list[AclEntry] = field(default_factory=list)


@dataclass
class GadgetRecord:
    meta: GadgetMeta
    data: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    gadget_id: str
    action: str
    target: str
    payload: str
    requested_by: str
    created_at: int
    state: SideEffectState = SideEffectState.PENDING


@dataclass(frozen=True)
class AuditEntry:
    id: str
    gadget_id: str
    actor: str
    action: str
    detail: str
    at: int


@dataclass(frozen=True)
class GadgetPermission:
    allowed: bool
    role: Role | None = None
    reason: str | None = None
