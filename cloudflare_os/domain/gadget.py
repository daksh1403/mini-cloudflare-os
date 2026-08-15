"""Gadget domain logic — the platform owns ALL access control.

This mirrors the Sandstorm/Cloudflare OS security model: a Gadget can never
grant itself access. The platform decides, and the Gadget trusts the platform
binding. Pure functions here are the TDD-tested core.
"""

from __future__ import annotations

from .types import (
    AclEntry,
    AuditEntry,
    GadgetMeta,
    GadgetPermission,
    GadgetRecord,
    Principal,
    Role,
)

MAX_ACL_ENTRIES = 50


def check_access(meta: GadgetMeta, principal: Principal | None, action: str) -> GadgetPermission:
    """Decide whether `principal` may perform `action` (read/write/admin)."""
    if principal is None:
        return GadgetPermission(False, None, "authentication required")
    entry = next((e for e in meta.acl if e.user_id == principal.user_id), None)
    if entry is None:
        return GadgetPermission(False, None, "not a member of this gadget")

    def role_allows(required: str) -> bool:
        if entry.role is Role.OWNER:
            return True
        if entry.role is Role.EDITOR:
            return required != "admin"
        return required == "read"

    return GadgetPermission(role_allows(action), entry.role)


def create_gadget(id: str, name: str, app: str, owner_id: str, created_at: int) -> GadgetRecord:
    """Mint a gadget; the owner is added to the ACL automatically."""
    if not id or not name or not app or not owner_id:
        raise ValueError("id, name, app and owner_id are required")
    if len(name) > 64:
        raise ValueError("name must be 64 characters or fewer")
    if len(app) > 32:
        raise ValueError("app must be 32 characters or fewer")
    meta = GadgetMeta(
        id=id,
        name=name,
        app=app,
        owner_id=owner_id,
        created_at=created_at,
        acl=[AclEntry(owner_id, Role.OWNER)],
    )
    return GadgetRecord(meta)


def grant_access(
    record: GadgetRecord, granter: Principal | None, user_id: str, role: Role
) -> GadgetRecord | None:
    """Add a collaborator. Only the owner may do this."""
    if granter is None or granter.user_id != record.meta.owner_id:
        return None
    if not user_id:
        raise ValueError("user_id is required")
    if role not in (Role.OWNER, Role.EDITOR, Role.VIEWER):
        raise ValueError("role must be owner, editor or viewer")
    if any(e.user_id == user_id for e in record.meta.acl):
        raise ValueError("user is already a member of this gadget")
    if len(record.meta.acl) >= MAX_ACL_ENTRIES:
        raise ValueError("gadget has reached the maximum number of members")
    meta = GadgetMeta(
        id=record.meta.id,
        name=record.meta.name,
        app=record.meta.app,
        owner_id=record.meta.owner_id,
        created_at=record.meta.created_at,
        acl=[*record.meta.acl, AclEntry(user_id, role)],
    )
    return GadgetRecord(meta, dict(record.data))


def revoke_access(record: GadgetRecord, revoker: Principal | None, user_id: str) -> GadgetRecord | None:
    """Remove a collaborator. Only the owner may do this."""
    if revoker is None or revoker.user_id != record.meta.owner_id:
        return None
    if user_id == record.meta.owner_id:
        raise ValueError("cannot remove the owner")
    meta = GadgetMeta(
        id=record.meta.id,
        name=record.meta.name,
        app=record.meta.app,
        owner_id=record.meta.owner_id,
        created_at=record.meta.created_at,
        acl=[e for e in record.meta.acl if e.user_id != user_id],
    )
    return GadgetRecord(meta, dict(record.data))


def update_gadget_data(record: GadgetRecord, updates: dict[str, str]) -> GadgetRecord:
    """App-layer write. The platform only cares about authorization."""
    return GadgetRecord(record.meta, {**record.data, **updates})


class MemoryStorage:
    """In-memory storage adapter — used by unit tests and the BDD runner."""

    def __init__(self) -> None:
        self._records: dict[str, GadgetRecord] = {}
        self._audit: list[AuditEntry] = []

    def get(self, id: str) -> GadgetRecord | None:
        return self._records.get(id)

    def put(self, record: GadgetRecord) -> None:
        self._records[record.meta.id] = record

    def append(self, entry: AuditEntry) -> None:
        self._audit.append(entry)

    def all(self) -> list[GadgetRecord]:
        return list(self._records.values())

    def audit_log(self) -> list[AuditEntry]:
        return list(self._audit)
