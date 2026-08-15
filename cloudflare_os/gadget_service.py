"""Gadget service — the per-instance app logic behind the platform.

Holds one Gadget's state (record + approvals + audit) and enforces the
platform's ACL decisions on every operation. This is the Python analog of a
Cloudflare Durable Object: one instance per Gadget.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from .domain.gadget import (
    check_access,
    create_gadget,
    grant_access,
    revoke_access,
    update_gadget_data,
)
from .domain.gatekeeper import decide_approval, queue_approval
from .domain.types import (
    ApprovalRequest,
    AuditEntry,
    GadgetRecord,
    Principal,
    Role,
    SideEffectState,
)


class Storage(Protocol):
    """Minimal persistence contract satisfied by MemoryStorage (and SQLite later)."""

    def get(self, id: str) -> GadgetRecord | None: ...

    def put(self, record: GadgetRecord) -> None: ...


@dataclass
class GadgetService:
    """Stateful per-gadget service.

    `storage` abstracts persistence (MemoryStorage in tests, SQLite in a real
    deployment), which keeps the security logic testable without a database.
    """

    gadget_id: str
    storage: Storage
    approvals: list[ApprovalRequest] = field(default_factory=list)
    audit: list[AuditEntry] = field(default_factory=list)
    _seq: int = 0

    def _load(self) -> GadgetRecord | None:
        return self.storage.get(self.gadget_id)

    def _save(self, record: GadgetRecord) -> None:
        self.storage.put(record)

    def _audit(self, actor: str, action: str, detail: str) -> None:
        self._seq += 1
        self.audit.append(
            AuditEntry(
                id=str(self._seq),
                gadget_id=self.gadget_id,
                actor=actor,
                action=action,
                detail=detail,
                at=int(time.time() * 1000),
            )
        )

    def init(self, principal: Principal | None, name: str, app: str) -> GadgetRecord:
        actor = principal.user_id if principal else "platform"
        record = self._load()
        if record is None:
            # First /init call mints the gadget; the caller becomes the owner.
            record = create_gadget(self.gadget_id, name, app, actor, int(time.time() * 1000))
            self._save(record)
        self._audit(actor, "gadget.init", f"created {name} ({app})")
        return record

    def meta(self, principal: Principal | None) -> GadgetRecord:
        record = self._require(principal, "read")
        return record

    def share(self, principal: Principal | None, user_id: str, role: Role) -> GadgetRecord:
        record = self._require(principal, "admin")
        updated = grant_access(record, principal, user_id, role)
        if updated is None:
            raise PermissionError("only the owner can share")
        assert principal is not None
        self._save(updated)
        self._audit(principal.user_id, "acl.grant", f"{role.value}:{user_id}")
        return updated

    def revoke(self, principal: Principal | None, user_id: str) -> GadgetRecord:
        record = self._require(principal, "admin")
        updated = revoke_access(record, principal, user_id)
        if updated is None:
            raise PermissionError("only the owner can revoke")
        assert principal is not None
        self._save(updated)
        self._audit(principal.user_id, "acl.revoke", user_id)
        return updated

    def read_data(self, principal: Principal | None) -> dict[str, str]:
        record = self._require(principal, "read")
        return dict(record.data)

    def write_data(self, principal: Principal | None, updates: dict[str, str]) -> dict[str, str]:
        record = self._require(principal, "write")
        updated = update_gadget_data(record, updates)
        assert principal is not None
        self._save(updated)
        self._audit(principal.user_id, "data.write", f"{len(updates)} key(s)")
        return dict(updated.data)

    def request_approval(
        self, principal: Principal | None, action: str, target: str, payload: str
    ) -> ApprovalRequest:
        self._require(principal, "write")
        assert principal is not None
        req = queue_approval(
            self.gadget_id,
            action,
            target,
            payload,
            principal.user_id,
            str(uuid.uuid4()),
            int(time.time() * 1000),
        )
        self.approvals.append(req)
        self._audit(principal.user_id, "gatekeeper.request", f"{action} -> {target}")
        return req

    def list_approvals(self, principal: Principal | None) -> list[ApprovalRequest]:
        self._require(principal, "read")
        return list(self.approvals)

    def decide_approval(
        self, principal: Principal | None, request_id: str, decision: SideEffectState
    ) -> ApprovalRequest:
        record = self._require(principal, "admin")
        target = next((a for a in self.approvals if a.id == request_id), None)
        if target is None:
            raise LookupError("approval not found")
        updated = decide_approval(target, principal, record.meta.owner_id, decision)
        if updated is None:
            raise PermissionError("only the owner can decide approvals")
        assert principal is not None
        self.approvals = [updated if a.id == request_id else a for a in self.approvals]
        self._audit(principal.user_id, f"gatekeeper.{decision.value}", f"approval {request_id}")
        return updated

    def audit_log(self, principal: Principal | None) -> list[AuditEntry]:
        self._require(principal, "read")
        return list(self.audit)

    def _require(self, principal: Principal | None, action: str) -> GadgetRecord:
        record = self._load()
        if record is None:
            raise LookupError("gadget not found")
        perm = check_access(record.meta, principal, action)
        if not perm.allowed:
            raise PermissionError(perm.reason or "forbidden")
        return record
