"""Cloudflare Durable Object — the real per-Gadget instance.

This is the Workers runtime equivalent of `GadgetService`: one Durable Object
instance per Gadget id, with transactional storage via `ctx.storage`. It
reuses the exact same domain security logic (check_access etc.) so the
pytest/behave suite that tests the domain is the same code that runs on
Cloudflare.

Security model (unchanged): the object enforces the platform's ACL decisions;
it never grants access on its own.

RPC design: each route is an explicit method with a JSON-safe signature
(strings / dict[str, str] / lists), matching the official
python-workers-examples Durable Object pattern (stub.add_message,
stub.get_messages). Returning arbitrary Python objects or nested dataclasses
across the RPC boundary is unreliable in the Python Workers beta, so we keep
everything JSON-serializable here.

NOTE: Cloudflare's Python Workers bundler flattens modules to the bundle
root (worker.py, durable_object.py, domain/...), so this file uses FLAT
absolute imports that match that layout. All helper functions are defined as
staticmethods ON the class, because module-level functions defined after the
class are not reliably visible to class methods inside the Pyodide runtime.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from domain.gadget import (
    check_access,
    create_gadget,
    grant_access,
    revoke_access,
    update_gadget_data,
)
from domain.gatekeeper import decide_approval, queue_approval
from domain.types import (
    AclEntry,
    ApprovalRequest,
    AuditEntry,
    GadgetMeta,
    GadgetRecord,
    Principal,
    Role,
    SideEffectState,
)
from workers import DurableObject


class GadgetObject(DurableObject):
    """One Durable Object per Gadget. State persists in `self.ctx.storage`."""

    # ---- pure helpers (staticmethods: reliable inside Pyodide) -----------

    @staticmethod
    def _principal(user_id: str | None) -> Principal | None:
        return Principal(user_id=user_id) if user_id else None

    @staticmethod
    def _record_to_json(record: GadgetRecord) -> dict[str, Any]:
        return {
            "meta": {
                "id": record.meta.id,
                "name": record.meta.name,
                "app": record.meta.app,
                "owner_id": record.meta.owner_id,
                "created_at": record.meta.created_at,
                "acl": [{"user_id": e.user_id, "role": e.role.value} for e in record.meta.acl],
            },
            "data": record.data,
        }

    @staticmethod
    def _record_from_json(raw: Any) -> GadgetRecord:
        meta = raw["meta"]
        return GadgetRecord(
            GadgetMeta(
                id=meta["id"],
                name=meta["name"],
                app=meta["app"],
                owner_id=meta["owner_id"],
                created_at=meta["created_at"],
                acl=[AclEntry(e["user_id"], Role(e["role"])) for e in meta["acl"]],
            ),
            dict(raw.get("data", {})),
        )

    @staticmethod
    def _approval_to_json(a: ApprovalRequest) -> dict[str, Any]:
        return {
            "id": a.id,
            "gadget_id": a.gadget_id,
            "action": a.action,
            "target": a.target,
            "payload": a.payload,
            "requested_by": a.requested_by,
            "created_at": a.created_at,
            "state": a.state.value,
        }

    @staticmethod
    def _approval_from_json(raw: Any) -> ApprovalRequest:
        return ApprovalRequest(
            id=raw["id"],
            gadget_id=raw["gadget_id"],
            action=raw["action"],
            target=raw["target"],
            payload=raw.get("payload", ""),
            requested_by=raw["requested_by"],
            created_at=raw["created_at"],
            state=SideEffectState(raw["state"]),
        )

    @staticmethod
    def _meta_out(meta: GadgetMeta) -> dict[str, Any]:
        return {
            "id": meta.id,
            "name": meta.name,
            "app": meta.app,
            "owner_id": meta.owner_id,
            "created_at": meta.created_at,
            "acl": [{"user_id": e.user_id, "role": e.role.value} for e in meta.acl],
        }

    @staticmethod
    def _approval_out(a: ApprovalRequest) -> dict[str, Any]:
        return {
            "id": a.id,
            "gadget_id": a.gadget_id,
            "action": a.action,
            "target": a.target,
            "payload": a.payload,
            "requested_by": a.requested_by,
            "created_at": a.created_at,
            "state": a.state.value,
        }

    @staticmethod
    def _audit_out(e: AuditEntry) -> dict[str, Any]:
        return {
            "id": e.id,
            "gadget_id": e.gadget_id,
            "actor": e.actor,
            "action": e.action,
            "detail": e.detail,
            "at": e.at,
        }

    # ---- state helpers ---------------------------------------------------

    async def _load(self) -> GadgetRecord | None:
        raw = await self.ctx.storage.get("record")
        if raw is None:
            return None
        # Stored as a JSON string for clone-safety across the storage boundary.
        return self._record_from_json(json.loads(raw))

    async def _save(self, record: GadgetRecord) -> None:
        await self.ctx.storage.put("record", json.dumps(self._record_to_json(record)))

    async def _approvals(self) -> list[ApprovalRequest]:
        raw = await self.ctx.storage.get("approvals")
        if raw is None:
            return []
        return [self._approval_from_json(a) for a in json.loads(raw)]

    async def _save_approvals(self, approvals: list[ApprovalRequest]) -> None:
        await self.ctx.storage.put("approvals", json.dumps([self._approval_to_json(a) for a in approvals]))

    async def _audit(self, actor: str, action: str, detail: str) -> None:
        raw = await self.ctx.storage.get("audit")
        entries: list[dict[str, Any]] = json.loads(raw) if raw else []
        entries.append(
            {
                "id": str(len(entries) + 1),
                "gadget_id": self.ctx.id.toString(),
                "actor": actor,
                "action": action,
                "detail": detail,
                "at": int(time.time() * 1000),
            }
        )
        await self.ctx.storage.put("audit", json.dumps(entries))

    async def _audit_log(self) -> list[AuditEntry]:
        raw = await self.ctx.storage.get("audit")
        entries: list[dict[str, Any]] = json.loads(raw) if raw else []
        return [
            AuditEntry(
                id=e["id"],
                gadget_id=e["gadget_id"],
                actor=e["actor"],
                action=e["action"],
                detail=e["detail"],
                at=e["at"],
            )
            for e in entries
        ]

    # ---- RPC methods (JSON-safe in/out) ----------------------------------

    async def init(self, name: str, app: str, user_id: str | None) -> dict[str, Any]:
        principal = self._principal(user_id)
        actor = principal.user_id if principal else "platform"
        record = await self._load()
        if record is None:
            record = create_gadget(self.ctx.id.toString(), name, app, actor, int(time.time() * 1000))
            await self._save(record)
            await self._audit(actor, "gadget.init", f"created {name} ({app})")
        return {"status": 200, "json": {"gadget": self._meta_out(record.meta)}}

    async def meta(self, user_id: str | None) -> dict[str, Any]:
        record, err = await self._require(user_id, "read")
        if err:
            return err
        return {"status": 200, "json": {"gadget": self._meta_out(record.meta)}}

    async def share(self, user_id: str | None, target_user: str, role: str) -> dict[str, Any]:
        record, err = await self._require(user_id, "admin")
        if err:
            return err
        updated = grant_access(record, self._principal(user_id), target_user, Role(role))
        if updated is None:
            return {"status": 403, "json": {"error": "only the owner can share"}}
        await self._save(updated)
        await self._audit(user_id, "acl.grant", f"{role}:{target_user}")
        return {"status": 200, "json": {"gadget": self._meta_out(updated.meta)}}

    async def revoke(self, user_id: str | None, target_user: str) -> dict[str, Any]:
        record, err = await self._require(user_id, "admin")
        if err:
            return err
        updated = revoke_access(record, self._principal(user_id), target_user)
        if updated is None:
            return {"status": 403, "json": {"error": "only the owner can revoke"}}
        await self._save(updated)
        await self._audit(user_id, "acl.revoke", target_user)
        return {"status": 200, "json": {"gadget": self._meta_out(updated.meta)}}

    async def read_data(self, user_id: str | None) -> dict[str, Any]:
        record, err = await self._require(user_id, "read")
        if err:
            return err
        return {"status": 200, "json": {"data": record.data}}

    async def write_data(self, user_id: str | None, values: dict[str, str]) -> dict[str, Any]:
        record, err = await self._require(user_id, "write")
        if err:
            return err
        updated = update_gadget_data(record, values)
        await self._save(updated)
        await self._audit(user_id, "data.write", f"{len(values)} key(s)")
        return {"status": 200, "json": {"data": updated.data}}

    async def request_approval(
        self, user_id: str | None, action: str, target: str, payload: str
    ) -> dict[str, Any]:
        record, err = await self._require(user_id, "write")
        if err:
            return err
        req = queue_approval(
            record.meta.id,
            action,
            target,
            payload,
            user_id,
            str(uuid.uuid4()),
            int(time.time() * 1000),
        )
        approvals = await self._approvals()
        approvals.append(req)
        await self._save_approvals(approvals)
        await self._audit(user_id, "gatekeeper.request", f"{action} -> {target}")
        return {"status": 200, "json": {"approval": self._approval_out(req)}}

    async def list_approvals(self, user_id: str | None) -> dict[str, Any]:
        _, err = await self._require(user_id, "read")
        if err:
            return err
        return {
            "status": 200,
            "json": {"approvals": [self._approval_out(a) for a in await self._approvals()]},
        }

    async def decide_approval(self, user_id: str | None, request_id: str, decision: str) -> dict[str, Any]:
        record, err = await self._require(user_id, "admin")
        if err:
            return err
        approvals = await self._approvals()
        target = next((a for a in approvals if a.id == request_id), None)
        if target is None:
            return {"status": 404, "json": {"error": "approval not found"}}
        updated = decide_approval(
            target, self._principal(user_id), record.meta.owner_id, SideEffectState(decision)
        )
        if updated is None:
            return {"status": 403, "json": {"error": "only the owner can decide approvals"}}
        approvals = [updated if a.id == request_id else a for a in approvals]
        await self._save_approvals(approvals)
        await self._audit(user_id, f"gatekeeper.{decision}", f"approval {request_id}")
        return {"status": 200, "json": {"approval": self._approval_out(updated)}}

    async def audit(self, user_id: str | None) -> dict[str, Any]:
        _, err = await self._require(user_id, "read")
        if err:
            return err
        return {
            "status": 200,
            "json": {"audit": [self._audit_out(e) for e in await self._audit_log()]},
        }

    async def _require(self, user_id: str | None, action: str) -> tuple[GadgetRecord, dict[str, Any] | None]:
        """Returns (record, None) on success, or (None, error-dict) on failure."""
        record = await self._load()
        if record is None:
            return None, {"status": 404, "json": {"error": "gadget not found"}}
        perm = check_access(record.meta, self._principal(user_id), action)
        if not perm.allowed:
            return None, {"status": 403, "json": {"error": perm.reason or "forbidden"}}
        return record, None
