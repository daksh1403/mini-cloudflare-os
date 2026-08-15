"""Platform Worker — the single entry point (FastAPI app).

The platform owns ALL access control:
  - it maps the caller to a Principal (here via the `x-user-id` header; in
    production this is a validated session/JWT),
  - it resolves "gadget id" → GadgetService (one instance per Gadget),
  - it never lets a caller touch a gadget they have no permission for
    (GadgetService enforces the ACL on every operation).

Gadget ids live in the URL: /gadgets/:id/...
"""

from __future__ import annotations

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .domain.types import (
    ApprovalRequest,
    AuditEntry,
    GadgetMeta,
    Principal,
    Role,
    SideEffectState,
)
from .gadget_service import GadgetService

app = FastAPI(title="Mini Cloudflare OS", version="0.1.0")


@app.exception_handler(PermissionError)
async def _permission_error(_: Request, exc: PermissionError) -> JSONResponse:
    return JSONResponse(status_code=403, content={"error": str(exc)})


@app.exception_handler(LookupError)
async def _not_found(_: Request, exc: LookupError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": str(exc)})

JsonDict = dict[str, object]


class InitBody(BaseModel):
    name: str = "untitled"
    app: str = "notes"


class ShareBody(BaseModel):
    user_id: str
    role: Role


class RevokeBody(BaseModel):
    user_id: str


class WriteBody(BaseModel):
    values: dict[str, str]


class GatekeeperBody(BaseModel):
    action: str
    target: str
    payload: str = ""


class DecideBody(BaseModel):
    id: str
    decision: SideEffectState


def _principal(user_id: str | None) -> Principal | None:
    return Principal(user_id=user_id) if user_id else None


def _service(gadget_id: str) -> GadgetService:
    # In production this resolves to a per-gadget Durable Object / SQLite
    # instance. Here we keep a process-local registry so the API is real and
    # the storage is swappable (MemoryStorage in tests).
    from .storage import gadget_registry

    return gadget_registry.get_or_create(gadget_id)


@app.get("/api/health")
def health() -> JsonDict:
    return {"status": "ok"}


@app.post("/gadgets/{gadget_id}/init")
def init_gadget(gadget_id: str, body: InitBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    principal = _principal(x_user_id)
    record = _service(gadget_id).init(principal, body.name, body.app)
    return {"gadget": _meta_out(record.meta)}


@app.get("/gadgets/{gadget_id}/meta")
def get_meta(gadget_id: str, x_user_id: str | None = Header(default=None)) -> JsonDict:
    record = _service(gadget_id).meta(_principal(x_user_id))
    return {"gadget": _meta_out(record.meta)}


@app.post("/gadgets/{gadget_id}/share")
def share(gadget_id: str, body: ShareBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    record = _service(gadget_id).share(_principal(x_user_id), body.user_id, body.role)
    return {"gadget": _meta_out(record.meta)}


@app.post("/gadgets/{gadget_id}/revoke")
def revoke(gadget_id: str, body: RevokeBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    record = _service(gadget_id).revoke(_principal(x_user_id), body.user_id)
    return {"gadget": _meta_out(record.meta)}


@app.get("/gadgets/{gadget_id}/data")
def read_data(gadget_id: str, x_user_id: str | None = Header(default=None)) -> JsonDict:
    return {"data": _service(gadget_id).read_data(_principal(x_user_id))}


@app.post("/gadgets/{gadget_id}/data")
def write_data(gadget_id: str, body: WriteBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    return {"data": _service(gadget_id).write_data(_principal(x_user_id), body.values)}


@app.post("/gadgets/{gadget_id}/gatekeeper")
def gatekeeper(gadget_id: str, body: GatekeeperBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    approval = _service(gadget_id).request_approval(
        _principal(x_user_id), body.action, body.target, body.payload
    )
    return {"approval": _approval_out(approval)}


@app.get("/gadgets/{gadget_id}/approvals")
def approvals(gadget_id: str, x_user_id: str | None = Header(default=None)) -> JsonDict:
    return {
        "approvals": [_approval_out(a) for a in _service(gadget_id).list_approvals(_principal(x_user_id))]
    }


@app.post("/gadgets/{gadget_id}/approvals/decide")
def decide(gadget_id: str, body: DecideBody, x_user_id: str | None = Header(default=None)) -> JsonDict:
    approval = _service(gadget_id).decide_approval(_principal(x_user_id), body.id, body.decision)
    return {"approval": _approval_out(approval)}


@app.get("/gadgets/{gadget_id}/audit")
def audit(gadget_id: str, x_user_id: str | None = Header(default=None)) -> JsonDict:
    return {"audit": [_audit_out(e) for e in _service(gadget_id).audit_log(_principal(x_user_id))]}


def _meta_out(meta: GadgetMeta) -> JsonDict:
    return {
        "id": meta.id,
        "name": meta.name,
        "app": meta.app,
        "owner_id": meta.owner_id,
        "created_at": meta.created_at,
        "acl": [{"user_id": e.user_id, "role": e.role.value} for e in meta.acl],
    }


def _approval_out(a: ApprovalRequest) -> JsonDict:
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


def _audit_out(e: AuditEntry) -> JsonDict:
    return {
        "id": e.id,
        "gadget_id": e.gadget_id,
        "actor": e.actor,
        "action": e.action,
        "detail": e.detail,
        "at": e.at,
    }
