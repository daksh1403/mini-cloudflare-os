"""Gatekeeper domain logic — the connector layer.

Side-effecting actions never fire directly. They are queued as pending
approvals with a full audit trail, and only an owner may approve or reject
them. This is the human-in-the-loop model from Cloudflare OS.
"""

from __future__ import annotations

from .types import ApprovalRequest, Principal, SideEffectState


def queue_approval(
    gadget_id: str,
    action: str,
    target: str,
    payload: str,
    requested_by: str,
    request_id: str,
    created_at: int,
) -> ApprovalRequest:
    if not action or not target:
        raise ValueError("action and target are required")
    if not requested_by:
        raise ValueError("requested_by is required")
    return ApprovalRequest(
        id=request_id,
        gadget_id=gadget_id,
        action=action,
        target=target,
        payload=payload,
        requested_by=requested_by,
        created_at=created_at,
    )


def decide_approval(
    request: ApprovalRequest,
    principal: Principal | None,
    owner_id: str,
    decision: SideEffectState,
) -> ApprovalRequest | None:
    """Approve or reject a pending approval. Only the owner may decide."""
    if principal is None or principal.user_id != owner_id:
        return None
    if request.state is not SideEffectState.PENDING:
        raise ValueError("approval is no longer pending")
    if decision not in (SideEffectState.APPROVED, SideEffectState.REJECTED):
        raise ValueError("decision must be approved or rejected")
    return ApprovalRequest(
        id=request.id,
        gadget_id=request.gadget_id,
        action=request.action,
        target=request.target,
        payload=request.payload,
        requested_by=request.requested_by,
        created_at=request.created_at,
        state=decision,
    )


class MemoryApprovalStore:
    """In-memory approval store — used by unit tests and the BDD runner."""

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

    def _key(self, gadget_id: str, request_id: str) -> str:
        return f"{gadget_id}:{request_id}"

    def create(self, request: ApprovalRequest) -> None:
        self._requests[self._key(request.gadget_id, request.id)] = request

    def list(self, gadget_id: str) -> list[ApprovalRequest]:
        return [r for r in self._requests.values() if r.gadget_id == gadget_id]

    def get(self, gadget_id: str, request_id: str) -> ApprovalRequest | None:
        return self._requests.get(self._key(gadget_id, request_id))

    def update(self, request: ApprovalRequest) -> None:
        self._requests[self._key(request.gadget_id, request.id)] = request
