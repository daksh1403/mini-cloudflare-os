"""Domain logic package — pure, testable core."""

from .gadget import check_access, create_gadget, grant_access, revoke_access, update_gadget_data
from .gatekeeper import decide_approval, queue_approval
from .types import (
    AclEntry,
    ApprovalRequest,
    AuditEntry,
    GadgetMeta,
    GadgetPermission,
    GadgetRecord,
    Principal,
    Role,
    SideEffectState,
)

__all__ = [
    "AclEntry",
    "ApprovalRequest",
    "AuditEntry",
    "GadgetMeta",
    "GadgetPermission",
    "GadgetRecord",
    "Principal",
    "Role",
    "SideEffectState",
    "check_access",
    "create_gadget",
    "decide_approval",
    "grant_access",
    "queue_approval",
    "revoke_access",
    "update_gadget_data",
]
