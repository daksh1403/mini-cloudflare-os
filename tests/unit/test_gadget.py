"""TDD unit tests — the Red/Green/Refactor core, pytest style.

Coverage of the platform's security model and gadget lifecycle:
  - happy paths (owner creates, reads, writes)
  - sad paths (stranger denied, bad roles, invalid inputs)
  - fixtures isolation (every test gets a fresh gadget)
"""

import pytest

from cloudflare_os.domain.gadget import (
    check_access,
    create_gadget,
    grant_access,
    revoke_access,
    update_gadget_data,
)
from cloudflare_os.domain.gatekeeper import decide_approval, queue_approval
from cloudflare_os.domain.types import Principal, Role, SideEffectState


@pytest.fixture
def alice() -> Principal:
    return Principal(user_id="alice")


@pytest.fixture
def mallory() -> Principal:
    return Principal(user_id="mallory")


@pytest.fixture
def gadget(alice: Principal) -> object:
    return create_gadget("g1", "Study Notes", "notes", alice.user_id, 1000)


# ---------------------------------------------------------------------------
# create_gadget — happy + sad paths
# ---------------------------------------------------------------------------


def test_create_gadget_adds_owner_as_owner(alice: Principal) -> None:
    record = create_gadget("g1", "Notes", "notes", alice.user_id, 1000)
    assert record.meta.owner_id == "alice"
    assert len(record.meta.acl) == 1
    assert record.meta.acl[0].role is Role.OWNER
    assert record.data == {}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"id": "", "name": "n", "app": "a", "owner_id": "u"},
        {"id": "g", "name": "", "app": "a", "owner_id": "u"},
        {"id": "g", "name": "n", "app": "", "owner_id": "u"},
        {"id": "g", "name": "n", "app": "a", "owner_id": ""},
    ],
)
def test_create_gadget_requires_all_fields(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        create_gadget(**kwargs, created_at=0)


def test_create_gadget_rejects_long_name() -> None:
    with pytest.raises(ValueError):
        create_gadget("g", "x" * 65, "notes", "u", 0)


# ---------------------------------------------------------------------------
# check_access — the platform security model
# ---------------------------------------------------------------------------


def test_owner_can_do_everything(gadget, alice: Principal) -> None:
    for action in ("read", "write", "admin"):
        perm = check_access(gadget.meta, alice, action)
        assert perm.allowed
        assert perm.role is Role.OWNER


def test_stranger_is_denied_everything(gadget, mallory: Principal) -> None:
    for action in ("read", "write", "admin"):
        perm = check_access(gadget.meta, mallory, action)
        assert not perm.allowed
        assert perm.reason == "not a member of this gadget"


def test_anonymous_is_denied_with_auth_reason(gadget) -> None:
    perm = check_access(gadget.meta, None, "read")
    assert not perm.allowed
    assert perm.reason == "authentication required"


def test_viewer_can_read_but_not_write_or_admin(gadget, alice: Principal) -> None:
    viewer = Principal(user_id="bob")
    updated = grant_access(gadget, alice, "bob", Role.VIEWER)
    assert updated is not None
    assert check_access(updated.meta, viewer, "read").allowed
    assert not check_access(updated.meta, viewer, "write").allowed
    assert not check_access(updated.meta, viewer, "admin").allowed


def test_editor_can_read_and_write_but_not_admin(gadget, alice: Principal) -> None:
    editor = Principal(user_id="bob")
    updated = grant_access(gadget, alice, "bob", Role.EDITOR)
    assert updated is not None
    assert check_access(updated.meta, editor, "read").allowed
    assert check_access(updated.meta, editor, "write").allowed
    assert not check_access(updated.meta, editor, "admin").allowed


# ---------------------------------------------------------------------------
# grant_access / revoke_access — sharing
# ---------------------------------------------------------------------------


def test_grant_access_adds_member(gadget, alice: Principal) -> None:
    updated = grant_access(gadget, alice, "bob", Role.EDITOR)
    assert updated is not None
    assert any(e.user_id == "bob" and e.role is Role.EDITOR for e in updated.meta.acl)


def test_grant_access_denied_for_non_owner(gadget, mallory: Principal) -> None:
    assert grant_access(gadget, mallory, "bob", Role.EDITOR) is None


def test_grant_access_rejects_duplicate_member(gadget, alice: Principal) -> None:
    with pytest.raises(ValueError):
        grant_access(gadget, alice, "alice", Role.EDITOR)


def test_revoke_access_removes_member(gadget, alice: Principal) -> None:
    updated = grant_access(gadget, alice, "bob", Role.VIEWER)
    assert updated is not None
    revoked = revoke_access(updated, alice, "bob")
    assert revoked is not None
    assert not any(e.user_id == "bob" for e in revoked.meta.acl)


def test_revoke_access_denied_for_non_owner(gadget, mallory: Principal) -> None:
    assert revoke_access(gadget, mallory, "bob") is None


def test_revoke_access_cannot_remove_owner(gadget, alice: Principal) -> None:
    with pytest.raises(ValueError):
        revoke_access(gadget, alice, "alice")


# ---------------------------------------------------------------------------
# update_gadget_data
# ---------------------------------------------------------------------------


def test_update_data_merges_and_preserves(gadget) -> None:
    updated = update_gadget_data(gadget, {"title": "Hello"})
    updated2 = update_gadget_data(updated, {"body": "World"})
    assert updated2.data == {"title": "Hello", "body": "World"}
    # Original record is untouched (immutable-style update).
    assert gadget.data == {}


# ---------------------------------------------------------------------------
# Gatekeeper — side effects need approval
# ---------------------------------------------------------------------------


def test_queue_approval_starts_pending() -> None:
    req = queue_approval("g1", "post", "twitter", "hello", "alice", "a1", 1000)
    assert req.state is SideEffectState.PENDING
    assert req.requested_by == "alice"


def test_owner_can_approve() -> None:
    req = queue_approval("g1", "post", "twitter", "hello", "alice", "a1", 1000)
    approved = decide_approval(req, Principal(user_id="alice"), "alice", SideEffectState.APPROVED)
    assert approved is not None
    assert approved.state is SideEffectState.APPROVED


def test_non_owner_cannot_decide() -> None:
    req = queue_approval("g1", "post", "twitter", "hello", "alice", "a1", 1000)
    assert decide_approval(req, Principal(user_id="mallory"), "alice", SideEffectState.APPROVED) is None


def test_decide_rejects_already_decided() -> None:
    req = queue_approval("g1", "post", "twitter", "hello", "alice", "a1", 1000)
    approved = decide_approval(req, Principal(user_id="alice"), "alice", SideEffectState.APPROVED)
    assert approved is not None
    with pytest.raises(ValueError):
        decide_approval(approved, Principal(user_id="alice"), "alice", SideEffectState.REJECTED)
