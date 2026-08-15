"""TDD tests for the GadgetService — the per-instance app logic."""

import pytest

from cloudflare_os.domain.gadget import MemoryStorage
from cloudflare_os.domain.types import Principal, Role, SideEffectState
from cloudflare_os.gadget_service import GadgetService


@pytest.fixture
def service() -> GadgetService:
    storage = MemoryStorage()
    service = GadgetService(gadget_id="g1", storage=storage)
    # The test suite acts as the gadget's owner from the start; the first
    # /init call mints the gadget with alice as owner.
    service.init(Principal(user_id="alice"), "Study Notes", "notes")
    return service


@pytest.fixture
def alice() -> Principal:
    return Principal(user_id="alice")


@pytest.fixture
def bob() -> Principal:
    return Principal(user_id="bob")


def test_init_sets_name_and_app(service: GadgetService, alice: Principal) -> None:
    record = service.init(alice, "Study Notes", "notes")
    assert record.meta.name == "Study Notes"
    assert record.meta.app == "notes"
    assert record.meta.owner_id == "alice"


def test_write_then_read_roundtrip(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    service.write_data(alice, {"title": "TDD"})
    data = service.read_data(alice)
    assert data == {"title": "TDD"}


def test_stranger_cannot_read(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    with pytest.raises(PermissionError):
        service.read_data(Principal(user_id="mallory"))


def test_viewer_cannot_write(service: GadgetService, alice: Principal, bob: Principal) -> None:
    service.init(alice, "Notes", "notes")
    service.share(alice, "bob", Role.VIEWER)
    with pytest.raises(PermissionError):
        service.write_data(bob, {"title": "hack"})


def test_editor_can_write(service: GadgetService, alice: Principal, bob: Principal) -> None:
    service.init(alice, "Notes", "notes")
    service.share(alice, "bob", Role.EDITOR)
    service.write_data(bob, {"title": "edit"})
    assert service.read_data(alice) == {"title": "edit"}


def test_gatekeeper_queues_pending(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    req = service.request_approval(alice, "post", "twitter", "hello")
    assert req.state is SideEffectState.PENDING
    assert len(service.list_approvals(alice)) == 1


def test_owner_approves_gatekeeper(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    req = service.request_approval(alice, "post", "twitter", "hello")
    decided = service.decide_approval(alice, req.id, SideEffectState.APPROVED)
    assert decided.state is SideEffectState.APPROVED


def test_non_owner_cannot_approve(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    req = service.request_approval(alice, "post", "twitter", "hello")
    with pytest.raises(PermissionError):
        service.decide_approval(Principal(user_id="mallory"), req.id, SideEffectState.APPROVED)


def test_audit_log_records_actions(service: GadgetService, alice: Principal) -> None:
    service.init(alice, "Notes", "notes")
    service.write_data(alice, {"title": "x"})
    service.request_approval(alice, "post", "twitter", "hello")
    entries = service.audit_log(alice)
    actions = [e.action for e in entries]
    assert "gadget.init" in actions
    assert "data.write" in actions
    assert "gatekeeper.request" in actions
